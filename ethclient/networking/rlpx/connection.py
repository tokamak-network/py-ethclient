"""
RLPx connection — manages the encrypted transport for a single peer.

Combines handshake, framing, and async read/write.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from coincurve import PublicKey

from ethclient.networking.rlpx.handshake import Handshake, _ecdh_raw
from ethclient.networking.rlpx.framing import FrameCoder, snappy_compress, snappy_decompress

logger = logging.getLogger(__name__)


class RLPxConnection:
    """An encrypted RLPx connection to a single peer."""

    def __init__(
        self,
        private_key: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.private_key = private_key
        self.reader = reader
        self.writer = writer
        self.handshake = Handshake(private_key)
        self.coder: Optional[FrameCoder] = None
        self.remote_pubkey: Optional[bytes] = None
        self.use_snappy: bool = False  # enabled after Hello exchange
        self.last_handshake_error: Optional[str] = None
        self._send_lock = asyncio.Lock()

    async def initiate_handshake(self, remote_pubkey: bytes) -> bool:
        """Perform initiator-side handshake."""
        self.remote_pubkey = remote_pubkey
        self.last_handshake_error = None
        try:
            # Send auth
            auth_data = await asyncio.to_thread(self.handshake.create_auth, remote_pubkey)
            self.writer.write(auth_data)
            await self.writer.drain()
            logger.debug("Sent auth message (%d bytes)", len(auth_data))

            # Read ack (with timeout)
            ack_size_bytes = await asyncio.wait_for(
                self.reader.readexactly(2), timeout=10.0
            )
            ack_size = int.from_bytes(ack_size_bytes, "big")
            ack_encrypted = await asyncio.wait_for(
                self.reader.readexactly(ack_size), timeout=10.0
            )
            ack_data = ack_size_bytes + ack_encrypted
            logger.debug("Received ack message (%d bytes)", len(ack_data))

            ack_msg = await asyncio.to_thread(self.handshake.handle_ack, ack_data)

            # Derive session keys
            keys = await asyncio.to_thread(
                self.handshake.derive_secrets,
                auth_data,
                ack_data,
                ack_msg.nonce,
                ack_msg.recipient_pubkey,
                True,
            )
            self.coder = FrameCoder(
                keys.aes_secret, keys.mac_secret,
                keys.egress_mac, keys.ingress_mac,
            )
            logger.debug("RLPx handshake completed (initiator)")
            return True
        except Exception as e:
            self.last_handshake_error = f"{type(e).__name__}: {e}"
            logger.debug("Initiator handshake failed: %s", e)
            return False

    async def accept_handshake(self) -> bool:
        """Perform recipient-side handshake."""
        self.last_handshake_error = None
        try:
            # Read auth
            auth_size_bytes = await asyncio.wait_for(
                self.reader.readexactly(2), timeout=10.0
            )
            auth_size = int.from_bytes(auth_size_bytes, "big")
            auth_encrypted = await asyncio.wait_for(
                self.reader.readexactly(auth_size), timeout=10.0
            )
            auth_data = auth_size_bytes + auth_encrypted

            auth_msg = await asyncio.to_thread(self.handshake.handle_auth, auth_data)
            self.remote_pubkey = b"\x04" + auth_msg.initiator_pubkey

            # Recover remote ephemeral pubkey from signature
            # The signature is over: ecdh(initiator, recipient) XOR initiator_nonce
            shared = _ecdh_raw(self.private_key, self.remote_pubkey)
            xor_val = bytes(a ^ b for a, b in zip(shared[:32], auth_msg.nonce))
            remote_eph_pub = await asyncio.to_thread(
                PublicKey.from_signature_and_message,
                auth_msg.signature,
                xor_val,
                None,
            )
            remote_ephemeral_pubkey = remote_eph_pub.format(compressed=False)[1:]

            # Send ack
            ack_data = await asyncio.to_thread(self.handshake.create_ack, self.remote_pubkey)
            self.writer.write(ack_data)
            await self.writer.drain()

            # Derive session keys
            keys = await asyncio.to_thread(
                self.handshake.derive_secrets,
                auth_data,
                ack_data,
                auth_msg.nonce,
                remote_ephemeral_pubkey,
                False,
            )
            self.coder = FrameCoder(
                keys.aes_secret, keys.mac_secret,
                keys.egress_mac, keys.ingress_mac,
            )
            logger.debug("RLPx handshake completed (recipient)")
            return True
        except Exception as e:
            self.last_handshake_error = f"{type(e).__name__}: {e}"
            logger.debug("Recipient handshake failed: %s", e)
            return False

    async def send_message(self, msg_code: int, payload: bytes) -> None:
        """Encrypt and send a framed message.

        Uses a lock to prevent concurrent encode_frame() calls from
        corrupting the stateful AES-CTR cipher and MAC state.
        """
        if self.coder is None:
            raise RuntimeError("Handshake not completed")
        async with self._send_lock:
            if self.writer.is_closing():
                raise ConnectionError("transport is closing")
            # Snappy applies to all messages after Hello exchange
            if self.use_snappy:
                payload = snappy_compress(payload)
            frame = self.coder.encode_frame(msg_code, payload)
            try:
                self.writer.write(frame)
                await self.writer.drain()
            except (OSError, ConnectionError, asyncio.IncompleteReadError) as exc:
                raise ConnectionError(f"send failed: {type(exc).__name__}: {exc}") from exc

    async def recv_message(self, timeout: float = 30.0) -> Optional[tuple[int, bytes]]:
        """Receive and decrypt a framed message.

        Returns (msg_code, payload) or None on error/timeout.
        """
        if self.coder is None:
            raise RuntimeError("Handshake not completed")
        try:
            # Read header (32 bytes)
            header_data = await asyncio.wait_for(
                self.reader.readexactly(32), timeout=timeout
            )
            frame_size = self.coder.decode_header(header_data)
            if frame_size is None:
                logger.debug("Header MAC verification failed")
                return None

            # Read body (padded + 16-byte MAC)
            padded_size = ((frame_size + 15) // 16) * 16
            body_data = await asyncio.wait_for(
                self.reader.readexactly(padded_size + 16), timeout=timeout
            )
            result = self.coder.decode_body(body_data, frame_size)
            if result is None:
                logger.debug("Body MAC verification failed")
                return None

            msg_code, payload = result
            # Snappy applies to all messages after Hello exchange
            if self.use_snappy:
                payload = snappy_decompress(payload)
            return msg_code, payload

        except asyncio.TimeoutError:
            logger.debug("recv_message timed out")
            return None
        except (asyncio.IncompleteReadError, ConnectionError) as e:
            # Propagate connection errors so caller can identify disconnect cause
            raise

    def close(self) -> None:
        """Close the connection."""
        try:
            self.writer.close()
        except Exception:
            pass
