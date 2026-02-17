"""
RLPx connection — manages the encrypted transport for a single peer.

Combines handshake, framing, and async read/write.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from ethclient.networking.rlpx.handshake import Handshake, ecies_encrypt
from ethclient.networking.rlpx.framing import FrameCoder, snappy_compress, snappy_decompress


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
        self.use_snappy: bool = True

    async def initiate_handshake(self, remote_pubkey: bytes) -> bool:
        """Perform initiator-side handshake."""
        self.remote_pubkey = remote_pubkey
        try:
            # Send auth
            auth_data = self.handshake.create_auth(remote_pubkey)
            self.writer.write(auth_data)
            await self.writer.drain()

            # Read ack
            ack_size_bytes = await self.reader.readexactly(2)
            ack_size = int.from_bytes(ack_size_bytes, "big")
            ack_encrypted = await self.reader.readexactly(ack_size)
            ack_data = ack_size_bytes + ack_encrypted

            ack_msg = self.handshake.handle_ack(ack_data, remote_pubkey)

            # Derive session keys
            keys = self.handshake.derive_secrets(
                auth_msg=auth_data,
                ack_msg=ack_data,
                remote_nonce=ack_msg.nonce,
                remote_ephemeral_pubkey=ack_msg.recipient_pubkey,
                is_initiator=True,
            )
            self.coder = FrameCoder(
                keys.aes_secret, keys.mac_secret,
                keys.egress_mac, keys.ingress_mac,
            )
            return True
        except Exception:
            return False

    async def accept_handshake(self) -> bool:
        """Perform recipient-side handshake."""
        try:
            # Read auth
            auth_size_bytes = await self.reader.readexactly(2)
            auth_size = int.from_bytes(auth_size_bytes, "big")
            auth_encrypted = await self.reader.readexactly(auth_size)
            auth_data = auth_size_bytes + auth_encrypted

            auth_msg = self.handshake.handle_auth(auth_data)
            self.remote_pubkey = b"\x04" + auth_msg.initiator_pubkey

            # Send ack
            ack_plain = self.handshake.create_ack()
            ack_encrypted = ecies_encrypt(self.remote_pubkey, ack_plain)
            ack_size = len(ack_encrypted)
            ack_data = ack_size.to_bytes(2, "big") + ack_encrypted
            self.writer.write(ack_data)
            await self.writer.drain()

            # Derive session keys
            keys = self.handshake.derive_secrets(
                auth_msg=auth_data,
                ack_msg=ack_data,
                remote_nonce=auth_msg.nonce,
                remote_ephemeral_pubkey=auth_msg.signature[:64],
                is_initiator=False,
            )
            self.coder = FrameCoder(
                keys.aes_secret, keys.mac_secret,
                keys.egress_mac, keys.ingress_mac,
            )
            return True
        except Exception:
            return False

    async def send_message(self, msg_code: int, payload: bytes) -> None:
        """Encrypt and send a framed message."""
        if self.coder is None:
            raise RuntimeError("Handshake not completed")
        if self.use_snappy and msg_code > 0:
            payload = snappy_compress(payload)
        frame = self.coder.encode_frame(msg_code, payload)
        self.writer.write(frame)
        await self.writer.drain()

    async def recv_message(self) -> Optional[tuple[int, bytes]]:
        """Receive and decrypt a framed message.

        Returns (msg_code, payload) or None on error.
        """
        if self.coder is None:
            raise RuntimeError("Handshake not completed")
        try:
            # Read header (32 bytes)
            header_data = await self.reader.readexactly(32)
            frame_size = self.coder.decode_header(header_data)
            if frame_size is None:
                return None

            # Read body (padded + 16-byte MAC)
            padded_size = ((frame_size + 15) // 16) * 16
            body_data = await self.reader.readexactly(padded_size + 16)
            result = self.coder.decode_body(body_data, frame_size)
            if result is None:
                return None

            msg_code, payload = result
            if self.use_snappy and msg_code > 0:
                payload = snappy_decompress(payload)
            return msg_code, payload

        except (asyncio.IncompleteReadError, ConnectionError):
            return None

    def close(self) -> None:
        """Close the connection."""
        try:
            self.writer.close()
        except Exception:
            pass
