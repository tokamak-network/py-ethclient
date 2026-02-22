"""
RLPx message framing — encrypts/decrypts messages for the RLPx transport.

Frame structure:
  header (32 bytes): header-data(16) || header-mac(16)
  body: frame-data(padded to 16 bytes) || frame-mac(16)

Header-data: frame-size(3 bytes, big-endian) || header-rlp(13 bytes, zero-padded)
"""

from __future__ import annotations

from typing import Optional

from Crypto.Cipher import AES

from ethclient.common import rlp


class FrameCoder:
    """Encrypts and decrypts RLPx frames using session keys."""

    def __init__(
        self,
        aes_secret: bytes,
        mac_secret: bytes,
        egress_mac,
        ingress_mac,
    ) -> None:
        self.mac_secret = mac_secret
        self.egress_mac = egress_mac
        self.ingress_mac = ingress_mac

        # AES-256-CTR for frame encryption (zero IV, counter state preserved)
        zero_iv = b"\x00" * 16
        self.egress_cipher = AES.new(aes_secret, AES.MODE_CTR, nonce=b"", initial_value=zero_iv)
        self.ingress_cipher = AES.new(aes_secret, AES.MODE_CTR, nonce=b"", initial_value=zero_iv)

        # AES-ECB for MAC seed encryption
        self.mac_enc = AES.new(mac_secret, AES.MODE_ECB)

    def encode_frame(self, msg_code: int, payload: bytes) -> bytes:
        """Encode and encrypt a single RLPx frame.

        Returns the complete frame bytes (header + body) ready to send.
        """
        # Build frame data: msg_code as RLP + payload
        code_rlp = rlp.encode(msg_code)
        frame_data = code_rlp + payload

        frame_size = len(frame_data)

        # Header: 3-byte frame size + 13 bytes header RLP (capability info)
        # For simplicity, header RLP is [0xC0, 0x80, 0x80] + zero padding
        header_data = frame_size.to_bytes(3, "big")
        header_rlp = bytes([0xC0 + 2, 0x80, 0x80])  # [0, 0] as RLP list
        header_data += header_rlp
        header_data = header_data.ljust(16, b"\x00")

        # Encrypt header
        encrypted_header = self.egress_cipher.encrypt(header_data)

        # Header MAC
        header_mac = self._update_egress_mac(encrypted_header)

        # Pad frame data to 16-byte boundary
        padded_size = ((frame_size + 15) // 16) * 16
        padded_frame = frame_data.ljust(padded_size, b"\x00")

        # Encrypt frame body
        encrypted_body = self.egress_cipher.encrypt(padded_frame)

        # Body MAC
        body_mac = self._update_egress_mac_body(encrypted_body)

        return encrypted_header + header_mac + encrypted_body + body_mac

    def decode_header(self, data: bytes) -> Optional[int]:
        """Decode frame header. Returns frame body size or None on MAC failure.

        Expects exactly 32 bytes (16 header + 16 MAC).
        """
        if len(data) < 32:
            return None

        encrypted_header = data[:16]
        header_mac = data[16:32]

        # Verify header MAC
        expected_mac = self._update_ingress_mac(encrypted_header)
        if expected_mac != header_mac:
            return None

        # Decrypt header
        header_data = self.ingress_cipher.decrypt(encrypted_header)

        # Parse frame size (first 3 bytes)
        frame_size = int.from_bytes(header_data[:3], "big")
        return frame_size

    def decode_body(self, data: bytes, frame_size: int) -> Optional[tuple[int, bytes]]:
        """Decode frame body. Returns (msg_code, payload) or None on MAC failure.

        data should contain the encrypted body + 16-byte MAC.
        """
        padded_size = ((frame_size + 15) // 16) * 16
        expected_len = padded_size + 16  # body + mac

        if len(data) < expected_len:
            return None

        encrypted_body = data[:padded_size]
        body_mac = data[padded_size:padded_size + 16]

        # Verify body MAC
        expected_mac = self._update_ingress_mac_body(encrypted_body)
        if expected_mac != body_mac:
            return None

        # Decrypt
        frame_data = self.ingress_cipher.decrypt(encrypted_body)
        frame_data = frame_data[:frame_size]  # remove padding

        # Parse: first item is msg_code (RLP encoded), rest is payload
        code_item, consumed = self._decode_msg_code(frame_data)
        payload = frame_data[consumed:]

        return code_item, payload

    def _decode_msg_code(self, data: bytes) -> tuple[int, int]:
        """Decode the message code from the start of frame data."""
        if not data:
            return 0, 0
        first = data[0]
        if first < 0x80:
            return first, 1
        elif first == 0x80:
            return 0, 1
        else:
            length = first - 0x80
            code = int.from_bytes(data[1:1 + length], "big")
            return code, 1 + length

    # MAC operations

    def _update_egress_mac(self, header_cipher: bytes) -> bytes:
        """Update egress MAC with header and return 16-byte MAC tag.

        go-ethereum order: AES_encrypt(digest) XOR seed → feed to MAC.
        """
        mac_digest = self.egress_mac.digest()[:16]
        aes_result = self.mac_enc.encrypt(mac_digest)
        xored = bytes(a ^ b for a, b in zip(aes_result, header_cipher))
        self.egress_mac.update(xored)
        return self.egress_mac.digest()[:16]

    def _update_egress_mac_body(self, body_cipher: bytes) -> bytes:
        """Update egress MAC with body and return 16-byte MAC tag."""
        self.egress_mac.update(body_cipher)
        mac_digest = self.egress_mac.digest()[:16]
        aes_result = self.mac_enc.encrypt(mac_digest)
        xored = bytes(a ^ b for a, b in zip(aes_result, mac_digest))
        self.egress_mac.update(xored)
        return self.egress_mac.digest()[:16]

    def _update_ingress_mac(self, header_cipher: bytes) -> bytes:
        """Update ingress MAC with header and return 16-byte MAC tag."""
        mac_digest = self.ingress_mac.digest()[:16]
        aes_result = self.mac_enc.encrypt(mac_digest)
        xored = bytes(a ^ b for a, b in zip(aes_result, header_cipher))
        self.ingress_mac.update(xored)
        return self.ingress_mac.digest()[:16]

    def _update_ingress_mac_body(self, body_cipher: bytes) -> bytes:
        """Update ingress MAC with body and return 16-byte MAC tag."""
        self.ingress_mac.update(body_cipher)
        mac_digest = self.ingress_mac.digest()[:16]
        aes_result = self.mac_enc.encrypt(mac_digest)
        xored = bytes(a ^ b for a, b in zip(aes_result, mac_digest))
        self.ingress_mac.update(xored)
        return self.ingress_mac.digest()[:16]


# ---------------------------------------------------------------------------
# Snappy compression for eth/68+
# ---------------------------------------------------------------------------

def snappy_compress(data: bytes) -> bytes:
    """Compress data with snappy."""
    try:
        import snappy
        return snappy.compress(data)
    except ImportError:
        return data


def snappy_decompress(data: bytes) -> bytes:
    """Decompress snappy data."""
    try:
        import snappy
        return snappy.decompress(data)
    except ImportError:
        return data
