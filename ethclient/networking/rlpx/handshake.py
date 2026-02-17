"""
RLPx ECIES handshake — auth/ack message exchange and session key derivation.

Implements the Elliptic Curve Integrated Encryption Scheme (ECIES)
used for the RLPx transport handshake.
"""

from __future__ import annotations

import os
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Optional

from Crypto.Cipher import AES
from coincurve import PrivateKey, PublicKey

from ethclient.common.crypto import keccak256
from ethclient.common import rlp


# ---------------------------------------------------------------------------
# ECIES encryption/decryption
# ---------------------------------------------------------------------------

def ecies_encrypt(
    recipient_pubkey: bytes,
    plaintext: bytes,
    shared_mac_data: bytes = b"",
) -> bytes:
    """ECIES encrypt a message for the given recipient public key.

    Returns: ephemeral_pubkey(65) || iv(16) || ciphertext || mac(32)
    """
    # Generate ephemeral key pair
    ephemeral_key = PrivateKey()
    ephemeral_pub = ephemeral_key.public_key.format(compressed=False)

    # ECDH shared secret
    recipient_pk = PublicKey(recipient_pubkey)
    shared = ephemeral_key.ecdh(recipient_pk.format())

    # Key derivation (concatenation KDF)
    key_material = _concat_kdf(shared)
    enc_key = key_material[:16]
    mac_key_seed = key_material[16:32]
    mac_key = hashlib.sha256(mac_key_seed).digest()

    # AES-128-CTR encryption
    iv = os.urandom(16)
    cipher = AES.new(enc_key, AES.MODE_CTR, nonce=b"", initial_value=iv)
    ciphertext = cipher.encrypt(plaintext)

    # HMAC-SHA256
    tag = _hmac_sha256(mac_key, iv + ciphertext + shared_mac_data)

    return ephemeral_pub + iv + ciphertext + tag


def ecies_decrypt(
    private_key: bytes,
    data: bytes,
    shared_mac_data: bytes = b"",
) -> bytes:
    """ECIES decrypt a message using the given private key."""
    if len(data) < 65 + 16 + 32:
        raise ValueError("ECIES data too short")

    ephemeral_pub = data[:65]
    iv = data[65:81]
    tag = data[-32:]
    ciphertext = data[81:-32]

    # ECDH shared secret
    pk = PrivateKey(private_key)
    recipient_pk = PublicKey(ephemeral_pub)
    shared = pk.ecdh(recipient_pk.format())

    # Key derivation
    key_material = _concat_kdf(shared)
    enc_key = key_material[:16]
    mac_key_seed = key_material[16:32]
    mac_key = hashlib.sha256(mac_key_seed).digest()

    # Verify HMAC
    expected_tag = _hmac_sha256(mac_key, iv + ciphertext + shared_mac_data)
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("ECIES MAC verification failed")

    # AES-128-CTR decryption
    cipher = AES.new(enc_key, AES.MODE_CTR, nonce=b"", initial_value=iv)
    return cipher.decrypt(ciphertext)


def _concat_kdf(shared_secret: bytes) -> bytes:
    """Concatenation KDF as used in ECIES (single round with counter=1)."""
    h = hashlib.sha256()
    h.update(b"\x00\x00\x00\x01")
    h.update(shared_secret)
    return h.digest()


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Handshake messages
# ---------------------------------------------------------------------------

@dataclass
class AuthMessage:
    """RLPx auth message (initiator -> recipient)."""
    signature: bytes = b""       # 65 bytes (r[32] + s[32] + v[1])
    initiator_pubkey: bytes = b""  # 64 bytes (uncompressed without prefix)
    nonce: bytes = b""           # 32 bytes
    version: int = 4

    def encode(self) -> bytes:
        return rlp.encode([
            self.signature,
            self.initiator_pubkey,
            self.nonce,
            self.version,
        ])

    @classmethod
    def decode(cls, data: bytes) -> AuthMessage:
        items = rlp.decode_list(data)
        return cls(
            signature=items[0],
            initiator_pubkey=items[1],
            nonce=items[2],
            version=rlp.decode_uint(items[3]) if items[3] else 4,
        )


@dataclass
class AckMessage:
    """RLPx ack message (recipient -> initiator)."""
    recipient_pubkey: bytes = b""  # 64 bytes
    nonce: bytes = b""           # 32 bytes
    version: int = 4

    def encode(self) -> bytes:
        return rlp.encode([
            self.recipient_pubkey,
            self.nonce,
            self.version,
        ])

    @classmethod
    def decode(cls, data: bytes) -> AckMessage:
        items = rlp.decode_list(data)
        return cls(
            recipient_pubkey=items[0],
            nonce=items[1],
            version=rlp.decode_uint(items[2]) if items[2] else 4,
        )


# ---------------------------------------------------------------------------
# Session keys derived from handshake
# ---------------------------------------------------------------------------

@dataclass
class SessionKeys:
    """Derived session keys for RLPx frame encryption."""
    aes_secret: bytes = b""      # 32 bytes — AES-256-CTR key
    mac_secret: bytes = b""      # 32 bytes — MAC key
    egress_mac: object = None    # running keccak256 for outgoing
    ingress_mac: object = None   # running keccak256 for incoming


# ---------------------------------------------------------------------------
# Handshake protocol
# ---------------------------------------------------------------------------

class Handshake:
    """Manages the RLPx ECIES handshake."""

    def __init__(self, private_key: bytes) -> None:
        self.private_key = private_key
        self.pk = PrivateKey(private_key)
        self.public_key = self.pk.public_key.format(compressed=False)
        self.ephemeral_key = PrivateKey()
        self.nonce = os.urandom(32)
        self._auth_msg: Optional[bytes] = None
        self._ack_msg: Optional[bytes] = None

    def create_auth(self, remote_pubkey: bytes) -> bytes:
        """Create the auth message for the initiator side.

        Returns the ECIES-encrypted auth message with size prefix.
        """
        # Compute shared secret for signature
        # static-shared-secret = ecdh(initiator-privkey, recipient-pubkey)
        remote_pk = PublicKey(remote_pubkey)
        shared = self.pk.ecdh(remote_pk.format())

        # XOR with nonce: shared ^ nonce
        xor_val = bytes(a ^ b for a, b in zip(shared[:32], self.nonce))

        # Sign with ephemeral key
        sig = self.ephemeral_key.sign_recoverable(xor_val, hasher=None)

        auth = AuthMessage(
            signature=sig,
            initiator_pubkey=self.public_key[1:],  # 64 bytes without 0x04
            nonce=self.nonce,
            version=4,
        )
        plaintext = auth.encode()
        encrypted = ecies_encrypt(remote_pubkey, plaintext)

        # Prepend size (2 bytes big-endian)
        size = len(encrypted)
        self._auth_msg = size.to_bytes(2, "big") + encrypted
        return self._auth_msg

    def handle_auth(self, data: bytes) -> AuthMessage:
        """Decrypt and parse an incoming auth message (recipient side)."""
        size = int.from_bytes(data[:2], "big")
        encrypted = data[2:2 + size]
        plaintext = ecies_decrypt(self.private_key, encrypted)
        self._auth_msg = data[:2 + size]
        return AuthMessage.decode(plaintext)

    def create_ack(self) -> bytes:
        """Create the ack message for the recipient side."""
        ack = AckMessage(
            recipient_pubkey=self.ephemeral_key.public_key.format(compressed=False)[1:],
            nonce=self.nonce,
            version=4,
        )
        # Note: for ack, we'd need the initiator's pubkey, but here we
        # just return it encrypted with a placeholder. In real use, pass remote_pubkey.
        plaintext = ack.encode()
        return plaintext

    def handle_ack(self, data: bytes, remote_pubkey: bytes) -> AckMessage:
        """Decrypt and parse an incoming ack message (initiator side)."""
        size = int.from_bytes(data[:2], "big")
        encrypted = data[2:2 + size]
        plaintext = ecies_decrypt(self.private_key, encrypted)
        self._ack_msg = data[:2 + size]
        return AckMessage.decode(plaintext)

    def derive_secrets(
        self,
        auth_msg: bytes,
        ack_msg: bytes,
        remote_nonce: bytes,
        remote_ephemeral_pubkey: bytes,
        is_initiator: bool,
    ) -> SessionKeys:
        """Derive session keys from the handshake."""
        # ephemeral-shared-secret = ecdh(ephemeral-privkey, remote-ephemeral-pubkey)
        remote_eph_pk = PublicKey(b"\x04" + remote_ephemeral_pubkey)
        eph_shared = self.ephemeral_key.ecdh(remote_eph_pk.format())

        # shared-secret = keccak256(eph-shared || keccak256(nonce-r || nonce-i))
        if is_initiator:
            nonce_hash = keccak256(remote_nonce + self.nonce)
        else:
            nonce_hash = keccak256(self.nonce + remote_nonce)
        shared_secret = keccak256(eph_shared + nonce_hash)

        # aes-secret = keccak256(eph-shared || shared-secret)
        aes_secret = keccak256(eph_shared + shared_secret)

        # mac-secret = keccak256(eph-shared || aes-secret)
        mac_secret = keccak256(eph_shared + aes_secret)

        # Initialize MAC states
        if is_initiator:
            egress_mac_init = _xor_bytes(mac_secret, remote_nonce)
            ingress_mac_init = _xor_bytes(mac_secret, self.nonce)
        else:
            egress_mac_init = _xor_bytes(mac_secret, self.nonce)
            ingress_mac_init = _xor_bytes(mac_secret, remote_nonce)

        import hashlib as _hashlib
        egress_mac = _hashlib.new("sha3_256")
        egress_mac.update(egress_mac_init)
        egress_mac.update(auth_msg)

        ingress_mac = _hashlib.new("sha3_256")
        ingress_mac.update(ingress_mac_init)
        ingress_mac.update(ack_msg)

        return SessionKeys(
            aes_secret=aes_secret,
            mac_secret=mac_secret,
            egress_mac=egress_mac,
            ingress_mac=ingress_mac,
        )


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
