"""
Cryptographic utilities for Ethereum.

- keccak256 hashing
- secp256k1 ECDSA signing and public key recovery
- Ethereum address derivation
"""

from __future__ import annotations

from Crypto.Hash import keccak as _keccak_mod
from coincurve import PrivateKey, PublicKey


def keccak256(data: bytes) -> bytes:
    """Compute Keccak-256 hash (NOT SHA3-256)."""
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return h.digest()


def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash."""
    from Crypto.Hash import SHA256
    return SHA256.new(data).digest()


def ripemd160(data: bytes) -> bytes:
    """Compute RIPEMD-160 hash."""
    from Crypto.Hash import RIPEMD160
    return RIPEMD160.new(data).digest()


# ---------------------------------------------------------------------------
# secp256k1
# ---------------------------------------------------------------------------

def ecdsa_sign(msg_hash: bytes, private_key: bytes) -> tuple[int, int, int]:
    """Sign a 32-byte message hash with a private key.

    Returns (v, r, s) where v is the recovery id (0 or 1).
    """
    if len(msg_hash) != 32:
        raise ValueError("Message hash must be 32 bytes")
    if len(private_key) != 32:
        raise ValueError("Private key must be 32 bytes")

    pk = PrivateKey(private_key)
    sig = pk.sign_recoverable(msg_hash, hasher=None)
    # coincurve returns 65 bytes: r(32) + s(32) + v(1)
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    v = sig[64]
    return v, r, s


def ecdsa_recover(msg_hash: bytes, v: int, r: int, s: int) -> bytes:
    """Recover the uncompressed public key (65 bytes) from a signature.

    v is the recovery id (0 or 1).
    Returns the 65-byte uncompressed public key (0x04 || x || y).
    """
    if len(msg_hash) != 32:
        raise ValueError("Message hash must be 32 bytes")

    sig_bytes = (
        r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])
    )
    pub = PublicKey.from_signature_and_message(sig_bytes, msg_hash, hasher=None)
    return pub.format(compressed=False)


def pubkey_to_address(pubkey: bytes) -> bytes:
    """Derive Ethereum address from uncompressed public key.

    Takes 65-byte uncompressed key (0x04 || x || y) or 64-byte raw (x || y).
    Returns 20-byte address.
    """
    if len(pubkey) == 65:
        pubkey = pubkey[1:]  # strip 0x04 prefix
    if len(pubkey) != 64:
        raise ValueError(f"Expected 64-byte public key, got {len(pubkey)}")
    return keccak256(pubkey)[12:]


def private_key_to_address(private_key: bytes) -> bytes:
    """Derive Ethereum address from a 32-byte private key."""
    pk = PrivateKey(private_key)
    pubkey = pk.public_key.format(compressed=False)
    return pubkey_to_address(pubkey)


def private_key_to_public_key(private_key: bytes) -> bytes:
    """Get 65-byte uncompressed public key from private key."""
    pk = PrivateKey(private_key)
    return pk.public_key.format(compressed=False)
