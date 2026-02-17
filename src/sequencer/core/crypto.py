"""Crypto utilities using eth-keys and pycryptodome."""

from eth_keys import keys
from Crypto.Hash import keccak


def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def sign(private_key: bytes, message_hash: bytes) -> tuple[int, int, int]:
    pk = keys.PrivateKey(private_key)
    signature = pk.sign_msg_hash(message_hash)
    return signature.v, signature.r, signature.s


def recover_address(message_hash: bytes, v: int, r: int, s: int) -> bytes:
    signature = keys.Signature(vrs=(v, r, s))
    public_key = signature.recover_public_key_from_msg_hash(message_hash)
    return keccak256(public_key.to_bytes())[12:]


def private_key_to_address(private_key: bytes) -> bytes:
    pk = keys.PrivateKey(private_key)
    public_key = pk.public_key
    return keccak256(public_key.to_bytes())[12:]