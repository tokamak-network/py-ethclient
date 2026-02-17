"""Tests for cryptographic utilities."""

import pytest
from ethclient.common.crypto import (
    keccak256,
    sha256,
    ripemd160,
    ecdsa_sign,
    ecdsa_recover,
    pubkey_to_address,
    private_key_to_address,
    private_key_to_public_key,
)


class TestKeccak256:
    def test_empty(self):
        result = keccak256(b"")
        assert result.hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

    def test_hello(self):
        result = keccak256(b"hello")
        assert len(result) == 32
        # Known keccak256("hello")
        assert result.hex() == "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"

    def test_deterministic(self):
        assert keccak256(b"test") == keccak256(b"test")


class TestSHA256:
    def test_empty(self):
        result = sha256(b"")
        assert result.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestRIPEMD160:
    def test_empty(self):
        result = ripemd160(b"")
        assert result.hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"


class TestECDSA:
    # Well-known test private key (DO NOT use in production)
    PRIVATE_KEY = bytes.fromhex(
        "4c0883a69102937d6231471b5dbb6204fe512961708279f4d6e05d88e6f0e0e9"
    )

    def test_sign_and_recover(self):
        msg_hash = keccak256(b"test message")
        v, r, s = ecdsa_sign(msg_hash, self.PRIVATE_KEY)

        assert v in (0, 1)
        assert r > 0
        assert s > 0

        pubkey = ecdsa_recover(msg_hash, v, r, s)
        assert len(pubkey) == 65
        assert pubkey[0] == 0x04

    def test_recovered_address_matches(self):
        msg_hash = keccak256(b"test message")
        v, r, s = ecdsa_sign(msg_hash, self.PRIVATE_KEY)
        pubkey = ecdsa_recover(msg_hash, v, r, s)
        addr = pubkey_to_address(pubkey)

        expected_addr = private_key_to_address(self.PRIVATE_KEY)
        assert addr == expected_addr

    def test_different_messages_different_signatures(self):
        msg1 = keccak256(b"message 1")
        msg2 = keccak256(b"message 2")
        v1, r1, s1 = ecdsa_sign(msg1, self.PRIVATE_KEY)
        v2, r2, s2 = ecdsa_sign(msg2, self.PRIVATE_KEY)
        assert (r1, s1) != (r2, s2)


class TestAddressDerivation:
    PRIVATE_KEY = bytes.fromhex(
        "4c0883a69102937d6231471b5dbb6204fe512961708279f4d6e05d88e6f0e0e9"
    )

    def test_address_length(self):
        addr = private_key_to_address(self.PRIVATE_KEY)
        assert len(addr) == 20

    def test_known_address(self):
        addr = private_key_to_address(self.PRIVATE_KEY)
        assert addr.hex() == "e008c9fbd96896486a0ceefe5fff33535616f394"

    def test_pubkey_formats(self):
        pubkey = private_key_to_public_key(self.PRIVATE_KEY)
        assert len(pubkey) == 65
        assert pubkey[0] == 0x04

        # Both formats should give same address
        addr1 = pubkey_to_address(pubkey)      # 65-byte with prefix
        addr2 = pubkey_to_address(pubkey[1:])  # 64-byte without prefix
        assert addr1 == addr2


class TestEdgeCases:
    def test_invalid_msg_hash_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            ecdsa_sign(b"short", b"\x01" * 32)

    def test_invalid_private_key_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            ecdsa_sign(b"\x00" * 32, b"short")

    def test_invalid_pubkey_length(self):
        with pytest.raises(ValueError, match="64-byte"):
            pubkey_to_address(b"\x00" * 32)
