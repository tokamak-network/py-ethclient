"""Unit tests for cryptographic utilities.

Tests the wrapper code in sequencer.core.crypto, not the underlying
libraries (coincurve, ethereum-rlp).
"""

import pytest
from eth_utils import to_canonical_address

from sequencer.core.crypto import (
    keccak256,
    sign,
    recover_address,
    private_key_to_address,
)
from tests.fixtures.keys import ALICE_PRIVATE_KEY, ALICE_ADDRESS, BOB_PRIVATE_KEY


class TestKeccak256:
    """Test keccak256 hashing wrapper."""

    def test_hash_empty(self):
        """Hash of empty bytes."""
        result = keccak256(b"")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_hash_consistency(self):
        """Same input produces same hash."""
        data = b"hello world"
        hash1 = keccak256(data)
        hash2 = keccak256(data)
        assert hash1 == hash2

    def test_hash_different_inputs(self):
        """Different inputs produce different hashes."""
        hash1 = keccak256(b"input1")
        hash2 = keccak256(b"input2")
        assert hash1 != hash2

    def test_hash_length(self):
        """Hash output is always 32 bytes."""
        for data in [b"", b"a", b"a" * 100, b"a" * 10000]:
            result = keccak256(data)
            assert len(result) == 32


class TestPrivateKeyToAddress:
    """Test private key to address derivation."""

    def test_derive_address(self):
        """Derive address from known private key."""
        address = private_key_to_address(ALICE_PRIVATE_KEY)
        assert isinstance(address, bytes)
        assert len(address) == 20
        assert address == ALICE_ADDRESS

    def test_different_keys_different_addresses(self):
        """Different private keys produce different addresses."""
        addr1 = private_key_to_address(ALICE_PRIVATE_KEY)
        addr2 = private_key_to_address(BOB_PRIVATE_KEY)
        assert addr1 != addr2

    def test_deterministic(self):
        """Same key always produces same address."""
        addr1 = private_key_to_address(ALICE_PRIVATE_KEY)
        addr2 = private_key_to_address(ALICE_PRIVATE_KEY)
        assert addr1 == addr2


class TestSign:
    """Test message signing."""

    def test_sign_hash(self):
        """Sign a message hash."""
        msg_hash = keccak256(b"test message")
        v, r, s = sign(ALICE_PRIVATE_KEY, msg_hash)
        
        assert isinstance(v, int)
        assert isinstance(r, int)
        assert isinstance(s, int)
        # Note: sign() returns raw recovery id (0 or 1), not Ethereum-style (27 or 28)
        assert v in (0, 1)
        assert r > 0
        assert s > 0

    def test_sign_produces_valid_signature(self):
        """Signature can be verified."""
        msg_hash = keccak256(b"test message")
        v, r, s = sign(ALICE_PRIVATE_KEY, msg_hash)
        
        # Should be able to recover
        recovered = recover_address(msg_hash, v, r, s)
        assert recovered == ALICE_ADDRESS

    def test_different_hashes_different_signatures(self):
        """Different hashes produce different signatures."""
        hash1 = keccak256(b"msg1")
        hash2 = keccak256(b"msg2")
        
        v1, r1, s1 = sign(ALICE_PRIVATE_KEY, hash1)
        v2, r2, s2 = sign(ALICE_PRIVATE_KEY, hash2)
        
        # At least one component should differ
        assert (r1, s1) != (r2, s2) or v1 != v2


class TestRecoverAddress:
    """Test address recovery from signature."""

    def test_recover_from_signature(self):
        """Recover address from valid signature."""
        msg_hash = keccak256(b"test message")
        v, r, s = sign(ALICE_PRIVATE_KEY, msg_hash)
        
        recovered = recover_address(msg_hash, v, r, s)
        assert recovered == ALICE_ADDRESS

    def test_different_signer(self):
        """Recover correct address for different signer."""
        msg_hash = keccak256(b"test message")
        v, r, s = sign(BOB_PRIVATE_KEY, msg_hash)
        
        recovered = recover_address(msg_hash, v, r, s)
        expected = private_key_to_address(BOB_PRIVATE_KEY)
        assert recovered == expected


class TestCryptoIntegration:
    """Integration scenarios for crypto utilities."""

    def test_sign_and_recover_roundtrip(self):
        """Full roundtrip: sign then recover."""
        message = b"important transaction"
        msg_hash = keccak256(message)
        
        # Sign
        v, r, s = sign(ALICE_PRIVATE_KEY, msg_hash)
        
        # Recover
        recovered = recover_address(msg_hash, v, r, s)
        
        # Verify
        assert recovered == ALICE_ADDRESS

    def test_multiple_messages_same_signer(self):
        """Sign multiple messages with same key."""
        messages = [b"msg1", b"msg2", b"msg3"]
        
        for msg in messages:
            msg_hash = keccak256(msg)
            v, r, s = sign(ALICE_PRIVATE_KEY, msg_hash)
            recovered = recover_address(msg_hash, v, r, s)
            assert recovered == ALICE_ADDRESS

    def test_signature_uniqueness(self):
        """Each signature is unique to the message."""
        messages = [b"unique1", b"unique2", b"unique3"]
        signatures = set()
        
        for msg in messages:
            msg_hash = keccak256(msg)
            v, r, s = sign(ALICE_PRIVATE_KEY, msg_hash)
            signatures.add((v, r, s))
        
        # Each message should produce a unique signature
        assert len(signatures) == len(messages)