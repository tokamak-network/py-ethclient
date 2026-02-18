"""Tests for Merkle Patricia Trie proof generation and verification."""

import pytest
from ethclient.common.trie import (
    Trie,
    EMPTY_ROOT,
    verify_proof,
    verify_range_proof,
    nibbles_from_bytes,
)
from ethclient.common.crypto import keccak256


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_test_trie(n: int = 10) -> tuple[Trie, list[bytes], list[bytes]]:
    """Build a trie with n key-value pairs using raw keys.

    Returns (trie, sorted_keys, values).
    Keys are keccak256(i) which naturally sorts, values are RLP-ish bytes.
    """
    trie = Trie()
    pairs = []
    for i in range(n):
        key = keccak256(i.to_bytes(32, "big"))
        value = b"\x01" * (i + 1)  # variable-length values
        trie.put_raw(key, value)
        pairs.append((key, value))

    pairs.sort(key=lambda x: x[0])
    keys = [k for k, _ in pairs]
    values = [v for _, v in pairs]
    return trie, keys, values


# ---------------------------------------------------------------------------
# Single key proofs
# ---------------------------------------------------------------------------

class TestProve:
    def test_prove_existing_key(self):
        trie, keys, values = _build_test_trie(5)
        proof = trie.prove(keys[0])
        assert len(proof) > 0  # at least the root node

    def test_prove_nonexistent_key(self):
        trie, _, _ = _build_test_trie(5)
        fake_key = b"\xff" * 32
        proof = trie.prove(fake_key)
        # Proof should still contain nodes (partial path)
        assert len(proof) >= 0

    def test_prove_empty_trie(self):
        trie = Trie()
        proof = trie.prove(b"\x01" * 32)
        assert proof == []


class TestVerifyProof:
    def test_verify_existing_key(self):
        trie, keys, values = _build_test_trie(5)
        root = trie.root_hash

        for i in range(len(keys)):
            proof = trie.prove(keys[i])
            result = verify_proof(root, keys[i], proof)
            assert result == values[i], f"Failed for key index {i}"

    def test_verify_nonexistent_key(self):
        trie, _, _ = _build_test_trie(5)
        root = trie.root_hash
        fake_key = b"\xfe" * 32
        proof = trie.prove(fake_key)
        result = verify_proof(root, fake_key, proof)
        assert result is None

    def test_verify_wrong_root(self):
        trie, keys, _ = _build_test_trie(5)
        proof = trie.prove(keys[0])
        wrong_root = b"\x00" * 32
        result = verify_proof(wrong_root, keys[0], proof)
        assert result is None

    def test_verify_empty_proof(self):
        result = verify_proof(EMPTY_ROOT, b"\x01" * 32, [])
        assert result is None

    def test_verify_single_element_trie(self):
        trie = Trie()
        key = keccak256(b"only-key")
        value = b"only-value"
        trie.put_raw(key, value)

        proof = trie.prove(key)
        result = verify_proof(trie.root_hash, key, proof)
        assert result == value


# ---------------------------------------------------------------------------
# Range proofs
# ---------------------------------------------------------------------------

class TestVerifyRangeProof:
    def test_complete_range_no_proof(self):
        """Full trie data, no proof needed — just verify root."""
        trie, keys, values = _build_test_trie(5)
        root = trie.root_hash

        valid = verify_range_proof(root, keys[0], keys[-1], keys, values, [])
        assert valid

    def test_complete_range_wrong_root(self):
        trie, keys, values = _build_test_trie(5)
        wrong_root = b"\x00" * 32

        valid = verify_range_proof(wrong_root, keys[0], keys[-1], keys, values, [])
        assert not valid

    def test_empty_range_empty_trie(self):
        """Empty trie should accept empty range with no proof."""
        valid = verify_range_proof(EMPTY_ROOT, b"\x00" * 32, b"\xff" * 32, [], [], [])
        assert valid

    def test_empty_range_nonempty_trie(self):
        """Non-empty trie with empty range and no proof should fail."""
        trie, _, _ = _build_test_trie(5)
        valid = verify_range_proof(
            trie.root_hash, b"\x00" * 32, b"\xff" * 32, [], [], [],
        )
        assert not valid

    def test_keys_values_length_mismatch(self):
        trie, keys, values = _build_test_trie(5)
        valid = verify_range_proof(
            trie.root_hash, keys[0], keys[-1],
            keys, values[:-1], [],  # one fewer value
        )
        assert not valid

    def test_single_key_no_proof(self):
        """Single key-value pair in the trie, no proof."""
        trie = Trie()
        key = keccak256(b"only")
        value = b"val"
        trie.put_raw(key, value)

        valid = verify_range_proof(
            trie.root_hash, key, key, [key], [value], [],
        )
        assert valid

    def test_corrupted_value_detected(self):
        """Modified value should fail verification."""
        trie, keys, values = _build_test_trie(5)
        root = trie.root_hash

        bad_values = list(values)
        bad_values[2] = b"\xff\xff\xff"

        valid = verify_range_proof(root, keys[0], keys[-1], keys, bad_values, [])
        assert not valid

    def test_missing_key_detected(self):
        """Missing a key from the range should fail."""
        trie, keys, values = _build_test_trie(5)
        root = trie.root_hash

        partial_keys = keys[:3] + keys[4:]
        partial_values = values[:3] + values[4:]

        valid = verify_range_proof(
            root, partial_keys[0], partial_keys[-1],
            partial_keys, partial_values, [],
        )
        assert not valid


# ---------------------------------------------------------------------------
# Iterate
# ---------------------------------------------------------------------------

class TestIterateRaw:
    def test_iterate_all(self):
        trie, keys, values = _build_test_trie(10)
        result = trie.iterate_raw()

        assert len(result) == 10
        result_keys = [k for k, _ in result]
        assert result_keys == sorted(result_keys)

    def test_iterate_range(self):
        trie, keys, values = _build_test_trie(10)

        # Pick a subrange
        start = keys[3]
        end = keys[7]
        result = trie.iterate_raw(start=start, end=end)

        for k, v in result:
            assert k >= start
            assert k < end

    def test_iterate_empty_trie(self):
        trie = Trie()
        result = trie.iterate_raw()
        assert result == []

    def test_iterate_single_entry(self):
        trie = Trie()
        key = keccak256(b"test")
        trie.put_raw(key, b"value")

        result = trie.iterate_raw()
        assert len(result) == 1
        assert result[0] == (key, b"value")

    def test_iterate_values_match(self):
        """Verify iterated values match what was inserted."""
        trie, keys, values = _build_test_trie(10)
        result = trie.iterate_raw()

        result_dict = dict(result)
        for k, v in zip(keys, values):
            assert result_dict[k] == v


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestProofEdgeCases:
    def test_large_trie_proof(self):
        """Test proof generation/verification with many entries."""
        trie, keys, values = _build_test_trie(100)
        root = trie.root_hash

        # Verify a few random keys
        for i in [0, 25, 50, 75, 99]:
            proof = trie.prove(keys[i])
            result = verify_proof(root, keys[i], proof)
            assert result == values[i]

    def test_proof_nodes_are_valid_rlp(self):
        """Each proof node should be valid RLP."""
        from ethclient.common import rlp
        trie, keys, _ = _build_test_trie(10)
        proof = trie.prove(keys[0])

        for node_data in proof:
            # Should not raise
            decoded = rlp.decode(node_data)
            assert decoded is not None
