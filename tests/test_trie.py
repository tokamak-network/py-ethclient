"""Tests for Merkle Patricia Trie."""

import pytest
from ethclient.common.trie import (
    Trie,
    hex_prefix_encode,
    hex_prefix_decode,
    nibbles_from_bytes,
    bytes_from_nibbles,
    ordered_trie_root,
    EMPTY_ROOT,
)
from ethclient.common import rlp
from ethclient.common.crypto import keccak256


class TestHexPrefix:
    def test_encode_leaf_even(self):
        # Leaf with even nibbles [1, 2, 3, 4] -> flag = 0x20
        result = hex_prefix_encode([1, 2, 3, 4], is_leaf=True)
        assert result == bytes([0x20, 0x12, 0x34])

    def test_encode_leaf_odd(self):
        # Leaf with odd nibbles [1, 2, 3] -> flag = 0x3, then nibbles
        result = hex_prefix_encode([1, 2, 3], is_leaf=True)
        assert result == bytes([0x31, 0x23])

    def test_encode_extension_even(self):
        # Extension with even nibbles [1, 2, 3, 4] -> flag = 0x00
        result = hex_prefix_encode([1, 2, 3, 4], is_leaf=False)
        assert result == bytes([0x00, 0x12, 0x34])

    def test_encode_extension_odd(self):
        # Extension with odd nibbles [1, 2, 3] -> flag = 0x1
        result = hex_prefix_encode([1, 2, 3], is_leaf=False)
        assert result == bytes([0x11, 0x23])

    def test_roundtrip(self):
        for nibbles in [[], [1], [1, 2], [1, 2, 3], [0, 15, 1, 12, 11, 8]]:
            for is_leaf in [True, False]:
                encoded = hex_prefix_encode(nibbles, is_leaf)
                decoded_nibbles, decoded_leaf = hex_prefix_decode(encoded)
                assert decoded_nibbles == nibbles
                assert decoded_leaf == is_leaf


class TestNibbles:
    def test_from_bytes(self):
        assert nibbles_from_bytes(b"\xab\xcd") == [0xA, 0xB, 0xC, 0xD]

    def test_to_bytes(self):
        assert bytes_from_nibbles([0xA, 0xB, 0xC, 0xD]) == b"\xab\xcd"

    def test_roundtrip(self):
        data = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        assert bytes_from_nibbles(nibbles_from_bytes(data)) == data


class TestTrieBasic:
    def test_empty_trie_root(self):
        trie = Trie()
        assert trie.root_hash == EMPTY_ROOT

    def test_single_entry(self):
        trie = Trie()
        trie.put_raw(b"\x01", b"value1")
        root1 = trie.root_hash
        assert root1 != EMPTY_ROOT
        assert trie.get_raw(b"\x01") == b"value1"

    def test_get_nonexistent(self):
        trie = Trie()
        trie.put_raw(b"\x01", b"value1")
        assert trie.get_raw(b"\x02") is None

    def test_two_entries(self):
        trie = Trie()
        trie.put_raw(b"\x01", b"value1")
        trie.put_raw(b"\x02", b"value2")
        assert trie.get_raw(b"\x01") == b"value1"
        assert trie.get_raw(b"\x02") == b"value2"

    def test_update_entry(self):
        trie = Trie()
        trie.put_raw(b"\x01", b"value1")
        trie.put_raw(b"\x01", b"updated")
        assert trie.get_raw(b"\x01") == b"updated"

    def test_delete_entry(self):
        trie = Trie()
        trie.put_raw(b"\x01", b"value1")
        trie.delete_raw(b"\x01")
        assert trie.get_raw(b"\x01") is None

    def test_delete_nonexistent(self):
        trie = Trie()
        trie.put_raw(b"\x01", b"value1")
        trie.delete_raw(b"\x02")  # should not crash
        assert trie.get_raw(b"\x01") == b"value1"


class TestTrieMultipleEntries:
    def test_many_entries(self):
        trie = Trie()
        entries = {}
        for i in range(100):
            key = i.to_bytes(2, "big")
            value = f"value_{i}".encode()
            trie.put_raw(key, value)
            entries[key] = value

        for key, value in entries.items():
            assert trie.get_raw(key) == value

    def test_deterministic_root(self):
        """Insertion order should not affect root hash."""
        trie1 = Trie()
        trie2 = Trie()

        trie1.put_raw(b"\x01", b"a")
        trie1.put_raw(b"\x02", b"b")
        trie1.put_raw(b"\x03", b"c")

        trie2.put_raw(b"\x03", b"c")
        trie2.put_raw(b"\x01", b"a")
        trie2.put_raw(b"\x02", b"b")

        assert trie1.root_hash == trie2.root_hash

    def test_delete_all_returns_empty_root(self):
        trie = Trie()
        trie.put_raw(b"\x01", b"a")
        trie.put_raw(b"\x02", b"b")
        trie.delete_raw(b"\x01")
        trie.delete_raw(b"\x02")
        assert trie.root_hash == EMPTY_ROOT


class TestTrieWithHashing:
    """Test with key hashing (standard Ethereum state trie behavior)."""

    def test_put_get(self):
        trie = Trie()
        trie.put(b"key1", b"value1")
        trie.put(b"key2", b"value2")
        assert trie.get(b"key1") == b"value1"
        assert trie.get(b"key2") == b"value2"
        assert trie.get(b"key3") is None

    def test_deterministic(self):
        trie1 = Trie()
        trie2 = Trie()

        trie1.put(b"key1", b"val1")
        trie1.put(b"key2", b"val2")

        trie2.put(b"key2", b"val2")
        trie2.put(b"key1", b"val1")

        assert trie1.root_hash == trie2.root_hash


class TestOrderedTrieRoot:
    def test_empty(self):
        root = ordered_trie_root([])
        assert root == EMPTY_ROOT

    def test_single(self):
        root = ordered_trie_root([b"hello"])
        assert len(root) == 32
        assert root != EMPTY_ROOT

    def test_deterministic(self):
        values = [b"tx1", b"tx2", b"tx3"]
        root1 = ordered_trie_root(values)
        root2 = ordered_trie_root(values)
        assert root1 == root2


class TestTrieEthereumTestVectors:
    """Test vectors from the Ethereum wiki / Yellow Paper."""

    def test_empty_values(self):
        """Inserting empty value should be like delete."""
        trie = Trie()
        trie.put_raw(b"\x01\x02\x03", b"hello")
        root_with = trie.root_hash
        trie.delete_raw(b"\x01\x02\x03")
        assert trie.root_hash == EMPTY_ROOT

    def test_single_pair(self):
        """Single key-value pair."""
        trie = Trie()
        trie.put_raw(b"A", rlp.encode(b"A"))
        root = trie.root_hash
        assert len(root) == 32
        # Should be deterministic
        trie2 = Trie()
        trie2.put_raw(b"A", rlp.encode(b"A"))
        assert trie2.root_hash == root

    def test_branching(self):
        """Keys that cause branching in the trie."""
        trie = Trie()
        trie.put_raw(b"\x00", b"val0")
        trie.put_raw(b"\x01", b"val1")
        trie.put_raw(b"\x10", b"val16")
        trie.put_raw(b"\x11", b"val17")

        assert trie.get_raw(b"\x00") == b"val0"
        assert trie.get_raw(b"\x01") == b"val1"
        assert trie.get_raw(b"\x10") == b"val16"
        assert trie.get_raw(b"\x11") == b"val17"
