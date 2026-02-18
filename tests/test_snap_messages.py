"""Tests for snap/1 message encoding/decoding roundtrip."""

import pytest
from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.networking.snap.protocol import SnapMsg, SNAP_VERSION
from ethclient.networking.snap.messages import (
    GetAccountRangeMessage,
    AccountRangeMessage,
    GetStorageRangesMessage,
    StorageRangesMessage,
    GetByteCodesMessage,
    ByteCodesMessage,
    GetTrieNodesMessage,
    TrieNodesMessage,
    SNAP_RESPONSE_BYTES,
)


class TestSnapProtocol:
    def test_version(self):
        assert SNAP_VERSION == 1

    def test_message_codes(self):
        assert SnapMsg.GET_ACCOUNT_RANGE == 0
        assert SnapMsg.ACCOUNT_RANGE == 1
        assert SnapMsg.GET_STORAGE_RANGES == 2
        assert SnapMsg.STORAGE_RANGES == 3
        assert SnapMsg.GET_BYTE_CODES == 4
        assert SnapMsg.BYTE_CODES == 5
        assert SnapMsg.GET_TRIE_NODES == 6
        assert SnapMsg.TRIE_NODES == 7


class TestGetAccountRange:
    def test_roundtrip(self):
        msg = GetAccountRangeMessage(
            request_id=42,
            root_hash=b"\xaa" * 32,
            starting_hash=b"\x00" * 32,
            limit_hash=b"\xff" * 32,
            response_bytes=512 * 1024,
        )
        encoded = msg.encode()
        decoded = GetAccountRangeMessage.decode(encoded)

        assert decoded.request_id == 42
        assert decoded.root_hash == b"\xaa" * 32
        assert decoded.starting_hash == b"\x00" * 32
        assert decoded.limit_hash == b"\xff" * 32
        assert decoded.response_bytes == 512 * 1024

    def test_defaults(self):
        msg = GetAccountRangeMessage()
        encoded = msg.encode()
        decoded = GetAccountRangeMessage.decode(encoded)

        assert decoded.request_id == 0
        assert decoded.response_bytes == SNAP_RESPONSE_BYTES


class TestAccountRange:
    def test_roundtrip_with_accounts(self):
        accounts = [
            (b"\x01" * 32, rlp.encode([0, 100, b"\x56" * 32, b"\xc5" * 32])),
            (b"\x02" * 32, rlp.encode([1, 200, b"\x56" * 32, b"\xc5" * 32])),
        ]
        proof = [b"\xde\xad" * 16, b"\xbe\xef" * 16]

        msg = AccountRangeMessage(
            request_id=7,
            accounts=accounts,
            proof=proof,
        )
        encoded = msg.encode()
        decoded = AccountRangeMessage.decode(encoded)

        assert decoded.request_id == 7
        assert len(decoded.accounts) == 2
        assert decoded.accounts[0][0] == b"\x01" * 32
        assert decoded.accounts[1][0] == b"\x02" * 32
        assert len(decoded.proof) == 2

    def test_empty_accounts(self):
        msg = AccountRangeMessage(request_id=1, accounts=[], proof=[])
        encoded = msg.encode()
        decoded = AccountRangeMessage.decode(encoded)

        assert decoded.request_id == 1
        assert decoded.accounts == []
        assert decoded.proof == []


class TestGetStorageRanges:
    def test_roundtrip(self):
        msg = GetStorageRangesMessage(
            request_id=10,
            root_hash=b"\xbb" * 32,
            account_hashes=[b"\x01" * 32, b"\x02" * 32],
            starting_hash=b"\x00" * 32,
            limit_hash=b"\xff" * 32,
            response_bytes=256 * 1024,
        )
        encoded = msg.encode()
        decoded = GetStorageRangesMessage.decode(encoded)

        assert decoded.request_id == 10
        assert decoded.root_hash == b"\xbb" * 32
        assert len(decoded.account_hashes) == 2
        assert decoded.starting_hash == b"\x00" * 32
        assert decoded.limit_hash == b"\xff" * 32
        assert decoded.response_bytes == 256 * 1024


class TestStorageRanges:
    def test_roundtrip_with_slots(self):
        slots = [
            # Account 1 storage
            [(b"\xa1" * 32, b"\x01"), (b"\xa2" * 32, b"\x02")],
            # Account 2 storage
            [(b"\xb1" * 32, b"\x10")],
        ]
        proof = [b"\xaa" * 32]

        msg = StorageRangesMessage(
            request_id=20,
            slots=slots,
            proof=proof,
        )
        encoded = msg.encode()
        decoded = StorageRangesMessage.decode(encoded)

        assert decoded.request_id == 20
        assert len(decoded.slots) == 2
        assert len(decoded.slots[0]) == 2
        assert len(decoded.slots[1]) == 1
        assert decoded.slots[0][0] == (b"\xa1" * 32, b"\x01")
        assert decoded.slots[1][0] == (b"\xb1" * 32, b"\x10")
        assert len(decoded.proof) == 1

    def test_empty_slots(self):
        msg = StorageRangesMessage(request_id=1, slots=[], proof=[])
        encoded = msg.encode()
        decoded = StorageRangesMessage.decode(encoded)

        assert decoded.slots == []
        assert decoded.proof == []


class TestGetByteCodes:
    def test_roundtrip(self):
        hashes = [keccak256(b"contract1"), keccak256(b"contract2")]
        msg = GetByteCodesMessage(
            request_id=30,
            hashes=hashes,
            response_bytes=1024 * 1024,
        )
        encoded = msg.encode()
        decoded = GetByteCodesMessage.decode(encoded)

        assert decoded.request_id == 30
        assert len(decoded.hashes) == 2
        assert decoded.hashes[0] == hashes[0]
        assert decoded.hashes[1] == hashes[1]
        assert decoded.response_bytes == 1024 * 1024

    def test_empty_hashes(self):
        msg = GetByteCodesMessage(request_id=0, hashes=[])
        encoded = msg.encode()
        decoded = GetByteCodesMessage.decode(encoded)
        assert decoded.hashes == []


class TestByteCodes:
    def test_roundtrip(self):
        codes = [b"\x60\x00\x60\x00", b"\x60\x01\x60\x01\x01"]
        msg = ByteCodesMessage(request_id=31, codes=codes)
        encoded = msg.encode()
        decoded = ByteCodesMessage.decode(encoded)

        assert decoded.request_id == 31
        assert len(decoded.codes) == 2
        assert decoded.codes[0] == codes[0]
        assert decoded.codes[1] == codes[1]

    def test_empty_codes(self):
        msg = ByteCodesMessage(request_id=0, codes=[])
        encoded = msg.encode()
        decoded = ByteCodesMessage.decode(encoded)
        assert decoded.codes == []


class TestGetTrieNodes:
    def test_roundtrip(self):
        paths = [
            [b"\x01\x02\x03"],                        # account trie path
            [b"\x04\x05\x06", b"\x07\x08", b"\x09"],  # storage trie paths
        ]
        msg = GetTrieNodesMessage(
            request_id=40,
            root_hash=b"\xcc" * 32,
            paths=paths,
            response_bytes=512 * 1024,
        )
        encoded = msg.encode()
        decoded = GetTrieNodesMessage.decode(encoded)

        assert decoded.request_id == 40
        assert decoded.root_hash == b"\xcc" * 32
        assert len(decoded.paths) == 2
        assert len(decoded.paths[0]) == 1
        assert len(decoded.paths[1]) == 3
        assert decoded.paths[0][0] == b"\x01\x02\x03"
        assert decoded.paths[1][2] == b"\x09"

    def test_empty_paths(self):
        msg = GetTrieNodesMessage(request_id=0, paths=[])
        encoded = msg.encode()
        decoded = GetTrieNodesMessage.decode(encoded)
        assert decoded.paths == []


class TestTrieNodes:
    def test_roundtrip(self):
        # Simulated RLP-encoded trie nodes
        nodes = [b"\xc0" * 40, b"\xc1" * 50, b"\xc2" * 60]
        msg = TrieNodesMessage(request_id=41, nodes=nodes)
        encoded = msg.encode()
        decoded = TrieNodesMessage.decode(encoded)

        assert decoded.request_id == 41
        assert len(decoded.nodes) == 3
        assert decoded.nodes[0] == nodes[0]

    def test_empty_nodes(self):
        msg = TrieNodesMessage(request_id=0, nodes=[])
        encoded = msg.encode()
        decoded = TrieNodesMessage.decode(encoded)
        assert decoded.nodes == []


class TestMessagePairConsistency:
    """Test that request/response message IDs pair correctly."""

    def test_account_range_ids(self):
        req = GetAccountRangeMessage(request_id=99)
        resp = AccountRangeMessage(request_id=99)
        assert GetAccountRangeMessage.decode(req.encode()).request_id == 99
        assert AccountRangeMessage.decode(resp.encode()).request_id == 99

    def test_storage_range_ids(self):
        req = GetStorageRangesMessage(request_id=100)
        resp = StorageRangesMessage(request_id=100)
        assert GetStorageRangesMessage.decode(req.encode()).request_id == 100
        assert StorageRangesMessage.decode(resp.encode()).request_id == 100

    def test_bytecodes_ids(self):
        req = GetByteCodesMessage(request_id=101)
        resp = ByteCodesMessage(request_id=101)
        assert GetByteCodesMessage.decode(req.encode()).request_id == 101
        assert ByteCodesMessage.decode(resp.encode()).request_id == 101

    def test_trie_nodes_ids(self):
        req = GetTrieNodesMessage(request_id=102)
        resp = TrieNodesMessage(request_id=102)
        assert GetTrieNodesMessage.decode(req.encode()).request_id == 102
        assert TrieNodesMessage.decode(resp.encode()).request_id == 102
