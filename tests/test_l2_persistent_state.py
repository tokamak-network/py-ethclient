"""Tests for L2 persistent state store (LMDB-backed)."""

import struct
import time

import pytest

from ethclient.l2.persistent_state import (
    L2PersistentState,
    L2PersistentStateStore,
    WALEntry,
    _encode_state_value,
    _decode_state_value,
)
from ethclient.l2.types import Batch, L2Tx


@pytest.fixture
def store(tmp_path):
    s = L2PersistentStateStore(tmp_path / "testdb", initial_state={"counter": 0})
    yield s
    s.close()


class TestPersistentState:
    def test_basic_read_write(self, store):
        store.state["counter"] = 42
        assert store.state["counter"] == 42
        assert "counter" in store.state

    def test_missing_key_raises(self, store):
        with pytest.raises(KeyError):
            _ = store.state["nonexistent"]

    def test_get_default(self, store):
        assert store.state.get("missing", 99) == 99

    def test_keys_items_values(self, store):
        store.state["a"] = 1
        store.state["b"] = "hello"
        keys = sorted(store.state.keys())
        assert "a" in keys
        assert "b" in keys
        assert "counter" in keys

    def test_len_and_iter(self, store):
        store.state["x"] = 10
        assert len(store.state) >= 2  # counter + x
        assert "x" in list(store.state)

    def test_delete_key(self, store):
        store.state["temp"] = 100
        del store.state["temp"]
        assert "temp" not in store.state
        assert store.state.get("temp") is None


class TestOverlayFlush:
    def test_flush_persists_to_lmdb(self, store):
        store.state["persistent_key"] = 999
        store.flush()
        # After flush, overlay is empty but value is in LMDB
        assert store.state["persistent_key"] == 999

    def test_close_reopen_preserves_state(self, tmp_path):
        db_path = tmp_path / "reopen_test"
        s1 = L2PersistentStateStore(db_path, initial_state={"init": 1})
        s1.state["added"] = 42
        s1.flush()
        s1.close()

        s2 = L2PersistentStateStore(db_path)
        assert s2.state["init"] == 1
        assert s2.state["added"] == 42
        s2.close()

    def test_delete_persists_after_flush(self, tmp_path):
        db_path = tmp_path / "del_test"
        s1 = L2PersistentStateStore(db_path, initial_state={"keep": 1, "remove": 2})
        s1.flush()
        del s1.state["remove"]
        s1.flush()
        s1.close()

        s2 = L2PersistentStateStore(db_path)
        assert s2.state["keep"] == 1
        assert "remove" not in s2.state
        s2.close()


class TestSnapshotRollback:
    def test_snapshot_rollback(self, store):
        store.state["val"] = 10
        snap = store.snapshot()
        store.state["val"] = 20
        store.state["new_key"] = "added"
        store.rollback(snap)
        assert store.state["val"] == 10
        assert "new_key" not in store.state

    def test_commit_clears_snapshots(self, store):
        store.snapshot()
        store.commit()
        # rollback with no snapshots is a no-op
        store.rollback()

    def test_multiple_snapshots(self, store):
        store.state["x"] = 1
        snap0 = store.snapshot()
        store.state["x"] = 2
        snap1 = store.snapshot()
        store.state["x"] = 3

        store.rollback(snap1)
        assert store.state["x"] == 2

        store.rollback(snap0)
        assert store.state["x"] == 1


class TestStateRoot:
    def test_state_root_consistency(self, store):
        """State root should match L2StateStore for same state."""
        from ethclient.l2.state import L2StateStore
        store.state["a"] = 1
        store.state["b"] = "hello"

        mem_store = L2StateStore({"counter": 0, "a": 1, "b": "hello"})
        assert store.compute_state_root() == mem_store.compute_state_root()

    def test_state_root_changes_on_mutation(self, store):
        root1 = store.compute_state_root()
        store.state["new"] = 42
        root2 = store.compute_state_root()
        assert root1 != root2


class TestBatchPersistence:
    def test_put_get_batch(self, store):
        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={"op": "test"})
        batch = Batch(
            number=0,
            transactions=[tx],
            old_state_root=b"\x00" * 32,
            new_state_root=b"\xff" * 32,
            sealed=True,
        )
        store.put_batch(batch)
        recovered = store.get_batch(0)
        assert recovered is not None
        assert recovered.number == 0
        assert len(recovered.transactions) == 1
        assert recovered.old_state_root == b"\x00" * 32
        assert recovered.new_state_root == b"\xff" * 32

    def test_get_missing_batch(self, store):
        assert store.get_batch(999) is None

    def test_get_all_batches(self, store):
        for i in range(3):
            batch = Batch(number=i, old_state_root=b"\x00" * 32, new_state_root=b"\x00" * 32, sealed=True)
            store.put_batch(batch)
        batches = store.get_all_batches()
        assert len(batches) == 3
        assert [b.number for b in batches] == [0, 1, 2]


class TestProofPersistence:
    def test_put_get_proof(self, store):
        proof_data = b"fake_proof_data_for_testing"
        store.put_proof(0, proof_data)
        assert store.get_proof(0) == proof_data

    def test_get_missing_proof(self, store):
        assert store.get_proof(999) is None


class TestMetadata:
    def test_batch_number(self, store):
        assert store.get_last_batch_number() == 0
        store.set_last_batch_number(5)
        assert store.get_last_batch_number() == 5

    def test_submitted_batch(self, store):
        assert store.get_last_submitted_batch() == -1
        store.set_last_submitted_batch(3)
        assert store.get_last_submitted_batch() == 3

    def test_nonces(self, store):
        nonces = {b"\x01" * 20: 5, b"\x02" * 20: 10}
        store.put_nonces(nonces)
        recovered = store.get_nonces()
        assert recovered[b"\x01" * 20] == 5
        assert recovered[b"\x02" * 20] == 10

    def test_pre_batch_root(self, store):
        assert store.get_pre_batch_root() is None
        root = b"\xab" * 32
        store.set_pre_batch_root(root)
        assert store.get_pre_batch_root() == root


class TestWAL:
    def test_wal_append_replay(self, store):
        entry = WALEntry(
            sequence=0,
            entry_type="batch_sealed",
            data=b"test_payload",
            timestamp=1000,
        )
        store.wal_append(entry)
        entries = store.wal_replay()
        assert len(entries) == 1
        assert entries[0].entry_type == "batch_sealed"
        assert entries[0].data == b"test_payload"
        assert entries[0].timestamp == 1000

    def test_wal_truncate(self, store):
        for i in range(5):
            entry = WALEntry(sequence=0, entry_type="tx_applied", data=b"", timestamp=i)
            store.wal_append(entry)

        entries = store.wal_replay()
        assert len(entries) == 5

        # Truncate first 3
        store.wal_truncate(3)
        remaining = store.wal_replay()
        assert len(remaining) == 2

    def test_wal_survives_reopen(self, tmp_path):
        db_path = tmp_path / "wal_test"
        s1 = L2PersistentStateStore(db_path)
        entry = WALEntry(sequence=0, entry_type="batch_sealed", data=b"important", timestamp=42)
        s1.wal_append(entry)
        s1.close()

        s2 = L2PersistentStateStore(db_path)
        entries = s2.wal_replay()
        assert len(entries) == 1
        assert entries[0].data == b"important"
        s2.close()


class TestWALEntry:
    def test_encode_decode_roundtrip(self):
        entry = WALEntry(sequence=42, entry_type="batch_proven", data=b"\xde\xad", timestamp=12345)
        raw = entry.encode()
        decoded = WALEntry.decode(raw)
        assert decoded.sequence == 42
        assert decoded.entry_type == "batch_proven"
        assert decoded.data == b"\xde\xad"
        assert decoded.timestamp == 12345


class TestStateValueEncoding:
    @pytest.mark.parametrize("value", [
        42,
        -1,
        0,
        "hello",
        b"\xde\xad\xbe\xef",
        {"nested": "dict"},
        [1, 2, 3],
    ])
    def test_encode_decode_roundtrip(self, value):
        encoded = _encode_state_value(value)
        decoded = _decode_state_value(encoded)
        assert decoded == value
