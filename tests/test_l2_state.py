"""Tests for L2StateStore: snapshot/rollback boundary checks, state root determinism."""

import pytest
from ethclient.l2.state import L2StateStore


class TestL2StateStore:
    def test_rollback_invalid_snapshot_id_raises(self):
        store = L2StateStore({"a": 1})
        store.snapshot()
        with pytest.raises(IndexError, match="Invalid snapshot_id"):
            store.rollback(5)

    def test_rollback_negative_snapshot_id_raises(self):
        store = L2StateStore({"a": 1})
        store.snapshot()
        with pytest.raises(IndexError, match="Invalid snapshot_id"):
            store.rollback(-1)

    def test_state_root_determinism(self):
        """Same state with different insertion order should produce the same root."""
        store1 = L2StateStore()
        store1.state["b"] = 2
        store1.state["a"] = 1
        root1 = store1.compute_state_root()

        store2 = L2StateStore()
        store2.state["a"] = 1
        store2.state["b"] = 2
        root2 = store2.compute_state_root()

        assert root1 == root2
