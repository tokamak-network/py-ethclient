"""Tests for L2 sequencer hardening — mempool cap, batch timeout, crash recovery."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from ethclient.l2.config import L2Config
from ethclient.l2.da import LocalDAProvider
from ethclient.l2.rollup import Rollup
from ethclient.l2.sequencer import Sequencer
from ethclient.l2.state import L2StateStore
from ethclient.l2.runtime import PythonRuntime
from ethclient.l2.types import L2Tx, STFResult


def _make_stf():
    def apply_tx(state, tx):
        state["counter"] = state.get("counter", 0) + 1
        return STFResult(success=True)
    return PythonRuntime(apply_tx)


class TestMempoolCap:
    def test_mempool_rejects_when_full(self):
        config = L2Config(mempool_max_size=3)
        stf = _make_stf()
        state_store = L2StateStore(stf.genesis_state())
        seq = Sequencer(stf=stf, state_store=state_store, config=config)

        # Fill mempool
        for i in range(3):
            err = seq.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=i, data={}))
            assert err is None

        # 4th should be rejected
        err = seq.submit_tx(L2Tx(sender=b"\x02" * 20, nonce=0, data={}))
        assert err == "mempool full"

    def test_mempool_accepts_after_drain(self):
        config = L2Config(mempool_max_size=2, max_txs_per_batch=64)
        stf = _make_stf()
        state_store = L2StateStore(stf.genesis_state())
        seq = Sequencer(stf=stf, state_store=state_store, config=config)

        # Fill
        seq.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={}))
        seq.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=1, data={}))

        # Drain via tick
        seq.tick()
        assert seq.pending_tx_count == 0

        # Should accept again
        err = seq.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=2, data={}))
        assert err is None


class TestBatchTimeout:
    def test_batch_sealed_on_timeout(self):
        config = L2Config(batch_timeout=0, max_txs_per_batch=64)
        stf = _make_stf()
        state_store = L2StateStore(stf.genesis_state())
        seq = Sequencer(stf=stf, state_store=state_store, config=config)

        seq.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={}))
        seq.tick()  # Process tx

        # Force timeout by setting _last_batch_time in the past
        seq._last_batch_time = time.monotonic() - 1.0
        seq._batch_timeout = 0.0  # immediate timeout

        # Need another tick to trigger timeout-based sealing
        # But current_batch_txs has txs, and elapsed >= timeout
        # tick() checks after processing mempool
        seq.tick()

        assert len(seq.sealed_batches) >= 1

    def test_no_timeout_seal_without_txs(self):
        config = L2Config(batch_timeout=0, max_txs_per_batch=64)
        stf = _make_stf()
        state_store = L2StateStore(stf.genesis_state())
        seq = Sequencer(stf=stf, state_store=state_store, config=config)

        # No txs submitted — timeout should not seal empty batch
        seq._last_batch_time = time.monotonic() - 100.0
        seq.tick()
        assert len(seq.sealed_batches) == 0

    def test_timeout_resets_after_seal(self):
        config = L2Config(batch_timeout=0, max_txs_per_batch=64)
        stf = _make_stf()
        state_store = L2StateStore(stf.genesis_state())
        seq = Sequencer(stf=stf, state_store=state_store, config=config)

        seq.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={}))
        old_time = time.monotonic() - 100.0
        seq._last_batch_time = old_time

        seq.tick()
        assert len(seq.sealed_batches) >= 1
        # After sealing, _last_batch_time should be reset
        assert seq._last_batch_time > old_time


class TestCrashRecovery:
    def test_wal_recovery(self, tmp_path):
        """Crash recovery via WAL replay should restore sealed batches."""
        from ethclient.l2.persistent_state import L2PersistentStateStore, WALEntry

        db_path = tmp_path / "recovery_test"
        store = L2PersistentStateStore(db_path)

        # Simulate: a batch was sealed and written to WAL
        from ethclient.l2.types import Batch
        batch = Batch(
            number=0,
            old_state_root=b"\x00" * 32,
            new_state_root=b"\x11" * 32,
            sealed=True,
        )
        entry = WALEntry(
            sequence=0,
            entry_type="batch_sealed",
            data=batch.encode(),
            timestamp=1000,
        )
        store.wal_append(entry)
        store.close()

        # Reopen and recover
        store2 = L2PersistentStateStore(db_path)
        entries = store2.wal_replay()
        assert len(entries) == 1
        assert entries[0].entry_type == "batch_sealed"

        recovered_batch = Batch.decode(entries[0].data)
        assert recovered_batch.number == 0
        assert recovered_batch.new_state_root == b"\x11" * 32
        store2.close()

    def test_rollup_recover_noop_for_memory(self):
        """recover() should be a no-op for in-memory state backend."""
        rollup = Rollup(stf=_make_stf())
        rollup.setup()
        # Should not raise
        rollup.recover()


class TestDefaultConfig:
    def test_default_mempool_size(self):
        config = L2Config()
        assert config.mempool_max_size == 10000

    def test_default_rate_limit(self):
        config = L2Config()
        assert config.rate_limit_rps == 10.0
        assert config.rate_limit_burst == 50

    def test_default_request_size(self):
        config = L2Config()
        assert config.max_request_size == 1_048_576

    def test_default_api_keys_empty(self):
        config = L2Config()
        assert config.api_keys == []

    def test_default_cors_origins(self):
        config = L2Config()
        assert config.cors_origins == ["*"]
