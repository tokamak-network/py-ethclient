"""Tests for L2 Sequencer: mempool, STF execution, batch assembly."""

import pytest
from ethclient.l2.types import L2Tx, L2State, STFResult
from ethclient.l2.runtime import PythonRuntime
from ethclient.l2.state import L2StateStore
from ethclient.l2.sequencer import Sequencer
from ethclient.l2.config import L2Config
from ethclient.l2.da import LocalDAProvider


def _counter_stf(state, tx):
    state["counter"] = state.get("counter", 0) + 1
    return STFResult(success=True)


def _failing_stf(state, tx):
    return STFResult(success=False, error="always fails")


class TestSequencer:
    def test_submit_tx(self):
        stf = PythonRuntime(_counter_stf)
        store = L2StateStore()
        seq = Sequencer(stf=stf, state_store=store)

        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={})
        error = seq.submit_tx(tx)
        assert error is None
        assert seq.pending_tx_count == 1

    def test_tick_processes_txs(self):
        stf = PythonRuntime(_counter_stf)
        store = L2StateStore()
        seq = Sequencer(stf=stf, state_store=store)

        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={})
        seq.submit_tx(tx)
        results = seq.tick()

        assert len(results) == 1
        assert results[0].success
        assert store.state.get("counter") == 1
        assert seq.pending_tx_count == 0

    def test_force_seal(self):
        stf = PythonRuntime(_counter_stf)
        store = L2StateStore()
        seq = Sequencer(stf=stf, state_store=store)

        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={})
        seq.submit_tx(tx)
        seq.tick()

        batch = seq.force_seal()
        assert batch is not None
        assert batch.number == 0
        assert batch.sealed
        assert len(batch.transactions) == 1
        assert batch.new_state_root != batch.old_state_root

    def test_force_seal_empty(self):
        stf = PythonRuntime(_counter_stf)
        store = L2StateStore()
        seq = Sequencer(stf=stf, state_store=store)
        assert seq.force_seal() is None

    def test_stf_failure_rollback(self):
        stf = PythonRuntime(_failing_stf)
        store = L2StateStore({"value": 42})
        seq = Sequencer(stf=stf, state_store=store)

        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={})
        seq.submit_tx(tx)
        results = seq.tick()

        assert len(results) == 1
        assert not results[0].success
        assert store.state.get("value") == 42
        assert seq.current_batch_size == 0

    def test_nonce_enforcement(self):
        stf = PythonRuntime(_counter_stf)
        store = L2StateStore()
        seq = Sequencer(stf=stf, state_store=store)

        sender = b"\x01" * 20
        # Submit nonce 0 — should succeed
        error = seq.submit_tx(L2Tx(sender=sender, nonce=0, data={}))
        assert error is None

        # Process it
        seq.tick()
        seq.force_seal()

        # Submit nonce 0 again — too low
        error = seq.submit_tx(L2Tx(sender=sender, nonce=0, data={}))
        assert error is not None
        assert "nonce too low" in error

    def test_batch_with_da(self):
        stf = PythonRuntime(_counter_stf)
        store = L2StateStore()
        da = LocalDAProvider()
        seq = Sequencer(stf=stf, state_store=store, da=da)

        seq.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={}))
        seq.tick()
        batch = seq.force_seal()

        assert batch.da_commitment != b""
        assert da.batch_count == 1
        assert da.verify_commitment(0, batch.da_commitment)

    def test_auto_seal_at_max_txs(self):
        stf = PythonRuntime(_counter_stf)
        store = L2StateStore()
        config = L2Config(max_txs_per_batch=2)
        seq = Sequencer(stf=stf, state_store=store, config=config)

        sender = b"\x01" * 20
        seq.submit_tx(L2Tx(sender=sender, nonce=0, data={}))
        seq.submit_tx(L2Tx(sender=sender, nonce=1, data={}))
        seq.tick()

        assert len(seq.sealed_batches) == 1
        assert seq.sealed_batches[0].sealed

    def test_multiple_batches(self):
        stf = PythonRuntime(_counter_stf)
        store = L2StateStore()
        seq = Sequencer(stf=stf, state_store=store)

        sender = b"\x01" * 20
        # Batch 0
        seq.submit_tx(L2Tx(sender=sender, nonce=0, data={}))
        seq.tick()
        batch0 = seq.force_seal()

        # Batch 1
        seq.submit_tx(L2Tx(sender=sender, nonce=1, data={}))
        seq.tick()
        batch1 = seq.force_seal()

        assert batch0.number == 0
        assert batch1.number == 1
        # Batch 1's old root should be batch 0's new root
        assert batch1.old_state_root == batch0.new_state_root

    def test_nonce_gap_rejected(self):
        stf = PythonRuntime(_counter_stf)
        store = L2StateStore()
        seq = Sequencer(stf=stf, state_store=store)

        sender = b"\x01" * 20
        # Skip nonce 0, submit nonce 1 — should fail
        error = seq.submit_tx(L2Tx(sender=sender, nonce=1, data={}))
        assert error is not None
        assert "nonce too high" in error
        assert seq.pending_tx_count == 0

    def test_multi_sender_independent_nonces(self):
        stf = PythonRuntime(_counter_stf)
        store = L2StateStore()
        seq = Sequencer(stf=stf, state_store=store)

        sender_a = b"\x01" * 20
        sender_b = b"\x02" * 20

        # Both senders start at nonce 0
        assert seq.submit_tx(L2Tx(sender=sender_a, nonce=0, data={})) is None
        assert seq.submit_tx(L2Tx(sender=sender_b, nonce=0, data={})) is None

        seq.tick()
        seq.force_seal()

        # Both advance independently to nonce 1
        assert seq.submit_tx(L2Tx(sender=sender_a, nonce=1, data={})) is None
        assert seq.submit_tx(L2Tx(sender=sender_b, nonce=1, data={})) is None

        # Cross-contamination: sender_a nonce 0 should fail
        error = seq.submit_tx(L2Tx(sender=sender_a, nonce=0, data={}))
        assert error is not None
        assert "nonce too low" in error

    def test_validate_tx_rejection(self):
        def validator(state, tx):
            if tx.value > 100:
                return "too much value"
            return None

        stf = PythonRuntime(_counter_stf, validator=validator)
        store = L2StateStore()
        seq = Sequencer(stf=stf, state_store=store)

        error = seq.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={}, value=200))
        assert error == "too much value"
        assert seq.pending_tx_count == 0
