"""Integration tests for the L2 rollup framework — full cycle end-to-end."""

import pytest
from ethclient.l2 import (
    Rollup, L2Tx, L2TxType, STFResult, L2Config, L2State,
    PythonRuntime, Sequencer, L2StateStore, Groth16ProofBackend,
    LocalDAProvider, InMemoryL1Backend, BatchSubmitter,
)


# ── Simple counter STF ──────────────────────────────────────────────

def counter_stf(state, tx):
    state["counter"] = state.get("counter", 0) + 1
    return STFResult(success=True)


# ── Balance transfer STF ────────────────────────────────────────────

def balance_stf(state, tx):
    op = tx.data.get("op")

    if op == "mint":
        to = tx.data["to"]
        amount = int(tx.data["amount"])
        state[to] = state.get(to, 0) + amount
        return STFResult(success=True, output={"minted": amount})

    if op == "transfer":
        sender_key = tx.data["from"]
        to_key = tx.data["to"]
        amount = int(tx.data["amount"])
        sender_balance = state.get(sender_key, 0)
        if sender_balance < amount:
            return STFResult(success=False, error="insufficient balance")
        state[sender_key] = sender_balance - amount
        state[to_key] = state.get(to_key, 0) + amount
        return STFResult(success=True, output={"transferred": amount})

    return STFResult(success=False, error=f"unknown op: {op}")


class TestFullCycleCounter:
    """Full cycle: STF → Rollup → setup → tx → batch → prove → L1 → verified."""

    def test_single_batch(self):
        rollup = Rollup(stf=counter_stf)
        rollup.setup()

        # Submit tx
        error = rollup.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={"op": "inc"}))
        assert error is None

        # Produce batch
        batch = rollup.produce_batch()
        assert batch.sealed
        assert len(batch.transactions) == 1

        # Prove and submit
        receipt = rollup.prove_and_submit(batch)
        assert receipt.verified
        assert receipt.batch_number == 0

        # State should reflect the tx
        assert rollup.state.get("counter") == 1

    def test_multi_batch_chaining(self):
        rollup = Rollup(stf=counter_stf)
        rollup.setup()

        sender = b"\x01" * 20

        # Batch 0: increment once
        rollup.submit_tx(L2Tx(sender=sender, nonce=0, data={}))
        batch0 = rollup.produce_batch()
        receipt0 = rollup.prove_and_submit(batch0)
        assert receipt0.verified

        # Batch 1: increment again
        rollup.submit_tx(L2Tx(sender=sender, nonce=1, data={}))
        batch1 = rollup.produce_batch()
        receipt1 = rollup.prove_and_submit(batch1)
        assert receipt1.verified

        # State should have counter=2
        assert rollup.state["counter"] == 2

        # Batch 1 old root == batch 0 new root (chain)
        assert batch1.old_state_root == batch0.new_state_root

    def test_prove_before_setup_raises(self):
        rollup = Rollup(stf=counter_stf)
        rollup.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={}))
        batch = rollup.produce_batch()
        with pytest.raises(RuntimeError):
            rollup.prove_and_submit(batch)


class TestFullCycleBalanceTransfer:
    """Custom STF with balance checking + transfer logic."""

    def test_mint_and_transfer(self):
        rollup = Rollup(stf=balance_stf)
        rollup.setup()

        sender = b"\x01" * 20

        # Mint 1000 to "alice"
        rollup.submit_tx(L2Tx(
            sender=sender, nonce=0,
            data={"op": "mint", "to": "alice", "amount": "1000"},
        ))
        batch0 = rollup.produce_batch()
        receipt0 = rollup.prove_and_submit(batch0)
        assert receipt0.verified
        assert rollup.state["alice"] == 1000

        # Transfer 300 from alice to bob
        rollup.submit_tx(L2Tx(
            sender=sender, nonce=1,
            data={"op": "transfer", "from": "alice", "to": "bob", "amount": "300"},
        ))
        batch1 = rollup.produce_batch()
        receipt1 = rollup.prove_and_submit(batch1)
        assert receipt1.verified
        assert rollup.state["alice"] == 700
        assert rollup.state["bob"] == 300

    def test_insufficient_balance_rollback(self):
        rollup = Rollup(stf=balance_stf)
        rollup.setup()

        sender = b"\x01" * 20

        # Mint 100 to "alice"
        rollup.submit_tx(L2Tx(
            sender=sender, nonce=0,
            data={"op": "mint", "to": "alice", "amount": "100"},
        ))
        batch0 = rollup.produce_batch()
        rollup.prove_and_submit(batch0)

        # Try to transfer 200 (more than balance) — STF should fail
        rollup.submit_tx(L2Tx(
            sender=sender, nonce=1,
            data={"op": "transfer", "from": "alice", "to": "bob", "amount": "200"},
        ))
        # Tick processes the tx; the failed tx is rolled back
        rollup._sequencer.tick()
        # No successful txs → force_seal returns None
        assert rollup._sequencer.force_seal() is None
        # alice still has 100
        assert rollup.state.get("alice") == 100


class TestRollupWithDefaults:
    """Test that Rollup works with all defaults (no STF provided)."""

    def test_default_stf(self):
        rollup = Rollup()
        rollup.setup()

        rollup.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={}))
        batch = rollup.produce_batch()
        receipt = rollup.prove_and_submit(batch)
        assert receipt.verified

    def test_callable_stf_wrapping(self):
        rollup = Rollup(stf=lambda state, tx: STFResult(success=True))
        rollup.setup()

        rollup.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={}))
        batch = rollup.produce_batch()
        receipt = rollup.prove_and_submit(batch)
        assert receipt.verified


class TestChainInfo:
    def test_chain_info(self):
        config = L2Config(name="test-chain", chain_id=12345)
        rollup = Rollup(stf=counter_stf, config=config)
        info = rollup.chain_info()
        assert info["name"] == "test-chain"
        assert info["chain_id"] == 12345
        assert info["is_setup"] is False

    def test_chain_info_after_setup(self):
        rollup = Rollup(stf=counter_stf)
        rollup.setup()
        info = rollup.chain_info()
        assert info["is_setup"] is True


class TestComponentLevel:
    """Test individual components working together."""

    def test_state_store_root_changes(self):
        store = L2StateStore()
        root0 = store.compute_state_root()
        store.state["x"] = 1
        root1 = store.compute_state_root()
        assert root0 != root1

    def test_state_store_snapshot_rollback(self):
        store = L2StateStore({"a": 1})
        snap = store.snapshot()
        store.state["a"] = 99
        store.rollback(snap)
        assert store.state["a"] == 1

    def test_batch_submitter(self):
        prover = Groth16ProofBackend()
        prover.setup(PythonRuntime(counter_stf), 64)
        l1 = InMemoryL1Backend()
        l1.deploy_verifier(prover.verification_key)
        submitter = BatchSubmitter(prover, l1)

        from ethclient.l2.types import Batch
        batch = Batch(
            number=0,
            transactions=[L2Tx(sender=b"\x01" * 20, nonce=0, data={}, timestamp=1)],
            old_state_root=b"\x11" * 32,
            new_state_root=b"\x22" * 32,
            da_commitment=b"\x33" * 32,
            sealed=True,
        )
        receipt = submitter.process_batch(batch)
        assert receipt.verified
        assert receipt.batch_number == 0
