"""Tests for L2 types: L2Tx, Batch, L2State, STFResult, BatchReceipt."""

import pytest
from ethclient.l2.types import (
    L2Tx, L2TxType, L2State, STFResult, Batch, BatchReceipt,
)


class TestL2Tx:
    def test_create_basic_tx(self):
        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={"op": "increment"})
        assert tx.sender == b"\x01" * 20
        assert tx.nonce == 0
        assert tx.data == {"op": "increment"}
        assert tx.tx_type == L2TxType.CALL

    def test_tx_hash_deterministic(self):
        tx1 = L2Tx(sender=b"\x01" * 20, nonce=0, data={"k": "v"}, timestamp=1000)
        tx2 = L2Tx(sender=b"\x01" * 20, nonce=0, data={"k": "v"}, timestamp=1000)
        assert tx1.tx_hash() == tx2.tx_hash()

    def test_tx_hash_differs_for_different_data(self):
        tx1 = L2Tx(sender=b"\x01" * 20, nonce=0, data={"a": "1"}, timestamp=1000)
        tx2 = L2Tx(sender=b"\x01" * 20, nonce=0, data={"b": "2"}, timestamp=1000)
        assert tx1.tx_hash() != tx2.tx_hash()

    def test_encode_decode_roundtrip(self):
        tx = L2Tx(
            sender=b"\xab" * 20,
            nonce=42,
            data={"key": "value", "num": 123},
            value=1000,
            tx_type=L2TxType.DEPOSIT,
            timestamp=99999,
        )
        encoded = tx.encode()
        decoded = L2Tx.decode(encoded)
        assert decoded.sender == tx.sender
        assert decoded.nonce == tx.nonce
        assert decoded.data == {"key": "value", "num": 123}
        assert decoded.value == tx.value
        assert decoded.tx_type == L2TxType.DEPOSIT
        assert decoded.timestamp == tx.timestamp

    def test_encode_decode_empty_data(self):
        tx = L2Tx(sender=b"\x00" * 20, nonce=0, data={}, timestamp=1)
        decoded = L2Tx.decode(tx.encode())
        assert decoded.data == {}

    def test_tx_types(self):
        assert L2TxType.CALL == 0
        assert L2TxType.DEPOSIT == 1
        assert L2TxType.WITHDRAWAL == 2


class TestL2State:
    def test_basic_state(self):
        state = L2State({"a": 1, "b": 2})
        assert state["a"] == 1

    def test_snapshot_and_restore(self):
        state = L2State({"x": 10})
        snap = state.snapshot()
        state["x"] = 20
        assert state["x"] == 20
        assert snap["x"] == 10

    def test_from_dict(self):
        state = L2State.from_dict({"k": "v"})
        assert state["k"] == "v"
        assert isinstance(state, L2State)


class TestSTFResult:
    def test_success(self):
        r = STFResult(success=True, output={"new_balance": 100})
        assert r.success
        assert r.output == {"new_balance": 100}
        assert r.error is None

    def test_failure(self):
        r = STFResult(success=False, error="insufficient funds")
        assert not r.success
        assert r.error == "insufficient funds"


class TestBatch:
    def test_create_batch(self):
        batch = Batch(number=0)
        assert batch.number == 0
        assert batch.transactions == []
        assert not batch.sealed

    def test_tx_commitment_deterministic(self):
        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={"a": "b"}, timestamp=1)
        b1 = Batch(number=0, transactions=[tx])
        b2 = Batch(number=0, transactions=[tx])
        assert b1.tx_commitment() == b2.tx_commitment()

    def test_tx_commitment_empty(self):
        b = Batch(number=0)
        assert len(b.tx_commitment()) == 32

    def test_encode_decode_roundtrip(self):
        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={"op": "inc"}, timestamp=100)
        batch = Batch(
            number=5,
            transactions=[tx],
            old_state_root=b"\xaa" * 32,
            new_state_root=b"\xbb" * 32,
            da_commitment=b"\xcc" * 32,
            sealed=True,
        )
        decoded = Batch.decode(batch.encode())
        assert decoded.number == 5
        assert len(decoded.transactions) == 1
        assert decoded.transactions[0].sender == b"\x01" * 20
        assert decoded.old_state_root == b"\xaa" * 32
        assert decoded.new_state_root == b"\xbb" * 32
        assert decoded.sealed

    def test_batch_status_flags(self):
        b = Batch(number=0)
        assert not b.sealed
        assert not b.proven
        assert not b.submitted
        assert not b.verified


class TestBatchReceipt:
    def test_receipt(self):
        r = BatchReceipt(
            batch_number=1,
            l1_tx_hash=b"\xde" * 32,
            verified=True,
            state_root=b"\xef" * 32,
        )
        assert r.batch_number == 1
        assert r.verified
