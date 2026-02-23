"""Tests for L2 RPC API (l2_* methods)."""

import pytest
from ethclient.l2.rollup import Rollup
from ethclient.l2.types import L2Tx, STFResult
from ethclient.l2.config import L2Config
from ethclient.rpc.server import RPCServer
from ethclient.l2.rpc_api import register_l2_api


def _counter_stf(state, tx):
    state["counter"] = state.get("counter", 0) + 1
    return STFResult(success=True)


def _make_rpc_rollup():
    """Create a Rollup + RPCServer with l2 API registered."""
    config = L2Config(max_txs_per_batch=4)
    rollup = Rollup(stf=_counter_stf, config=config)
    rollup.setup()
    rpc = RPCServer()
    register_l2_api(rpc, rollup)
    return rpc, rollup


class TestL2RPC:
    def test_send_transaction(self):
        rpc, rollup = _make_rpc_rollup()
        handler = rpc._methods["l2_sendTransaction"]
        result = handler({"sender": "0x" + "01" * 20, "nonce": 0, "data": {}})
        assert "txHash" in result
        assert result["txHash"].startswith("0x")

    def test_send_transaction_invalid_sender(self):
        rpc, rollup = _make_rpc_rollup()
        handler = rpc._methods["l2_sendTransaction"]
        result = handler({"sender": "not-hex", "nonce": 0})
        assert "error" in result
        assert "invalid sender" in result["error"]

    def test_send_transaction_invalid_nonce_hex(self):
        rpc, rollup = _make_rpc_rollup()
        handler = rpc._methods["l2_sendTransaction"]
        result = handler({"sender": "0x" + "01" * 20, "nonce": "zzz"})
        assert "error" in result
        assert "invalid numeric" in result["error"]

    def test_get_state(self):
        rpc, rollup = _make_rpc_rollup()
        handler = rpc._methods["l2_getState"]
        state = handler()
        assert isinstance(state, dict)

    def test_get_state_root(self):
        rpc, rollup = _make_rpc_rollup()
        handler = rpc._methods["l2_getStateRoot"]
        root = handler()
        assert root.startswith("0x")

    def test_get_batch_not_found(self):
        rpc, rollup = _make_rpc_rollup()
        handler = rpc._methods["l2_getBatch"]
        result = handler(999)
        assert result is None

    def test_get_batch_found(self):
        rpc, rollup = _make_rpc_rollup()
        # Submit + produce a batch
        rollup.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={}))
        rollup.produce_batch()

        handler = rpc._methods["l2_getBatch"]
        result = handler(0)
        assert result is not None
        assert result["number"] == 0
        assert result["txCount"] == 1
        assert result["sealed"] is True

    def test_produce_batch(self):
        rpc, rollup = _make_rpc_rollup()
        rollup.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={}))

        handler = rpc._methods["l2_produceBatch"]
        result = handler()
        assert "number" in result
        assert result["txCount"] == 1

    def test_produce_batch_empty(self):
        rpc, rollup = _make_rpc_rollup()
        handler = rpc._methods["l2_produceBatch"]
        result = handler()
        assert "error" in result

    def test_prove_and_submit(self):
        rpc, rollup = _make_rpc_rollup()
        rollup.submit_tx(L2Tx(sender=b"\x01" * 20, nonce=0, data={}))
        rollup.produce_batch()

        handler = rpc._methods["l2_proveAndSubmit"]
        result = handler(0)
        assert result["verified"] is True
        assert result["batchNumber"] == 0
        assert result["l1TxHash"].startswith("0x")

    def test_prove_and_submit_not_found(self):
        rpc, rollup = _make_rpc_rollup()
        handler = rpc._methods["l2_proveAndSubmit"]
        result = handler(999)
        assert "error" in result
        assert "not found" in result["error"]

    def test_chain_info(self):
        rpc, rollup = _make_rpc_rollup()
        handler = rpc._methods["l2_chainInfo"]
        info = handler()
        assert info["name"] == "py-rollup"
        assert info["chain_id"] == 42170
        assert info["is_setup"] is True
        assert "state_root" in info
