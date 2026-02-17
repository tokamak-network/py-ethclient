"""
Tests for Phase 6: JSON-RPC Server.

Uses FastAPI TestClient for synchronous testing.
"""

import pytest
from fastapi.testclient import TestClient

from ethclient.rpc.server import RPCServer, RPCError, hex_to_int, int_to_hex, bytes_to_hex, hex_to_bytes, parse_block_param


# ===================================================================
# Utility tests
# ===================================================================

class TestUtils:
    def test_hex_to_int(self):
        assert hex_to_int("0x0") == 0
        assert hex_to_int("0x1") == 1
        assert hex_to_int("0xff") == 255
        assert hex_to_int("0x100") == 256

    def test_int_to_hex(self):
        assert int_to_hex(0) == "0x0"
        assert int_to_hex(255) == "0xff"
        assert int_to_hex(256) == "0x100"

    def test_bytes_to_hex(self):
        assert bytes_to_hex(b"") == "0x"
        assert bytes_to_hex(b"\x00") == "0x00"
        assert bytes_to_hex(b"\xff") == "0xff"
        assert bytes_to_hex(b"\xde\xad") == "0xdead"

    def test_hex_to_bytes(self):
        assert hex_to_bytes("0x") == b""
        assert hex_to_bytes("0x00") == b"\x00"
        assert hex_to_bytes("0xdead") == b"\xde\xad"

    def test_parse_block_param(self):
        assert parse_block_param("latest") == "latest"
        assert parse_block_param("earliest") == "earliest"
        assert parse_block_param("pending") == "pending"
        assert parse_block_param("safe") == "safe"
        assert parse_block_param("0x0") == 0
        assert parse_block_param("0x10") == 16


# ===================================================================
# RPC Server framework tests
# ===================================================================

class TestRPCServer:
    def setup_method(self):
        self.rpc = RPCServer()

        @self.rpc.method("test_echo")
        def echo(msg: str) -> str:
            return msg

        @self.rpc.method("test_add")
        def add(a: int, b: int) -> int:
            return a + b

        @self.rpc.method("test_error")
        def fail():
            raise RPCError(42, "test error", {"detail": "extra"})

        @self.rpc.method("test_no_args")
        def no_args() -> str:
            return "hello"

        self.client = TestClient(self.rpc.app)

    def _call(self, method: str, params=None, id=1):
        body = {"jsonrpc": "2.0", "method": method, "id": id}
        if params is not None:
            body["params"] = params
        return self.client.post("/", json=body).json()

    def test_echo(self):
        result = self._call("test_echo", ["hello"])
        assert result["result"] == "hello"
        assert result["id"] == 1
        assert result["jsonrpc"] == "2.0"

    def test_add(self):
        result = self._call("test_add", [3, 4])
        assert result["result"] == 7

    def test_no_args(self):
        result = self._call("test_no_args")
        assert result["result"] == "hello"

    def test_method_not_found(self):
        result = self._call("nonexistent")
        assert "error" in result
        assert result["error"]["code"] == -32601

    def test_custom_error(self):
        result = self._call("test_error")
        assert "error" in result
        assert result["error"]["code"] == 42
        assert result["error"]["message"] == "test error"
        assert result["error"]["data"] == {"detail": "extra"}

    def test_invalid_params(self):
        result = self._call("test_add", ["not", "numbers", "too many"])
        assert "error" in result

    def test_invalid_json_rpc_version(self):
        body = {"jsonrpc": "1.0", "method": "test_echo", "params": ["hi"], "id": 1}
        result = self.client.post("/", json=body).json()
        assert "error" in result
        assert result["error"]["code"] == -32600

    def test_batch_request(self):
        batch = [
            {"jsonrpc": "2.0", "method": "test_echo", "params": ["a"], "id": 1},
            {"jsonrpc": "2.0", "method": "test_add", "params": [1, 2], "id": 2},
        ]
        result = self.client.post("/", json=batch).json()
        assert len(result) == 2
        assert result[0]["result"] == "a"
        assert result[1]["result"] == 3

    def test_empty_batch(self):
        result = self.client.post("/", json=[]).json()
        assert "error" in result

    def test_notification_no_response(self):
        # Notification = no "id" field
        body = {"jsonrpc": "2.0", "method": "test_no_args"}
        response = self.client.post("/", json=body)
        # Notifications should return 204 or null
        assert response.status_code in (200, 204)

    def test_named_params(self):
        result = self._call("test_add", {"a": 10, "b": 20})
        assert result["result"] == 30

    def test_non_dict_request(self):
        body = "not json"
        response = self.client.post("/", content=body, headers={"content-type": "application/json"})
        result = response.json()
        assert "error" in result


# ===================================================================
# eth_ API tests
# ===================================================================

class TestEthAPI:
    def setup_method(self):
        self.rpc = RPCServer()
        from ethclient.rpc.eth_api import register_eth_api
        register_eth_api(self.rpc, store=None, chain=None, mempool=None)
        self.client = TestClient(self.rpc.app)

    def _call(self, method: str, params=None, id=1):
        body = {"jsonrpc": "2.0", "method": method, "id": id}
        if params is not None:
            body["params"] = params
        return self.client.post("/", json=body).json()

    # -- Account methods --

    def test_get_balance_no_store(self):
        result = self._call("eth_getBalance", ["0x" + "00" * 20, "latest"])
        assert result["result"] == "0x0"

    def test_get_transaction_count_no_store(self):
        result = self._call("eth_getTransactionCount", ["0x" + "00" * 20, "latest"])
        assert result["result"] == "0x0"

    def test_get_code_no_store(self):
        result = self._call("eth_getCode", ["0x" + "00" * 20, "latest"])
        assert result["result"] == "0x"

    def test_get_storage_at_no_store(self):
        result = self._call("eth_getStorageAt", ["0x" + "00" * 20, "0x0", "latest"])
        assert result["result"] == "0x" + "00" * 32

    # -- Block methods --

    def test_block_number_no_store(self):
        result = self._call("eth_blockNumber")
        assert result["result"] == "0x0"

    def test_get_block_by_number_no_store(self):
        result = self._call("eth_getBlockByNumber", ["0x0", False])
        assert result["result"] is None

    def test_get_block_by_hash_no_store(self):
        result = self._call("eth_getBlockByHash", ["0x" + "00" * 32, False])
        assert result["result"] is None

    # -- Transaction methods --

    def test_get_transaction_by_hash(self):
        result = self._call("eth_getTransactionByHash", ["0x" + "ab" * 32])
        assert result["result"] is None

    def test_get_transaction_receipt(self):
        result = self._call("eth_getTransactionReceipt", ["0x" + "ab" * 32])
        assert result["result"] is None

    # -- Call/Estimate --

    def test_eth_call(self):
        result = self._call("eth_call", [{"to": "0x" + "00" * 20}, "latest"])
        assert result["result"] == "0x"

    def test_estimate_gas(self):
        result = self._call("eth_estimateGas", [{"to": "0x" + "00" * 20}])
        assert result["result"] == hex(21000)

    # -- Fee methods --

    def test_gas_price(self):
        result = self._call("eth_gasPrice")
        assert "result" in result
        assert hex_to_int(result["result"]) > 0

    def test_max_priority_fee(self):
        result = self._call("eth_maxPriorityFeePerGas")
        assert "result" in result

    def test_fee_history(self):
        result = self._call("eth_feeHistory", ["0x1", "latest"])
        assert "result" in result
        assert "baseFeePerGas" in result["result"]

    # -- Chain info --

    def test_chain_id(self):
        result = self._call("eth_chainId")
        assert result["result"] == "0x1"

    def test_syncing(self):
        result = self._call("eth_syncing")
        assert result["result"] is False

    # -- Logs --

    def test_get_logs(self):
        result = self._call("eth_getLogs", [{}])
        assert result["result"] == []

    def test_get_block_receipts(self):
        result = self._call("eth_getBlockReceipts", ["latest"])
        assert result["result"] == []

    # -- net_ methods --

    def test_net_version(self):
        result = self._call("net_version")
        assert result["result"] == "1"

    def test_net_peer_count(self):
        result = self._call("net_peerCount")
        assert result["result"] == "0x0"

    def test_net_listening(self):
        result = self._call("net_listening")
        assert result["result"] is True

    # -- web3_ methods --

    def test_web3_client_version(self):
        result = self._call("web3_clientVersion")
        assert result["result"] == "py-ethclient/0.1.0"

    def test_web3_sha3(self):
        # keccak256(0x) = keccak256(b"")
        result = self._call("web3_sha3", ["0x"])
        assert "result" in result
        # keccak256(b"") is a known value
        assert result["result"].startswith("0x")
        assert len(result["result"]) == 66  # 0x + 32 bytes hex


# ===================================================================
# Format helper tests
# ===================================================================

class TestFormatHelpers:
    def test_format_block_header(self):
        from ethclient.rpc.eth_api import _format_block_header
        from ethclient.common.types import BlockHeader

        header = BlockHeader(
            number=100,
            gas_limit=30_000_000,
            gas_used=21000,
            timestamp=1700000000,
            base_fee_per_gas=1_000_000_000,
        )
        result = _format_block_header(header)

        assert result["number"] == hex(100)
        assert result["gasLimit"] == hex(30_000_000)
        assert result["gasUsed"] == hex(21000)
        assert result["baseFeePerGas"] == hex(1_000_000_000)
        assert "hash" in result
        assert result["hash"].startswith("0x")
