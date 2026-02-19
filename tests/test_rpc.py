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

    # -- Call/Estimate (no store) --

    def test_eth_call_no_store(self):
        result = self._call("eth_call", [{"to": "0x" + "00" * 20}, "latest"])
        assert result["result"] == "0x"

    def test_estimate_gas_no_store(self):
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

    def test_eth_config(self):
        result = self._call("eth_config")
        assert "result" in result
        assert "current" in result["result"]
        assert "chainId" in result["result"]["current"]
        assert "blobSchedule" in result["result"]["current"]
        assert "target" in result["result"]["current"]["blobSchedule"]
        assert "baseFeeUpdateFraction" in result["result"]["current"]["blobSchedule"]

    def test_syncing(self):
        result = self._call("eth_syncing")
        assert result["result"] is False

    def test_syncing_with_provider(self):
        from ethclient.rpc.eth_api import register_eth_api
        rpc = RPCServer()
        register_eth_api(
            rpc,
            store=None,
            chain=None,
            mempool=None,
            syncing_provider=lambda: True,
        )
        client = TestClient(rpc.app)
        result = client.post("/", json={"jsonrpc": "2.0", "method": "eth_syncing", "id": 1}).json()
        assert result["result"] is True

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

    def test_net_peer_count_with_provider(self):
        from ethclient.rpc.eth_api import register_eth_api
        rpc = RPCServer()
        register_eth_api(
            rpc,
            store=None,
            chain=None,
            mempool=None,
            peer_count_provider=lambda: 3,
        )
        client = TestClient(rpc.app)
        result = client.post("/", json={"jsonrpc": "2.0", "method": "net_peerCount", "id": 1}).json()
        assert result["result"] == "0x3"

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

# ===================================================================
# eth_call / eth_estimateGas with real EVM execution
# ===================================================================

class TestEthCallEVM:
    """Tests for eth_call and eth_estimateGas with actual EVM execution."""

    def setup_method(self):
        from ethclient.storage.memory_backend import MemoryBackend
        from ethclient.common.config import ChainConfig
        from ethclient.rpc.eth_api import register_eth_api

        self.store = MemoryBackend()
        self.config = ChainConfig(chain_id=1)
        self.rpc = RPCServer()
        register_eth_api(self.rpc, store=self.store, config=self.config)
        self.client = TestClient(self.rpc.app)

    def _call(self, method: str, params=None, id=1):
        body = {"jsonrpc": "2.0", "method": method, "id": id}
        if params is not None:
            body["params"] = params
        return self.client.post("/", json=body).json()

    def _deploy_code(self, address_hex: str, code: bytes):
        """Deploy bytecode at the given address."""
        from ethclient.common.types import Account, EMPTY_CODE_HASH
        from ethclient.common.crypto import keccak256
        addr = hex_to_bytes(address_hex)
        acc = self.store.get_account(addr)
        if acc is None:
            acc = Account()
            self.store.put_account(addr, acc)
        code_hash = keccak256(code)
        acc.code_hash = code_hash
        self.store._code[code_hash] = code

    # -- eth_call tests --

    def test_eth_call_simple_transfer(self):
        """EOA → EOA transfer (no code) returns 0x."""
        result = self._call("eth_call", [{"to": "0x" + "01" * 20}, "latest"])
        assert result["result"] == "0x"

    def test_eth_call_contract_return(self):
        """Contract returns a value: PUSH1 42 PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN."""
        # Bytecode: PUSH1 0x2a PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN
        code = bytes([
            0x60, 0x2a,  # PUSH1 42
            0x60, 0x00,  # PUSH1 0
            0x52,        # MSTORE
            0x60, 0x20,  # PUSH1 32
            0x60, 0x00,  # PUSH1 0
            0xf3,        # RETURN
        ])
        contract = "0x" + "cc" * 20
        self._deploy_code(contract, code)

        result = self._call("eth_call", [{"to": contract}, "latest"])
        assert "result" in result
        # Should return 32 bytes with value 42 at the last byte
        ret = hex_to_bytes(result["result"])
        assert len(ret) == 32
        assert int.from_bytes(ret, "big") == 42

    def test_eth_call_with_value(self):
        """Call with value to an address without code succeeds."""
        result = self._call("eth_call", [
            {"to": "0x" + "01" * 20, "value": "0x1"},
            "latest",
        ])
        assert result["result"] == "0x"

    def test_eth_call_revert(self):
        """Contract that REVERTs returns RPC error code 3."""
        # PUSH1 0 PUSH1 0 REVERT
        code = bytes([0x60, 0x00, 0x60, 0x00, 0xfd])
        contract = "0x" + "dd" * 20
        self._deploy_code(contract, code)

        result = self._call("eth_call", [{"to": contract}, "latest"])
        assert "error" in result
        assert result["error"]["code"] == 3

    def test_eth_call_no_from(self):
        """Call without 'from' field uses zero address."""
        result = self._call("eth_call", [{"to": "0x" + "01" * 20}, "latest"])
        assert result["result"] == "0x"

    def test_eth_call_no_gas(self):
        """Call without 'gas' field uses 30M default."""
        code = bytes([
            0x60, 0x2a,  # PUSH1 42
            0x60, 0x00, 0x52,  # MSTORE at 0
            0x60, 0x20, 0x60, 0x00, 0xf3,  # RETURN 32 bytes from 0
        ])
        contract = "0x" + "ee" * 20
        self._deploy_code(contract, code)

        result = self._call("eth_call", [{"to": contract}, "latest"])
        assert "result" in result
        assert hex_to_bytes(result["result"]) != b""

    def test_eth_call_state_unchanged(self):
        """eth_call with SSTORE does not persist state changes."""
        # PUSH1 1 PUSH1 0 SSTORE STOP
        code = bytes([
            0x60, 0x01,  # PUSH1 1
            0x60, 0x00,  # PUSH1 0
            0x55,        # SSTORE
            0x00,        # STOP
        ])
        contract = "0x" + "ff" * 20
        self._deploy_code(contract, code)

        # Call — should execute SSTORE but not persist
        self._call("eth_call", [{"to": contract}, "latest"])

        # Verify storage is unchanged
        val = self.store.get_storage(hex_to_bytes(contract), 0)
        assert val == 0

    def test_eth_call_storage_read(self):
        """SLOAD reads pre-existing storage."""
        contract_addr = hex_to_bytes("0x" + "ab" * 20)
        # Set storage slot 0 = 99
        self.store.put_storage(contract_addr, 0, 99)
        # PUSH1 0 SLOAD PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
        code = bytes([
            0x60, 0x00,  # PUSH1 0
            0x54,        # SLOAD
            0x60, 0x00,  # PUSH1 0
            0x52,        # MSTORE
            0x60, 0x20,  # PUSH1 32
            0x60, 0x00,  # PUSH1 0
            0xf3,        # RETURN
        ])
        self._deploy_code("0x" + "ab" * 20, code)

        result = self._call("eth_call", [{"to": "0x" + "ab" * 20}, "latest"])
        assert "result" in result
        ret = hex_to_bytes(result["result"])
        assert int.from_bytes(ret, "big") == 99

    def test_eth_call_input_data(self):
        """CALLDATALOAD reads input data correctly."""
        # PUSH1 0 CALLDATALOAD PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
        code = bytes([
            0x60, 0x00,  # PUSH1 0
            0x35,        # CALLDATALOAD
            0x60, 0x00,  # PUSH1 0
            0x52,        # MSTORE
            0x60, 0x20,  # PUSH1 32
            0x60, 0x00,  # PUSH1 0
            0xf3,        # RETURN
        ])
        contract = "0x" + "ca" * 20
        self._deploy_code(contract, code)

        # Send data = 0x00...05 (32 bytes with value 5)
        calldata = "0x" + "00" * 31 + "05"
        result = self._call("eth_call", [{"to": contract, "data": calldata}, "latest"])
        assert "result" in result
        ret = hex_to_bytes(result["result"])
        assert int.from_bytes(ret, "big") == 5

    def test_eth_call_precompile_identity(self):
        """Call to identity precompile (0x04) echoes input."""
        # Identity precompile at address 0x04
        precompile = "0x" + "00" * 19 + "04"
        data = "0x" + "aabbccdd"
        result = self._call("eth_call", [{"to": precompile, "data": data}, "latest"])
        assert "result" in result
        assert result["result"] == "0xaabbccdd"

    # -- eth_estimateGas tests --

    def test_estimate_simple_transfer(self):
        """Simple transfer estimation = 21000."""
        result = self._call("eth_estimateGas", [{"to": "0x" + "01" * 20}])
        assert "result" in result
        assert hex_to_int(result["result"]) == 21000

    def test_estimate_contract_call(self):
        """Contract call gas > 21000 (includes opcode gas)."""
        # PUSH1 42 PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
        code = bytes([
            0x60, 0x2a, 0x60, 0x00, 0x52,
            0x60, 0x20, 0x60, 0x00, 0xf3,
        ])
        contract = "0x" + "bb" * 20
        self._deploy_code(contract, code)

        result = self._call("eth_estimateGas", [{"to": contract}])
        assert "result" in result
        gas = hex_to_int(result["result"])
        assert gas > 21000  # Intrinsic 21000 + opcode costs

    def test_estimate_contract_create(self):
        """Contract creation gas includes CREATE overhead."""
        # Simple initcode: PUSH1 0 PUSH1 0 RETURN (returns empty code)
        initcode = "0x" + "60006000f3".ljust(10, "0")
        result = self._call("eth_estimateGas", [{"data": initcode}])
        assert "result" in result
        gas = hex_to_int(result["result"])
        # CREATE intrinsic = 21000 + 32000 = 53000 minimum
        assert gas >= 53000

    def test_estimate_revert(self):
        """Reverted contract returns RPC error."""
        code = bytes([0x60, 0x00, 0x60, 0x00, 0xfd])  # REVERT
        contract = "0x" + "dd" * 20
        self._deploy_code(contract, code)

        result = self._call("eth_estimateGas", [{"to": contract}])
        assert "error" in result
        assert result["error"]["code"] == 3


class TestSimulateCallDirect:
    """Direct tests for simulate_call() function."""

    def test_simulate_call_basic(self):
        from ethclient.storage.memory_backend import MemoryBackend
        from ethclient.common.config import ChainConfig
        from ethclient.common.types import BlockHeader
        from ethclient.blockchain.chain import simulate_call

        store = MemoryBackend()
        config = ChainConfig(chain_id=1)
        header = BlockHeader(gas_limit=30_000_000, base_fee_per_gas=0)

        result = simulate_call(
            sender=b"\x00" * 20,
            to=b"\x01" * 20,
            data=b"",
            value=0,
            gas_limit=100_000,
            header=header,
            store=store,
            config=config,
        )
        assert result.success is True
        assert result.return_data == b""
        assert result.gas_used == 21000  # simple transfer

    def test_simulate_call_with_code(self):
        from ethclient.storage.memory_backend import MemoryBackend
        from ethclient.common.config import ChainConfig
        from ethclient.common.types import BlockHeader, Account
        from ethclient.common.crypto import keccak256
        from ethclient.blockchain.chain import simulate_call

        store = MemoryBackend()
        config = ChainConfig(chain_id=1)
        header = BlockHeader(gas_limit=30_000_000, base_fee_per_gas=0)

        # Deploy simple return bytecode
        code = bytes([0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3])
        to_addr = b"\xcc" * 20
        acc = Account()
        acc.code_hash = keccak256(code)
        store.put_account(to_addr, acc)
        store._code[acc.code_hash] = code

        result = simulate_call(
            sender=b"\x00" * 20,
            to=to_addr,
            data=b"",
            value=0,
            gas_limit=100_000,
            header=header,
            store=store,
            config=config,
        )
        assert result.success is True
        assert int.from_bytes(result.return_data, "big") == 42
        assert result.gas_used > 21000


# ===================================================================
# Format helper tests
# ===================================================================

# ===================================================================
# Transaction index / receipt lookup tests
# ===================================================================

class TestTransactionIndex:
    """Tests for tx/receipt lookup via RPC with real Store data."""

    def setup_method(self):
        from ethclient.storage.memory_backend import MemoryBackend
        from ethclient.common.config import ChainConfig
        from ethclient.common.types import (
            Block, BlockHeader, Transaction, Receipt, Log, TxType,
        )
        from ethclient.rpc.eth_api import register_eth_api

        self.store = MemoryBackend()
        self.rpc = RPCServer()
        register_eth_api(self.rpc, store=self.store, config=ChainConfig(chain_id=1))
        self.client = TestClient(self.rpc.app)

        # Create two transactions
        self.tx0 = Transaction(
            tx_type=TxType.LEGACY, nonce=0, gas_limit=21000,
            to=b"\x01" * 20, value=1000, gas_price=10,
            v=27, r=1, s=1,
        )
        self.tx1 = Transaction(
            tx_type=TxType.FEE_MARKET, nonce=1, gas_limit=50000,
            to=b"\x02" * 20, value=2000, chain_id=1,
            max_fee_per_gas=20, max_priority_fee_per_gas=5,
            v=0, r=2, s=2,
        )

        # Build block with these transactions
        self.header = BlockHeader(
            number=1, gas_limit=30_000_000, gas_used=71000,
            timestamp=1700000000, base_fee_per_gas=10,
        )
        self.block = Block(
            header=self.header,
            transactions=[self.tx0, self.tx1],
        )
        self.block_hash = self.header.block_hash()

        # Store block + receipts + canonical mapping
        self.store.put_block(self.block)
        self.store.put_canonical_hash(1, self.block_hash)

        log0 = Log(address=b"\x01" * 20, topics=[b"\xaa" * 32], data=b"\xdd")
        self.receipt0 = Receipt(
            succeeded=True, cumulative_gas_used=21000,
            logs=[log0], tx_type=TxType.LEGACY,
        )
        self.receipt1 = Receipt(
            succeeded=True, cumulative_gas_used=71000,
            logs=[], tx_type=TxType.FEE_MARKET,
        )
        self.store.put_receipts(self.block_hash, [self.receipt0, self.receipt1])

    def _call(self, method: str, params=None, id=1):
        body = {"jsonrpc": "2.0", "method": method, "id": id}
        if params is not None:
            body["params"] = params
        return self.client.post("/", json=body).json()

    def test_get_transaction_by_hash(self):
        tx_hash_hex = bytes_to_hex(self.tx0.tx_hash())
        result = self._call("eth_getTransactionByHash", [tx_hash_hex])
        tx = result["result"]
        assert tx is not None
        assert tx["hash"] == tx_hash_hex
        assert tx["blockNumber"] == hex(1)
        assert tx["transactionIndex"] == hex(0)
        assert tx["to"] == bytes_to_hex(b"\x01" * 20)
        assert tx["gas"] == hex(21000)
        assert tx["type"] == hex(0)
        assert tx["gasPrice"] == hex(10)

    def test_get_transaction_by_hash_second_tx(self):
        tx_hash_hex = bytes_to_hex(self.tx1.tx_hash())
        result = self._call("eth_getTransactionByHash", [tx_hash_hex])
        tx = result["result"]
        assert tx is not None
        assert tx["transactionIndex"] == hex(1)
        assert tx["type"] == hex(2)
        assert tx["maxFeePerGas"] == hex(20)

    def test_get_transaction_by_hash_not_found(self):
        result = self._call("eth_getTransactionByHash", ["0x" + "ff" * 32])
        assert result["result"] is None

    def test_get_transaction_receipt(self):
        tx_hash_hex = bytes_to_hex(self.tx0.tx_hash())
        result = self._call("eth_getTransactionReceipt", [tx_hash_hex])
        r = result["result"]
        assert r is not None
        assert r["transactionHash"] == tx_hash_hex
        assert r["blockNumber"] == hex(1)
        assert r["transactionIndex"] == hex(0)
        assert r["status"] == hex(1)
        assert r["cumulativeGasUsed"] == hex(21000)
        assert r["gasUsed"] == hex(21000)  # first tx: cumulative == gas_used
        assert len(r["logs"]) == 1
        assert r["logs"][0]["logIndex"] == hex(0)

    def test_get_transaction_receipt_second_tx(self):
        tx_hash_hex = bytes_to_hex(self.tx1.tx_hash())
        result = self._call("eth_getTransactionReceipt", [tx_hash_hex])
        r = result["result"]
        assert r is not None
        assert r["gasUsed"] == hex(50000)  # 71000 - 21000
        assert r["cumulativeGasUsed"] == hex(71000)
        assert r["type"] == hex(2)

    def test_get_transaction_receipt_not_found(self):
        result = self._call("eth_getTransactionReceipt", ["0x" + "ff" * 32])
        assert result["result"] is None

    def test_get_block_by_number_tx_hashes(self):
        result = self._call("eth_getBlockByNumber", [hex(1), False])
        block = result["result"]
        assert block is not None
        assert len(block["transactions"]) == 2
        # Should be tx hashes (strings), not objects
        assert isinstance(block["transactions"][0], str)
        assert block["transactions"][0] == bytes_to_hex(self.tx0.tx_hash())

    def test_get_block_by_number_full_txs(self):
        result = self._call("eth_getBlockByNumber", [hex(1), True])
        block = result["result"]
        assert block is not None
        assert len(block["transactions"]) == 2
        # Should be tx objects (dicts)
        assert isinstance(block["transactions"][0], dict)
        assert block["transactions"][0]["hash"] == bytes_to_hex(self.tx0.tx_hash())
        assert block["transactions"][1]["transactionIndex"] == hex(1)

    def test_get_block_by_hash_full_txs(self):
        bh_hex = bytes_to_hex(self.block_hash)
        result = self._call("eth_getBlockByHash", [bh_hex, True])
        block = result["result"]
        assert block is not None
        assert len(block["transactions"]) == 2

    def test_get_block_tx_count_by_number(self):
        result = self._call("eth_getBlockTransactionCountByNumber", [hex(1)])
        assert result["result"] == hex(2)

    def test_get_block_tx_count_by_hash(self):
        bh_hex = bytes_to_hex(self.block_hash)
        result = self._call("eth_getBlockTransactionCountByHash", [bh_hex])
        assert result["result"] == hex(2)


class TestEngineAPIV3:
    """Engine API V3 behavior tests."""

    def setup_method(self):
        from ethclient.blockchain.fork_choice import ForkChoice
        from ethclient.common.config import ChainConfig
        from ethclient.common.types import BlockHeader
        from ethclient.rpc.engine_api import register_engine_api
        from ethclient.storage.memory_backend import MemoryBackend

        self.store = MemoryBackend()
        self.config = ChainConfig(
            chain_id=11155111,
            london_block=0,
            shanghai_time=0,
            cancun_time=0,
        )
        self.fork_choice = ForkChoice(self.store)

        # Canonical parent block (block 0)
        self.parent_header = BlockHeader(
            number=0,
            gas_limit=30_000_000,
            gas_used=15_000_000,
            timestamp=1,
            base_fee_per_gas=1_000_000_000,
            difficulty=0,
            nonce=b"\x00" * 8,
        )
        self.parent_hash = self.parent_header.block_hash()
        self.store.put_block_header(self.parent_header)
        self.store.put_canonical_hash(0, self.parent_hash)

        self.rpc = RPCServer()
        register_engine_api(
            self.rpc,
            store=self.store,
            fork_choice=self.fork_choice,
            chain_config=self.config,
        )
        self.client = TestClient(self.rpc.app)

    def _call(self, method: str, params=None, id=1):
        body = {"jsonrpc": "2.0", "method": method, "id": id}
        if params is not None:
            body["params"] = params
        return self.client.post("/", json=body).json()

    def _fcu_state(self, head_hash: str | None = None) -> dict:
        return {
            "headBlockHash": head_hash or bytes_to_hex(self.parent_hash),
            "safeBlockHash": "0x" + "00" * 32,
            "finalizedBlockHash": "0x" + "00" * 32,
        }

    def _attrs_v3(self, timestamp_hex: str = "0x2") -> dict:
        return {
            "timestamp": timestamp_hex,
            "prevRandao": "0x" + "11" * 32,
            "suggestedFeeRecipient": "0x" + "22" * 20,
            "withdrawals": [],
            "parentBeaconBlockRoot": "0x" + "33" * 32,
            "transactions": [],
            "noTxPool": True,
            "gasLimit": hex(self.parent_header.gas_limit),
        }

    def test_forkchoice_v3_deterministic_payload_id(self):
        attrs = self._attrs_v3()
        result1 = self._call("engine_forkchoiceUpdatedV3", [self._fcu_state(), attrs])
        result2 = self._call("engine_forkchoiceUpdatedV3", [self._fcu_state(), attrs])
        assert result1["result"]["payloadStatus"]["status"] == "VALID"
        assert result2["result"]["payloadStatus"]["status"] == "VALID"
        assert result1["result"]["payloadId"] == result2["result"]["payloadId"]

    def test_get_payload_v3_unknown_payload(self):
        result = self._call("engine_getPayloadV3", ["0x0102030405060708"])
        assert result["error"]["code"] == -38001

    def test_forkchoice_v3_missing_withdrawals(self):
        attrs = self._attrs_v3()
        attrs.pop("withdrawals")
        result = self._call("engine_forkchoiceUpdatedV3", [self._fcu_state(), attrs])
        assert result["error"]["code"] == -32602

    def test_forkchoice_v3_unsupported_fork(self):
        from ethclient.common.config import ChainConfig
        from ethclient.rpc.engine_api import register_engine_api

        rpc = RPCServer()
        # Cancun not yet active at timestamp 0x2
        cfg = ChainConfig(chain_id=11155111, london_block=0, shanghai_time=0, cancun_time=10)
        register_engine_api(rpc, store=self.store, fork_choice=self.fork_choice, chain_config=cfg)
        client = TestClient(rpc.app)

        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "engine_forkchoiceUpdatedV3",
            "params": [self._fcu_state(), self._attrs_v3("0x2")],
        }
        result = client.post("/", json=body).json()
        assert result["error"]["code"] == -38005

    def test_engine_v3_block_production_loop(self):
        # 1) forkchoiceUpdatedV3 -> payload id
        fcu = self._call("engine_forkchoiceUpdatedV3", [self._fcu_state(), self._attrs_v3()])
        assert fcu["result"]["payloadStatus"]["status"] == "VALID"
        payload_id = fcu["result"]["payloadId"]
        assert payload_id is not None

        # 2) getPayloadV3 -> non-dummy payload
        gp = self._call("engine_getPayloadV3", [payload_id])
        payload = gp["result"]["executionPayload"]
        assert payload["blockHash"] != "0x" + "00" * 32
        assert payload["stateRoot"] != "0x" + "00" * 32
        assert payload["receiptsRoot"] != "0x" + "00" * 32

        # 3) newPayloadV3 -> VALID
        np = self._call(
            "engine_newPayloadV3",
            [payload, [], self._attrs_v3()["parentBeaconBlockRoot"]],
        )
        assert np["result"]["status"] == "VALID"
        new_head = payload["blockHash"]

        # 4) forkchoiceUpdatedV3 with new head -> VALID
        fcu2 = self._call("engine_forkchoiceUpdatedV3", [self._fcu_state(new_head), None])
        assert fcu2["result"]["payloadStatus"]["status"] == "VALID"

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
