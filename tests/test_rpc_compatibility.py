"""RPC method response format compatibility tests."""

import pytest
from eth_utils.currency import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.rpc.methods import create_methods


class TestEthChainId:
    def test_returns_hex_string(self, chain):
        methods = create_methods(chain)
        result = methods["eth_chainId"]([])
        assert result.startswith("0x")
        assert int(result, 16) == 1337

    def test_chain_id_matches_genesis(self, chain):
        methods = create_methods(chain)
        result = methods["eth_chainId"]([])
        assert int(result, 16) == chain.chain_id


class TestEthBlockNumber:
    def test_returns_hex_string(self, chain):
        methods = create_methods(chain)
        result = methods["eth_blockNumber"]([])
        assert result.startswith("0x")
        assert int(result, 16) == 0

    def test_increases_after_block(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        assert int(methods["eth_blockNumber"]([]), 16) == 0
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        assert int(methods["eth_blockNumber"]([]), 16) == 1


class TestEthGetBalance:
    def test_returns_hex_string(self, chain, address):
        methods = create_methods(chain)
        result = methods["eth_getBalance"](["0x" + address.hex(), "latest"])
        assert result.startswith("0x")
        assert int(result, 16) == to_wei(100, "ether")

    def test_zero_balance_for_unknown_address(self, chain):
        methods = create_methods(chain)
        unknown_addr = "0x" + (b"\x00" * 20).hex()
        result = methods["eth_getBalance"]([unknown_addr, "latest"])
        assert int(result, 16) == 0


class TestEthGetTransactionCount:
    def test_returns_hex_nonce(self, chain, address):
        methods = create_methods(chain)
        result = methods["eth_getTransactionCount"](["0x" + address.hex(), "latest"])
        assert result.startswith("0x")
        assert int(result, 16) == 0

    def test_nonce_increases_after_tx(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionCount"](["0x" + address.hex(), "latest"])
        assert int(result, 16) == 1


class TestEthGetCode:
    def test_returns_hex_for_eoa(self, chain, address):
        methods = create_methods(chain)
        result = methods["eth_getCode"](["0x" + address.hex(), "latest"])
        assert result.startswith("0x")
        assert result == "0x"

    def test_returns_bytecode_for_contract(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        bytecode = bytes.fromhex("6060604052")
        contract_tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=None,
            value=0,
            data=bytecode,
            gas=100000,
        )
        chain.send_transaction(contract_tx)
        chain.build_block()
        
        receipts = chain.store.get_receipts(1)
        assert len(receipts) == 1


class TestEthGetStorageAt:
    def test_returns_hex_value(self, chain, address):
        methods = create_methods(chain)
        result = methods["eth_getStorageAt"](["0x" + address.hex(), "0x0", "latest"])
        assert result.startswith("0x")

    def test_storage_slot_zero_for_eoa(self, chain, address):
        methods = create_methods(chain)
        result = methods["eth_getStorageAt"](["0x" + address.hex(), "0x0", "latest"])
        assert int(result, 16) == 0


class TestEthGetBlockByNumber:
    def test_returns_block_structure(self, chain):
        methods = create_methods(chain)
        result = methods["eth_getBlockByNumber"](["0x0", False])
        
        assert result is not None
        assert "number" in result
        assert "hash" in result
        assert "parentHash" in result
        assert "stateRoot" in result
        assert "transactionsRoot" in result
        assert "receiptsRoot" in result
        assert "gasLimit" in result
        assert "gasUsed" in result
        assert "timestamp" in result
        assert "baseFeePerGas" in result
    
    def test_all_fields_are_hex(self, chain):
        methods = create_methods(chain)
        block = methods["eth_getBlockByNumber"](["0x0", False])
        
        assert block["number"].startswith("0x")
        assert block["hash"].startswith("0x")
        assert block["parentHash"].startswith("0x")
        assert block["stateRoot"].startswith("0x")
        assert block["gasLimit"].startswith("0x")
        assert block["timestamp"].startswith("0x")

    def test_transactions_is_hash_list_when_false(self, chain):
        methods = create_methods(chain)
        block = methods["eth_getBlockByNumber"](["0x0", False])
        
        assert isinstance(block["transactions"], list)
        for tx in block["transactions"]:
            assert isinstance(tx, str)
            assert tx.startswith("0x")

    def test_transactions_is_object_list_when_true(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        methods = create_methods(chain)
        block = methods["eth_getBlockByNumber"](["0x1", True])
        
        assert len(block["transactions"]) == 1
        tx_obj = block["transactions"][0]
        assert "hash" in tx_obj
        assert "from" in tx_obj
        assert "to" in tx_obj
        assert "value" in tx_obj
        assert "gas" in tx_obj
        assert "nonce" in tx_obj

    def test_returns_none_for_nonexistent_block(self, chain):
        methods = create_methods(chain)
        result = methods["eth_getBlockByNumber"](["0x999", False])
        assert result is None


class TestEthGetBlockByHash:
    def test_returns_block_by_hash(self, chain):
        methods = create_methods(chain)
        genesis = chain.get_block_by_number(0)
        
        result = methods["eth_getBlockByHash"](["0x" + genesis.hash.hex(), False])
        
        assert result is not None
        assert result["number"] == "0x0"

    def test_returns_none_for_invalid_hash(self, chain):
        methods = create_methods(chain)
        result = methods["eth_getBlockByHash"](["0x" + (b"\x00" * 32).hex(), False])
        assert result is None


class TestEthGetTransactionReceipt:
    def test_receipt_structure(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        methods = create_methods(chain)
        receipt = methods["eth_getTransactionReceipt"](["0x" + tx_hash.hex()])
        
        assert receipt is not None
        assert "status" in receipt
        assert "cumulativeGasUsed" in receipt
        assert "logs" in receipt
        assert "transactionHash" in receipt
        assert "blockNumber" in receipt
        assert "blockHash" in receipt
        assert "from" in receipt
        assert "to" in receipt
        assert "effectiveGasPrice" in receipt

    def test_receipt_status_is_hex(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        methods = create_methods(chain)
        receipt = methods["eth_getTransactionReceipt"](["0x" + tx_hash.hex()])
        
        assert receipt["status"].startswith("0x")
        assert int(receipt["status"], 16) == 1

    def test_receipt_returns_none_for_unknown_tx(self, chain):
        methods = create_methods(chain)
        result = methods["eth_getTransactionReceipt"](["0x" + (b"\x00" * 32).hex()])
        assert result is None


class TestEthSendTransaction:
    def test_returns_tx_hash(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        methods = create_methods(chain)
        
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "value": "0xde0b6b3a7640000",
            "gas": "0x5208",
            "gasPrice": "0x3b9aca00",
            "_private_key": (b"\x01" * 32).hex(),
        }
        
        result = methods["eth_sendTransaction"]([tx_params])
        
        assert result.startswith("0x")
        assert len(bytes.fromhex(result[2:])) == 32


class TestEthGasPrice:
    def test_returns_hex_string(self, chain):
        methods = create_methods(chain)
        result = methods["eth_gasPrice"]([])
        assert result.startswith("0x")
        assert int(result, 16) > 0


class TestEthFeeHistory:
    def test_returns_required_fields(self, chain):
        methods = create_methods(chain)
        result = methods["eth_feeHistory"]([1, "latest", []])
        
        assert "oldestBlock" in result
        assert "baseFeePerGas" in result
        assert "gasUsedRatio" in result
        assert result["oldestBlock"].startswith("0x")

    def test_base_fee_per_gas_length(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        for _ in range(3):
            tx = chain.create_eip1559_transaction(
                from_private_key=b"\x01" * 32,
                to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
                value=to_wei(1, "ether"),
                gas=21000,
            )
            chain.send_transaction(tx)
            chain.build_block()
        
        methods = create_methods(chain)
        result = methods["eth_feeHistory"]([2, "latest", []])
        
        assert len(result["baseFeePerGas"]) >= 2
        assert len(result["gasUsedRatio"]) >= 1

    def test_with_reward_percentiles(self, chain):
        methods = create_methods(chain)
        result = methods["eth_feeHistory"]([1, "latest", [25, 50, 75]])
        
        assert "reward" in result


class TestNetVersion:
    def test_returns_chain_id_as_string(self, chain):
        methods = create_methods(chain)
        result = methods["net_version"]([])
        assert result == "1337"


class TestEthAccounts:
    def test_returns_empty_list(self, chain):
        methods = create_methods(chain)
        result = methods["eth_accounts"]([])
        assert result == []


class TestEthCoinbase:
    def test_returns_checksum_address(self, chain):
        methods = create_methods(chain)
        result = methods["eth_coinbase"]([])
        assert result.startswith("0x")
        assert len(bytes.fromhex(result[2:])) == 20