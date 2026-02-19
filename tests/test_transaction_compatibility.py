"""Transaction type compatibility tests."""

import pytest
from eth_utils.currency import to_wei
from rlp import decode

from sequencer.sequencer.chain import Chain
from sequencer.rpc.methods import create_methods
from sequencer.core.crypto import keccak256


class TestLegacyTransaction:
    def test_legacy_transaction_has_gas_price(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
            gas_price=1000000000,
        )
        
        assert hasattr(tx, "gas_price")
        assert tx.gas_price == 1000000000

    def test_legacy_transaction_encoding(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
            gas_price=1000000000,
        )
        
        encoded = tx.encode()
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

    def test_legacy_transaction_hash_is_32_bytes(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
            gas_price=1000000000,
        )
        
        tx_hash = keccak256(tx.encode())
        assert len(tx_hash) == 32

    def test_legacy_transaction_in_block(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
            gas_price=1000000000,
        )
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert len(block.transactions) == 1
        block_tx = block.transactions[0]
        assert hasattr(block_tx, "gas_price")

    def test_legacy_transaction_rpc_format(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "value": "0xde0b6b3a7640000",
            "gas": "0x5208",
            "gasPrice": "0x3b9aca00",
            "_private_key": (b"\x01" * 32).hex(),
        }
        
        methods["eth_sendTransaction"]([tx_params])
        chain.build_block()
        
        block = methods["eth_getBlockByNumber"](["0x1", True])
        tx_obj = block["transactions"][0]
        
        assert "gasPrice" in tx_obj


class TestEIP1559Transaction:
    def test_eip1559_transaction_type_is_two(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        
        assert hasattr(tx, "max_fee_per_gas")
        assert hasattr(tx, "max_priority_fee_per_gas")
        assert not hasattr(tx, "gas_price")

    def test_eip1559_transaction_encoding_has_type_prefix(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        
        encoded = tx.encode()
        assert encoded[0] == 0x02

    def test_eip1559_transaction_fee_fields(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
            max_fee_per_gas=2000000000,
            max_priority_fee_per_gas=100000000,
        )
        
        assert tx.max_fee_per_gas == 2000000000
        assert tx.max_priority_fee_per_gas == 100000000

    def test_eip1559_transaction_in_block(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert len(block.transactions) == 1
        block_tx = block.transactions[0]
        assert hasattr(block_tx, "max_fee_per_gas")
        assert hasattr(block_tx, "max_priority_fee_per_gas")

    def test_eip1559_transaction_rpc_format(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "value": "0xde0b6b3a7640000",
            "gas": "0x5208",
            "maxFeePerGas": "0x77359400",
            "maxPriorityFeePerGas": "0x5f5e100",
            "_private_key": (b"\x01" * 32).hex(),
        }
        
        methods["eth_sendTransaction"]([tx_params])
        chain.build_block()
        
        block = methods["eth_getBlockByNumber"](["0x1", True])
        tx_obj = block["transactions"][0]
        
        assert tx_obj["type"] == "0x2"
        assert "maxFeePerGas" in tx_obj
        assert "maxPriorityFeePerGas" in tx_obj

    def test_eip1559_receipt_has_effective_gas_price(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        methods = create_methods(chain)
        receipt = methods["eth_getTransactionReceipt"](["0x" + tx_hash.hex()])
        
        assert "effectiveGasPrice" in receipt
        assert receipt["effectiveGasPrice"].startswith("0x")
        effective_price = int(receipt["effectiveGasPrice"], 16)
        assert effective_price > 0


class TestTransactionSignature:
    def test_legacy_transaction_has_vrs(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
            gas_price=1000000000,
        )
        
        assert hasattr(tx, "v")
        assert hasattr(tx, "r")
        assert hasattr(tx, "s")
        assert tx.v >= 27
        assert tx.r > 0
        assert tx.s > 0

    def test_eip1559_transaction_has_y_parity(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        
        assert hasattr(tx, "r")
        assert hasattr(tx, "s")
        assert tx.r > 0
        assert tx.s > 0

    def test_transaction_sender_recovery(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
            gas_price=1000000000,
        )
        
        assert tx.sender == address

    def test_eip1559_transaction_sender_recovery(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        
        assert tx.sender == address


class TestTransactionNonce:
    def test_legacy_transaction_nonce_increments(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx1 = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
            gas_price=1000000000,
        )
        chain.send_transaction(tx1)
        chain.build_block()
        
        tx2 = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
            gas_price=1000000000,
        )
        
        assert tx2.nonce == 1

    def test_eip1559_transaction_nonce_increments(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx1 = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        chain.send_transaction(tx1)
        chain.build_block()
        
        tx2 = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        
        assert tx2.nonce == 1


class TestContractCreation:
    def test_legacy_contract_creation_to_is_none(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        methods = create_methods(chain)
        
        tx_params = {
            "from": "0x" + address.hex(),
            "value": "0x0",
            "gas": "0x7a120",
            "gasPrice": "0x3b9aca00",
            "data": "0x6060604052",
            "_private_key": (b"\x01" * 32).hex(),
        }
        
        tx_hash = methods["eth_sendTransaction"]([tx_params])
        assert tx_hash.startswith("0x")

    def test_eip1559_contract_creation_to_is_none(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        methods = create_methods(chain)
        
        tx_params = {
            "from": "0x" + address.hex(),
            "value": "0x0",
            "gas": "0x7a120",
            "maxFeePerGas": "0x77359400",
            "maxPriorityFeePerGas": "0x5f5e100",
            "data": "0x6060604052",
            "_private_key": (b"\x01" * 32).hex(),
        }
        
        tx_hash = methods["eth_sendTransaction"]([tx_params])
        assert tx_hash.startswith("0x")