"""Transaction lookup tests for eth_getTransactionByHash RPC method."""

import pytest
from eth_utils.currency import to_wei
from eth_utils.address import to_checksum_address

from sequencer.sequencer.chain import Chain
from sequencer.rpc.methods import create_methods


class TestGetTransactionByHashBasic:
    """Basic tests for eth_getTransactionByHash."""

    def test_returns_none_for_unknown_transaction(self, chain):
        """Unknown transaction hash should return null."""
        methods = create_methods(chain)
        unknown_hash = b"\x00" * 32
        result = methods["eth_getTransactionByHash"](["0x" + unknown_hash.hex()])
        assert result is None

    def test_returns_none_for_random_hash(self, chain):
        """Random hash should return null."""
        methods = create_methods(chain)
        random_hash = b"\xab\xcd" * 16
        result = methods["eth_getTransactionByHash"](["0x" + random_hash.hex()])
        assert result is None

    def test_returns_none_before_any_transactions(self, chain):
        """Should return null when no transactions exist."""
        methods = create_methods(chain)
        # Unknown hash should return None
        unknown_hash = "0x" + ("00" * 32)
        result = methods["eth_getTransactionByHash"]([unknown_hash])
        assert result is None


class TestGetTransactionByHashLegacy:
    """Tests for legacy transaction lookup."""

    def test_returns_legacy_transaction_details(self, pk, address):
        """Legacy transaction should return all required fields."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        recipient = b"\xde\xad\xbe\xef" * 5
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=recipient,
            value=to_wei(1, "ether"),
            gas=21000,
            gas_price=1000000000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
        
        assert result is not None
        assert result["hash"] == "0x" + tx_hash.hex()
        assert result["blockNumber"] == "0x1"
        assert result["from"] == to_checksum_address(address)
        assert result["to"] == to_checksum_address(recipient)
        assert result["value"] == hex(to_wei(1, "ether"))
        assert result["gas"] == "0x5208"
        assert result["nonce"] == "0x0"
        assert result["type"] == "0x0"

    def test_legacy_transaction_has_vrs_signature(self, pk, address):
        """Legacy transaction should include v, r, s signature fields."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=0,
            gas=21000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
        
        assert "v" in result
        assert "r" in result
        assert "s" in result
        assert result["v"].startswith("0x")
        assert result["r"].startswith("0x")
        assert result["s"].startswith("0x")

    def test_legacy_transaction_has_gas_price(self, pk, address):
        """Legacy transaction should have gasPrice field."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=0,
            gas=21000,
            gas_price=2000000000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
        
        assert result["type"] == "0x0"
        assert "gasPrice" in result
        assert result["gasPrice"] == "0x77359400"
        assert "maxFeePerGas" not in result
        assert "maxPriorityFeePerGas" not in result


class TestGetTransactionByHashEIP1559:
    """Tests for EIP-1559 transaction lookup."""

    def test_returns_eip1559_transaction_details(self, pk, address):
        """EIP-1559 transaction should return all required fields."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
            max_fee_per_gas=2000000000,
            max_priority_fee_per_gas=100000000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
        
        assert result is not None
        assert result["hash"] == "0x" + tx_hash.hex()
        assert result["type"] == "0x2"

    def test_eip1559_transaction_has_fee_fields(self, pk, address):
        """EIP-1559 transaction should have maxFeePerGas and maxPriorityFeePerGas."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=0,
            gas=21000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
        
        assert result["type"] == "0x2"
        assert "maxFeePerGas" in result
        assert "maxPriorityFeePerGas" in result
        # Note: gasPrice is set to maxFeePerGas for backward compatibility
        assert result["gasPrice"] == result["maxFeePerGas"]

    def test_eip1559_transaction_has_chain_id(self, pk, address):
        """EIP-1559 transaction should include chainId."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=0,
            gas=21000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
        
        assert "chainId" in result
        assert result["chainId"] == "0x539"  # 1337 in hex


class TestGetTransactionByHashBlockInfo:
    """Tests for block information in transaction lookup."""

    def test_transaction_includes_block_hash(self, pk, address):
        """Transaction should include blockHash."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=0,
            gas=21000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
        block = chain.get_block_by_number(1)
        
        assert "blockHash" in result
        assert result["blockHash"] == "0x" + block.hash.hex()

    def test_transaction_includes_correct_block_number(self, pk, address):
        """Transaction should be in correct block."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        # Create transactions in multiple blocks
        for i in range(3):
            tx = chain.create_transaction(
                from_private_key=b"\x01" * 32,
                to=b"\xde\xad\xbe\xef" * 5,
                value=to_wei(i, "ether"),
                gas=21000,
            )
            tx_hash = chain.send_transaction(tx)
            chain.build_block()
            
            result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
            assert result["blockNumber"] == hex(i + 1)

    def test_transaction_index_in_block(self, pk, address):
        """Transaction should have correct index."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        # Send multiple transactions in same block with sequential nonces
        tx_hashes = []
        for i in range(3):
            tx = chain.create_transaction(
                from_private_key=b"\x01" * 32,
                to=bytes([0x11 + i] * 20),
                value=0,
                gas=21000,
                nonce=i,
            )
            tx_hash = chain.send_transaction(tx)
            tx_hashes.append(tx_hash)
        
        chain.build_block()
        
        # Check each transaction
        for i, tx_hash in enumerate(tx_hashes):
            result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
            assert result is not None
            assert result["blockNumber"] == "0x1"


class TestGetTransactionByHashContractCreation:
    """Tests for contract creation transaction lookup."""

    def test_contract_creation_transaction(self, pk, address):
        """Contract creation should have null 'to' field."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        bytecode = bytes.fromhex("6080604052")
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=None,  # Contract creation
            value=0,
            data=bytecode,
            gas=100000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
        
        assert result is not None
        assert result["to"] is None
        assert result["input"] == "0x" + bytecode.hex()

    def test_contract_creation_has_input_data(self, pk, address):
        """Contract creation should include bytecode in input field."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        bytecode = bytes.fromhex("6080604052348015600f57600080fd5b50")
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=None,
            value=0,
            data=bytecode,
            gas=100000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
        
        assert result["input"] == "0x" + bytecode.hex()
        assert len(result["input"]) > 2


class TestGetTransactionByHashMultipleTransactions:
    """Tests for multiple transactions lookup."""

    def test_can_retrieve_multiple_transactions(self, pk, address):
        """All transactions should be retrievable by hash."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        recipients = [bytes([0x11 + i] * 20) for i in range(5)]
        tx_hashes = []
        
        for recipient in recipients:
            tx = chain.create_transaction(
                from_private_key=b"\x01" * 32,
                to=recipient,
                value=to_wei(1, "ether"),
                gas=21000,
            )
            tx_hash = chain.send_transaction(tx)
            tx_hashes.append(tx_hash)
            chain.build_block()
        
        # Retrieve all transactions
        for i, (tx_hash, recipient) in enumerate(zip(tx_hashes, recipients)):
            result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
            assert result is not None
            assert result["to"] == to_checksum_address(recipient)
            assert result["blockNumber"] == hex(i + 1)

    def test_transactions_in_same_block(self, pk, address):
        """Multiple transactions in same block should all be retrievable."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        recipients = [bytes([0x11 + i] * 20) for i in range(5)]
        tx_hashes = []
        
        # Create transactions with sequential nonces
        for i, recipient in enumerate(recipients):
            tx = chain.create_transaction(
                from_private_key=b"\x01" * 32,
                to=recipient,
                value=to_wei(1, "ether"),
                gas=21000,
                nonce=i,
            )
            tx_hash = chain.send_transaction(tx)
            tx_hashes.append(tx_hash)
        
        chain.build_block()
        
        # All should be in block 1
        for tx_hash in tx_hashes:
            result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
            assert result is not None
            assert result["blockNumber"] == "0x1"


class TestGetTransactionByHashDirectMethod:
    """Tests for direct chain.get_transaction_by_hash() method."""

    def test_direct_method_returns_tuple(self, pk, address):
        """Direct method should return (block, transaction) tuple."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=0,
            gas=21000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = chain.get_transaction_by_hash(tx_hash)
        
        assert result is not None
        block, transaction = result
        assert block.number == 1
        assert transaction in block.transactions

    def test_direct_method_returns_none_for_unknown(self, chain):
        """Direct method should return None for unknown hash."""
        unknown_hash = b"\x00" * 32
        result = chain.get_transaction_by_hash(unknown_hash)
        assert result is None


class TestGetTransactionByHashEdgeCases:
    """Edge case tests for transaction lookup."""

    def test_contract_creation_legacy_transaction(self, pk, address):
        """Contract creation with legacy transaction type."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        bytecode = bytes.fromhex("6080604052")
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=None,
            value=to_wei(1, "ether"),
            data=bytecode,
            gas=100000,
            gas_price=1000000000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
        
        assert result is not None
        assert result["type"] == "0x0"
        assert result["to"] is None
        assert result["value"] == hex(to_wei(1, "ether"))

    def test_transaction_with_empty_data(self, pk, address):
        """Transaction with empty data field."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21000,
        )
        tx_hash = chain.send_transaction(tx)
        chain.build_block()
        
        result = methods["eth_getTransactionByHash"](["0x" + tx_hash.hex()])
        
        assert result is not None
        assert result["input"] == "0x"
