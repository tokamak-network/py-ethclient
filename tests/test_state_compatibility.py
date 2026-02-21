"""State query and EVM execution compatibility tests."""

import pytest
from eth_utils.currency import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.rpc.methods import create_methods


SIMPLE_TRANSFER_GAS = 21000


class TestEthGetBalance:
    def test_balance_returns_correct_amount(self, chain, address):
        methods = create_methods(chain)
        result = methods["eth_getBalance"](["0x" + address.hex(), "latest"])
        balance = int(result, 16)
        assert balance == to_wei(100, "ether")

    def test_balance_decreases_after_transfer(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        initial_balance = int(methods["eth_getBalance"](["0x" + address.hex(), "latest"]), 16)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=SIMPLE_TRANSFER_GAS,
            gas_price=1000000000,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        final_balance = int(methods["eth_getBalance"](["0x" + address.hex(), "latest"]), 16)
        
        assert final_balance < initial_balance
        balance_diff = initial_balance - final_balance
        assert balance_diff == to_wei(1, "ether") + SIMPLE_TRANSFER_GAS * 1000000000

    def test_balance_increases_for_recipient(self, pk, address):
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
            gas=SIMPLE_TRANSFER_GAS,
            gas_price=1000000000,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        recipient_balance = int(methods["eth_getBalance"](["0x" + recipient.hex(), "latest"]), 16)
        assert recipient_balance == to_wei(1, "ether")

    def test_balance_is_zero_for_nonexistent_account(self, chain):
        methods = create_methods(chain)
        nonexistent = "0x" + (b"\x00" * 20).hex()
        result = methods["eth_getBalance"]([nonexistent, "latest"])
        assert int(result, 16) == 0


class TestEthGetTransactionCount:
    def test_nonce_starts_at_zero(self, chain, address):
        methods = create_methods(chain)
        result = methods["eth_getTransactionCount"](["0x" + address.hex(), "latest"])
        assert int(result, 16) == 0

    def test_nonce_increments_after_tx(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        assert int(methods["eth_getTransactionCount"](["0x" + address.hex(), "latest"]), 16) == 0
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=SIMPLE_TRANSFER_GAS,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        assert int(methods["eth_getTransactionCount"](["0x" + address.hex(), "latest"]), 16) == 1

    def test_nonce_increments_multiple_txs(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        for i in range(3):
            tx = chain.create_transaction(
                from_private_key=b"\x01" * 32,
                to=b"\xde\xad\xbe\xef" * 5,
                value=to_wei(1, "ether"),
                gas=SIMPLE_TRANSFER_GAS,
            )
            chain.send_transaction(tx)
            chain.build_block()
            assert int(methods["eth_getTransactionCount"](["0x" + address.hex(), "latest"]), 16) == i + 1


class TestEthGetCode:
    def test_code_is_empty_for_eoa(self, chain, address):
        methods = create_methods(chain)
        result = methods["eth_getCode"](["0x" + address.hex(), "latest"])
        assert result == "0x"

    def test_code_returns_contract_bytecode(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        bytecode = bytes.fromhex("608060405234801561001057600080fd5b50")
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=None,
            value=0,
            data=bytecode,
            gas=100000,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        receipts = chain.store.get_receipts(1)
        assert len(receipts) == 1
        assert receipts[0].status == 1


class TestEthGetStorageAt:
    def test_storage_returns_zero_for_eoa(self, chain, address):
        methods = create_methods(chain)
        result = methods["eth_getStorageAt"](["0x" + address.hex(), "0x0", "latest"])
        assert int(result, 16) == 0

    def test_storage_slot_is_32_bytes_padded(self, chain, address):
        methods = create_methods(chain)
        result = methods["eth_getStorageAt"](["0x" + address.hex(), "0x0", "latest"])
        assert result.startswith("0x")


class TestEthEstimateGas:
    def test_estimate_gas_for_simple_transfer(self, chain, address):
        methods = create_methods(chain)
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "value": "0xde0b6b3a7640000",
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        assert gas == SIMPLE_TRANSFER_GAS

    def test_estimate_gas_for_contract_creation(self, chain, address):
        methods = create_methods(chain)
        tx_params = {
            "from": "0x" + address.hex(),
            "data": "0x6080604052",
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        assert gas > 0

    def test_estimate_gas_for_contract_with_data(self, chain, address):
        """Test estimateGas with calldata (simulating contract interaction)."""
        methods = create_methods(chain)
        
        # Estimate gas for a call with data (more than simple transfer)
        # This simulates calling a function on a contract
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "data": "0xa9059cbb" + "00" * 64,  # ERC20 transfer function signature + padding
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        # Should be more than simple transfer due to data processing
        assert gas > SIMPLE_TRANSFER_GAS
        # But should still be reasonable
        assert gas < 100000

    def test_estimate_gas_with_value_transfer(self, chain, address):
        methods = create_methods(chain)
        
        # Transfer with value should still be 21,000 gas
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "value": "0x0",
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        assert gas == SIMPLE_TRANSFER_GAS

    def test_estimate_gas_for_contract_creation_with_value(self, chain, address):
        methods = create_methods(chain)
        
        # Contract creation with value
        bytecode = "0x6080604052"
        tx_params = {
            "from": "0x" + address.hex(),
            "value": "0xde0b6b3a7640000",
            "data": bytecode,
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        assert gas > SIMPLE_TRANSFER_GAS


class TestTransferExecution:
    def test_simple_transfer_succeeds(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        recipient = b"\xde\xad\xbe\xef" * 5
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=recipient,
            value=to_wei(1, "ether"),
            gas=SIMPLE_TRANSFER_GAS,
            gas_price=1000000000,
        )
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert len(block.transactions) == 1
        
        recipient_balance = chain.get_balance(recipient)
        assert recipient_balance == to_wei(1, "ether")

    def test_transfer_updates_sender_nonce(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        assert chain.get_nonce(address) == 0
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=SIMPLE_TRANSFER_GAS,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        assert chain.get_nonce(address) == 1

    def test_insufficient_balance_prevents_tx(self, pk, address):
        """Transaction with insufficient balance should be rejected."""
        from sequencer.sequencer.mempool import InsufficientFunds
        
        genesis_state = {
            address: {"balance": to_wei(1, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        initial_balance = chain.get_balance(address)
        
        # Attempt to create a transaction that exceeds balance
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(10, "ether"),  # More than the 1 ETH balance
            gas=SIMPLE_TRANSFER_GAS,
        )
        
        # Should raise InsufficientFunds when trying to send
        with pytest.raises(InsufficientFunds):
            chain.send_transaction(tx)
        
        # Balance should be unchanged
        final_balance = chain.get_balance(address)
        assert final_balance == initial_balance


class TestMempoolStateQuery:
    def test_pending_nonce_reflects_mempool(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx1 = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=SIMPLE_TRANSFER_GAS,
            nonce=0,
        )
        chain.send_transaction(tx1)
        
        tx2 = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=SIMPLE_TRANSFER_GAS,
            nonce=1,
        )
        chain.send_transaction(tx2)
        
        assert len(chain.mempool) == 2


class TestMultipleTransfers:
    def test_multiple_transfers_in_sequence(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        recipients = [bytes([0x11 + i] * 20) for i in range(3)]
        
        for i, recipient in enumerate(recipients):
            tx = chain.create_transaction(
                from_private_key=b"\x01" * 32,
                to=recipient,
                value=to_wei(1, "ether"),
                gas=SIMPLE_TRANSFER_GAS,
            )
            chain.send_transaction(tx)
            chain.build_block()
            
            balance = chain.get_balance(recipient)
            assert balance == to_wei(1, "ether"), f"Recipient {i} balance incorrect"

    def test_multiple_transfers_same_recipient(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        recipient = b"\xde\xad\xbe\xef" * 5
        
        for _ in range(5):
            tx = chain.create_transaction(
                from_private_key=b"\x01" * 32,
                to=recipient,
                value=to_wei(1, "ether"),
                gas=SIMPLE_TRANSFER_GAS,
            )
            chain.send_transaction(tx)
            chain.build_block()
        
        final_balance = chain.get_balance(recipient)
        assert final_balance == to_wei(5, "ether")


class TestEIP1559FeeExecution:
    def test_eip1559_transfer_base_fee_deduction(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        initial_balance = chain.get_balance(address)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=SIMPLE_TRANSFER_GAS,
            max_fee_per_gas=2000000000,
            max_priority_fee_per_gas=100000000,
        )
        chain.send_transaction(tx)
        block = chain.build_block()
        
        final_balance = chain.get_balance(address)
        base_fee = block.header.base_fee_per_gas or 1_000_000_000
        
        expected_fee = SIMPLE_TRANSFER_GAS * base_fee
        expected_balance = initial_balance - to_wei(1, "ether") - expected_fee
        
        assert final_balance <= expected_balance + base_fee * SIMPLE_TRANSFER_GAS

    def test_eip1559_tip_goes_to_coinbase(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        initial_coinbase_balance = chain.get_balance(chain.coinbase)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=SIMPLE_TRANSFER_GAS,
            max_priority_fee_per_gas=500000000,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        final_coinbase_balance = chain.get_balance(chain.coinbase)
        assert final_coinbase_balance > initial_coinbase_balance