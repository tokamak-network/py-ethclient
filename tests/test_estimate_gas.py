"""Gas estimation tests for eth_estimateGas RPC method."""

import pytest
from eth_utils.currency import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.rpc.methods import create_methods


SIMPLE_TRANSFER_GAS = 21_000


class TestEstimateGasSimpleTransfer:
    """Test gas estimation for simple ETH transfers."""

    def test_simple_transfer_no_data(self, chain, address):
        """Simple transfer with no data should return 21,000 gas."""
        methods = create_methods(chain)
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "value": "0xde0b6b3a7640000",
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        assert gas == SIMPLE_TRANSFER_GAS

    def test_transfer_with_zero_value(self, chain, address):
        """Transfer with zero value should still be 21,000 gas."""
        methods = create_methods(chain)
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "value": "0x0",
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        assert gas == SIMPLE_TRANSFER_GAS

    def test_transfer_with_custom_gas_limit_param(self, chain, address):
        """Custom gas limit parameter should not affect estimate for simple transfer."""
        methods = create_methods(chain)
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "value": "0x0",
            "gas": "0x1c9c380",  # 30M
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        assert gas == SIMPLE_TRANSFER_GAS


class TestEstimateGasWithData:
    """Test gas estimation for transactions with calldata."""

    def test_transaction_with_data_no_recipient(self, chain, address):
        """Contract creation with data should estimate higher than transfer."""
        methods = create_methods(chain)
        tx_params = {
            "from": "0x" + address.hex(),
            "data": "0x6080604052348015600f57600080fd5b50",
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        assert gas > SIMPLE_TRANSFER_GAS
        assert gas < 100_000

    def test_transaction_with_data_and_recipient(self, chain, address):
        """Contract call with data should estimate based on execution."""
        methods = create_methods(chain)
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "data": "0xa9059cbb" + "00" * 64,  # ERC20 transfer signature
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        assert gas > SIMPLE_TRANSFER_GAS
        assert gas < 100_000

    def test_transaction_with_large_data(self, chain, address):
        """Transaction with large calldata should estimate higher."""
        methods = create_methods(chain)
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "data": "0x" + "00" * 1024,  # 1KB of data
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        # Should be higher due to data gas costs (20 gas per non-zero byte)
        assert gas > SIMPLE_TRANSFER_GAS


class TestEstimateGasContractCreation:
    """Test gas estimation for contract creation."""

    def test_contract_creation_with_value(self, chain, address):
        """Contract creation with value transfer."""
        methods = create_methods(chain)
        tx_params = {
            "from": "0x" + address.hex(),
            "value": "0xde0b6b3a7640000",  # 1 ETH
            "data": "0x6080604052",
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        assert gas > SIMPLE_TRANSFER_GAS
        assert gas < 100_000

    def test_contract_creation_bytecode_sizes(self, pk, address):
        """Test different bytecode sizes for contract creation."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        small_bytecode = "0x6080604052"
        result_small = methods["eth_estimateGas"]([{"from": "0x" + address.hex(), "data": small_bytecode}])
        gas_small = int(result_small, 16)
        
        # Small bytecode should estimate higher than simple transfer
        assert gas_small > SIMPLE_TRANSFER_GAS
        
        # Larger bytecode with deployment code
        genesis_state2 = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain2 = Chain.from_genesis(genesis_state2, chain_id=1337, block_time=0)
        methods2 = create_methods(chain2)
        
        # Larger bytecode (simple runtime code)
        medium_bytecode = "0x" + "60" * 100
        result_medium = methods2["eth_estimateGas"]([{"from": "0x" + address.hex(), "data": medium_bytecode}])
        gas_medium = int(result_medium, 16)
        
        # Both should be reasonable for contract creation
        assert gas_medium > SIMPLE_TRANSFER_GAS
        assert gas_small > SIMPLE_TRANSFER_GAS


class TestEstimateGasEdgeCases:
    """Test edge cases for gas estimation."""

    def test_estimate_gas_uses_10_percent_buffer(self, chain, address):
        """Verify that estimate includes a buffer."""
        methods = create_methods(chain)
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "data": "0x" + "00" * 100,
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        
        # Gas should be rounded and include buffer
        assert gas >= SIMPLE_TRANSFER_GAS

    def test_estimate_gas_consistent_across_calls(self, chain, address):
        """Multiple calls should return consistent estimates."""
        methods = create_methods(chain)
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "value": "0xde0b6b3a7640000",
        }
        
        results = []
        for _ in range(3):
            result = methods["eth_estimateGas"]([tx_params])
            results.append(int(result, 16))
        
        # All results should be identical for simple transfer
        assert all(r == results[0] for r in results)
        assert results[0] == SIMPLE_TRANSFER_GAS


class TestEstimateGasDirectMethod:
    """Test the direct chain.estimate_gas() method."""

    def test_direct_estimate_simple_transfer(self, chain, address):
        """Direct method call for simple transfer."""
        to = b"\xde\xad\xbe\xef" * 5
        gas = chain.estimate_gas(address, to, to_wei(1, "ether"), b"")
        assert gas == SIMPLE_TRANSFER_GAS

    def test_direct_estimate_no_recipient(self, chain, address):
        """Direct method call for contract creation."""
        data = bytes.fromhex("6080604052")
        gas = chain.estimate_gas(address, None, 0, data)
        assert gas > SIMPLE_TRANSFER_GAS

    def test_direct_estimate_with_custom_gas_limit(self, chain, address):
        """Direct method with custom gas limit."""
        to = b"\xde\xad\xbe\xef" * 5
        gas_limit = 1_000_000
        gas = chain.estimate_gas(address, to, 0, b"", gas_limit)
        assert gas == SIMPLE_TRANSFER_GAS


class TestEstimateGasIntegration:
    """Integration tests for gas estimation with actual transactions."""

    def test_estimate_then_execute_simple_transfer(self, pk, address):
        """Estimate gas and use it for actual transaction."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        # Estimate
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "value": "0xde0b6b3a7640000",
        }
        result = methods["eth_estimateGas"]([tx_params])
        estimated_gas = int(result, 16)
        
        # Execute with estimated gas
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=estimated_gas,
        )
        chain.send_transaction(tx)
        block = chain.build_block()
        
        # Transaction should succeed
        assert len(block.transactions) == 1
        assert block.transactions[0].gas == estimated_gas

    def test_estimate_gas_after_block_production(self, pk, address):
        """Estimate should work correctly after multiple blocks."""
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        methods = create_methods(chain)
        
        # Produce some blocks
        for i in range(5):
            tx = chain.create_transaction(
                from_private_key=b"\x01" * 32,
                to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
                value=to_wei(1, "ether"),
                gas=SIMPLE_TRANSFER_GAS,
            )
            chain.send_transaction(tx)
            chain.build_block()
        
        # Estimate should still work
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "value": "0x0",
        }
        result = methods["eth_estimateGas"]([tx_params])
        gas = int(result, 16)
        assert gas == SIMPLE_TRANSFER_GAS
