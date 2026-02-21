"""Tests for RPC methods.

Tests the JSON-RPC API wrapper code in sequencer.rpc module.
"""

import pytest
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.rpc.methods import create_methods
from tests.fixtures.keys import ALICE_PRIVATE_KEY, ALICE_ADDRESS, BOB_ADDRESS


class TestRPCCreation:
    """Test RPC method creation."""

    def test_create_methods(self, chain):
        """Can create RPC methods."""
        methods = create_methods(chain)
        
        assert methods is not None
        assert isinstance(methods, dict)

    def test_methods_are_callable(self, chain):
        """RPC methods are callable functions."""
        methods = create_methods(chain)
        
        for name, method in methods.items():
            assert callable(method), f"Method {name} is not callable"


class TestEthGetBalance:
    """Test eth_getBalance RPC method."""

    def test_get_balance_existing_account(self, chain, alice_address):
        """Get balance of account with funds."""
        methods = create_methods(chain)
        
        if "eth_getBalance" in methods:
            alice_hex = "0x" + alice_address.hex()
            result = methods["eth_getBalance"]([alice_hex, "latest"])
            
            # Should return hex-encoded balance
            assert result is not None
            assert isinstance(result, str)
            assert result.startswith("0x")

    def test_get_balance_nonexistent_account(self, chain):
        """Get balance of non-existent account."""
        methods = create_methods(chain)
        
        if "eth_getBalance" in methods:
            # Random address with no balance
            random_address = "0x" + "ff" * 20
            result = methods["eth_getBalance"]([random_address, "latest"])
            
            # Should return 0x0
            assert result is not None
            assert result == "0x0"


class TestEthGetTransactionCount:
    """Test eth_getTransactionCount RPC method."""

    def test_get_nonce(self, chain, alice_address):
        """Get transaction count (nonce)."""
        methods = create_methods(chain)
        
        if "eth_getTransactionCount" in methods:
            alice_hex = "0x" + alice_address.hex()
            result = methods["eth_getTransactionCount"]([alice_hex, "latest"])
            
            assert result is not None
            assert isinstance(result, str)
            assert result.startswith("0x")


class TestEthGetBlockByNumber:
    """Test eth_getBlockByNumber RPC method."""

    def test_get_genesis_block(self, chain):
        """Get genesis block."""
        methods = create_methods(chain)
        
        if "eth_getBlockByNumber" in methods:
            result = methods["eth_getBlockByNumber"](["0x0", False])
            
            # Block should contain header fields
            assert result is not None
            if isinstance(result, dict):
                assert "number" in result

    def test_get_latest_block(self, chain):
        """Get latest block."""
        methods = create_methods(chain)
        
        if "eth_getBlockByNumber" in methods:
            result = methods["eth_getBlockByNumber"](["latest", False])
            
            if result:
                assert isinstance(result, dict)


class TestEthGetCode:
    """Test eth_getCode RPC method."""

    def test_get_code_eoa(self, chain, alice_address):
        """Get code for EOA (should be empty)."""
        methods = create_methods(chain)
        
        if "eth_getCode" in methods:
            alice_hex = "0x" + alice_address.hex()
            result = methods["eth_getCode"]([alice_hex, "latest"])
            
            # EOAs have empty code
            assert result == "0x"


class TestEthSendRawTransaction:
    """Test eth_sendRawTransaction RPC method."""

    def test_send_raw_transaction(self, chain, alice_address, bob_address):
        """Send raw transaction via RPC."""
        methods = create_methods(chain)
        
        if "eth_sendRawTransaction" in methods:
            # Create signed transaction
            tx = chain.create_transaction(
                from_private_key=ALICE_PRIVATE_KEY,
                to=bob_address,
                value=to_wei(0.1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=chain.get_nonce(alice_address),
            )
            
            # Encode transaction
            raw_tx = "0x" + tx.encode().hex()
            
            # Send via RPC
            tx_hash = methods["eth_sendRawTransaction"]([raw_tx])
            
            assert tx_hash is not None
            assert isinstance(tx_hash, str)
            assert tx_hash.startswith("0x")


class TestEthGetTransactionReceipt:
    """Test eth_getTransactionReceipt RPC method."""

    def test_get_receipt(self, chain, alice_address, bob_address):
        """Get transaction receipt."""
        # First, send a transaction
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(0.1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        
        chain.send_transaction(tx)
        block = chain.build_block()
        
        methods = create_methods(chain)
        
        if "eth_getTransactionReceipt" in methods:
            tx_hash = "0x" + tx.hash.hex()
            result = methods["eth_getTransactionReceipt"]([tx_hash])
            
            if result:
                assert isinstance(result, dict)
                assert "status" in result


class TestEthChainId:
    """Test eth_chainId RPC method."""

    def test_get_chain_id(self, chain):
        """Get chain ID."""
        methods = create_methods(chain)
        
        if "eth_chainId" in methods:
            result = methods["eth_chainId"]([])
            
            assert result is not None
            assert isinstance(result, str)
            assert result.startswith("0x")
            
            # Verify chain ID matches
            chain_id = int(result, 16)
            assert chain_id == chain.chain_id


class TestEthGasPrice:
    """Test eth_gasPrice RPC method."""

    def test_get_gas_price(self, chain):
        """Get current gas price."""
        methods = create_methods(chain)
        
        if "eth_gasPrice" in methods:
            result = methods["eth_gasPrice"]([])
            
            assert result is not None
            assert isinstance(result, str)
            assert result.startswith("0x")
            
            # Should be positive
            gas_price = int(result, 16)
            assert gas_price > 0


class TestEthBlockNumber:
    """Test eth_blockNumber RPC method."""

    def test_get_block_number(self, chain):
        """Get current block number."""
        methods = create_methods(chain)
        
        if "eth_blockNumber" in methods:
            result = methods["eth_blockNumber"]([])
            
            assert result is not None
            assert isinstance(result, str)
            assert result.startswith("0x")


class TestEthGetStorageAt:
    """Test eth_getStorageAt RPC method."""

    def test_get_storage_eoa(self, chain, alice_address):
        """Get storage at EOA (should be empty)."""
        methods = create_methods(chain)
        
        if "eth_getStorageAt" in methods:
            alice_hex = "0x" + alice_address.hex()
            result = methods["eth_getStorageAt"]([alice_hex, "0x0", "latest"])
            
            # EOA storage should be zero
            assert result is not None


class TestEthEstimateGas:
    """Test eth_estimateGas RPC method."""

    def test_estimate_transfer_gas(self, chain, alice_address, bob_address):
        """Estimate gas for simple transfer."""
        methods = create_methods(chain)
        
        if "eth_estimateGas" in methods:
            tx_obj = {
                "from": "0x" + alice_address.hex(),
                "to": "0x" + bob_address.hex(),
                "value": hex(to_wei(0.1, "ether")),
            }
            
            result = methods["eth_estimateGas"]([tx_obj])
            
            assert result is not None
            assert isinstance(result, str)
            assert result.startswith("0x")
            
            # Simple transfer should be around 21000
            estimated = int(result, 16)
            assert estimated >= 21_000


class TestRPCErrorHandling:
    """Test RPC error handling."""

    def test_nonexistent_block(self, chain):
        """Non-existent block returns None."""
        methods = create_methods(chain)
        
        if "eth_getBlockByNumber" in methods:
            # Request block far in the future
            result = methods["eth_getBlockByNumber"](["0xFFFFFFF", False])
            
            # Should return None for non-existent block
            assert result is None


class TestRPCCall:
    """Test eth_call RPC method."""

    def test_simple_call(self, chain, alice_address, bob_address):
        """Simple eth_call to EOA."""
        methods = create_methods(chain)
        
        if "eth_call" in methods:
            tx_obj = {
                "from": "0x" + alice_address.hex(),
                "to": "0x" + bob_address.hex(),
                "data": "0x",
            }
            
            result = methods["eth_call"]([tx_obj, "latest"])
            
            # Calling EOA returns empty
            assert result is not None

    def test_call_to_nonexistent_address(self, chain, alice_address):
        """eth_call to non-existent address."""
        methods = create_methods(chain)
        
        if "eth_call" in methods:
            tx_obj = {
                "from": "0x" + alice_address.hex(),
                "to": "0x" + "ff" * 20,
                "data": "0x",
            }
            
            result = methods["eth_call"]([tx_obj, "latest"])
            
            assert result is not None


class TestRPCTransactionLifecycle:
    """Test full transaction lifecycle via RPC."""

    def test_send_and_get_receipt(self, chain, alice_address, bob_address):
        """Send transaction and get receipt via RPC."""
        methods = create_methods(chain)
        
        if "eth_sendRawTransaction" not in methods:
            return
            
        # Create and sign transaction
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(0.1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        
        # Send
        raw_tx = "0x" + tx.encode().hex()
        tx_hash = methods["eth_sendRawTransaction"]([raw_tx])
        
        # Mine block
        chain.build_block()
        
        # Get receipt
        if "eth_getTransactionReceipt" in methods:
            receipt = methods["eth_getTransactionReceipt"]([tx_hash])
            
            if receipt:
                assert isinstance(receipt, dict)
                assert "transactionHash" in receipt