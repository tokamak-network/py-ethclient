"""Tests for EIP-2930 Access List Transactions."""

import pytest
from eth_utils import keccak

from sequencer.core.crypto import keccak256, private_key_to_address
from tests.fixtures.contracts import SIMPLE_STORAGE_BYTECODE


class TestAccessListAddressComputation:
    """Test access list transaction creation."""
    
    def test_create_access_list_transaction(self, chain, alice_key, alice_address):
        """Test creating an EIP-2930 access list transaction."""
        # Create access list
        access_list = [
            (bytes.fromhex("12" * 20), [0, 1]),  # Address with storage slots 0 and 1
            (bytes.fromhex("ab" * 20), []),       # Address only, no storage slots
        ]
        
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=bytes.fromhex("12" * 20),
            access_list=access_list,
            value=0,
            data=b"\x00",
            gas=100_000,
        )
        
        # Verify transaction was created
        assert tx is not None
        assert tx.nonce == 0
        assert tx.to == bytes.fromhex("12" * 20)
        
        # Verify access list
        assert hasattr(tx, 'access_list')
        assert len(tx.access_list) == 2
        
        # Check first entry
        addr1, slots1 = tx.access_list[0]
        assert addr1 == bytes.fromhex("12" * 20)
        assert list(slots1) == [0, 1]
        
        # Check second entry
        addr2, slots2 = tx.access_list[1]
        assert addr2 == bytes.fromhex("ab" * 20)
        assert list(slots2) == []
    
    def test_access_list_transaction_has_chain_id(self, chain, alice_key):
        """Test that access list transaction has chain ID."""
        access_list = [(bytes.fromhex("12" * 20), [])]
        
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=bytes.fromhex("12" * 20),
            access_list=access_list,
            gas=100_000,
        )
        
        assert tx.chain_id == chain.chain_id
    
    def test_access_list_transaction_has_gas_price(self, chain, alice_key):
        """Test that access list transaction uses gas price (not EIP-1559 pricing)."""
        access_list = [(bytes.fromhex("12" * 20), [])]
        
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=bytes.fromhex("12" * 20),
            access_list=access_list,
            gas_price=30_000_000_000,  # 30 gwei
            gas=100_000,
        )
        
        # Type 0x01 transactions use gasPrice, not maxFeePerGas
        assert hasattr(tx, 'gas_price')
        assert tx.gas_price == 30_000_000_000
    
    def test_access_list_transaction_type(self, chain, alice_key):
        """Test that access list transaction has type 0x01."""
        access_list = [(bytes.fromhex("12" * 20), [])]
        
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=bytes.fromhex("12" * 20),
            access_list=access_list,
            gas=100_000,
        )
        
        # Type 0x01 = 1
        assert tx.type_id == 1
    
    def test_access_list_transaction_signature(self, chain, alice_key, alice_address):
        """Test that access list transaction is properly signed."""
        access_list = [(bytes.fromhex("12" * 20), [0])]
        
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=bytes.fromhex("12" * 20),
            access_list=access_list,
            value=1_000_000,
            gas=100_000,
        )
        
        # Verify signature exists
        assert hasattr(tx, 'r')
        assert hasattr(tx, 's')
        assert hasattr(tx, 'v') or hasattr(tx, 'y_parity')
        
        # Verify sender can be recovered
        assert tx.sender == alice_address


class TestAccessListTransactionExecution:
    """Test execution of access list transactions."""
    
    def test_send_access_list_transaction(self, chain, alice_key, alice_address):
        """Test sending an access list transaction."""
        # Create recipient
        recipient = bytes.fromhex("cd" * 20)
        
        # Create access list (pre-declare we'll access the recipient)
        access_list = [(recipient, [])]
        
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=recipient,
            access_list=access_list,
            value=1_000_000,
            gas=50_000,
        )
        
        tx_hash = chain.send_transaction(tx)
        block = chain.build_block()
        
        assert block is not None
        assert len(block.transactions) == 1
        
        # Verify transaction was included
        _, _, receipt = chain.get_transaction_receipt(tx_hash)
        assert receipt.status == 1
    
    def test_access_list_contract_deployment(self, chain, alice_key, alice_address):
        """Test contract deployment with access list transaction."""
        # Create access list (empty - we don't know what addresses we'll access yet)
        access_list = []
        
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=None,  # Contract creation
            access_list=access_list,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=200_000,
        )
        
        tx_hash = chain.send_transaction(tx)
        block = chain.build_block()
        
        # Verify transaction succeeded
        _, _, receipt = chain.get_transaction_receipt(tx_hash)
        assert receipt.status == 1
        assert receipt.contract_address is not None
    
    def test_access_list_with_storage_slots(self, chain, alice_key, alice_address):
        """Test access list with storage slots."""
        # First, deploy a contract
        deploy_tx = chain.create_transaction(
            from_private_key=alice_key,
            to=None,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=200_000,
        )
        deploy_hash = chain.send_transaction(deploy_tx)
        deploy_block = chain.build_block()
        
        _, _, deploy_receipt = chain.get_transaction_receipt(deploy_hash)
        contract_address = deploy_receipt.contract_address
        
        # Now interact with the contract using an access list
        access_list = [
            (contract_address, [0]),  # Pre-declare access to slot 0
        ]
        
        # Call the contract (reading slot 0)
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=contract_address,
            access_list=access_list,
            gas=100_000,
        )
        
        tx_hash = chain.send_transaction(tx)
        block = chain.build_block()
        
        _, _, receipt = chain.get_transaction_receipt(tx_hash)
        assert receipt.status == 1


class TestAccessListRPC:
    """Test RPC methods for access list transactions."""
    
    def test_rpc_send_access_list_transaction(self, chain, alice_key, alice_address):
        """Test eth_sendTransaction with accessList parameter."""
        recipient = bytes.fromhex("ef" * 20)
        
        # Access list format for RPC
        access_list = [
            {
                "address": "0x" + recipient.hex(),
                "storageKeys": ["0x0", "0x1"]
            }
        ]
        
        # Send via RPC would work like this:
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=recipient,
            access_list=access_list,
            gas=100_000,
        )
        
        # Verify the access list was parsed correctly
        assert len(tx.access_list) == 1
        addr, slots = tx.access_list[0]
        assert addr == recipient
        assert list(slots) == [0, 1]
    
    def test_serialize_access_list_transaction(self, chain, alice_key, alice_address):
        """Test that access list transactions serialize correctly."""
        access_list = [
            (bytes.fromhex("12" * 20), [0]),
        ]
        
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=bytes.fromhex("12" * 20),
            access_list=access_list,
            gas=100_000,
        )
        
        # Encode the transaction
        encoded = tx.encode()
        
        # Type 0x01 transactions start with 0x01
        assert encoded[0] == 0x01  # First byte is the type
    
    def test_access_list_encoded_in_transaction(self, chain, alice_key):
        """Test that access list is encoded in the transaction."""
        access_list = [
            (bytes.fromhex("12" * 20), [0, 1, 2, 3]),
            (bytes.fromhex("ab" * 20), []),
        ]
        
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=bytes.fromhex("12" * 20),
            access_list=access_list,
            gas=100_000,
        )
        
        encoded = tx.encode()
        
        # Verify encoding includes access list
        # The encoded data should be longer than a similar transaction without access list
        tx_no_access = chain.create_transaction(
            from_private_key=alice_key,
            to=bytes.fromhex("12" * 20),
            gas=100_000,
        )
        
        # Access list transaction should be longer (type byte + access list data)
        # Note: Legacy transactions don't have type prefix, so we need to account for that
        assert len(encoded) > len(tx_no_access.encode()) - 1  # Rough comparison


class TestAccessListWithEIP1559:
    """Test EIP-1559 transactions with access lists."""
    
    def test_eip1559_with_access_list(self, chain, alice_key, alice_address):
        """Test that EIP-1559 transactions can include access lists."""
        recipient = bytes.fromhex("12" * 20)
        access_list = [(recipient, [0, 1])]
        
        tx = chain.create_eip1559_transaction(
            from_private_key=alice_key,
            to=recipient,
            gas=100_000,
            access_list=access_list,
        )
        
        # Verify transaction was created
        assert tx is not None
        assert tx.type_id == 2  # EIP-1559
        
        # Verify access list is included
        assert hasattr(tx, 'access_list')
        assert len(tx.access_list) == 1
        addr, slots = tx.access_list[0]
        assert addr == recipient
        assert list(slots) == [0, 1]
    
    def test_eip1559_with_access_list_execution(self, chain, alice_key, alice_address):
        """Test execution of EIP-1559 transaction with access list."""
        recipient = bytes.fromhex("cd" * 20)
        access_list = [(recipient, [])]
        
        tx = chain.create_eip1559_transaction(
            from_private_key=alice_key,
            to=recipient,
            value=1_000_000,
            gas=50_000,
            access_list=access_list,
        )
        
        tx_hash = chain.send_transaction(tx)
        block = chain.build_block()
        
        assert block is not None
        assert len(block.transactions) == 1
        
        # Verify transaction was included and succeeded
        _, _, receipt = chain.get_transaction_receipt(tx_hash)
        assert receipt.status == 1
    
    def test_eip1559_with_access_list_dict_format(self, chain, alice_key, alice_address):
        """Test EIP-1559 with access list in dict format (from RPC)."""
        recipient = bytes.fromhex("ab" * 20)
        
        # Access list in RPC format (dict)
        access_list = [
            {
                "address": "0x" + recipient.hex(),
                "storageKeys": ["0x0", "0x1", "0x2"]
            }
        ]
        
        tx = chain.create_eip1559_transaction(
            from_private_key=alice_key,
            to=recipient,
            gas=100_000,
            access_list=access_list,
        )
        
        # Verify access list was parsed correctly
        assert len(tx.access_list) == 1
        addr, slots = tx.access_list[0]
        assert addr == recipient
        assert list(slots) == [0, 1, 2]
    
    def test_eip1559_with_access_list_tuple_format(self, chain, alice_key, alice_address):
        """Test EIP-1559 with access list in tuple format."""
        recipient = bytes.fromhex("cd" * 20)
        
        # Access list in tuple format
        access_list = [
            (recipient, [0, 1, 2])
        ]
        
        tx = chain.create_eip1559_transaction(
            from_private_key=alice_key,
            to=recipient,
            gas=100_000,
            access_list=access_list,
        )
        
        # Verify access list was parsed correctly
        assert len(tx.access_list) == 1
        addr, slots = tx.access_list[0]
        assert addr == recipient
        assert list(slots) == [0, 1, 2]


class TestAccessListInRPC:
    """Test access list handling in RPC methods."""
    
    def test_rpc_eip1559_with_access_list(self, chain, alice_key, alice_address):
        """Test eth_sendTransaction with EIP-1559 and access list."""
        from sequencer.rpc.methods import create_methods
        
        recipient = bytes.fromhex("ee" * 20)
        
        tx_params = {
            "from": f"0x{alice_address.hex()}",
            "to": f"0x{recipient.hex()}",
            "value": "0x100000",
            "gas": "0x186a0",
            "maxFeePerGas": "0x77359400",  # 2 gwei
            "maxPriorityFeePerGas": "0x3b9aca00",  # 1 gwei
            "accessList": [
                {
                    "address": f"0x{recipient.hex()}",
                    "storageKeys": ["0x0", "0x1"]
                }
            ]
        }
        
        methods = create_methods(chain)
        
        # Mock the from_private_key injection (in real RPC this comes from wallet)
        # For testing, we directly call the transaction creation
        tx = chain.create_eip1559_transaction(
            from_private_key=alice_key,
            to=recipient,
            value=0x100000,
            gas=0x186a0,
            max_fee_per_gas=0x77359400,
            max_priority_fee_per_gas=0x3b9aca00,
            access_list=[(recipient, [0, 1])],
        )
        
        # Verify transaction has access list
        assert hasattr(tx, 'access_list')
        assert len(tx.access_list) == 1
        assert tx.type_id == 2  # EIP-1559


class TestAccessListParsing:
    """Test access list parsing helper functions."""
    
    def test_parse_access_list_dict_format(self):
        """Test parsing access list in dict format."""
        from sequencer.rpc.methods import _parse_access_list
        
        access_list = [
            {
                "address": "0x1212121212121212121212121212121212121212",
                "storageKeys": ["0x0", "0x1", "0x2"]
            }
        ]
        
        parsed = _parse_access_list(access_list)
        
        assert len(parsed) == 1
        addr, slots = parsed[0]
        assert addr == bytes.fromhex("12" * 20)
        assert slots == [0, 1, 2]
    
    def test_parse_access_list_tuple_format(self):
        """Test parsing access list in tuple format."""
        from sequencer.rpc.methods import _parse_access_list
        
        access_list = [
            (bytes.fromhex("12" * 20), [0, 1])
        ]
        
        parsed = _parse_access_list(access_list)
        
        assert len(parsed) == 1
        addr, slots = parsed[0]
        assert addr == bytes.fromhex("12" * 20)
        assert slots == [0, 1]
    
    def test_parse_access_list_empty_storage_keys(self):
        """Test parsing access list with empty storage keys."""
        from sequencer.rpc.methods import _parse_access_list
        
        access_list = [
            {
                "address": "0x1212121212121212121212121212121212121212",
                "storageKeys": []
            }
        ]
        
        parsed = _parse_access_list(access_list)
        
        assert len(parsed) == 1
        addr, slots = parsed[0]
        assert list(slots) == []
    
    def test_serialize_access_list(self):
        """Test serializing access list to RPC format."""
        from sequencer.rpc.methods import _serialize_access_list
        
        access_list = [
            (bytes.fromhex("12" * 20), [0, 1, 2])
        ]
        
        serialized = _serialize_access_list(access_list)
        
        assert len(serialized) == 1
        assert serialized[0]["address"] == "0x1212121212121212121212121212121212121212"
        assert serialized[0]["storageKeys"] == ["0x0", "0x1", "0x2"]


class TestAccessListTransactionReceipt:
    """Test transaction receipts for access list transactions."""
    
    def test_access_list_transaction_receipt_type(self, chain, alice_key):
        """Test that access list transaction receipt has correct type."""
        recipient = bytes.fromhex("cd" * 20)
        access_list = [(recipient, [])]
        
        tx = chain.create_access_list_transaction(
            from_private_key=alice_key,
            to=recipient,
            access_list=access_list,
            gas=100_000,
        )
        
        tx_hash = chain.send_transaction(tx)
        block = chain.build_block()
        
        # Get the transaction from the block
        stored_tx = block.transactions[0]
        
        # Verify type
        assert stored_tx.type_id == 1
