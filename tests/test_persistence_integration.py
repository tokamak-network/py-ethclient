"""Integration tests for state persistence across node restarts.

These tests verify SQLite persistence of:
- Blocks and transactions
- Transaction receipts
- EVM state (contract code, storage, account balances, nonces)
"""

import os
import tempfile

import pytest
from eth_keys import keys
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain


class TestEVMPersistence:
    """Test EVM state persistence across node restarts."""

    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database file path."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        yield db_path
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)

    @pytest.fixture
    def pk_and_address(self):
        """Create private key and address."""
        pk = keys.PrivateKey(bytes.fromhex("01" * 32))
        address = pk.public_key.to_canonical_address()
        return pk, address

    def test_contract_code_persistence(self, temp_db_path, pk_and_address):
        """
        Test that contract code persists across restarts.
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # SimpleStorage bytecode
        SIMPLE_STORAGE_BYTECODE = bytes.fromhex(
            "6080604052348015600e575f5ffd5b5060b780601a5f395ff3fe6080604052348015600e575f5ffd5b5060043610603a575f3560e01c80632096525514603e5780633fa4f2451460535780635524107714605a575b5f5ffd5b5f545b60405190815260200160405180910390f35b60415f5481565b60696065366004606b565b5f55565b005b5f60208284031215607a575f5ffd5b503591905056fea2646970667358221220f8e380cdbf230c90b815074c9d3e30359f89a7ebc26e356ecb4a53b30b84694564736f6c63430008220033"
        )
        
        # ===== Phase 1: Deploy contract =====
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Deploy contract
        nonce = node1.get_nonce(address)
        signed_tx = node1.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=500_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        node1.send_transaction(signed_tx)
        node1.build_block()
        
        # Get contract address
        receipts = node1.store.get_receipts(1)
        contract_address = receipts[0].contract_address
        assert contract_address is not None
        print(f"✅ Contract deployed at: {contract_address.hex()}")
        
        # Verify contract code exists
        code = node1.get_code(contract_address)
        assert len(code) > 0
        print(f"✅ Contract code length before restart: {len(code)} bytes")
        
        # Shutdown
        node1.store.close()
        print("✅ Node shutdown")
        
        # ===== Phase 2: Restart and verify code persists =====
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        print("✅ Node restarted")
        
        # Verify contract code persists
        code = node2.get_code(contract_address)
        assert len(code) > 0
        print(f"✅ Contract code length after restart: {len(code)} bytes")
        
        node2.store.close()

    def test_contract_storage_persistence(self, temp_db_path, pk_and_address):
        """
        Test that contract storage persists across restarts.
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # SimpleStorage bytecode
        SIMPLE_STORAGE_BYTECODE = bytes.fromhex(
            "6080604052348015600e575f5ffd5b5060b780601a5f395ff3fe6080604052348015600e575f5ffd5b5060043610603a575f3560e01c80632096525514603e5780633fa4f2451460535780635524107714605a575b5f5ffd5b5f545b60405190815260200160405180910390f35b60415f5481565b60696065366004606b565b5f55565b005b5f60208284031215607a575f5ffd5b503591905056fea2646970667358221220f8e380cdbf230c90b815074c9d3e30359f89a7ebc26e356ecb4a53b30b84694564736f6c63430008220033"
        )
        
        SET_VALUE_SELECTOR = bytes.fromhex("55241077")
        
        # ===== Phase 1: Deploy and set value =====
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Deploy contract
        nonce = node1.get_nonce(address)
        signed_tx = node1.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=500_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        node1.send_transaction(signed_tx)
        node1.build_block()
        
        contract_address = node1.store.get_receipts(1)[0].contract_address
        
        # Set value to 12345
        calldata = SET_VALUE_SELECTOR + (12345).to_bytes(32, 'big')
        nonce = node1.get_nonce(address)
        signed_tx = node1.create_transaction(
            from_private_key=pk.to_bytes(),
            to=contract_address,
            value=0,
            data=calldata,
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        node1.send_transaction(signed_tx)
        node1.build_block()
        
        # Verify value was set
        value = node1.get_storage_at(contract_address, 0)
        assert value == 12345
        print(f"✅ Storage value set to: {value}")
        
        node1.store.close()
        
        # ===== Phase 2: Restart and verify storage =====
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Verify storage value persists
        value = node2.get_storage_at(contract_address, 0)
        assert value == 12345
        print(f"✅ Storage value after restart: {value}")
        
        node2.store.close()

    def test_account_balance_persistence(self, temp_db_path, pk_and_address):
        """
        Test that account balances persist across restarts.
        """
        pk, address = pk_and_address
        
        recipient = bytes.fromhex("deadbeef" * 5)
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # ===== Phase 1: Make transfers =====
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        initial_balance = node1.get_balance(address)
        
        # Transfer 10 ETH to recipient
        nonce = node1.get_nonce(address)
        signed_tx = node1.create_transaction(
            from_private_key=pk.to_bytes(),
            to=recipient,
            value=to_wei(10, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        node1.send_transaction(signed_tx)
        node1.build_block()
        
        # Verify balances
        sender_balance_after = node1.get_balance(address)
        recipient_balance = node1.get_balance(recipient)
        
        assert sender_balance_after < initial_balance
        assert recipient_balance == to_wei(10, "ether")
        print(f"✅ Sender balance: {sender_balance_after / 1e18} ETH")
        print(f"✅ Recipient balance: {recipient_balance / 1e18} ETH")
        
        node1.store.close()
        
        # ===== Phase 2: Restart and verify balances =====
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Verify balances persist
        sender_balance_restored = node2.get_balance(address)
        recipient_balance_restored = node2.get_balance(recipient)
        
        assert sender_balance_restored == sender_balance_after
        assert recipient_balance_restored == to_wei(10, "ether")
        print(f"✅ Sender balance restored: {sender_balance_restored / 1e18} ETH")
        print(f"✅ Recipient balance restored: {recipient_balance_restored / 1e18} ETH")
        
        node2.store.close()

    def test_account_nonce_persistence(self, temp_db_path, pk_and_address):
        """
        Test that account nonces persist across restarts.
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # ===== Phase 1: Make transactions =====
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Make 3 transactions
        for i in range(3):
            nonce = node1.get_nonce(address)
            signed_tx = node1.create_transaction(
                from_private_key=pk.to_bytes(),
                to=bytes.fromhex("deadbeef" * 5),
                value=to_wei(1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            node1.send_transaction(signed_tx)
            node1.build_block()
        
        expected_nonce = node1.get_nonce(address)
        assert expected_nonce == 3
        print(f"✅ Nonce after 3 transactions: {expected_nonce}")
        
        node1.store.close()
        
        # ===== Phase 2: Restart and verify nonce =====
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Verify nonce persists
        restored_nonce = node2.get_nonce(address)
        assert restored_nonce == 3
        print(f"✅ Nonce after restart: {restored_nonce}")
        
        # Can continue with next transaction
        nonce = node2.get_nonce(address)
        assert nonce == 3
        
        signed_tx = node2.create_transaction(
            from_private_key=pk.to_bytes(),
            to=bytes.fromhex("deadbeef" * 5),
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        node2.send_transaction(signed_tx)
        node2.build_block()
        
        assert node2.get_nonce(address) == 4
        print("✅ Can continue making transactions after restart")
        
        node2.store.close()

    def test_full_state_recovery(self, temp_db_path, pk_and_address):
        """
        Test complete state recovery including contract and interactions.
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # SimpleStorage bytecode
        SIMPLE_STORAGE_BYTECODE = bytes.fromhex(
            "6080604052348015600e575f5ffd5b5060b780601a5f395ff3fe6080604052348015600e575f5ffd5b5060043610603a575f3560e01c80632096525514603e5780633fa4f2451460535780635524107714605a575b5f5ffd5b5f545b60405190815260200160405180910390f35b60415f5481565b60696065366004606b565b5f55565b005b5f60208284031215607a575f5ffd5b503591905056fea2646970667358221220f8e380cdbf230c90b815074c9d3e30359f89a7ebc26e356ecb4a53b30b84694564736f6c63430008220033"
        )
        
        SET_VALUE_SELECTOR = bytes.fromhex("55241077")
        GET_VALUE_SELECTOR = bytes.fromhex("20965255")
        
        # ===== Phase 1: Deploy and interact =====
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Deploy contract
        nonce = node1.get_nonce(address)
        signed_tx = node1.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=500_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        node1.send_transaction(signed_tx)
        node1.build_block()
        
        contract_address = node1.store.get_receipts(1)[0].contract_address
        
        # Set value
        calldata = SET_VALUE_SELECTOR + (42).to_bytes(32, 'big')
        nonce = node1.get_nonce(address)
        signed_tx = node1.create_transaction(
            from_private_key=pk.to_bytes(),
            to=contract_address,
            value=0,
            data=calldata,
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        node1.send_transaction(signed_tx)
        node1.build_block()
        
        # Get initial state
        initial_code = node1.get_code(contract_address)
        initial_storage = node1.get_storage_at(contract_address, 0)
        initial_balance = node1.get_balance(address)
        initial_nonce = node1.get_nonce(address)
        
        print(f"✅ Contract deployed and value set")
        print(f"   Code length: {len(initial_code)} bytes")
        print(f"   Storage at slot 0: {initial_storage}")
        print(f"   Balance: {initial_balance / 1e18} ETH")
        print(f"   Nonce: {initial_nonce}")
        
        node1.store.close()
        
        # ===== Phase 2: Restart and verify all state =====
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Verify all state persisted
        restored_code = node2.get_code(contract_address)
        restored_storage = node2.get_storage_at(contract_address, 0)
        restored_balance = node2.get_balance(address)
        restored_nonce = node2.get_nonce(address)
        
        assert len(restored_code) == len(initial_code)
        assert restored_storage == initial_storage == 42
        assert restored_balance == initial_balance
        assert restored_nonce == initial_nonce
        
        print(f"✅ All state restored correctly")
        print(f"   Code length: {len(restored_code)} bytes")
        print(f"   Storage at slot 0: {restored_storage}")
        print(f"   Balance: {restored_balance / 1e18} ETH")
        print(f"   Nonce: {restored_nonce}")
        
        # ===== Phase 3: Continue operations after restart =====
        # Update value
        calldata = SET_VALUE_SELECTOR + (100).to_bytes(32, 'big')
        nonce = node2.get_nonce(address)
        signed_tx = node2.create_transaction(
            from_private_key=pk.to_bytes(),
            to=contract_address,
            value=0,
            data=calldata,
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        node2.send_transaction(signed_tx)
        node2.build_block()
        
        # Verify new value
        new_storage = node2.get_storage_at(contract_address, 0)
        assert new_storage == 100
        print(f"✅ Can update storage after restart: {new_storage}")
        
        node2.store.close()


class TestSQLitePersistence:
    """Test SQLite persistence for blocks and receipts."""

    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database file path."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        yield db_path
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)

    @pytest.fixture
    def pk_and_address(self):
        """Create private key and address."""
        pk = keys.PrivateKey(bytes.fromhex("01" * 32))
        address = pk.public_key.to_canonical_address()
        return pk, address

    def test_block_persistence_across_restarts(self, temp_db_path, pk_and_address):
        """
        Test that blocks are properly persisted in SQLite.
        
        Steps:
        1. Start node with SQLite storage
        2. Create several blocks with transactions
        3. Shutdown node (close database)
        4. Restart node with same database
        5. Verify all blocks exist
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # ===== Phase 1: Create blocks =====
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Create 5 blocks with transactions
        for i in range(5):
            nonce = node1.get_nonce(address)
            signed_tx = node1.create_transaction(
                from_private_key=pk.to_bytes(),
                to=bytes.fromhex("deadbeef" * 5),
                value=to_wei(1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            node1.send_transaction(signed_tx)
            node1.build_block()
        
        # Record all block hashes
        block_hashes = []
        for i in range(6):  # Blocks 0-5
            block = node1.store.get_block(i)
            assert block is not None
            block_hashes.append(block.hash)
            print(f"Block {i}: {block.hash.hex()[:16]}...")
        
        assert node1.store.get_latest_number() == 5
        
        # Shutdown
        node1.store.close()
        print("✅ Node shutdown")
        
        # ===== Phase 2: Restart and verify =====
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        print("✅ Node restarted")
        
        # Verify all blocks persisted
        assert node2.store.get_latest_number() == 5
        
        for i in range(6):
            block = node2.store.get_block(i)
            assert block is not None
            assert block.hash == block_hashes[i]
            print(f"✅ Block {i} persisted: {block.hash.hex()[:16]}...")
        
        node2.store.close()

    def test_receipt_persistence_across_restarts(self, temp_db_path, pk_and_address):
        """
        Test that transaction receipts are properly persisted in SQLite.
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # ===== Phase 1: Create transactions =====
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        tx_hashes = []
        
        # Create 3 transactions
        for i in range(3):
            nonce = node1.get_nonce(address)
            # Valid 20-byte Ethereum address
            recipient = bytes.fromhex("deadbeef" * 5)  # 20 bytes
            
            signed_tx = node1.create_transaction(
                from_private_key=pk.to_bytes(),
                to=recipient,
                value=to_wei(1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            tx_hash = node1.send_transaction(signed_tx)
            node1.build_block()
            tx_hashes.append(tx_hash)
            print(f"✅ Transaction {i+1}: {tx_hash.hex()[:16]}...")
        
        node1.store.close()
        print("✅ Node shutdown")
        
        # ===== Phase 2: Restart and verify =====
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        print("✅ Node restarted")
        
        # Verify all transaction receipts persisted
        for i, tx_hash in enumerate(tx_hashes):
            result = node2.store.get_transaction_receipt(tx_hash)
            assert result is not None
            block_num, tx_idx, receipt = result
            assert receipt.status == 1  # Success
            print(f"✅ Transaction {i+1} receipt persisted: block {block_num}, tx {tx_idx}")
        
        node2.store.close()

    def test_contract_deployment_receipt_persistence(self, temp_db_path, pk_and_address):
        """
        Test that contract deployment receipts with contract_address are persisted.
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # SimpleStorage contract bytecode
        SIMPLE_STORAGE_BYTECODE = bytes.fromhex(
            "6080604052348015600e575f5ffd5b5060b780601a5f395ff3fe6080604052348015600e575f5ffd5b5060043610603a575f3560e01c80632096525514603e5780633fa4f2451460535780635524107714605a575b5f5ffd5b5f545b60405190815260200160405180910390f35b60415f5481565b60696065366004606b565b5f55565b005b5f60208284031215607a575f5ffd5b503591905056fea2646970667358221220f8e380cdbf230c90b815074c9d3e30359f89a7ebc26e356ecb4a53b30b84694564736f6c63430008220033"
        )
        
        # ===== Phase 1: Deploy contract =====
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Deploy contract
        nonce = node1.get_nonce(address)
        signed_tx = node1.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,  # Contract creation
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=500_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        tx_hash = node1.send_transaction(signed_tx)
        node1.build_block()
        
        # Get deployment receipt
        receipts = node1.store.get_receipts(1)
        assert len(receipts) > 0
        assert receipts[0].status == 1
        contract_address = receipts[0].contract_address
        assert contract_address is not None
        print(f"✅ Contract deployed at: {contract_address.hex()}")
        
        node1.store.close()
        print("✅ Node shutdown")
        
        # ===== Phase 2: Restart and verify =====
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        print("✅ Node restarted")
        
        # Verify deployment receipt persisted
        result = node2.store.get_transaction_receipt(tx_hash)
        assert result is not None
        block_num, tx_idx, receipt = result
        assert receipt.status == 1
        assert receipt.contract_address == contract_address
        print(f"✅ Deployment receipt persisted: contract at {contract_address.hex()}")
        
        # Verify block with deployment persisted
        block = node2.store.get_block(block_num)
        assert block is not None
        print(f"✅ Block {block_num} persisted")
        
        node2.store.close()

    def test_can_continue_adding_blocks_after_restart(self, temp_db_path, pk_and_address):
        """
        Test that we can continue adding new blocks after restart.
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # ===== Phase 1: Create initial blocks =====
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Create 2 blocks
        for i in range(2):
            nonce = node1.get_nonce(address)
            signed_tx = node1.create_transaction(
                from_private_key=pk.to_bytes(),
                to=bytes.fromhex("deadbeef" * 5),
                value=to_wei(1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            node1.send_transaction(signed_tx)
            node1.build_block()
        
        initial_block_count = node1.store.get_latest_number()
        assert initial_block_count == 2
        print(f"✅ Initial blocks: {initial_block_count}")
        
        node1.store.close()
        
        # ===== Phase 2: Restart and add more blocks =====
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Verify we have the same block count
        assert node2.store.get_latest_number() == 2
        print("✅ Blocks persisted after restart")
        
        # Add 3 more blocks
        for i in range(3):
            nonce = node2.get_nonce(address)
            signed_tx = node2.create_transaction(
                from_private_key=pk.to_bytes(),
                to=bytes.fromhex("deadbeef" * 5),
                value=to_wei(1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            node2.send_transaction(signed_tx)
            node2.build_block()
        
        # Verify total block count
        final_block_count = node2.store.get_latest_number()
        assert final_block_count == 5
        print(f"✅ Added blocks after restart: {initial_block_count} -> {final_block_count}")
        
        node2.store.close()

    def test_block_chain_continuity_after_restart(self, temp_db_path, pk_and_address):
        """
        Test that block chain is continuous after restart.
        Each block's parent_hash should equal previous block's hash.
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # ===== Phase 1: Create blocks =====
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Create 5 blocks
        for i in range(5):
            nonce = node1.get_nonce(address)
            signed_tx = node1.create_transaction(
                from_private_key=pk.to_bytes(),
                to=bytes.fromhex("deadbeef" * 5),
                value=to_wei(1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            node1.send_transaction(signed_tx)
            node1.build_block()
        
        # Record block hashes and parent hashes
        block_data = []
        for i in range(6):  # Blocks 0-5
            block = node1.store.get_block(i)
            block_data.append({
                'number': i,
                'hash': block.hash,
                'parent_hash': block.header.parent_hash,
            })
        
        node1.store.close()
        
        # ===== Phase 2: Restart and verify continuity =====
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Verify all blocks exist with correct hashes
        for i, data in enumerate(block_data):
            block = node2.store.get_block(i)
            assert block is not None
            assert block.hash == data['hash']
            assert block.header.parent_hash == data['parent_hash']
        
        # Verify chain continuity
        for i in range(1, 6):
            prev_block = node2.store.get_block(i - 1)
            curr_block = node2.store.get_block(i)
            assert curr_block.header.parent_hash == prev_block.hash
            print(f"✅ Block {i} parent matches block {i-1} hash")
        
        node2.store.close()

    def test_multiple_deployments_persistence(self, temp_db_path, pk_and_address):
        """
        Test that multiple contract deployments are persisted.
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        SIMPLE_STORAGE_BYTECODE = bytes.fromhex(
            "6080604052348015600e575f5ffd5b5060b780601a5f395ff3fe6080604052348015600e575f5ffd5b5060043610603a575f3560e01c80632096525514603e5780633fa4f2451460535780635524107714605a575b5f5ffd5b5f545b60405190815260200160405180910390f35b60415f5481565b60696065366004606b565b5f55565b005b5f60208284031215607a575f5ffd5b503591905056fea2646970667358221220f8e380cdbf230c90b815074c9d3e30359f89a7ebc26e356ecb4a53b30b84694564736f6c63430008220033"
        )
        
        # ===== Phase 1: Deploy multiple contracts =====
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        tx_hashes = []
        contract_addresses = []
        
        # Deploy 3 contracts
        for i in range(3):
            nonce = node1.get_nonce(address)
            signed_tx = node1.create_transaction(
                from_private_key=pk.to_bytes(),
                to=None,
                value=0,
                data=SIMPLE_STORAGE_BYTECODE,
                gas=500_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            tx_hash = node1.send_transaction(signed_tx)
            node1.build_block()
            
            receipts = node1.store.get_receipts(i + 1)
            assert receipts[0].status == 1
            contract_address = receipts[0].contract_address
            tx_hashes.append(tx_hash)
            contract_addresses.append(contract_address)
            print(f"✅ Deployed contract {i+1} at: {contract_address.hex()}")
        
        node1.store.close()
        
        # ===== Phase 2: Restart and verify =====
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Verify all deployment receipts persisted
        for i, (tx_hash, contract_addr) in enumerate(zip(tx_hashes, contract_addresses)):
            result = node2.store.get_transaction_receipt(tx_hash)
            assert result is not None
            block_num, tx_idx, receipt = result
            assert receipt.status == 1
            assert receipt.contract_address == contract_addr
            print(f"✅ Contract {i+1} deployment persisted: {contract_addr.hex()}")
        
        node2.store.close()

    def test_sqlite_in_memory_mode(self, pk_and_address):
        """
        Test that SQLite can also work in-memory (similar to InMemoryStore).
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # Use :memory: for in-memory SQLite
        node = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=":memory:",
        )
        
        # Create a block
        nonce = node.get_nonce(address)
        signed_tx = node.create_transaction(
            from_private_key=pk.to_bytes(),
            to=bytes.fromhex("deadbeef" * 5),
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        node.send_transaction(signed_tx)
        node.build_block()
        
        # Verify block exists
        assert node.store.get_latest_number() == 1
        block = node.store.get_block(1)
        assert block is not None
        
        print("✅ SQLite in-memory mode works")
        
        node.store.close()


class TestBlockAndReceiptIntegrity:
    """Test that block and receipt data remains consistent."""

    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database file path."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        yield db_path
        if os.path.exists(db_path):
            os.unlink(db_path)

    @pytest.fixture
    def pk_and_address(self):
        """Create private key and address."""
        pk = keys.PrivateKey(bytes.fromhex("01" * 32))
        address = pk.public_key.to_canonical_address()
        return pk, address

    def test_block_hash_consistency_after_restart(self, temp_db_path, pk_and_address):
        """
        Test that block hashes remain the same after restart.
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # Create blocks
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        for i in range(3):
            nonce = node1.get_nonce(address)
            signed_tx = node1.create_transaction(
                from_private_key=pk.to_bytes(),
                to=bytes.fromhex("deadbeef" * 5),
                value=to_wei(1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            node1.send_transaction(signed_tx)
            node1.build_block()
        
        # Get all block hashes
        original_hashes = {}
        for i in range(4):
            block = node1.store.get_block(i)
            original_hashes[i] = block.hash
        
        node1.store.close()
        
        # Restart
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        # Verify hashes match
        for i, original_hash in original_hashes.items():
            block = node2.store.get_block(i)
            assert block.hash == original_hash
            print(f"✅ Block {i} hash consistent: {block.hash.hex()[:16]}...")
        
        node2.store.close()

    def test_gas_used_persistence(self, temp_db_path, pk_and_address):
        """
        Test that gas_used in blocks is persisted correctly.
        """
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        # Create transactions
        node1 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        gas_used_values = []
        
        for i in range(3):
            nonce = node1.get_nonce(address)
            signed_tx = node1.create_transaction(
                from_private_key=pk.to_bytes(),
                to=bytes.fromhex("deadbeef" * 5),
                value=to_wei(1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            node1.send_transaction(signed_tx)
            node1.build_block()
            
            block = node1.store.get_block(i + 1)
            gas_used_values.append(block.header.gas_used)
            print(f"Block {i+1} gas_used: {block.header.gas_used}")
        
        node1.store.close()
        
        # Restart and verify
        node2 = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        for i, original_gas in enumerate(gas_used_values):
            block = node2.store.get_block(i + 1)
            assert block.header.gas_used == original_gas
            print(f"✅ Block {i+1} gas_used persisted: {block.header.gas_used}")
        
        node2.store.close()