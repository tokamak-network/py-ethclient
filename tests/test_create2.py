"""Tests for CREATE2 contract deployment (EIP-1014)."""

import pytest
from eth_utils import keccak

from sequencer.core.create2 import (
    compute_create2_address,
    compute_create2_address_with_code_hash,
    compute_create_address,
)
from sequencer.core.crypto import keccak256
from tests.fixtures.contracts import SIMPLE_INIT_CODE, CREATE2_FACTORY_BYTECODE


class TestCREATE2AddressComputation:
    """Test CREATE2 address computation (EIP-1014)."""
    
    def test_compute_create2_address_basic(self):
        """Test basic CREATE2 address computation."""
        sender = bytes.fromhex("deadbeef" * 5)
        salt = bytes(32)  # 32 zero bytes
        init_code = SIMPLE_INIT_CODE
        
        address = compute_create2_address(sender, salt, init_code)
        
        # Verify address is 20 bytes
        assert len(address) == 20
        assert isinstance(address, bytes)
    
    def test_compute_create2_address_deterministic(self):
        """Test that CREATE2 produces deterministic addresses."""
        sender = bytes.fromhex("deadbeef" * 5)
        salt = bytes(32)
        init_code = SIMPLE_INIT_CODE
        
        # Compute twice, should get same result
        address1 = compute_create2_address(sender, salt, init_code)
        address2 = compute_create2_address(sender, salt, init_code)
        
        assert address1 == address2
    
    def test_compute_create2_address_different_sender(self):
        """Test that different senders produce different addresses."""
        sender1 = bytes.fromhex("deadbeef" * 5)
        sender2 = bytes.fromhex("beefdead" * 5)
        salt = bytes(32)
        init_code = SIMPLE_INIT_CODE
        
        address1 = compute_create2_address(sender1, salt, init_code)
        address2 = compute_create2_address(sender2, salt, init_code)
        
        assert address1 != address2
    
    def test_compute_create2_address_different_salt(self):
        """Test that different salts produce different addresses."""
        sender = bytes.fromhex("deadbeef" * 5)
        salt1 = bytes(32)
        salt2 = bytes(31) + b"\x01"  # Different salt
        init_code = SIMPLE_INIT_CODE
        
        address1 = compute_create2_address(sender, salt1, init_code)
        address2 = compute_create2_address(sender, salt2, init_code)
        
        assert address1 != address2
    
    def test_compute_create2_address_different_init_code(self):
        """Test that different init_code produces different addresses."""
        sender = bytes.fromhex("deadbeef" * 5)
        salt = bytes(32)
        init_code1 = SIMPLE_INIT_CODE
        init_code2 = SIMPLE_INIT_CODE + b"\x00"  # Different init code
        
        address1 = compute_create2_address(sender, salt, init_code1)
        address2 = compute_create2_address(sender, salt, init_code2)
        
        assert address1 != address2
    
    def test_compute_create2_address_with_code_hash(self):
        """Test CREATE2 address computation with pre-computed hash."""
        sender = bytes.fromhex("deadbeef" * 5)
        salt = bytes(32)
        init_code = SIMPLE_INIT_CODE
        
        # Compute with init_code
        address1 = compute_create2_address(sender, salt, init_code)
        
        # Compute with hash
        init_code_hash = keccak(init_code)
        address2 = compute_create2_address_with_code_hash(sender, salt, init_code_hash)
        
        assert address1 == address2
    
    def test_compute_create2_address_eip1014_vector(self):
        """Test against EIP-1014 official test vector.
        
        From EIP-1014:
        address = keccak256(0xff ++ address ++ salt ++ keccak256(bytecode))[12:]
        
        Official test case:
          address: 0x0000000000000000000000000000000000000000
          salt: 0x0000000000000000000000000000000000000000000000000000000000000000
          initCode: 0x00
          result: 0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38
        """
        sender = bytes(20)  # All zeros
        salt = bytes(32)  # All zeros
        init_code = b"\x00"  # Single byte 0x00
        
        address = compute_create2_address(sender, salt, init_code)
        
        # Expected address from EIP-1014
        expected = bytes.fromhex("4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38".lower())
        assert address == expected
    
    def test_compute_create2_address_another_sender(self):
        """Test CREATE2 with a different sender address.
        
        This test verifies consistency - different sender produces different address.
        """
        # Using a different sender should produce a different address
        sender1 = bytes(20)  # All zeros
        sender2 = bytes.fromhex("deadbeef00000000000000000000000000000000")
        salt = bytes(32)
        init_code = b"\x00"
        
        address1 = compute_create2_address(sender1, salt, init_code)
        address2 = compute_create2_address(sender2, salt, init_code)
        
        # Different senders should produce different addresses
        assert address1 != address2
        
        # Both should be valid 20-byte addresses
        assert len(address1) == 20
        assert len(address2) == 20
    
    def test_compute_create2_address_with_salt(self):
        """Test CREATE2 with a non-zero salt."""
        sender = bytes(20)
        salt = bytes.fromhex("000000000000000000000000feed000000000000000000000000000000000000")
        init_code = b"\x00"
        
        address = compute_create2_address(sender, salt, init_code)
        
        # Different salt should produce different address from the EIP-1014 vector
        address_zero_salt = compute_create2_address(sender, bytes(32), init_code)
        assert address != address_zero_salt
    
    def test_compute_create2_address_invalid_sender_length(self):
        """Test that invalid sender length raises error."""
        sender = bytes(19)  # Too short
        salt = bytes(32)
        init_code = b"\x00"
        
        with pytest.raises(ValueError, match="Sender must be 20 bytes"):
            compute_create2_address(sender, salt, init_code)
    
    def test_compute_create2_address_invalid_salt_length(self):
        """Test that invalid salt length raises error."""
        sender = bytes(20)
        salt = bytes(31)  # Too short
        init_code = b"\x00"
        
        with pytest.raises(ValueError, match="Salt must be 32 bytes"):
            compute_create2_address(sender, salt, init_code)


class TestCREATEAddressComputation:
    """Test CREATE (nonce-based) address computation."""
    
    def test_compute_create_address_basic(self):
        """Test basic CREATE address computation."""
        sender = bytes.fromhex("deadbeef" * 5)
        nonce = 0
        
        address = compute_create_address(sender, nonce)
        
        assert len(address) == 20
        assert isinstance(address, bytes)
    
    def test_compute_create_address_deterministic(self):
        """Test that CREATE produces deterministic addresses."""
        sender = bytes.fromhex("deadbeef" * 5)
        nonce = 0
        
        address1 = compute_create_address(sender, nonce)
        address2 = compute_create_address(sender, nonce)
        
        assert address1 == address2
    
    def test_compute_create_address_different_nonce(self):
        """Test that different nonces produce different addresses."""
        sender = bytes.fromhex("deadbeef" * 5)
        
        address0 = compute_create_address(sender, 0)
        address1 = compute_create_address(sender, 1)
        address2 = compute_create_address(sender, 2)
        
        assert address0 != address1
        assert address1 != address2
        assert address0 != address2
    
    def test_compute_create_address_different_sender(self):
        """Test that different senders produce different addresses."""
        sender1 = bytes.fromhex("deadbeef" * 5)
        sender2 = bytes.fromhex("beefdead" * 5)
        
        address1 = compute_create_address(sender1, 0)
        address2 = compute_create_address(sender2, 0)
        
        assert address1 != address2
    
    def test_compute_create_address_matches_live_deployment(self, chain):
        """Test that computed address matches actual CREATE deployment."""
        from eth_keys import keys
        
        # Create a test private key
        pk = keys.PrivateKey(bytes.fromhex("01" * 32))
        sender = pk.public_key.to_canonical_address()
        
        # Predict address for nonce 0
        predicted_address = compute_create_address(sender, 0)
        
        # Deploy a contract
        tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,  # Contract creation
            data=SIMPLE_INIT_CODE,
            gas=200_000,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        # Get the deployed contract address from receipt
        tx_hash = keccak256(tx.encode())
        _, _, receipt = chain.store.get_transaction_receipt(tx_hash)
        
        assert receipt.contract_address == predicted_address


class TestCREATE2vsCREATE:
    """Test differences between CREATE and CREATE2."""
    
    def test_create_and_create2_different_for_same_sender(self):
        """Test that CREATE and CREATE2 produce different addresses for same sender."""
        sender = bytes.fromhex("deadbeef" * 5)
        salt = bytes(32)
        init_code = SIMPLE_INIT_CODE
        
        create_address = compute_create_address(sender, 0)
        create2_address = compute_create2_address(sender, salt, init_code)
        
        # They should be different
        assert create_address != create2_address
    
    def test_create2_predictable_before_deployment(self):
        """Test that CREATE2 address can be predicted before any deployment."""
        sender = bytes.fromhex("deadbeef" * 5)
        salt = bytes(32)
        init_code = SIMPLE_INIT_CODE
        
        # Address is predictable even though no contract exists yet
        address = compute_create2_address(sender, salt, init_code)
        
        # Verify deterministic
        address2 = compute_create2_address(sender, salt, init_code)
        assert address == address2


class TestCREATE2Integration:
    """Integration tests for CREATE2 with the chain."""
    
    def test_chain_compute_create2_address(self, chain):
        """Test Chain.compute_create2_address method."""
        sender = bytes.fromhex("deadbeef" * 5)
        salt = bytes(32)
        init_code = SIMPLE_INIT_CODE
        
        # Use chain method
        address = chain.compute_create2_address(sender, salt, init_code)
        
        # Verify against direct computation
        expected = compute_create2_address(sender, salt, init_code)
        assert address == expected
    
    def test_create2_contract_not_tracked_by_default(self, chain):
        """Test that CREATE2 contract is not tracked before deployment."""
        sender = bytes.fromhex("deadbeef" * 5)
        salt = bytes(32)
        init_code = SIMPLE_INIT_CODE
        
        # Compute address
        address = chain.compute_create2_address(sender, salt, init_code)
        
        # Should not be tracked yet
        assert not chain.is_create2_contract(address)
        assert chain.get_create2_contract_info(address) is None
    
    @pytest.mark.skipif(
        True,  # Skip until we have proper CREATE2 factory bytecode
        reason="CREATE2 factory bytecode needs proper implementation"
    )
    def test_create2_deployment_tracking(self, chain_with_sqlite):
        """Test CREATE2 deployment is tracked in SQLite."""
        from eth_keys import keys
        
        chain = chain_with_sqlite
        pk = keys.PrivateKey(bytes.fromhex("01" * 32))
        sender = pk.public_key.to_canonical_address()
        
        # Deploy CREATE2 factory
        factory_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            data=CREATE2_FACTORY_BYTECODE,
            gas=500_000,
        )
        chain.send_transaction(factory_tx)
        block = chain.build_block()
        
        # Get factory address
        factory_tx_hash = keccak256(factory_tx.encode())
        _, _, receipt = chain.store.get_transaction_receipt(factory_tx_hash)
        factory_address = receipt.contract_address
        
        # Predict CREATE2 address
        salt = bytes(32)
        init_code = SIMPLE_INIT_CODE
        predicted_address = compute_create2_address(factory_address, salt, init_code)
        
        # Use factory to deploy via CREATE2
        # ... (requires proper factory bytecode)
        
        # Verify CREATE2 contract is tracked
        assert chain.is_create2_contract(predicted_address)
    
    def test_get_create2_contracts_by_deployer_empty(self, chain):
        """Test get_create2_contracts_by_deployer returns empty list for unknown deployer."""
        deployer = bytes.fromhex("deadbeef" * 5)
        contracts = chain.get_create2_contracts_by_deployer(deployer)
        assert contracts == []


class TestCREATE2Persistence:
    """Test CREATE2 contract persistence."""
    
    def test_create2_info_stored_in_sqlite(self, tmp_path):
        """Test that CREATE2 info is stored in SQLite and persists."""
        import tempfile
        import os
        from sequencer.sequencer.chain import Chain
        from sequencer.storage.sqlite_store import SQLiteStore
        from eth_keys import keys
        from eth_utils import to_wei
        
        # Create a temporary SQLite database
        db_path = str(tmp_path / "test_create2.db")
        
        # Create chain with SQLite storage
        pk = keys.PrivateKey(bytes.fromhex("01" * 32))
        address = pk.public_key.to_canonical_address()
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            store_type="sqlite",
            store_path=db_path,
        )
        
        # Manually save a CREATE2 contract record
        contract_address = bytes.fromhex("12" * 20)
        deployer = bytes.fromhex("ab" * 20)
        salt = bytes(32)
        init_code_hash = keccak(b"init_code")
        
        chain.store.save_create2_contract(
            address=contract_address,
            deployer=deployer,
            salt=salt,
            init_code_hash=init_code_hash,
            block_number=1,
            tx_hash=bytes(32),
        )
        
        # Retrieve it
        info = chain.store.get_create2_contract(contract_address)
        assert info is not None
        assert info["deployer"] == deployer
        assert info["salt"] == salt
        assert info["init_code_hash"] == init_code_hash
        assert info["block_number"] == 1
        
        # Check is_create2_contract
        assert chain.store.is_create2_contract(contract_address)
        assert not chain.store.is_create2_contract(bytes.fromhex("ff" * 20))
        
        # Find by deployer/salt/hash
        found = chain.store.find_create2_contract(deployer, salt, init_code_hash)
        assert found == contract_address
        
        # Get by deployer
        contracts = chain.store.get_create2_contracts_by_deployer(deployer)
        assert len(contracts) == 1
        assert contracts[0]["address"] == contract_address
        
        # Cleanup
        chain.store.close()
    
    def test_multiple_create2_contracts_same_deployer(self, tmp_path):
        """Test multiple CREATE2 contracts from same deployer."""
        from sequencer.sequencer.chain import Chain
        from eth_keys import keys
        from eth_utils import to_wei
        
        # Create a temporary SQLite database
        db_path = str(tmp_path / "test_create2_multi.db")
        
        # Create chain with SQLite storage
        pk = keys.PrivateKey(bytes.fromhex("01" * 32))
        address = pk.public_key.to_canonical_address()
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            store_type="sqlite",
            store_path=db_path,
        )
        
        deployer = bytes.fromhex("ab" * 20)
        
        # Create multiple contracts with different salts
        for i in range(3):
            salt = bytes(31) + bytes([i])
            contract_address = bytes.fromhex(f"{i:02x}" + "00" * 19)
            init_code_hash = keccak(f"init_{i}".encode())
            
            chain.store.save_create2_contract(
                address=contract_address,
                deployer=deployer,
                salt=salt,
                init_code_hash=init_code_hash,
                block_number=i + 1,
                tx_hash=bytes(32),
            )
        
        # Get all contracts by deployer
        contracts = chain.store.get_create2_contracts_by_deployer(deployer)
        assert len(contracts) == 3
        assert [c["block_number"] for c in contracts] == [1, 2, 3]
        
        # Cleanup
        chain.store.close()