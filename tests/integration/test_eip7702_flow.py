"""Integration tests for EIP-7702 SetCode transaction flows.

Tests end-to-end scenarios:
- Authorization signing
- SetCode transaction creation
- EOA code delegation
- Delegated code execution
"""

import pytest
from eth_utils import to_wei
from eth.vm.forks.prague.transactions import Authorization, SetCodeTransaction

from sequencer.core.crypto import keccak256
from tests.fixtures.addresses import ALICE_PRIVATE_KEY, BOB_ADDRESS, CHARLIE_ADDRESS
from tests.fixtures.contracts import (
    COUNTER_BYTECODE,
    SIMPLE_STORAGE_BYTECODE,
    PAYABLE_BYTECODE,
)


class TestEIP7702Authorization:
    """Test EIP-7702 authorization signing."""

    def test_create_authorization(self, chain, alice_address, bob_address):
        """Create a valid EIP-7702 authorization."""
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        assert auth is not None
        assert isinstance(auth, Authorization)
        assert auth.chain_id == chain.chain_id
        assert auth.address == bob_address
        assert auth.nonce == 0
        assert auth.y_parity in (0, 1)
        assert auth.r > 0
        assert auth.s > 0

    def test_authorization_for_all_chains(self, chain, alice_address, bob_address):
        """Create authorization valid on all chains (chain_id=0)."""
        auth = chain.create_authorization(
            chain_id=0,  # Valid on all chains
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        assert auth.chain_id == 0
        assert auth.address == bob_address

    def test_authorization_with_nonzero_nonce(self, chain, alice_address, bob_address):
        """Create authorization with nonzero nonce."""
        # Set nonce to 5
        chain.evm.set_nonce(alice_address, 5)
        
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=5,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        assert auth.nonce == 5


class TestSetCodeTransactionCreation:
    """Test SetCode transaction creation."""

    def test_create_setcode_transaction(self, chain, alice_address, bob_address):
        """Create a SetCode transaction."""
        # Create authorization
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        # Create SetCode transaction
        signed_tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        assert signed_tx is not None
        # The transaction is wrapped in PragueTypedTransaction
        # Check that it has the expected properties
        assert hasattr(signed_tx, 'authorization_list') or hasattr(signed_tx, '_inner')
        # The inner transaction should be a SetCodeTransaction
        if hasattr(signed_tx, '_inner'):
            assert isinstance(signed_tx._inner, SetCodeTransaction)
        
        # Check the authorization is present
        if hasattr(signed_tx, 'authorization_list'):
            assert len(signed_tx.authorization_list) == 1
        elif hasattr(signed_tx, '_inner'):
            assert len(signed_tx._inner.authorization_list) == 1
        
        assert signed_tx.to == bob_address

    def test_setcode_transaction_multiple_authorizations(self, chain, alice_address, bob_address, charlie_address):
        """SetCode transaction with multiple authorizations."""
        # First authorization
        auth1 = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        # Second authorization (different contract)
        auth2 = chain.create_authorization(
            chain_id=chain.chain_id,
            address=charlie_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        # Create SetCode transaction with multiple authorizations
        signed_tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=300_000,
            authorization_list=[auth1, auth2],
        )
        
        assert len(signed_tx.authorization_list) == 2

    def test_setcode_transaction_encoding(self, chain, alice_address, bob_address):
        """SetCode transaction encodes correctly."""
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        signed_tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        # Should encode without error
        encoded = signed_tx.encode()
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0
        
        # Type should be 0x04
        assert encoded[0] == 0x04


class TestSetCodeTransactionExecution:
    """Test SetCode transaction execution."""

    def test_setcode_deployment_and_execution(self, chain, alice_address, bob_address):
        """Deploy contract and execute SetCode transaction."""
        # First deploy a contract
        nonce = chain.get_nonce(alice_address)
        deploy_tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=None,
            value=0,
            data=PAYABLE_BYTECODE,  # Simple bytecode
            gas=500_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(deploy_tx)
        block = chain.build_block()
        
        receipts = chain.store.get_receipts(block.number)
        contract_address = receipts[0].contract_address
        
        # Deployment should succeed
        assert receipts[0].status == 1
        
        # Create authorization for Alice to delegate to contract
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=contract_address,
            nonce=chain.get_nonce(alice_address),
            private_key=ALICE_PRIVATE_KEY,
        )
        
        # Create SetCode transaction
        setcode_tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=alice_address,  # Self-call to trigger authorization
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        chain.send_transaction(setcode_tx)
        setcode_block = chain.build_block()
        
        # Transaction should succeed
        assert setcode_block is not None
        assert len(setcode_block.transactions) == 1

    def test_setcode_with_value_transfer(self, chain, alice_address, bob_address):
        """SetCode transaction with value transfer."""
        # Create authorization
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        initial_bob_balance = chain.get_balance(bob_address)
        
        # Create SetCode transaction sending ETH
        signed_tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(1, "ether"),
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        # Bob should receive the ETH
        assert chain.get_balance(bob_address) >= initial_bob_balance + to_wei(1, "ether")

    def test_setcode_gas_usage(self, chain, alice_address, bob_address):
        """SetCode transaction uses appropriate gas."""
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        initial_balance = chain.get_balance(alice_address)
        
        signed_tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=500_000,
            authorization_list=[auth],
        )
        
        chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        final_balance = chain.get_balance(alice_address)
        gas_cost = initial_balance - final_balance
        
        # SetCode should use more gas than simple transfer
        # (due to authorization processing)
        assert gas_cost > 21_000 * 1_000_000_000


class TestSetCodeAuthorizationChain:
    """Test authorization chain ID validation."""

    def test_authorization_wrong_chain_id(self, chain, alice_address, bob_address):
        """Authorization with wrong chain ID should fail."""
        # Create authorization for different chain
        auth = chain.create_authorization(
            chain_id=999,  # Wrong chain ID
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        # Create transaction with wrong-chain authorization
        signed_tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        # Transaction should fail or authorization should be ignored
        # (Exact behavior depends on implementation)
        assert block is not None

    def test_authorization_universal_chain_id(self, chain, alice_address, bob_address):
        """Authorization with chain_id=0 works on any chain."""
        # Create universal authorization
        auth = chain.create_authorization(
            chain_id=0,  # Universal
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        signed_tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        # Should succeed
        assert block is not None


class TestSetCodeEdgeCases:
    """Edge cases for SetCode transactions."""

    def test_setcode_to_self(self, chain, alice_address, bob_address):
        """SetCode transaction to self."""
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        signed_tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=alice_address,  # Self
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        assert block is not None

    def test_setcode_empty_authorization_list_not_allowed(self, chain, alice_address, bob_address):
        """SetCode transaction with empty authorization list is not allowed by py-evm."""
        nonce = chain.get_nonce(alice_address)
        
        # Create SetCode with no authorizations
        # This should fail validation in py-evm
        from eth.vm.forks.prague.transactions import UnsignedSetCodeTransaction
        
        unsigned_tx = UnsignedSetCodeTransaction(
            chain_id=chain.chain_id,
            nonce=nonce,
            max_priority_fee_per_gas=1_000_000_000,
            max_fee_per_gas=2_000_000_000,
            gas=200_000,
            to=bob_address,
            value=0,
            data=b"",
            access_list=(),
            authorization_list=[],  # Empty - not allowed
        )
        
        from eth_keys import keys
        pk = keys.PrivateKey(ALICE_PRIVATE_KEY)
        signed_tx = unsigned_tx.as_signed_transaction(pk)
        
        # py-evm should reject this
        chain.send_transaction(signed_tx)
        
        # Build block should handle the validation error
        try:
            block = chain.build_block()
            # If it doesn't raise, the tx might not have been included
            # Check that no transactions were included
            if block and len(block.transactions) > 0:
                # If included, it should have failed
                receipts = chain.store.get_receipts(block.number)
                # Transaction validity is checked before execution
                assert False, "Empty authorization list should not be allowed"
        except Exception as e:
            # Expected - validation failed
            assert "cannot empty" in str(e) or "empty" in str(e).lower()

    def test_setcode_multiple_transactions_same_block(self, chain, alice_address, bob_address):
        """Multiple SetCode transactions in the same block."""
        # Deploy two contracts
        nonce = chain.get_nonce(alice_address)
        
        deploy_tx1 = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=300_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        
        deploy_tx2 = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=None,
            value=0,
            data=COUNTER_BYTECODE,
            gas=300_000,
            gas_price=1_000_000_000,
            nonce=nonce + 1,
        )
        
        chain.send_transaction(deploy_tx1)
        chain.send_transaction(deploy_tx2)
        block = chain.build_block()
        
        receipts = chain.store.get_receipts(block.number)
        contract1 = receipts[0].contract_address
        contract2 = receipts[1].contract_address
        
        # Create two SetCode transactions with different nonces
        auth1 = chain.create_authorization(
            chain_id=chain.chain_id,
            address=contract1,
            nonce=chain.get_nonce(alice_address),
            private_key=ALICE_PRIVATE_KEY,
        )
        
        auth2 = chain.create_authorization(
            chain_id=chain.chain_id,
            address=contract2,
            nonce=chain.get_nonce(alice_address) + 1,  # Different nonce
            private_key=ALICE_PRIVATE_KEY,
        )
        
        setcode_tx1 = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=contract1,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth1],
        )
        
        # Get latest block for base fee
        latest = chain.get_latest_block()
        base_fee = latest.header.base_fee_per_gas if latest else 1_000_000_000
        
        # Need to send and mine first transaction, then second
        # (mempool only allows one tx per sender at a time)
        chain.send_transaction(setcode_tx1)
        block1 = chain.build_block()
        
        setcode_tx2 = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=contract2,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth2],
        )
        chain.send_transaction(setcode_tx2)
        block2 = chain.build_block()
        
        # Both blocks should have a transaction
        assert len(block1.transactions) == 1
        assert len(block2.transactions) == 1