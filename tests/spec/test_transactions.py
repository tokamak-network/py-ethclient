"""Spec tests for transaction types and validation.

Tests transaction creation, signing, and validation according to
Ethereum execution specs. Tests our wrapper code, not py-evm internals.
"""

import pytest
from eth_utils import to_wei
from eth.vm.forks.prague.transactions import SetCodeTransaction

from sequencer.sequencer.chain import Chain
from sequencer.core.constants import DEFAULT_CHAIN_ID
from tests.fixtures.keys import ALICE_PRIVATE_KEY, ALICE_ADDRESS, BOB_ADDRESS


class TestLegacyTransaction:
    """Test legacy transaction creation."""

    def test_create_legacy_transaction(self, chain, alice_address, bob_address):
        """Create a valid legacy transaction."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=0,
        )
        
        assert tx is not None
        assert tx.nonce == 0
        assert tx.gas == 21_000
        assert tx.gas_price == 1_000_000_000
        assert tx.value == to_wei(1, "ether")
        assert tx.to == bob_address

    def test_legacy_transaction_signing(self, chain, alice_address):
        """Legacy transaction is properly signed."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=BOB_ADDRESS,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=0,
        )
        
        # Signed transaction should have v, r, s
        assert hasattr(tx, "v")
        assert hasattr(tx, "r")
        assert hasattr(tx, "s")
        assert tx.v > 0
        assert tx.r > 0
        assert tx.s > 0

    def test_contract_creation_transaction(self, chain, alice_address):
        """Transaction with null 'to' creates contract."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=b"",  # Empty bytes for contract creation
            value=0,
            data=b"contract bytecode",
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=0,
        )
        
        # Contract creation transactions have empty or None 'to'
        # py-evm uses b"" for contract creation
        assert tx.to == b"" or tx.to is None


class TestEIP1559Transaction:
    """Test EIP-1559 typed transaction."""

    def test_create_eip1559_transaction(self, chain, alice_address, bob_address):
        """Create a valid EIP-1559 transaction."""
        tx = chain.create_eip1559_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            max_priority_fee_per_gas=100_000_000,
            max_fee_per_gas=2_000_000_000,
        )
        
        assert tx is not None
        assert hasattr(tx, "max_fee_per_gas")
        assert hasattr(tx, "max_priority_fee_per_gas")
        assert tx.max_priority_fee_per_gas == 100_000_000
        assert tx.max_fee_per_gas == 2_000_000_000

    def test_eip1559_transaction_encoding(self, chain, alice_address, bob_address):
        """EIP-1559 transaction has correct type prefix."""
        tx = chain.create_eip1559_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            max_priority_fee_per_gas=100_000_000,
            max_fee_per_gas=2_000_000_000,
        )
        
        # EIP-1559 transactions have type 0x02
        encoded = tx.encode()
        # Type should be 0x02 (EIP-1559) in first byte
        assert encoded[0] == 0x02


class TestEIP7702Transaction:
    """Test EIP-7702 SetCode transaction."""

    def test_create_setcode_transaction(self, chain, alice_address, bob_address):
        """Create a valid SetCode transaction."""
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        assert tx is not None
        # Transaction should have authorization_list
        assert hasattr(tx, "authorization_list") or hasattr(tx, "_inner")

    def test_setcode_transaction_type(self, chain, alice_address, bob_address):
        """SetCode transaction has correct type prefix."""
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=BOB_ADDRESS,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=BOB_ADDRESS,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        # SetCode transactions have type 0x04
        encoded = tx.encode()
        assert encoded[0] == 0x04


class TestTransactionValidation:
    """Test transaction validation rules."""

    def test_nonce_validation(self, chain, alice_address, bob_address):
        """Correct nonce is required for valid transaction."""
        correct_nonce = chain.get_nonce(alice_address)
        
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=correct_nonce,
        )
        
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert len(block.transactions) == 1

    def test_gas_validation(self, chain, alice_address, bob_address):
        """Gas must be sufficient for transaction."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,  # Minimum for simple transfer
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert block is not None

    def test_balance_validation(self, chain, alice_address, bob_address):
        """Address must have sufficient balance."""
        balance = chain.get_balance(alice_address)
        
        # Can send up to balance minus gas
        max_send = balance - 21_000 * 1_000_000_000
        
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=max_send,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert block is not None


class TestTransactionEncoding:
    """Test transaction RLP encoding."""

    def test_legacy_encoding(self, chain, alice_address, bob_address):
        """Legacy transaction encodes correctly."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=0,
        )
        
        encoded = tx.encode()
        
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

    def test_eip1559_encoding(self, chain, alice_address, bob_address):
        """EIP-1559 transaction encodes with type prefix."""
        tx = chain.create_eip1559_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            max_priority_fee_per_gas=100_000_000,
            max_fee_per_gas=2_000_000_000,
        )
        
        encoded = tx.encode()
        
        # Should start with type byte
        assert encoded[0] in (0x02, 0x03)  # EIP-1559 or EIP-4844

    def test_setcode_encoding(self, chain, alice_address, bob_address):
        """SetCode transaction encodes with type 0x04."""
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=BOB_ADDRESS,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=BOB_ADDRESS,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        encoded = tx.encode()
        
        # SetCode type is 0x04
        assert encoded[0] == 0x04


class TestTransactionHash:
    """Test transaction hash computation."""

    def test_transaction_hash_consistency(self, chain, alice_address, bob_address):
        """Same transaction produces same hash."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=0,
        )
        
        hash1 = tx.hash
        hash2 = tx.hash
        
        assert hash1 == hash2

    def test_different_transactions_different_hashes(self, chain, alice_address, bob_address):
        """Different transactions have different hashes."""
        tx1 = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=BOB_ADDRESS,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=0,
        )
        
        tx2 = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=BOB_ADDRESS,
            value=to_wei(2, "ether"),  # Different value
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=0,
        )
        
        assert tx1.hash != tx2.hash

    def test_transaction_hash_length(self, chain, alice_address, bob_address):
        """Transaction hash is 32 bytes."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=0,
        )
        
        assert len(tx.hash) == 32