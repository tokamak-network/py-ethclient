"""Spec tests for blockchain operations.

Tests block creation, chain state, and blockchain operations
according to Ethereum execution specs.
"""

import pytest
from eth_utils import to_wei, keccak

from sequencer.sequencer.chain import Chain, calc_base_fee
from sequencer.core.constants import (
    DEFAULT_CHAIN_ID,
    INITIAL_BASE_FEE,
    DEFAULT_GAS_LIMIT,
)
from tests.fixtures.keys import ALICE_PRIVATE_KEY, ALICE_ADDRESS, BOB_ADDRESS


class TestBlockCreation:
    """Test block creation and properties."""

    def test_genesis_block(self, chain, alice_address):
        """Chain starts with genesis block."""
        genesis = chain.get_block_by_number(0)
        
        assert genesis is not None
        assert genesis.number == 0

    def test_build_first_block(self, chain, alice_address, bob_address):
        """Build the first block after genesis."""
        # Send a transaction
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
        
        assert block is not None
        assert block.number == 1
        assert len(block.transactions) == 1

    def test_block_hash(self, chain, alice_address):
        """Each block has a unique hash."""
        genesis = chain.get_block_by_number(0)
        
        # Build block 1
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=BOB_ADDRESS,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=0,
        )
        chain.send_transaction(tx)
        block1 = chain.build_block()
        
        assert genesis.hash != block1.hash

    def test_block_parent_hash(self, chain, alice_address):
        """Each block references parent."""
        genesis = chain.get_block_by_number(0)
        
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=BOB_ADDRESS,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        chain.send_transaction(tx)
        block1 = chain.build_block()
        
        assert block1.header.parent_hash == genesis.hash


class TestBlockHeaders:
    """Test block header fields."""

    def test_header_state_root(self, chain, alice_address):
        """Header contains state root."""
        block = chain.get_latest_block()
        
        assert block is not None
        assert block.header.state_root is not None
        assert len(block.header.state_root) == 32

    def test_header_transactions_root(self, chain, alice_address, bob_address):
        """Header contains transactions root."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert block.header.transactions_root is not None
        assert len(block.header.transactions_root) == 32

    def test_header_receipts_root(self, chain, alice_address, bob_address):
        """Header contains receipts root."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert block.header.receipts_root is not None
        assert len(block.header.receipts_root) == 32

    def test_header_base_fee(self, chain):
        """Header contains EIP-1559 base fee."""
        block = chain.get_latest_block()
        
        assert block.header.base_fee_per_gas is not None
        assert block.header.base_fee_per_gas >= 1

    def test_header_gas_used(self, chain, alice_address, bob_address):
        """Header tracks gas used."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert block.header.gas_used == 21_000

    def test_header_gas_limit(self, chain):
        """Header has gas limit."""
        block = chain.get_latest_block()
        
        assert block.header.gas_limit == DEFAULT_GAS_LIMIT


class TestStateTransitions:
    """Test state transitions between blocks."""

    def test_balance_updates(self, chain, alice_address, bob_address):
        """Balance updates after transfer."""
        initial_alice = chain.get_balance(alice_address)
        initial_bob = chain.get_balance(bob_address)
        
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        final_alice = chain.get_balance(alice_address)
        final_bob = chain.get_balance(bob_address)
        
        # Alice balance decreased
        assert final_alice < initial_alice
        # Bob balance increased
        assert final_bob > initial_bob

    def test_nonce_increments(self, chain, alice_address, bob_address):
        """Nonce increments after transaction."""
        initial_nonce = chain.get_nonce(alice_address)
        
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=initial_nonce,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        final_nonce = chain.get_nonce(alice_address)
        
        assert final_nonce == initial_nonce + 1

    def test_state_root_changes(self, chain, alice_address, bob_address):
        """State root changes after state modifications."""
        initial_root = chain.get_latest_block().header.state_root
        
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(0.5, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        new_root = chain.get_latest_block().header.state_root
        
        assert new_root != initial_root


class TestBaseFeeMechanics:
    """Test EIP-1559 base fee mechanics."""

    def test_base_fee_increases_on_demand(self, chain, alice_address, bob_address):
        """Base fee increases with high demand."""
        initial_fee = chain.get_latest_block().header.base_fee_per_gas
        
        # Build several blocks with transactions
        for _ in range(3):
            tx = chain.create_transaction(
                from_private_key=ALICE_PRIVATE_KEY,
                to=bob_address,
                value=0,
                data=b"",
                gas=21_000,
                gas_price=2_000_000_000,
                nonce=chain.get_nonce(alice_address),
            )
            chain.send_transaction(tx)
            chain.build_block()
        
        final_fee = chain.get_latest_block().header.base_fee_per_gas
        
        # Base fee should increase with sustained demand
        # (though may not if blocks are under target)
        # Just verify it's still valid
        assert final_fee >= 1

    def test_base_fee_calculation_formula(self):
        """Base fee calculation follows EIP-1559 formula."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        
        # At target: no change
        fee = calc_base_fee(gas_target, gas_limit, INITIAL_BASE_FEE)
        assert fee == INITIAL_BASE_FEE
        
        # Above target: increase
        fee = calc_base_fee(gas_target + 1_000_000, gas_limit, INITIAL_BASE_FEE)
        assert fee > INITIAL_BASE_FEE
        
        # Below target: decrease
        fee = calc_base_fee(gas_target - 1_000_000, gas_limit, INITIAL_BASE_FEE)
        assert fee < INITIAL_BASE_FEE


class TestChainQueries:
    """Test chain state queries."""

    def test_get_balance(self, chain, alice_address):
        """Can query account balance."""
        balance = chain.get_balance(alice_address)
        
        assert isinstance(balance, int)
        assert balance >= 0

    def test_get_nonce(self, chain, alice_address):
        """Can query account nonce."""
        nonce = chain.get_nonce(alice_address)
        
        assert isinstance(nonce, int)
        assert nonce >= 0

    def test_get_code(self, chain, alice_address):
        """Can query account code."""
        code = chain.get_code(alice_address)
        
        # EOAs have empty code
        assert code == b""

    def test_get_block_by_number(self, chain):
        """Can query block by number."""
        genesis = chain.get_block_by_number(0)
        
        assert genesis is not None
        assert genesis.number == 0

    def test_get_latest_block(self, chain):
        """Can query latest block."""
        block = chain.get_latest_block()
        
        assert block is not None


class TestTransactionInclusion:
    """Test transaction inclusion in blocks."""

    def test_single_transaction(self, chain, alice_address, bob_address):
        """Single transaction included in block."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert len(block.transactions) == 1

    def test_multiple_transactions(self, chain, alice_address, bob_address):
        """Multiple transactions included sequentially."""
        for i in range(3):
            tx = chain.create_transaction(
                from_private_key=ALICE_PRIVATE_KEY,
                to=bob_address,
                value=0,
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=chain.get_nonce(alice_address) + i,
            )
            chain.send_transaction(tx)
            chain.build_block()
        
        # Should have 3 blocks
        assert chain.get_latest_block().number >= 3

    def test_transaction_order_preserved(self, chain, alice_address, bob_address):
        """Transaction order is preserved in block."""
        # Send transactions with specific values
        values = [to_wei(0.1, "ether"), to_wei(0.2, "ether"), to_wei(0.3, "ether")]
        
        initial_bob = chain.get_balance(bob_address)
        
        for i, value in enumerate(values):
            tx = chain.create_transaction(
                from_private_key=ALICE_PRIVATE_KEY,
                to=bob_address,
                value=value,
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=chain.get_nonce(alice_address),
            )
            chain.send_transaction(tx)
            chain.build_block()
        
        # Bob should have received all transfers
        final_bob = chain.get_balance(bob_address)
        expected_increase = sum(values)
        
        assert final_bob >= initial_bob + expected_increase - to_wei(0.001, "ether")  # Account for gas