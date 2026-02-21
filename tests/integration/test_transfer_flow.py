"""Integration tests for ETH transfer flows.

Tests end-to-end scenarios:
- EOA to EOA transfers
- Insufficient balance handling
- Nonce management
- Gas estimation
- Multiple transfers in sequence
"""

import pytest
from eth_utils import to_wei

from sequencer.core.crypto import keccak256
from tests.fixtures.addresses import ALICE_PRIVATE_KEY, BOB_ADDRESS, CHARLIE_ADDRESS


class TestTransferFlow:
    """Test ETH transfer scenarios."""

    def test_eoa_to_eoa_transfer(self, chain, alice_address, bob_address):
        """Alice sends 1 ETH to Bob."""
        # Initial balances
        alice_initial = chain.get_balance(alice_address)
        bob_initial = chain.get_balance(bob_address)
        
        # Create and send transaction
        nonce = chain.get_nonce(alice_address)
        signed_tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        
        tx_hash = chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        # Verify block
        assert block is not None
        assert len(block.transactions) == 1
        
        # Verify balances
        alice_final = chain.get_balance(alice_address)
        bob_final = chain.get_balance(bob_address)
        
        # Alice: initial - 1 ETH - gas
        gas_used = 21_000
        gas_cost = gas_used * 1_000_000_000
        assert alice_final == alice_initial - to_wei(1, "ether") - gas_cost
        
        # Bob: initial + 1 ETH
        assert bob_final == bob_initial + to_wei(1, "ether")
        
        # Verify nonce incremented
        assert chain.get_nonce(alice_address) == 1

    def test_insufficient_balance_fails(self, chain, alice_address, bob_address):
        """Transfer with insufficient balance should be rejected immediately."""
        from sequencer.sequencer.mempool import InsufficientFunds
        
        # Get initial balance
        initial_balance = chain.get_balance(alice_address)
        
        # Try to send more than we have
        nonce = chain.get_nonce(alice_address)
        signed_tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=initial_balance + to_wei(1, "ether"),  # More than available
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        
        # The transaction should be rejected with InsufficientFunds
        with pytest.raises(InsufficientFunds):
            chain.send_transaction(signed_tx)
        
        # Balance should be unchanged
        final_balance = chain.get_balance(alice_address)
        assert final_balance == initial_balance

    def test_nonce_increment(self, chain, alice_address, bob_address):
        """Nonce increments after each transaction."""
        initial_nonce = chain.get_nonce(alice_address)
        
        # Send first transaction
        signed_tx1 = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(0.1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=initial_nonce,
        )
        chain.send_transaction(signed_tx1)
        chain.build_block()
        
        # Nonce should be 1
        assert chain.get_nonce(alice_address) == initial_nonce + 1
        
        # Send second transaction
        signed_tx2 = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(0.1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=initial_nonce + 1,
        )
        chain.send_transaction(signed_tx2)
        chain.build_block()
        
        # Nonce should be 2
        assert chain.get_nonce(alice_address) == initial_nonce + 2

    def test_multiple_transfers_same_block(self, chain, alice_address, bob_address, charlie_address):
        """Multiple transfers in the same block."""
        # Add funds for Charlie
        chain.evm.set_balance(charlie_address, to_wei(50, "ether"))
        
        # Create multiple transactions
        alice_nonce = chain.get_nonce(alice_address)
        tx1 = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(0.5, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=alice_nonce,
        )
        
        tx2 = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=charlie_address,
            value=to_wei(0.5, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=alice_nonce + 1,
        )
        
        chain.send_transaction(tx1)
        chain.send_transaction(tx2)
        block = chain.build_block()
        
        # Both transactions should be in the block
        assert block is not None
        assert len(block.transactions) == 2
        
        # Verify balances
        assert chain.get_balance(bob_address) >= to_wei(0.5, "ether")
        assert chain.get_balance(charlie_address) >= to_wei(0.5, "ether")

    def test_transfer_to_self(self, chain, alice_address):
        """Transfer to own address."""
        initial_balance = chain.get_balance(alice_address)
        initial_nonce = chain.get_nonce(alice_address)
        
        # Transfer to self
        signed_tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=alice_address,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=initial_nonce,
        )
        
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        # Balance should decrease by gas cost only
        gas_cost = 21_000 * 1_000_000_000
        final_balance = chain.get_balance(alice_address)
        assert final_balance == initial_balance - gas_cost
        
        # Nonce should increment
        assert chain.get_nonce(alice_address) == initial_nonce + 1

    def test_zero_value_transfer(self, chain, alice_address, bob_address):
        """Transfer with zero value."""
        initial_balance = chain.get_balance(bob_address)
        initial_nonce = chain.get_nonce(alice_address)
        
        # Transfer zero ETH
        signed_tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=initial_nonce,
        )
        
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        # Bob's balance unchanged
        assert chain.get_balance(bob_address) == initial_balance
        
        # Nonce incremented
        assert chain.get_nonce(alice_address) == initial_nonce + 1

    def test_eip1559_transfer(self, chain, alice_address, bob_address):
        """EIP-1559 transaction for transfer."""
        # Get latest block for base fee
        latest = chain.get_latest_block()
        base_fee = latest.header.base_fee_per_gas if latest else 1_000_000_000
        
        # Create EIP-1559 transaction
        nonce = chain.get_nonce(alice_address)
        signed_tx = chain.create_eip1559_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(0.5, "ether"),
            data=b"",
            gas=21_000,
            max_priority_fee_per_gas=1_000_000_000,
            max_fee_per_gas=base_fee * 2,
            nonce=nonce,
        )
        
        chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        assert block is not None
        assert len(block.transactions) == 1
        
        # Verify transfer succeeded
        assert chain.get_balance(bob_address) >= to_wei(0.5, "ether")

    def test_gas_price_affects_cost(self, chain, alice_address, bob_address):
        """Higher gas price results in higher total cost."""
        initial_balance = chain.get_balance(alice_address)
        
        # Low gas price transaction
        tx1 = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(0.1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,  # 1 Gwei
            nonce=chain.get_nonce(alice_address),
        )
        chain.send_transaction(tx1)
        chain.build_block()
        
        balance_after_tx1 = chain.get_balance(alice_address)
        cost_tx1 = initial_balance - balance_after_tx1 - to_wei(0.1, "ether")
        
        # Higher gas price transaction
        tx2 = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(0.1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=2_000_000_000,  # 2 Gwei
            nonce=chain.get_nonce(alice_address),
        )
        chain.send_transaction(tx2)
        chain.build_block()
        
        balance_after_tx2 = chain.get_balance(alice_address)
        cost_tx2 = balance_after_tx1 - balance_after_tx2 - to_wei(0.1, "ether")
        
        # Higher gas price should cost more
        assert cost_tx2 > cost_tx1


class TestTransferEdgeCases:
    """Edge cases and error handling for transfers."""

    def test_transfer_to_empty_account(self, chain, alice_address):
        """Transfer to account that doesn't exist yet."""
        new_address = bytes.fromhex("beef" + "00" * 18)
        
        # New account should have zero balance
        assert chain.get_balance(new_address) == 0
        assert chain.get_nonce(new_address) == 0
        assert chain.get_code(new_address) == b""
        
        # Transfer to new account
        nonce = chain.get_nonce(alice_address)
        signed_tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=new_address,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        # Account should now exist with balance
        assert chain.get_balance(new_address) == to_wei(1, "ether")

    def test_transfer_with_data_fails(self, chain, alice_address, bob_address):
        """EOA transfer with data requires more gas."""
        nonce = chain.get_nonce(alice_address)
        
        # Transfer with data (needs more gas for data bytes)
        # Each non-zero byte costs more gas
        signed_tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=to_wei(0.1, "ether"),
            data=b"hello",  # Extra data - costs gas
            gas=25_000,  # Increased gas for data
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        
        chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        # Transaction should succeed with enough gas
        assert block is not None
        assert len(block.transactions) == 1
        
        # Verify transfer happened
        assert chain.get_balance(bob_address) >= to_wei(0.1, "ether")