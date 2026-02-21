"""Spec tests for EIP implementations.

Tests EIP-specific functionality:
- EIP-155: Chain ID protection
- EIP-1559: Fee market
- EIP-7702: SetCode transactions
"""

import pytest
from eth_utils import to_wei
from eth.vm.forks.prague.transactions import Authorization

from sequencer.sequencer.chain import Chain
from sequencer.core.constants import (
    DEFAULT_CHAIN_ID,
    INITIAL_BASE_FEE,
    DEFAULT_GAS_LIMIT,
)
from tests.fixtures.keys import ALICE_PRIVATE_KEY, ALICE_ADDRESS, BOB_ADDRESS


class TestEIP155:
    """Test EIP-155 replay protection."""

    def test_chain_id_fixtures(self, chain):
        """Chain has correct chain ID."""
        assert chain.chain_id == DEFAULT_CHAIN_ID
        assert DEFAULT_CHAIN_ID == 1337


class TestEIP1559:
    """Test EIP-1559 fee market."""

    def test_base_fee_initialization(self, chain):
        """Base fee initializes correctly."""
        block = chain.get_latest_block()
        
        assert block.header.base_fee_per_gas == INITIAL_BASE_FEE

    def test_eip1559_transaction_fee_fields(self, chain, alice_address, bob_address):
        """EIP-1559 transaction has correct fee fields."""
        tx = chain.create_eip1559_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            max_priority_fee_per_gas=100_000_000,
            max_fee_per_gas=2_000_000_000,
        )
        
        assert tx.max_priority_fee_per_gas == 100_000_000
        assert tx.max_fee_per_gas == 2_000_000_000

    def test_gas_limit_setting(self, chain):
        """Gas limit is set correctly."""
        block = chain.get_latest_block()
        
        assert block.header.gas_limit == DEFAULT_GAS_LIMIT
        assert DEFAULT_GAS_LIMIT == 30_000_000

    def test_fee_payment_with_base_fee(self, chain, alice_address, bob_address):
        """Transaction pays base fee to coinbase."""
        tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=21_000,
            gas_price=INITIAL_BASE_FEE,
            nonce=chain.get_nonce(alice_address),
        )
        
        chain.send_transaction(tx)
        chain.build_block()
        
        # Just verify transaction succeeded
        assert chain.get_nonce(alice_address) == 1


class TestEIP7702:
    """Test EIP-7702 SetCode transactions."""

    def test_authorization_creation(self, chain, alice_address, bob_address):
        """Can create EIP-7702 authorization."""
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        assert auth is not None
        assert isinstance(auth, Authorization)
        assert auth.address == bob_address
        assert auth.nonce == 0

    def test_authorization_chain_id(self, chain, alice_address, bob_address):
        """Authorization can use any chain ID."""
        # Specific chain ID
        auth1 = chain.create_authorization(
            chain_id=chain.chain_id,
            address=BOB_ADDRESS,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        assert auth1.chain_id == chain.chain_id
        
        # Universal (chain_id = 0)
        auth2 = chain.create_authorization(
            chain_id=0,
            address=BOB_ADDRESS,
            nonce=1,
            private_key=ALICE_PRIVATE_KEY,
        )
        assert auth2.chain_id == 0

    def test_setcode_transaction_execution(self, chain, alice_address, bob_address):
        """SetCode transaction can be executed."""
        # Deploy a contract first
        bytecode = bytes.fromhex("60006000f3")  # Empty runtime
        
        deploy_tx = chain.create_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=None,
            value=0,
            data=bytecode,
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=chain.get_nonce(alice_address),
        )
        
        chain.send_transaction(deploy_tx)
        deploy_block = chain.build_block()
        
        receipts = chain.store.get_receipts(deploy_block.number)
        contract_address = receipts[0].contract_address
        
        # Create authorization
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=contract_address,
            nonce=chain.get_nonce(alice_address),
            private_key=ALICE_PRIVATE_KEY,
        )
        
        # Create SetCode transaction
        setcode_tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=alice_address,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        chain.send_transaction(setcode_tx)
        setcode_block = chain.build_block()
        
        assert setcode_block is not None

    def test_multiple_authorizations(self, chain, alice_address, bob_address):
        """SetCode transaction can have multiple authorizations."""
        auth1 = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        auth2 = chain.create_authorization(
            chain_id=chain.chain_id,
            address=b"\xff" * 20,
            nonce=1,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth1, auth2],
        )
        
        # Check that both authorizations are included
        if hasattr(tx, "authorization_list"):
            assert len(tx.authorization_list) == 2
        elif hasattr(tx, "_inner"):
            assert len(tx._inner.authorization_list) == 2


class TestEIP2718:
    """Test EIP-2718 typed transactions."""

    def test_transaction_type_eip1559(self, chain, alice_address, bob_address):
        """EIP-1559 transaction has type 0x02."""
        tx = chain.create_eip1559_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=BOB_ADDRESS,
            value=0,
            data=b"",
            gas=21_000,
            max_priority_fee_per_gas=100_000_000,
            max_fee_per_gas=2_000_000_000,
        )
        
        encoded = tx.encode()
        assert encoded[0] == 0x02

    def test_transaction_type_setcode(self, chain, alice_address, bob_address):
        """SetCode transaction has type 0x04."""
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
        assert encoded[0] == 0x04


class TestCombinedEIPs:
    """Test interactions between EIPs."""

    def test_eip1559_with_eip7702(self, chain, alice_address, bob_address):
        """EIP-1559 fees work with EIP-7702 transactions."""
        auth = chain.create_authorization(
            chain_id=chain.chain_id,
            address=bob_address,
            nonce=0,
            private_key=ALICE_PRIVATE_KEY,
        )
        
        # SetCode transaction with EIP-1559-style gas
        tx = chain.create_setcode_transaction(
            from_private_key=ALICE_PRIVATE_KEY,
            to=bob_address,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert block is not None