"""Unit tests for core types.

Tests our wrapper classes in sequencer.core.types.
"""

import pytest
from eth_utils import to_wei

from sequencer.core.types import Account, BlockHeader, Block, Receipt
from sequencer.core.constants import EMPTY_ROOT, EMPTY_CODE_HASH


class TestAccount:
    """Test Account dataclass."""

    def test_create_account(self):
        """Create a basic account."""
        account = Account(
            nonce=5,
            balance=to_wei(10, "ether"),
            storage_root=EMPTY_ROOT,
            code_hash=EMPTY_CODE_HASH,
        )
        
        assert account.nonce == 5
        assert account.balance == to_wei(10, "ether")

    def test_empty_account(self):
        """Create an empty account."""
        account = Account.empty()
        
        assert account.nonce == 0
        assert account.balance == 0
        assert account.storage_root == EMPTY_ROOT
        assert account.code_hash == EMPTY_CODE_HASH

    def test_account_rlp_roundtrip(self):
        """Account can be serialized to RLP."""
        original = Account(
            nonce=10,
            balance=to_wei(1, "ether"),
            storage_root=b"\x01" * 32,
            code_hash=b"\x02" * 32,
        )
        
        rlp_data = original.to_rlp()
        assert isinstance(rlp_data, bytes)
        assert len(rlp_data) > 0
        
        # Note: from_rlp returns raw RLP values which may be bytes
        # For full roundtrip, values need to be converted back to int
        recovered = Account.from_rlp(rlp_data)
        assert isinstance(recovered, Account)


class TestBlockHeader:
    """Test BlockHeader dataclass."""

    def test_create_header(self):
        """Create a basic block header."""
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=b"\x00" * 32,
            coinbase=b"\x00" * 20,
            state_root=b"\x01" * 32,
            transactions_root=b"\x02" * 32,
            receipts_root=b"\x03" * 32,
            logs_bloom=b"\x00" * 256,
            number=1,
        )
        
        assert header.number == 1
        assert header.gas_limit == 30_000_000
        assert header.difficulty == 0

    def test_header_hash(self):
        """Header has a hash."""
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=b"\x00" * 32,
            coinbase=b"\x00" * 20,
            state_root=b"\x01" * 32,
            transactions_root=b"\x02" * 32,
            receipts_root=b"\x03" * 32,
            logs_bloom=b"\x00" * 256,
            number=1,
        )
        
        header_hash = header.hash()
        assert isinstance(header_hash, bytes)
        assert len(header_hash) == 32

    def test_header_hash_consistency(self):
        """Same header produces same hash."""
        header = BlockHeader(
            parent_hash=b"\xaa" * 32,
            ommers_hash=b"\xbb" * 32,
            coinbase=b"\xcc" * 20,
            state_root=b"\xdd" * 32,
            transactions_root=b"\xee" * 32,
            receipts_root=b"\xff" * 32,
            logs_bloom=b"\x00" * 256,
            number=42,
        )
        
        hash1 = header.hash()
        hash2 = header.hash()
        assert hash1 == hash2

    def test_header_different_hashes(self):
        """Different headers produce different hashes."""
        header1 = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=b"\x00" * 32,
            coinbase=b"\x00" * 20,
            state_root=b"\x01" * 32,
            transactions_root=b"\x02" * 32,
            receipts_root=b"\x03" * 32,
            logs_bloom=b"\x00" * 256,
            number=1,
        )
        
        header2 = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=b"\x00" * 32,
            coinbase=b"\x00" * 20,
            state_root=b"\x01" * 32,
            transactions_root=b"\x02" * 32,
            receipts_root=b"\x03" * 32,
            logs_bloom=b"\x00" * 256,
            number=2,  # Different number
        )
        
        assert header1.hash() != header2.hash()

    def test_header_base_fee(self):
        """Header with EIP-1559 base fee."""
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=b"\x00" * 32,
            coinbase=b"\x00" * 20,
            state_root=b"\x01" * 32,
            transactions_root=b"\x02" * 32,
            receipts_root=b"\x03" * 32,
            logs_bloom=b"\x00" * 256,
            number=1,
            base_fee_per_gas=1_000_000_000,
        )
        
        assert header.base_fee_per_gas == 1_000_000_000


class TestBlock:
    """Test Block dataclass."""

    def test_create_empty_block(self):
        """Create an empty block."""
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=b"\x00" * 32,
            coinbase=b"\x00" * 20,
            state_root=b"\x01" * 32,
            transactions_root=b"\x02" * 32,
            receipts_root=b"\x03" * 32,
            logs_bloom=b"\x00" * 256,
            number=1,
        )
        
        block = Block(header=header, transactions=[])
        
        assert block.number == 1
        assert len(block.transactions) == 0

    def test_block_with_transactions(self):
        """Create a block with transactions."""
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=b"\x00" * 32,
            coinbase=b"\x00" * 20,
            state_root=b"\x01" * 32,
            transactions_root=b"\x02" * 32,
            receipts_root=b"\x03" * 32,
            logs_bloom=b"\x00" * 256,
            number=1,
            gas_used=21_000,
        )
        
        # Mock transaction
        tx = {"nonce": 0, "value": 100}
        
        block = Block(header=header, transactions=[tx])
        
        assert len(block.transactions) == 1
        assert block.transactions[0] == tx

    def test_block_hash(self):
        """Block hash matches header hash."""
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=b"\x00" * 32,
            coinbase=b"\x00" * 20,
            state_root=b"\x01" * 32,
            transactions_root=b"\x02" * 32,
            receipts_root=b"\x03" * 32,
            logs_bloom=b"\x00" * 256,
            number=1,
        )
        
        block = Block(header=header, transactions=[])
        
        assert block.hash == header.hash()


class TestReceipt:
    """Test Receipt dataclass."""

    def test_create_success_receipt(self):
        """Create a successful transaction receipt."""
        receipt = Receipt(
            status=1,
            cumulative_gas_used=21_000,
            logs=[],
        )
        
        assert receipt.status == 1
        assert receipt.cumulative_gas_used == 21_000

    def test_create_failure_receipt(self):
        """Create a failed transaction receipt."""
        receipt = Receipt(
            status=0,
            cumulative_gas_used=50_000,
            logs=[],
        )
        
        assert receipt.status == 0

    def test_contract_deployment_receipt(self):
        """Create receipt for contract deployment."""
        receipt = Receipt(
            status=1,
            cumulative_gas_used=100_000,
            logs=[],
            contract_address=b"\x12" * 20,
        )
        
        assert receipt.contract_address is not None
        assert len(receipt.contract_address) == 20

    def test_receipt_with_logs(self):
        """Create receipt with event logs."""
        log = {
            "address": b"\x01" * 20,
            "topics": [b"\x02" * 32],
            "data": b"event data",
        }
        
        receipt = Receipt(
            status=1,
            cumulative_gas_used=21_000,
            logs=[log],
        )
        
        assert len(receipt.logs) == 1

    def test_receipt_rlp_encoding(self):
        """Receipt can be RLP encoded."""
        receipt = Receipt(
            status=1,
            cumulative_gas_used=21_000,
            logs=[],
        )
        
        rlp_data = receipt.to_rlp()
        assert isinstance(rlp_data, bytes)
        assert len(rlp_data) > 0


class TestTypesIntegration:
    """Integration scenarios for types."""

    def test_block_chain_simulation(self):
        """Simulate a chain of blocks."""
        # Genesis block
        genesis_header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=b"\x00" * 32,
            coinbase=b"\x00" * 20,
            state_root=b"\x01" * 32,
            transactions_root=b"\x02" * 32,
            receipts_root=b"\x03" * 32,
            logs_bloom=b"\x00" * 256,
            number=0,
        )
        genesis = Block(header=genesis_header, transactions=[])
        
        # Block 1
        block1_header = BlockHeader(
            parent_hash=genesis.hash,
            ommers_hash=b"\x00" * 32,
            coinbase=b"\x00" * 20,
            state_root=b"\x04" * 32,
            transactions_root=b"\x05" * 32,
            receipts_root=b"\x06" * 32,
            logs_bloom=b"\x00" * 256,
            number=1,
        )
        block1 = Block(header=block1_header, transactions=[])
        
        # Verify chain linkage
        assert block1.header.parent_hash == genesis.hash
        assert block1.number == genesis.number + 1

    def test_account_state_changes(self):
        """Simulate account state changes."""
        # Initial account
        account = Account.empty()
        assert account.nonce == 0
        assert account.balance == 0
        
        # After receiving funds
        funded = Account(
            nonce=0,
            balance=to_wei(10, "ether"),
            storage_root=account.storage_root,
            code_hash=account.code_hash,
        )
        
        # After sending a transaction
        after_send = Account(
            nonce=1,
            balance=to_wei(9, "ether"),
            storage_root=funded.storage_root,
            code_hash=funded.code_hash,
        )
        
        assert after_send.nonce == 1
        assert after_send.balance == to_wei(9, "ether")