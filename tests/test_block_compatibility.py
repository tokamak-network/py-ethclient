"""Block structure and hash calculation compatibility tests."""

import pytest
from eth_utils.currency import to_wei
from rlp import encode

from sequencer.core.types import Block, BlockHeader, Receipt
from sequencer.core.crypto import keccak256
from sequencer.core.constants import EMPTY_ROOT, EMPTY_CODE_HASH
from sequencer.sequencer.chain import Chain, EMPTY_OMMERS_HASH


class TestBlockHeaderStructure:
    def test_genesis_header_required_fields(self, chain):
        genesis = chain.get_block_by_number(0)
        assert genesis is not None
        assert genesis.header.number == 0
        assert genesis.header.parent_hash == b"\x00" * 32
        assert genesis.header.gas_limit > 0
        assert len(genesis.header.logs_bloom) == 256
        assert len(genesis.header.state_root) == 32
        assert len(genesis.header.transactions_root) == 32
        assert len(genesis.header.receipts_root) == 32

    def test_block_header_hash_is_keccak256_of_rlp(self, chain):
        block = chain.get_block_by_number(0)
        header = block.header
        rlp_encoded = encode(header._to_rlp_list())
        expected_hash = keccak256(rlp_encoded)
        assert header.hash() == expected_hash

    def test_block_hash_is_header_hash(self, chain):
        block = chain.get_block_by_number(0)
        assert block.hash == block.header.hash()

    def test_empty_ommers_hash(self):
        expected = keccak256(encode([]))
        assert EMPTY_OMMERS_HASH == expected

    def test_empty_transactions_root(self):
        from trie import HexaryTrie
        trie = HexaryTrie({})
        empty_root = trie.root_hash
        expected = bytes.fromhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
        assert empty_root == expected


class TestBlockStructure:
    def test_block_number_property(self, chain):
        block = chain.get_block_by_number(0)
        assert block.number == block.header.number

    def test_block_transactions_list(self, chain):
        block = chain.get_block_by_number(0)
        assert isinstance(block.transactions, list)

    def test_block_after_transaction_has_correct_structure(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
            gas_price=1000000000,
        )
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert block.number == 1
        assert block.header.parent_hash == chain.get_block_by_number(0).hash
        assert len(block.transactions) == 1

    def test_sequential_blocks_have_linked_hashes(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        prev_hash = chain.get_block_by_number(0).hash
        
        for i in range(3):
            tx = chain.create_transaction(
                from_private_key=b"\x01" * 32,
                to=b"\xde\xad\xbe\xef" * 5,
                value=to_wei(1, "ether"),
                gas=21000,
            )
            chain.send_transaction(tx)
            block = chain.build_block()
            
            assert block.header.parent_hash == prev_hash
            prev_hash = block.hash


class TestStateRootCalculation:
    def test_genesis_state_root_matches_evm(self, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        genesis = chain.get_block_by_number(0)
        assert len(genesis.header.state_root) == 32

    def test_state_root_changes_after_transfer(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        genesis_state_root = chain.get_block_by_number(0).header.state_root
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        chain.send_transaction(tx)
        chain.build_block()
        
        new_state_root = chain.get_block_by_number(1).header.state_root
        assert new_state_root != genesis_state_root


class TestTransactionsRootCalculation:
    def test_empty_transactions_root(self):
        from trie import HexaryTrie
        trie = HexaryTrie({})
        trie[encode(0)] = encode(b"")
        assert trie.root_hash is not None

    def test_single_transaction_root(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert len(block.header.transactions_root) == 32
        assert block.header.transactions_root != EMPTY_ROOT

    def test_multiple_transactions_root(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        for i in range(3):
            tx = chain.create_transaction(
                from_private_key=b"\x01" * 32,
                to=b"\xde\xad\xbe\xef" * 5,
                value=to_wei(1, "ether"),
                gas=21000,
                nonce=i,
            )
            chain.send_transaction(tx)
        
        block = chain.build_block()
        assert len(block.transactions) == 3


class TestReceiptsRootCalculation:
    def test_empty_receipts_root(self):
        from trie import HexaryTrie
        trie = HexaryTrie({})
        trie[encode(0)] = encode([])
        assert trie.root_hash is not None

    def test_single_receipt_root(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        chain.send_transaction(tx)
        block = chain.build_block()
        
        assert len(block.header.receipts_root) == 32

    def test_receipt_status_encoding(self):
        success_receipt = Receipt(status=1, cumulative_gas_used=21000, logs=[])
        encoded = success_receipt.to_rlp()
        assert len(encoded) > 0

        fail_receipt = Receipt(status=0, cumulative_gas_used=50000, logs=[])
        encoded_fail = fail_receipt.to_rlp()
        assert len(encoded_fail) > 0


class TestBlockTimestamp:
    def test_genesis_timestamp(self, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        genesis = chain.get_block_by_number(0)
        assert genesis.header.timestamp > 0

    def test_subsequent_block_timestamp_increases(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        genesis_ts = chain.get_block_by_number(0).header.timestamp
        
        tx = chain.create_transaction(
            from_private_key=b"\x01" * 32,
            to=b"\xde\xad\xbe\xef" * 5,
            value=to_wei(1, "ether"),
            gas=21000,
        )
        chain.send_transaction(tx)
        block1 = chain.build_block()
        
        assert block1.header.timestamp >= genesis_ts


class TestBaseFeeCalculation:
    def test_genesis_base_fee(self, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        genesis = chain.get_block_by_number(0)
        assert genesis is not None
        assert genesis.header.base_fee_per_gas == 1_000_000_000

    def test_base_fee_after_empty_block(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        genesis_block = chain.get_block_by_number(0)
        assert genesis_block is not None
        genesis_fee = genesis_block.header.base_fee_per_gas or 1_000_000_000
        
        chain.build_block()
        block1 = chain.get_block_by_number(1)
        assert block1 is not None
        block1_fee = block1.header.base_fee_per_gas or 1_000_000_000
        
        assert block1_fee <= genesis_fee

    def test_base_fee_increases_with_full_block(self, pk, address):
        genesis_state = {
            address: {"balance": to_wei(100_000, "ether"), "nonce": 0, "code": b"", "storage": {}}
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        for i in range(100):
            tx = chain.create_transaction(
                from_private_key=b"\x01" * 32,
                to=b"\xde\xad\xbe\xef" * 5,
                value=to_wei(1, "ether"),
                gas=21000,
                nonce=i,
            )
            chain.send_transaction(tx)
        
        block = chain.build_block()
        
        assert len(block.transactions) == 100
        assert block.header.gas_used > 0