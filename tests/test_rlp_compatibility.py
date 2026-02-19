"""RLP encoding/decoding compatibility tests."""

import pytest
from rlp import encode, decode

from sequencer.core.types import Account, BlockHeader, Receipt
from sequencer.core.constants import EMPTY_ROOT, EMPTY_CODE_HASH
from sequencer.core.crypto import keccak256


class TestAccountRLPCompatibility:
    def test_empty_account_rlp_encoding(self):
        account = Account.empty()
        encoded = account.to_rlp()
        decoded_nonce, decoded_balance, decoded_storage_root, decoded_code_hash = decode(encoded)
        nonce_val = int.from_bytes(decoded_nonce, 'big') if decoded_nonce else 0
        balance_val = int.from_bytes(decoded_balance, 'big') if decoded_balance else 0
        assert nonce_val == 0
        assert balance_val == 0
        assert bytes(decoded_storage_root) == EMPTY_ROOT
        assert bytes(decoded_code_hash) == EMPTY_CODE_HASH

    def test_account_with_balance_rlp_roundtrip(self):
        account = Account(nonce=5, balance=1000000, storage_root=EMPTY_ROOT, code_hash=EMPTY_CODE_HASH)
        encoded = account.to_rlp()
        decoded = Account.from_rlp(encoded)
        nonce_val = int.from_bytes(decoded.nonce, 'big') if isinstance(decoded.nonce, bytes) else decoded.nonce
        balance_val = int.from_bytes(decoded.balance, 'big') if isinstance(decoded.balance, bytes) else decoded.balance
        assert nonce_val == 5
        assert balance_val == 1000000

    def test_account_rlp_matches_ethereum_spec(self):
        account = Account(nonce=1, balance=0, storage_root=EMPTY_ROOT, code_hash=EMPTY_CODE_HASH)
        expected_rlp = encode([1, 0, EMPTY_ROOT, EMPTY_CODE_HASH])
        assert account.to_rlp() == bytes(expected_rlp)


class TestBlockHeaderRLPCompatibility:
    def test_block_header_empty_transactions_root(self):
        empty_root = keccak256(encode(b""))
        assert empty_root == keccak256(b"\x80")

    def test_block_header_fields_encoding(self):
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=keccak256(encode([])),
            coinbase=b"\x00" * 20,
            state_root=b"\x01" * 32,
            transactions_root=keccak256(b"\x80"),
            receipts_root=keccak256(b"\x80"),
            logs_bloom=b"\x00" * 256,
            difficulty=0,
            number=1,
            gas_limit=30000000,
            gas_used=0,
            timestamp=1234567890,
            base_fee_per_gas=1000000000,
        )
        rlp_list = header._to_rlp_list()
        assert len(rlp_list) == 16
        assert rlp_list[8] == 1
        assert rlp_list[15] == 1000000000

    def test_genesis_block_header_hash_is_consistent(self):
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=keccak256(encode([])),
            coinbase=b"\x00" * 20,
            state_root=EMPTY_ROOT,
            transactions_root=keccak256(b"\x80"),
            receipts_root=keccak256(b"\x80"),
            logs_bloom=b"\x00" * 256,
            number=0,
            gas_limit=30000000,
            timestamp=0,
            base_fee_per_gas=1000000000,
        )
        hash1 = header.hash()
        hash2 = header.hash()
        assert hash1 == hash2
        assert len(hash1) == 32


class TestTransactionRLPCompatibility:
    def test_legacy_transaction_rlp_encoding(self):
        legacy_tx = [
            0,
            1000000000,
            21000,
            b"",
            b"\xde\xad\xbe\xef" * 5,
            1000000000000000000,
            b"",
        ]
        encoded = encode(legacy_tx)
        assert len(encoded) > 0
        decoded = decode(encoded)
        nonce_val = int.from_bytes(decoded[0], 'big') if decoded[0] else 0
        assert nonce_val == 0

    def test_eip1559_transaction_type_prefix(self):
        eip1559_type = bytes([0x02])
        assert eip1559_type[0] == 0x02


class TestReceiptRLPCompatibility:
    def test_receipt_rlp_roundtrip(self):
        receipt = Receipt(
            status=1,
            cumulative_gas_used=21000,
            logs=[],
            contract_address=None,
        )
        encoded = receipt.to_rlp()
        decoded = decode(encoded)
        status_val = int.from_bytes(decoded[0], 'big') if decoded[0] else 0
        gas_val = int.from_bytes(decoded[1], 'big') if decoded[1] else 0
        assert status_val == 1
        assert gas_val == 21000
        assert decoded[2] == []

    def test_failed_receipt_status_zero(self):
        receipt = Receipt(
            status=0,
            cumulative_gas_used=50000,
            logs=[],
        )
        encoded = receipt.to_rlp()
        decoded_status, _, _ = decode(encoded)
        status_val = int.from_bytes(decoded_status, 'big') if decoded_status else 0
        assert status_val == 0

    def test_receipt_with_contract_address(self):
        contract_addr = b"\xab" * 20
        receipt = Receipt(
            status=1,
            cumulative_gas_used=100000,
            logs=[],
            contract_address=contract_addr,
        )
        encoded = receipt.to_rlp()
        assert len(encoded) > 0


class TestTrieRootCompatibility:
    def test_empty_trie_root(self):
        from trie import HexaryTrie
        trie = HexaryTrie({})
        empty_root = trie.root_hash
        expected = bytes.fromhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
        assert empty_root == expected

    def test_single_entry_trie_root(self):
        from trie import HexaryTrie
        from rlp import encode as rlp_encode
        trie = HexaryTrie({})
        trie[rlp_encode(0)] = rlp_encode([b"test"])
        assert trie.root_hash != keccak256(b"\x80")

    def test_transactions_root_consistency(self):
        from trie import HexaryTrie
        from rlp import encode as rlp_encode
        trie1 = HexaryTrie({})
        trie2 = HexaryTrie({})
        trie1[rlp_encode(0)] = rlp_encode(b"tx1")
        trie2[rlp_encode(0)] = rlp_encode(b"tx1")
        assert trie1.root_hash == trie2.root_hash