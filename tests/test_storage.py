"""Tests for storage layer."""

import pytest
from ethclient.storage.memory_backend import MemoryBackend
from ethclient.common.types import (
    Account,
    Block,
    BlockHeader,
    Transaction,
    Receipt,
    Log,
    EMPTY_CODE_HASH,
    EMPTY_TRIE_ROOT,
    ZERO_HASH,
    ZERO_ADDRESS,
)
from ethclient.common.trie import EMPTY_ROOT
from ethclient.common.crypto import keccak256
from ethclient.common.config import Genesis, GenesisAlloc, ChainConfig


# ---------------------------------------------------------------------------
# Account CRUD
# ---------------------------------------------------------------------------

class TestAccountCRUD:
    def test_get_nonexistent(self):
        store = MemoryBackend()
        assert store.get_account(b"\x01" * 20) is None

    def test_put_get(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        acc = Account(nonce=1, balance=1000)
        store.put_account(addr, acc)
        got = store.get_account(addr)
        assert got is not None
        assert got.nonce == 1
        assert got.balance == 1000

    def test_delete(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.put_account(addr, Account(balance=100))
        store.delete_account(addr)
        assert store.get_account(addr) is None

    def test_account_exists(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        assert not store.account_exists(addr)
        store.put_account(addr, Account(balance=1))
        assert store.account_exists(addr)

    def test_empty_account_not_exists(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.put_account(addr, Account())  # all zeros
        assert not store.account_exists(addr)

    def test_balance_operations(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        assert store.get_balance(addr) == 0
        store.set_balance(addr, 500)
        assert store.get_balance(addr) == 500

    def test_nonce_operations(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        assert store.get_nonce(addr) == 0
        store.set_nonce(addr, 5)
        assert store.get_nonce(addr) == 5
        store.increment_nonce(addr)
        assert store.get_nonce(addr) == 6


# ---------------------------------------------------------------------------
# Code storage
# ---------------------------------------------------------------------------

class TestCodeStorage:
    def test_put_get_code(self):
        store = MemoryBackend()
        code = b"\x60\x00\x60\x00\xf3"  # PUSH 0 PUSH 0 RETURN
        code_hash = keccak256(code)
        store.put_code(code_hash, code)
        assert store.get_code(code_hash) == code

    def test_account_code(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.put_account(addr, Account())
        code = b"\x60\x42"
        store.set_account_code(addr, code)

        assert store.get_account_code(addr) == code
        acc = store.get_account(addr)
        assert acc.code_hash == keccak256(code)

    def test_empty_code(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        assert store.get_account_code(addr) == b""


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

class TestStorageSlots:
    def test_get_default(self):
        store = MemoryBackend()
        assert store.get_storage(b"\x01" * 20, 0) == 0

    def test_put_get(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.put_storage(addr, 42, 0xDEAD)
        assert store.get_storage(addr, 42) == 0xDEAD

    def test_put_zero_deletes(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.put_storage(addr, 1, 100)
        store.put_storage(addr, 1, 0)
        assert store.get_storage(addr, 1) == 0

    def test_original_storage(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.put_storage(addr, 1, 100)
        store.commit_original_storage()
        store.put_storage(addr, 1, 200)
        assert store.get_original_storage(addr, 1) == 100
        assert store.get_storage(addr, 1) == 200

    def test_delete_account_clears_storage(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.put_account(addr, Account(balance=100))
        store.put_storage(addr, 1, 42)
        store.put_storage(addr, 2, 43)
        store.delete_account(addr)
        assert store.get_storage(addr, 1) == 0
        assert store.get_storage(addr, 2) == 0


# ---------------------------------------------------------------------------
# Block storage
# ---------------------------------------------------------------------------

class TestBlockStorage:
    def _make_header(self, number: int = 0) -> BlockHeader:
        return BlockHeader(
            number=number,
            timestamp=1000 + number,
            gas_limit=30_000_000,
        )

    def test_put_get_header(self):
        store = MemoryBackend()
        header = self._make_header(1)
        store.put_block_header(header)
        block_hash = header.block_hash()
        got = store.get_block_header(block_hash)
        assert got is not None
        assert got.number == 1

    def test_canonical_chain(self):
        store = MemoryBackend()
        header = self._make_header(1)
        store.put_block_header(header)
        block_hash = header.block_hash()
        store.put_canonical_hash(1, block_hash)

        assert store.get_canonical_hash(1) == block_hash
        got = store.get_block_header_by_number(1)
        assert got is not None
        assert got.number == 1

    def test_latest_block_number(self):
        store = MemoryBackend()
        assert store.get_latest_block_number() == 0

        for i in range(5):
            header = self._make_header(i)
            store.put_block_header(header)
            store.put_canonical_hash(i, header.block_hash())

        assert store.get_latest_block_number() == 4

    def test_put_get_block(self):
        store = MemoryBackend()
        header = self._make_header(1)
        block = Block(header=header)
        store.put_block(block)

        got = store.get_block(header.block_hash())
        assert got is not None
        assert got.header.number == 1

    def test_block_by_number(self):
        store = MemoryBackend()
        header = self._make_header(5)
        block = Block(header=header)
        store.put_block(block)
        store.put_canonical_hash(5, header.block_hash())

        got = store.get_block_by_number(5)
        assert got is not None
        assert got.header.number == 5


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------

class TestReceipts:
    def test_put_get_receipts(self):
        store = MemoryBackend()
        block_hash = b"\xAB" * 32
        receipts = [
            Receipt(succeeded=True, cumulative_gas_used=21000),
            Receipt(succeeded=True, cumulative_gas_used=42000),
        ]
        store.put_receipts(block_hash, receipts)
        got = store.get_receipts(block_hash)
        assert got is not None
        assert len(got) == 2
        assert got[0].cumulative_gas_used == 21000

    def test_nonexistent(self):
        store = MemoryBackend()
        assert store.get_receipts(b"\x00" * 32) is None


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

class TestSnapshots:
    def test_snapshot_rollback(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.set_balance(addr, 1000)

        snap = store.snapshot()
        store.set_balance(addr, 2000)
        assert store.get_balance(addr) == 2000

        store.rollback(snap)
        assert store.get_balance(addr) == 1000

    def test_snapshot_commit(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.set_balance(addr, 1000)

        snap = store.snapshot()
        store.set_balance(addr, 2000)
        store.commit(snap)
        assert store.get_balance(addr) == 2000

    def test_nested_snapshots(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.set_balance(addr, 100)

        snap1 = store.snapshot()
        store.set_balance(addr, 200)

        snap2 = store.snapshot()
        store.set_balance(addr, 300)

        store.rollback(snap2)
        assert store.get_balance(addr) == 200

        store.rollback(snap1)
        assert store.get_balance(addr) == 100

    def test_storage_rollback(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.put_storage(addr, 1, 100)

        snap = store.snapshot()
        store.put_storage(addr, 1, 200)
        assert store.get_storage(addr, 1) == 200

        store.rollback(snap)
        assert store.get_storage(addr, 1) == 100


# ---------------------------------------------------------------------------
# State root computation
# ---------------------------------------------------------------------------

class TestStateRoot:
    def test_empty_state(self):
        store = MemoryBackend()
        root = store.compute_state_root()
        assert root == EMPTY_ROOT

    def test_single_account(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.put_account(addr, Account(balance=1000))
        root = store.compute_state_root()
        assert root != EMPTY_ROOT
        assert len(root) == 32

    def test_deterministic(self):
        """Same state should always produce the same root."""
        store1 = MemoryBackend()
        store2 = MemoryBackend()

        addr1 = b"\x01" * 20
        addr2 = b"\x02" * 20

        # Insert in different order
        store1.put_account(addr1, Account(balance=100))
        store1.put_account(addr2, Account(balance=200))

        store2.put_account(addr2, Account(balance=200))
        store2.put_account(addr1, Account(balance=100))

        assert store1.compute_state_root() == store2.compute_state_root()

    def test_with_storage(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.put_account(addr, Account(balance=1000))
        store.put_storage(addr, 0, 42)

        root1 = store.compute_state_root()

        store.put_storage(addr, 0, 43)
        root2 = store.compute_state_root()

        assert root1 != root2

    def test_with_code(self):
        store = MemoryBackend()
        addr = b"\x01" * 20
        store.put_account(addr, Account())
        store.set_account_code(addr, b"\x60\x00")

        root = store.compute_state_root()
        assert root != EMPTY_ROOT


# ---------------------------------------------------------------------------
# Genesis initialization
# ---------------------------------------------------------------------------

class TestGenesisInit:
    def test_simple_genesis(self):
        store = MemoryBackend()
        genesis = Genesis(
            config=ChainConfig(chain_id=1337),
            gas_limit=30_000_000,
            alloc=[
                GenesisAlloc(
                    address=b"\x01" * 20,
                    balance=10**18,
                ),
                GenesisAlloc(
                    address=b"\x02" * 20,
                    balance=5 * 10**18,
                ),
            ],
        )

        block_hash = store.init_from_genesis(genesis)
        assert len(block_hash) == 32

        # Check accounts
        assert store.get_balance(b"\x01" * 20) == 10**18
        assert store.get_balance(b"\x02" * 20) == 5 * 10**18

        # Check genesis block
        block = store.get_block(block_hash)
        assert block is not None
        assert block.header.number == 0
        assert block.header.state_root != ZERO_HASH

        # Check canonical chain
        assert store.get_canonical_hash(0) == block_hash
        assert store.get_latest_block_number() == 0

    def test_genesis_with_code(self):
        store = MemoryBackend()
        code = b"\x60\x00\x60\x00\xf3"
        genesis = Genesis(
            config=ChainConfig(chain_id=1),
            gas_limit=10_000_000,
            alloc=[
                GenesisAlloc(
                    address=b"\xAA" * 20,
                    balance=0,
                    code=code,
                ),
            ],
        )
        store.init_from_genesis(genesis)
        assert store.get_account_code(b"\xAA" * 20) == code
