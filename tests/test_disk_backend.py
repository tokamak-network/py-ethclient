"""Tests specific to DiskBackend — persistence, flush, overlay isolation."""

import pytest
from ethclient.storage.memory_backend import MemoryBackend
from ethclient.storage.disk_backend import DiskBackend
from ethclient.common.types import (
    Account,
    Block,
    BlockHeader,
    Receipt,
    Transaction,
    ZERO_HASH,
)
from ethclient.common.trie import EMPTY_ROOT
from ethclient.common.crypto import keccak256
from ethclient.common.config import Genesis, GenesisAlloc, ChainConfig


@pytest.fixture
def disk_store(tmp_path):
    backend = DiskBackend(tmp_path)
    yield backend
    backend.close()


# ---------------------------------------------------------------------------
# Persistence: write → flush → close → reopen → verify
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_account_persists(self, tmp_path):
        addr = b"\x01" * 20
        store = DiskBackend(tmp_path)
        store.put_account(addr, Account(nonce=5, balance=1000))
        store.flush()
        store.close()

        store2 = DiskBackend(tmp_path)
        acc = store2.get_account(addr)
        assert acc is not None
        assert acc.nonce == 5
        assert acc.balance == 1000
        store2.close()

    def test_code_persists(self, tmp_path):
        code = b"\x60\x42\x60\x00\x52"
        code_hash = keccak256(code)

        store = DiskBackend(tmp_path)
        store.put_code(code_hash, code)
        store.flush()
        store.close()

        store2 = DiskBackend(tmp_path)
        assert store2.get_code(code_hash) == code
        store2.close()

    def test_storage_persists(self, tmp_path):
        addr = b"\x01" * 20
        store = DiskBackend(tmp_path)
        store.put_storage(addr, 42, 0xBEEF)
        store.flush()
        store.close()

        store2 = DiskBackend(tmp_path)
        assert store2.get_storage(addr, 42) == 0xBEEF
        store2.close()

    def test_block_data_persists(self, tmp_path):
        header = BlockHeader(number=10, timestamp=1234, gas_limit=30_000_000)
        block = Block(header=header)

        store = DiskBackend(tmp_path)
        store.put_block(block)
        store.put_canonical_hash(10, header.block_hash())
        store.close()

        store2 = DiskBackend(tmp_path)
        got = store2.get_block(header.block_hash())
        assert got is not None
        assert got.header.number == 10
        assert store2.get_canonical_hash(10) == header.block_hash()
        assert store2.get_latest_block_number() == 10
        store2.close()

    def test_latest_block_meta_visible_across_instances(self, tmp_path):
        writer = DiskBackend(tmp_path)
        reader = DiskBackend(tmp_path)
        header = BlockHeader(number=12, timestamp=1234, gas_limit=30_000_000)

        writer.put_block_header(header)
        writer.put_canonical_hash(12, header.block_hash())

        # Reader should observe meta update even without reopening.
        assert reader.get_latest_block_number() == 12
        writer.close()
        reader.close()

    def test_receipts_persist(self, tmp_path):
        block_hash = b"\xAB" * 32
        receipts = [
            Receipt(succeeded=True, cumulative_gas_used=21000),
        ]
        store = DiskBackend(tmp_path)
        store.put_receipts(block_hash, receipts)
        store.close()

        store2 = DiskBackend(tmp_path)
        got = store2.get_receipts(block_hash)
        assert got is not None
        assert len(got) == 1
        assert got[0].cumulative_gas_used == 21000
        store2.close()

    def test_block_batch_commit_and_head_snapshot(self, tmp_path):
        store = DiskBackend(tmp_path)
        h1 = BlockHeader(number=1, timestamp=1, gas_limit=30_000_000)
        h2 = BlockHeader(number=2, parent_hash=h1.block_hash(), timestamp=2, gas_limit=30_000_000)

        head_num, head_hash = store.get_chain_head_snapshot()
        assert head_num == 0
        assert head_hash is None

        last = store.put_block_batch(
            [
                (h1, ([], [], None)),
                (h2, ([], [], None)),
            ]
        )
        assert last == 2
        assert store.get_latest_block_number() == 2
        assert store.get_canonical_hash(1) == h1.block_hash()
        assert store.get_canonical_hash(2) == h2.block_hash()
        store.close()

    def test_block_batch_accepts_raw_rlp_body_items(self, tmp_path):
        store = DiskBackend(tmp_path)
        h1 = BlockHeader(number=1, timestamp=1, gas_limit=30_000_000)

        # Raw RLP tx item and empty ommers list are valid for mp pipeline bodies.
        raw_tx = Transaction(nonce=1, gas_limit=21_000, gas_price=1).encode_rlp()
        store.put_block_batch([(h1, ([raw_tx], [], None))])

        body = store.get_block_body(h1.block_hash())
        assert body is not None
        assert store.get_latest_block_number() == 1
        store.close()

    def test_unflushed_state_lost_on_reopen(self, tmp_path):
        """Overlay data not flushed should be lost after close/reopen."""
        addr = b"\x01" * 20
        store = DiskBackend(tmp_path)
        store.put_account(addr, Account(balance=999))
        # No flush!
        store.close()

        store2 = DiskBackend(tmp_path)
        assert store2.get_account(addr) is None
        store2.close()


# ---------------------------------------------------------------------------
# Overlay isolation
# ---------------------------------------------------------------------------

class TestOverlay:
    def test_overlay_reads_before_flush(self, disk_store):
        """Writes to overlay should be readable before flush."""
        addr = b"\x01" * 20
        disk_store.put_account(addr, Account(balance=500))
        acc = disk_store.get_account(addr)
        assert acc is not None
        assert acc.balance == 500

    def test_overlay_overrides_disk(self, tmp_path):
        """Overlay should override disk values."""
        addr = b"\x01" * 20

        # Write to disk
        store = DiskBackend(tmp_path)
        store.put_account(addr, Account(balance=100))
        store.flush()

        # Override in overlay
        store.put_account(addr, Account(balance=999))
        assert store.get_account(addr).balance == 999
        store.close()

    def test_delete_in_overlay(self, tmp_path):
        addr = b"\x01" * 20

        store = DiskBackend(tmp_path)
        store.put_account(addr, Account(balance=100))
        store.flush()

        store.delete_account(addr)
        assert store.get_account(addr) is None
        store.close()

    def test_flush_clears_overlay(self, tmp_path):
        """After flush, overlay should be empty and reads come from disk."""
        addr = b"\x01" * 20
        store = DiskBackend(tmp_path)
        store.put_account(addr, Account(balance=100))
        store.flush()

        # overlay should be empty now
        assert len(store._overlay.accounts) == 0

        # But read still works from disk
        assert store.get_account(addr).balance == 100
        store.close()


# ---------------------------------------------------------------------------
# Flush atomicity
# ---------------------------------------------------------------------------

class TestFlush:
    def test_batch_flush(self, tmp_path):
        """Multiple state changes should be flushed atomically."""
        store = DiskBackend(tmp_path)
        for i in range(10):
            addr = bytes([i]) * 20
            store.put_account(addr, Account(balance=i * 100))
            store.put_storage(addr, 0, i * 10)

        store.flush()
        store.close()

        store2 = DiskBackend(tmp_path)
        for i in range(10):
            addr = bytes([i]) * 20
            acc = store2.get_account(addr)
            assert acc is not None
            assert acc.balance == i * 100
            assert store2.get_storage(addr, 0) == i * 10
        store2.close()

    def test_flush_deletes(self, tmp_path):
        """Flush should persist deletions."""
        addr = b"\x01" * 20
        store = DiskBackend(tmp_path)
        store.put_account(addr, Account(balance=100))
        store.put_storage(addr, 1, 42)
        store.flush()

        store.delete_account(addr)
        store.put_storage(addr, 1, 0)
        store.flush()
        store.close()

        store2 = DiskBackend(tmp_path)
        assert store2.get_account(addr) is None
        assert store2.get_storage(addr, 1) == 0
        store2.close()


# ---------------------------------------------------------------------------
# State root consistency: MemoryBackend vs DiskBackend
# ---------------------------------------------------------------------------

class TestStateRootConsistency:
    def test_same_root_simple(self, tmp_path):
        """Identical state should produce identical root across backends."""
        mem = MemoryBackend()
        disk = DiskBackend(tmp_path)

        addr1 = b"\x01" * 20
        addr2 = b"\x02" * 20

        for store in [mem, disk]:
            store.put_account(addr1, Account(nonce=1, balance=10**18))
            store.put_account(addr2, Account(nonce=0, balance=5 * 10**18))

        assert mem.compute_state_root() == disk.compute_state_root()
        disk.close()

    def test_same_root_with_storage(self, tmp_path):
        mem = MemoryBackend()
        disk = DiskBackend(tmp_path)

        addr = b"\x01" * 20
        for store in [mem, disk]:
            store.put_account(addr, Account(balance=1000))
            store.put_storage(addr, 0, 42)
            store.put_storage(addr, 1, 0xDEADBEEF)
            store.put_storage(addr, 100, 999)

        assert mem.compute_state_root() == disk.compute_state_root()
        disk.close()

    def test_same_root_with_code(self, tmp_path):
        mem = MemoryBackend()
        disk = DiskBackend(tmp_path)

        addr = b"\x01" * 20
        code = b"\x60\x42\x60\x00\x52\x60\x20\x60\x00\xf3"

        for store in [mem, disk]:
            store.put_account(addr, Account())
            store.set_account_code(addr, code)

        assert mem.compute_state_root() == disk.compute_state_root()
        disk.close()

    def test_same_root_after_flush(self, tmp_path):
        """State root should be identical before and after flush."""
        disk = DiskBackend(tmp_path)

        addr = b"\x01" * 20
        disk.put_account(addr, Account(balance=1000))
        disk.put_storage(addr, 0, 42)

        root_before = disk.compute_state_root()
        disk.flush()
        root_after = disk.compute_state_root()

        assert root_before == root_after
        disk.close()

    def test_mixed_disk_overlay_root(self, tmp_path):
        """Root should be correct with some data on disk and some in overlay."""
        mem = MemoryBackend()
        disk = DiskBackend(tmp_path)

        addr1 = b"\x01" * 20
        addr2 = b"\x02" * 20

        # Put addr1 on disk via flush
        disk.put_account(addr1, Account(balance=100))
        disk.put_storage(addr1, 0, 42)
        disk.flush()

        # Put addr2 in overlay only
        disk.put_account(addr2, Account(balance=200))
        disk.put_storage(addr2, 1, 99)

        # Memory backend with same state
        mem.put_account(addr1, Account(balance=100))
        mem.put_storage(addr1, 0, 42)
        mem.put_account(addr2, Account(balance=200))
        mem.put_storage(addr2, 1, 99)

        assert mem.compute_state_root() == disk.compute_state_root()
        disk.close()


# ---------------------------------------------------------------------------
# Snapshot / rollback with disk
# ---------------------------------------------------------------------------

class TestDiskSnapshots:
    def test_snapshot_rollback_overlay_only(self, disk_store):
        """Rollback should restore overlay state."""
        addr = b"\x01" * 20
        disk_store.put_account(addr, Account(balance=100))

        snap = disk_store.snapshot()
        disk_store.put_account(addr, Account(balance=999))
        assert disk_store.get_account(addr).balance == 999

        disk_store.rollback(snap)
        assert disk_store.get_account(addr).balance == 100

    def test_nested_snapshot_rollback(self, disk_store):
        addr = b"\x01" * 20
        disk_store.set_balance(addr, 100)

        snap1 = disk_store.snapshot()
        disk_store.set_balance(addr, 200)

        snap2 = disk_store.snapshot()
        disk_store.set_balance(addr, 300)

        disk_store.rollback(snap2)
        assert disk_store.get_balance(addr) == 200

        disk_store.rollback(snap1)
        assert disk_store.get_balance(addr) == 100

    def test_snapshot_with_disk_data(self, tmp_path):
        """Snapshot/rollback should work with data already flushed to disk."""
        addr = b"\x01" * 20
        store = DiskBackend(tmp_path)
        store.put_account(addr, Account(balance=100))
        store.flush()

        # Now modify in overlay
        snap = store.snapshot()
        store.set_balance(addr, 999)
        assert store.get_balance(addr) == 999

        store.rollback(snap)
        # Should read from disk since overlay was restored
        assert store.get_balance(addr) == 100
        store.close()

    def test_storage_rollback(self, disk_store):
        addr = b"\x01" * 20
        disk_store.put_storage(addr, 1, 100)

        snap = disk_store.snapshot()
        disk_store.put_storage(addr, 1, 200)
        assert disk_store.get_storage(addr, 1) == 200

        disk_store.rollback(snap)
        assert disk_store.get_storage(addr, 1) == 100


# ---------------------------------------------------------------------------
# Genesis initialization with DiskBackend
# ---------------------------------------------------------------------------

class TestDiskGenesis:
    def test_genesis_init(self, tmp_path):
        store = DiskBackend(tmp_path)
        genesis = Genesis(
            config=ChainConfig(chain_id=1337),
            gas_limit=30_000_000,
            alloc=[
                GenesisAlloc(
                    address=b"\x01" * 20,
                    balance=10**18,
                ),
            ],
        )
        block_hash = store.init_from_genesis(genesis)
        assert len(block_hash) == 32

        # Verify state
        assert store.get_balance(b"\x01" * 20) == 10**18

        # Verify block stored (directly in LMDB)
        block = store.get_block(block_hash)
        assert block is not None
        assert block.header.number == 0

        # Flush state and reopen
        store.flush()
        store.close()

        store2 = DiskBackend(tmp_path)
        assert store2.get_balance(b"\x01" * 20) == 10**18
        assert store2.get_block(block_hash) is not None
        store2.close()

    def test_genesis_root_matches_memory(self, tmp_path):
        """Genesis state root should be identical across backends."""
        genesis = Genesis(
            config=ChainConfig(chain_id=1337),
            gas_limit=30_000_000,
            alloc=[
                GenesisAlloc(address=b"\x01" * 20, balance=10**18),
                GenesisAlloc(address=b"\x02" * 20, balance=5 * 10**18),
            ],
        )

        mem = MemoryBackend()
        disk = DiskBackend(tmp_path)

        hash_mem = mem.init_from_genesis(genesis)
        hash_disk = disk.init_from_genesis(genesis)

        # Genesis block hash should be identical
        assert hash_mem == hash_disk
        disk.close()


# ---------------------------------------------------------------------------
# Iterator tests
# ---------------------------------------------------------------------------

class TestIterators:
    def test_iter_accounts_overlay_only(self, disk_store):
        addr1 = b"\x01" * 20
        addr2 = b"\x02" * 20
        disk_store.put_account(addr1, Account(balance=100))
        disk_store.put_account(addr2, Account(balance=200))

        accounts = dict(disk_store.iter_accounts())
        assert len(accounts) == 2
        assert accounts[addr1].balance == 100
        assert accounts[addr2].balance == 200

    def test_iter_accounts_mixed(self, tmp_path):
        addr1 = b"\x01" * 20
        addr2 = b"\x02" * 20
        store = DiskBackend(tmp_path)

        # Put addr1 on disk
        store.put_account(addr1, Account(balance=100))
        store.flush()

        # Put addr2 in overlay
        store.put_account(addr2, Account(balance=200))

        accounts = dict(store.iter_accounts())
        assert len(accounts) == 2
        assert accounts[addr1].balance == 100
        assert accounts[addr2].balance == 200
        store.close()

    def test_iter_storage(self, disk_store):
        addr = b"\x01" * 20
        disk_store.put_storage(addr, 0, 42)
        disk_store.put_storage(addr, 1, 99)

        storage = dict(disk_store.iter_storage())
        assert len(storage) == 2
        assert storage[(addr, 0)] == 42
        assert storage[(addr, 1)] == 99


# ---------------------------------------------------------------------------
# Snap sync data
# ---------------------------------------------------------------------------

class TestSnapSync:
    def test_snap_progress_persists(self, tmp_path):
        store = DiskBackend(tmp_path)
        progress = {"phase": "accounts", "cursor": "0x1234"}
        store.put_snap_progress(progress)
        store.close()

        store2 = DiskBackend(tmp_path)
        got = store2.get_snap_progress()
        assert got == progress
        store2.close()

    def test_snap_accounts(self, tmp_path):
        store = DiskBackend(tmp_path)
        acct_hash = b"\xAA" * 32
        acct_rlp = b"\xC0\x80\x80"
        store.put_snap_account(acct_hash, acct_rlp)
        store.close()

        # Verify it's in LMDB
        store2 = DiskBackend(tmp_path)
        with store2._env.begin(db=store2._dbs[b"snap_accounts"]) as txn:
            data = txn.get(acct_hash)
            assert bytes(data) == acct_rlp
        store2.close()
