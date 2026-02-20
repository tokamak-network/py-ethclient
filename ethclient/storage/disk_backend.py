"""
Disk-based storage backend using LMDB.

Provides persistent storage with an in-memory overlay for snapshot/rollback.
Block data (headers, bodies, receipts) is written directly to LMDB.
State data (accounts, code, storage) goes through the overlay and is
flushed to LMDB via flush().
"""

from __future__ import annotations

import copy
import json
import struct
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional, Sequence

import lmdb

from ethclient.common.types import (
    Account,
    Block,
    BlockHeader,
    Transaction,
    Receipt,
    Withdrawal,
    EMPTY_CODE_HASH,
    EMPTY_TRIE_ROOT,
)
from ethclient.common.trie import Trie, EMPTY_ROOT
from ethclient.common import rlp
from ethclient.storage.store import Store


# Sentinel for deleted entries in overlay
class _Sentinel(Enum):
    DELETED = "DELETED"


_DELETED = _Sentinel.DELETED

# LMDB named databases
_DB_NAMES = [
    b"accounts",
    b"code",
    b"storage",
    b"original_storage",
    b"headers",
    b"header_numbers",
    b"bodies",
    b"receipts",
    b"tx_index",
    b"canonical",
    b"snap_accounts",
    b"snap_storage",
    b"meta",
]

# 1 GB default map size — LMDB grows sparse files
_DEFAULT_MAP_SIZE = 1 * 1024 * 1024 * 1024


def _num_key(n: int) -> bytes:
    """Encode a block number as 8-byte big-endian."""
    return struct.pack(">Q", n)


def _storage_key(address: bytes, slot: int) -> bytes:
    """Encode (address, slot) as 52-byte key: address(20) + slot(32)."""
    return address + slot.to_bytes(32, "big")


def _decode_storage_key(key: bytes) -> tuple[bytes, int]:
    """Decode 52-byte storage key into (address, slot)."""
    return key[:20], int.from_bytes(key[20:], "big")


def _encode_storage_value(val: int) -> bytes:
    """Encode a storage value as minimal big-endian bytes."""
    if val == 0:
        return b"\x00"
    return val.to_bytes((val.bit_length() + 7) // 8, "big")


def _decode_storage_value(data: bytes) -> int:
    """Decode a storage value from big-endian bytes."""
    return int.from_bytes(data, "big")


class _StateOverlay:
    """In-memory write buffer for state changes."""

    __slots__ = ("accounts", "code", "storage", "original_storage")

    def __init__(self) -> None:
        # address -> Account | _DELETED
        self.accounts: dict[bytes, Account | _Sentinel] = {}
        # code_hash -> bytes
        self.code: dict[bytes, bytes] = {}
        # (address, slot) -> int | _DELETED
        self.storage: dict[tuple[bytes, int], int | _Sentinel] = {}
        # (address, slot) -> int | _DELETED
        self.original_storage: dict[tuple[bytes, int], int | _Sentinel] = {}

    def copy(self) -> _StateOverlay:
        new = _StateOverlay()
        new.accounts = {
            k: (copy.copy(v) if isinstance(v, Account) else v)
            for k, v in self.accounts.items()
        }
        new.code = dict(self.code)
        new.storage = dict(self.storage)
        new.original_storage = dict(self.original_storage)
        return new


class DiskBackend(Store):
    """LMDB-backed persistent storage with in-memory overlay."""

    def __init__(self, data_dir: Path, map_size: int = _DEFAULT_MAP_SIZE) -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._env = lmdb.open(
            str(self._data_dir / "chaindata"),
            max_dbs=len(_DB_NAMES),
            map_size=map_size,
        )

        # Open named databases
        self._dbs: dict[bytes, lmdb._Database] = {}
        for name in _DB_NAMES:
            self._dbs[name] = self._env.open_db(name)

        # In-memory overlay for state
        self._overlay = _StateOverlay()
        self._snapshots: list[_StateOverlay] = []

        # Cache latest block number from meta
        self._latest_block = self._load_meta_int("latest_block", -1)

    def close(self) -> None:
        """Close the LMDB environment."""
        self._env.close()

    # -----------------------------------------------------------------
    # Meta helpers
    # -----------------------------------------------------------------

    def _load_meta_int(self, key: str, default: int) -> int:
        with self._env.begin(db=self._dbs[b"meta"]) as txn:
            val = txn.get(key.encode())
            if val is None:
                return default
            return int.from_bytes(val, "big", signed=True)

    def _save_meta_int(self, key: str, value: int) -> None:
        with self._env.begin(db=self._dbs[b"meta"], write=True) as txn:
            # Use 8 bytes signed for block numbers (supports -1)
            txn.put(key.encode(), value.to_bytes(8, "big", signed=True))

    # -----------------------------------------------------------------
    # Account state (overlay → LMDB)
    # -----------------------------------------------------------------

    def get_account(self, address: bytes) -> Optional[Account]:
        # Check overlay first
        val = self._overlay.accounts.get(address)
        if val is _DELETED:
            return None
        if isinstance(val, Account):
            return val

        # Fall through to LMDB
        with self._env.begin(db=self._dbs[b"accounts"]) as txn:
            data = txn.get(address)
            if data is None:
                return None
            return Account.decode_rlp(bytes(data))

    def put_account(self, address: bytes, account: Account) -> None:
        self._overlay.accounts[address] = account

    def delete_account(self, address: bytes) -> None:
        self._overlay.accounts[address] = _DELETED
        # Mark all storage for this address as deleted
        # First, overlay storage keys
        for key in list(self._overlay.storage.keys()):
            if key[0] == address:
                self._overlay.storage[key] = _DELETED
        # Then, scan LMDB storage for this address and mark deleted
        prefix = address
        with self._env.begin(db=self._dbs[b"storage"]) as txn:
            cursor = txn.cursor()
            if cursor.set_range(prefix):
                for key, _ in cursor:
                    key = bytes(key)
                    if not key.startswith(prefix):
                        break
                    addr, slot = _decode_storage_key(key)
                    self._overlay.storage[(addr, slot)] = _DELETED

    def account_exists(self, address: bytes) -> bool:
        acc = self.get_account(address)
        if acc is None:
            return False
        return not acc.is_empty()

    # -----------------------------------------------------------------
    # Code (overlay → LMDB)
    # -----------------------------------------------------------------

    def get_code(self, code_hash: bytes) -> Optional[bytes]:
        val = self._overlay.code.get(code_hash)
        if val is not None:
            return val
        with self._env.begin(db=self._dbs[b"code"]) as txn:
            data = txn.get(code_hash)
            return bytes(data) if data is not None else None

    def put_code(self, code_hash: bytes, code: bytes) -> None:
        self._overlay.code[code_hash] = code

    def get_account_code(self, address: bytes) -> bytes:
        acc = self.get_account(address)
        if acc is None or acc.code_hash == EMPTY_CODE_HASH:
            return b""
        return self.get_code(acc.code_hash) or b""

    # -----------------------------------------------------------------
    # Storage (overlay → LMDB)
    # -----------------------------------------------------------------

    def get_storage(self, address: bytes, key: int) -> int:
        val = self._overlay.storage.get((address, key))
        if val is _DELETED:
            return 0
        if isinstance(val, int):
            return val

        with self._env.begin(db=self._dbs[b"storage"]) as txn:
            data = txn.get(_storage_key(address, key))
            if data is None:
                return 0
            return _decode_storage_value(bytes(data))

    def put_storage(self, address: bytes, key: int, value: int) -> None:
        if value == 0:
            self._overlay.storage[(address, key)] = _DELETED
        else:
            self._overlay.storage[(address, key)] = value

    def get_original_storage(self, address: bytes, key: int) -> int:
        val = self._overlay.original_storage.get((address, key))
        if val is _DELETED:
            return 0
        if isinstance(val, int):
            return val

        with self._env.begin(db=self._dbs[b"original_storage"]) as txn:
            data = txn.get(_storage_key(address, key))
            if data is None:
                return 0
            return _decode_storage_value(bytes(data))

    def commit_original_storage(self) -> None:
        """Snapshot current storage as 'original' for SSTORE gas calc.

        Merges overlay storage into original_storage overlay, and for
        any disk-only storage not overridden in the overlay, we leave
        them to be read from the original_storage LMDB db on demand.
        """
        # Copy current storage overlay to original_storage overlay
        self._overlay.original_storage = dict(self._overlay.storage)

    # -----------------------------------------------------------------
    # Iterators
    # -----------------------------------------------------------------

    def iter_accounts(self) -> Iterator[tuple[bytes, Account]]:
        """Iterate all accounts: overlay overrides, then disk remainder."""
        # Yield overlay accounts first (skip deleted)
        seen = set()
        for addr, val in self._overlay.accounts.items():
            seen.add(addr)
            if val is not _DELETED and isinstance(val, Account):
                yield (addr, val)

        # Yield LMDB accounts not in overlay
        with self._env.begin(db=self._dbs[b"accounts"]) as txn:
            cursor = txn.cursor()
            for key, data in cursor:
                addr = bytes(key)
                if addr not in seen:
                    yield (addr, Account.decode_rlp(bytes(data)))

    def iter_storage(self) -> Iterator[tuple[tuple[bytes, int], int]]:
        """Iterate all storage: overlay overrides, then disk remainder."""
        seen: set[tuple[bytes, int]] = set()
        for (addr, slot), val in self._overlay.storage.items():
            seen.add((addr, slot))
            if val is not _DELETED and isinstance(val, int) and val != 0:
                yield ((addr, slot), val)

        with self._env.begin(db=self._dbs[b"storage"]) as txn:
            cursor = txn.cursor()
            for key, data in cursor:
                addr, slot = _decode_storage_key(bytes(key))
                if (addr, slot) not in seen:
                    val = _decode_storage_value(bytes(data))
                    if val != 0:
                        yield ((addr, slot), val)

    def iter_original_storage(self) -> Iterator[tuple[tuple[bytes, int], int]]:
        """Iterate all original storage: overlay overrides, then disk."""
        seen: set[tuple[bytes, int]] = set()
        for (addr, slot), val in self._overlay.original_storage.items():
            seen.add((addr, slot))
            if val is not _DELETED and isinstance(val, int) and val != 0:
                yield ((addr, slot), val)

        with self._env.begin(db=self._dbs[b"original_storage"]) as txn:
            cursor = txn.cursor()
            for key, data in cursor:
                addr, slot = _decode_storage_key(bytes(key))
                if (addr, slot) not in seen:
                    val = _decode_storage_value(bytes(data))
                    if val != 0:
                        yield ((addr, slot), val)

    # -----------------------------------------------------------------
    # Block headers (direct LMDB)
    # -----------------------------------------------------------------

    def get_block_header(self, block_hash: bytes) -> Optional[BlockHeader]:
        with self._env.begin(db=self._dbs[b"headers"]) as txn:
            data = txn.get(block_hash)
            if data is None:
                return None
            return BlockHeader.decode_rlp(bytes(data))

    def get_block_header_by_number(self, number: int) -> Optional[BlockHeader]:
        bh = self.get_canonical_hash(number)
        if bh is None:
            return None
        return self.get_block_header(bh)

    def put_block_header(self, header: BlockHeader) -> None:
        block_hash = header.block_hash()
        data = header.encode_rlp()
        with self._env.begin(write=True) as txn:
            txn.put(block_hash, data, db=self._dbs[b"headers"])
            txn.put(_num_key(header.number), block_hash, db=self._dbs[b"header_numbers"])

    # -----------------------------------------------------------------
    # Block bodies (direct LMDB)
    # -----------------------------------------------------------------

    def get_block_body(
        self, block_hash: bytes
    ) -> Optional[tuple[list[Transaction], list[BlockHeader], Optional[list[Withdrawal]]]]:
        with self._env.begin(db=self._dbs[b"bodies"]) as txn:
            data = txn.get(block_hash)
            if data is None:
                return None
            return self._decode_body(bytes(data))

    def put_block_body(
        self,
        block_hash: bytes,
        transactions: list[Transaction],
        ommers: list[BlockHeader],
        withdrawals: Optional[list[Withdrawal]] = None,
    ) -> None:
        data = self._encode_body(transactions, ommers, withdrawals)
        with self._env.begin(db=self._dbs[b"bodies"], write=True) as txn:
            txn.put(block_hash, data)

    @staticmethod
    def _encode_body(
        transactions: list[Transaction | bytes],
        ommers: list[BlockHeader | bytes],
        withdrawals: Optional[list[Withdrawal | bytes]],
    ) -> bytes:
        # Accept both decoded objects and raw RLP bytes for pipeline compatibility.
        tx_rlps = [tx.encode_rlp() if isinstance(tx, Transaction) else tx for tx in transactions]
        ommer_rlps = [o.encode_rlp() if isinstance(o, BlockHeader) else o for o in ommers]
        parts: list = [tx_rlps, ommer_rlps]
        if withdrawals is not None:
            w_rlps = [
                rlp.encode(w.to_rlp_list()) if isinstance(w, Withdrawal) else w
                for w in withdrawals
            ]
            parts.append(w_rlps)
        return rlp.encode(parts)

    @staticmethod
    def _decode_body(
        data: bytes,
    ) -> tuple[list[Transaction], list[BlockHeader], Optional[list[Withdrawal]]]:
        items = rlp.decode_list(data)
        txs = [Transaction.decode_rlp(raw) for raw in items[0]]
        ommers = [BlockHeader.decode_rlp(raw) for raw in items[1]]
        withdrawals = None
        if len(items) > 2:
            withdrawals = [
                Withdrawal.from_rlp_list(rlp.decode_list(raw)) for raw in items[2]
            ]
        return (txs, ommers, withdrawals)

    # -----------------------------------------------------------------
    # Block (combined)
    # -----------------------------------------------------------------

    def get_block(self, block_hash: bytes) -> Optional[Block]:
        header = self.get_block_header(block_hash)
        if header is None:
            return None
        body = self.get_block_body(block_hash)
        if body is None:
            return Block(header=header)
        txs, ommers, withdrawals = body
        return Block(header=header, transactions=txs, ommers=ommers, withdrawals=withdrawals)

    def get_block_by_number(self, number: int) -> Optional[Block]:
        bh = self.get_canonical_hash(number)
        if bh is None:
            return None
        return self.get_block(bh)

    def put_block(self, block: Block) -> None:
        block_hash = block.header.block_hash()
        self.put_block_header(block.header)
        self.put_block_body(
            block_hash, block.transactions, block.ommers, block.withdrawals,
        )
        # Index transactions
        if block.transactions:
            with self._env.begin(db=self._dbs[b"tx_index"], write=True) as txn:
                for i, tx in enumerate(block.transactions):
                    tx_hash = tx.tx_hash()
                    txn.put(tx_hash, block_hash + struct.pack(">I", i))

    # -----------------------------------------------------------------
    # Receipts (direct LMDB)
    # -----------------------------------------------------------------

    def get_receipts(self, block_hash: bytes) -> Optional[list[Receipt]]:
        with self._env.begin(db=self._dbs[b"receipts"]) as txn:
            data = txn.get(block_hash)
            if data is None:
                return None
            items = rlp.decode_list(bytes(data))
            return [Receipt.decode_rlp(raw) for raw in items]

    def put_receipts(self, block_hash: bytes, receipts: list[Receipt]) -> None:
        encoded = rlp.encode([r.encode_rlp() for r in receipts])
        with self._env.begin(db=self._dbs[b"receipts"], write=True) as txn:
            txn.put(block_hash, encoded)

    def get_transaction_receipt(
        self, tx_hash: bytes
    ) -> Optional[tuple[Receipt, bytes, int]]:
        with self._env.begin(db=self._dbs[b"tx_index"]) as txn:
            data = txn.get(tx_hash)
            if data is None:
                return None
            block_hash = data[:32]
            tx_index = struct.unpack(">I", data[32:36])[0]

        receipts = self.get_receipts(bytes(block_hash))
        if receipts is None or tx_index >= len(receipts):
            return None
        return receipts[tx_index], bytes(block_hash), tx_index

    # -----------------------------------------------------------------
    # Canonical chain (direct LMDB)
    # -----------------------------------------------------------------

    def get_canonical_hash(self, number: int) -> Optional[bytes]:
        with self._env.begin(db=self._dbs[b"canonical"]) as txn:
            data = txn.get(_num_key(number))
            return bytes(data) if data is not None else None

    def put_canonical_hash(self, number: int, block_hash: bytes) -> None:
        with self._env.begin(db=self._dbs[b"canonical"], write=True) as txn:
            txn.put(_num_key(number), block_hash)
        if number > self._latest_block:
            self._latest_block = number
            self._save_meta_int("latest_block", number)

    def get_latest_block_number(self) -> int:
        """Return latest canonical block, refreshing from LMDB meta.

        In multi-process mode, another process may advance canonical head.
        Always reconcile cached value with on-disk meta before returning.
        """
        latest_meta = self._load_meta_int("latest_block", -1)
        if latest_meta > self._latest_block:
            self._latest_block = latest_meta
        return max(self._latest_block, 0)

    def get_chain_head_snapshot(self) -> tuple[int, Optional[bytes]]:
        """Read-only snapshot of current canonical head."""
        latest = max(self._latest_block, 0)
        with self._env.begin(db=self._dbs[b"canonical"]) as txn:
            head_hash = txn.get(_num_key(latest))
            return latest, (bytes(head_hash) if head_hash is not None else None)

    def put_block_batch(
        self,
        entries: Sequence[tuple[BlockHeader, tuple[list[Transaction], list[BlockHeader], Optional[list[Withdrawal]]]]],
    ) -> int:
        """Commit multiple blocks atomically in a single LMDB write transaction.

        Returns the last committed block number, or current head if entries is empty.
        """
        if not entries:
            return max(self._latest_block, 0)

        latest = max(self._latest_block, 0)
        with self._env.begin(write=True) as txn:
            for header, body in entries:
                block_hash = header.block_hash()
                header_rlp = header.encode_rlp()

                # Header + number index
                txn.put(block_hash, header_rlp, db=self._dbs[b"headers"])
                txn.put(_num_key(header.number), block_hash, db=self._dbs[b"header_numbers"])

                # Body
                txs, ommers, withdrawals = body
                body_rlp = self._encode_body(txs, ommers, withdrawals)
                txn.put(block_hash, body_rlp, db=self._dbs[b"bodies"])

                # Canonical mapping
                txn.put(_num_key(header.number), block_hash, db=self._dbs[b"canonical"])
                if header.number > latest:
                    latest = header.number

            txn.put(
                b"latest_block",
                latest.to_bytes(8, "big", signed=True),
                db=self._dbs[b"meta"],
            )

        self._latest_block = latest
        return latest

    # -----------------------------------------------------------------
    # State root computation
    # -----------------------------------------------------------------

    def compute_state_root(self) -> bytes:
        """Compute MPT root from all accounts (overlay + disk merged)."""
        state_trie = Trie()
        has_accounts = False

        for address, account in self.iter_accounts():
            if account.is_empty() and self.get_account_code(address) == b"":
                continue
            has_accounts = True

            storage_root = self._compute_storage_root(address)
            account.storage_root = storage_root

            account_rlp = account.encode_rlp()
            state_trie.put(address, account_rlp)

        if not has_accounts:
            return EMPTY_ROOT

        return state_trie.root_hash

    def _compute_storage_root(self, address: bytes) -> bytes:
        """Compute storage trie root for one account (overlay + disk)."""
        storage_trie = Trie()
        has_storage = False

        # Collect all storage for this address from overlay and disk
        # Overlay storage for this address
        overlay_keys: set[tuple[bytes, int]] = set()
        for (addr, slot), val in self._overlay.storage.items():
            if addr != address:
                continue
            overlay_keys.add((addr, slot))
            if val is not _DELETED and isinstance(val, int) and val != 0:
                has_storage = True
                key_bytes = slot.to_bytes(32, "big")
                value_rlp = rlp.encode(rlp.encode_uint(val))
                storage_trie.put(key_bytes, value_rlp)

        # Disk storage for this address (skip overlay-covered keys)
        prefix = address
        with self._env.begin(db=self._dbs[b"storage"]) as txn:
            cursor = txn.cursor()
            if cursor.set_range(prefix):
                for key, data in cursor:
                    key = bytes(key)
                    if not key.startswith(prefix):
                        break
                    addr, slot = _decode_storage_key(key)
                    if (addr, slot) in overlay_keys:
                        continue
                    val = _decode_storage_value(bytes(data))
                    if val != 0:
                        has_storage = True
                        key_bytes = slot.to_bytes(32, "big")
                        value_rlp = rlp.encode(rlp.encode_uint(val))
                        storage_trie.put(key_bytes, value_rlp)

        if not has_storage:
            return EMPTY_TRIE_ROOT

        return storage_trie.root_hash

    # -----------------------------------------------------------------
    # State snapshots (overlay-based)
    # -----------------------------------------------------------------

    def snapshot(self) -> int:
        self._snapshots.append(self._overlay.copy())
        return len(self._snapshots) - 1

    def rollback(self, snapshot_id: int) -> None:
        if snapshot_id >= len(self._snapshots):
            return
        self._overlay = self._snapshots[snapshot_id]
        self._snapshots = self._snapshots[:snapshot_id]

    def commit(self, snapshot_id: int) -> None:
        self._snapshots = self._snapshots[:snapshot_id]

    # -----------------------------------------------------------------
    # Transaction index (direct LMDB)
    # -----------------------------------------------------------------

    def get_transaction_by_hash(
        self, tx_hash: bytes
    ) -> Optional[tuple[Transaction, bytes, int]]:
        with self._env.begin(db=self._dbs[b"tx_index"]) as txn:
            data = txn.get(tx_hash)
            if data is None:
                return None
            block_hash = bytes(data[:32])
            tx_index = struct.unpack(">I", data[32:36])[0]

        body = self.get_block_body(block_hash)
        if body is None or tx_index >= len(body[0]):
            return None
        return body[0][tx_index], block_hash, tx_index

    # -----------------------------------------------------------------
    # Snap sync data (direct LMDB)
    # -----------------------------------------------------------------

    def put_snap_account(self, account_hash: bytes, account_rlp: bytes) -> None:
        with self._env.begin(db=self._dbs[b"snap_accounts"], write=True) as txn:
            txn.put(account_hash, account_rlp)

    def put_snap_storage(
        self, account_hash: bytes, slot_hash: bytes, value: bytes,
    ) -> None:
        with self._env.begin(db=self._dbs[b"snap_storage"], write=True) as txn:
            txn.put(account_hash + slot_hash, value)

    def put_snap_code(self, code_hash: bytes, code: bytes) -> None:
        self.put_code(code_hash, code)

    def get_snap_progress(self) -> Optional[dict]:
        with self._env.begin(db=self._dbs[b"meta"]) as txn:
            data = txn.get(b"snap_progress")
            if data is None:
                return None
            return json.loads(bytes(data))

    def put_snap_progress(self, progress: dict) -> None:
        with self._env.begin(db=self._dbs[b"meta"], write=True) as txn:
            txn.put(b"snap_progress", json.dumps(progress).encode())

    # -----------------------------------------------------------------
    # Flush: commit overlay to LMDB
    # -----------------------------------------------------------------

    def flush(self) -> None:
        """Atomically write all overlay changes to LMDB."""
        overlay = self._overlay

        with self._env.begin(write=True) as txn:
            # Accounts
            for addr, val in overlay.accounts.items():
                if val is _DELETED:
                    txn.delete(addr, db=self._dbs[b"accounts"])
                elif isinstance(val, Account):
                    txn.put(addr, val.encode_rlp(), db=self._dbs[b"accounts"])

            # Code
            for code_hash, code in overlay.code.items():
                txn.put(code_hash, code, db=self._dbs[b"code"])

            # Storage
            for (addr, slot), val in overlay.storage.items():
                sk = _storage_key(addr, slot)
                if val is _DELETED:
                    txn.delete(sk, db=self._dbs[b"storage"])
                elif isinstance(val, int):
                    txn.put(sk, _encode_storage_value(val), db=self._dbs[b"storage"])

            # Original storage
            for (addr, slot), val in overlay.original_storage.items():
                sk = _storage_key(addr, slot)
                if val is _DELETED:
                    txn.delete(sk, db=self._dbs[b"original_storage"])
                elif isinstance(val, int):
                    txn.put(sk, _encode_storage_value(val), db=self._dbs[b"original_storage"])

        # Clear overlay after successful flush
        self._overlay = _StateOverlay()
        self._snapshots.clear()
