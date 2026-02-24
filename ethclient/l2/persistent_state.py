"""LMDB-backed L2 state store with overlay pattern.

Provides transparent persistence for L2 state, batches, proofs, and metadata.
STF code sees a dict interface unchanged — writes go to overlay, reads fall through
to LMDB. flush() atomically writes overlay to disk.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

import lmdb

from ethclient.common.trie import Trie
from ethclient.common import rlp
from ethclient.l2.types import Batch


class L2PersistentState(dict):
    """Dict interface with overlay + LMDB transparent read-through.

    STF writes ``state["key"] = value`` → overlay dict.
    ``state.get("key")`` → overlay first, then LMDB fallback.
    """

    def __init__(self, lmdb_env: lmdb.Environment, db_handle: Any, initial: Optional[dict] = None):
        super().__init__()
        self._env = lmdb_env
        self._db = db_handle
        self._overlay: dict[str, Any] = {}
        self._deleted: set[str] = set()
        if initial:
            self._overlay.update(initial)

    def __setitem__(self, key: str, value: Any) -> None:
        self._overlay[key] = value
        self._deleted.discard(key)

    def __getitem__(self, key: str) -> Any:
        if key in self._overlay:
            return self._overlay[key]
        if key in self._deleted:
            raise KeyError(key)
        val = self._lmdb_get(key)
        if val is None:
            raise KeyError(key)
        return val

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str):
            if key in self._overlay:
                return True
            if key in self._deleted:
                return False
            return self._lmdb_get(key) is not None
        return False

    def __delitem__(self, key: str) -> None:
        if key in self._overlay:
            del self._overlay[key]
        self._deleted.add(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self) -> list[str]:
        all_keys = set(self._overlay.keys())
        with self._env.begin(db=self._db) as txn:
            cursor = txn.cursor()
            for k_bytes, _ in cursor:
                k = k_bytes.decode()
                if k not in self._deleted:
                    all_keys.add(k)
        return list(all_keys)

    def values(self) -> list[Any]:
        return [self[k] for k in self.keys()]

    def items(self) -> list[tuple[str, Any]]:
        return [(k, self[k]) for k in self.keys()]

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self.keys())

    def __bool__(self) -> bool:
        if self._overlay:
            return True
        with self._env.begin(db=self._db) as txn:
            cursor = txn.cursor()
            for k_bytes, _ in cursor:
                k = k_bytes.decode()
                if k not in self._deleted:
                    return True
        return False

    def snapshot(self) -> L2PersistentState:
        """Create a snapshot (overlay-only copy; LMDB is immutable between flushes)."""
        import copy
        snap = L2PersistentState(self._env, self._db)
        snap._overlay = copy.deepcopy(self._overlay)
        snap._deleted = set(self._deleted)
        return snap

    def flush_to_lmdb(self) -> None:
        """Write overlay to LMDB and clear it."""
        with self._env.begin(db=self._db, write=True) as txn:
            for key in self._deleted:
                txn.delete(key.encode())
            for key, value in self._overlay.items():
                txn.put(key.encode(), _encode_state_value(value))
        self._overlay.clear()
        self._deleted.clear()

    def _lmdb_get(self, key: str) -> Any:
        with self._env.begin(db=self._db) as txn:
            raw = txn.get(key.encode())
        if raw is None:
            return None
        return _decode_state_value(raw)


def _encode_state_value(value: Any) -> bytes:
    """Encode a state value for LMDB storage."""
    if isinstance(value, bytes):
        return b"\x01" + value
    if isinstance(value, int):
        return b"\x02" + value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    if isinstance(value, str):
        return b"\x03" + value.encode()
    if isinstance(value, dict):
        return b"\x04" + json.dumps(value, sort_keys=True).encode()
    if isinstance(value, list):
        return b"\x05" + json.dumps(value, sort_keys=True).encode()
    return b"\x03" + str(value).encode()


def _decode_state_value(raw: bytes) -> Any:
    """Decode a state value from LMDB storage."""
    tag = raw[0:1]
    payload = raw[1:]
    if tag == b"\x01":
        return payload
    if tag == b"\x02":
        return int.from_bytes(payload, "big", signed=True)
    if tag == b"\x03":
        return payload.decode()
    if tag == b"\x04":
        return json.loads(payload)
    if tag == b"\x05":
        return json.loads(payload)
    return payload.decode()


# ── Trie encoding (matches state.py exactly) ──

def _encode_key(key: Any) -> bytes:
    if isinstance(key, bytes):
        return key
    return str(key).encode()


def _encode_value(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, int):
        return b"\x01" + rlp.encode_uint(value)
    if isinstance(value, str):
        return b"\x02" + value.encode()
    if isinstance(value, dict):
        parts = []
        for k in sorted(value.keys()):
            parts.append([_encode_key(k), _encode_value(value[k])])
        return b"\x03" + rlp.encode(parts)
    if isinstance(value, list):
        encoded = [_encode_value(item) for item in value]
        return b"\x04" + rlp.encode(encoded)
    return b"\x02" + str(value).encode()


# ── WAL Entry ──

@dataclass
class WALEntry:
    """Write-ahead log entry for crash recovery."""

    sequence: int
    entry_type: str  # "tx_applied" | "batch_sealed" | "batch_proven" | "batch_submitted"
    data: bytes
    timestamp: int

    def encode(self) -> bytes:
        type_bytes = self.entry_type.encode()
        return (
            struct.pack(">QHQ", self.sequence, len(type_bytes), self.timestamp)
            + type_bytes
            + self.data
        )

    @classmethod
    def decode(cls, raw: bytes) -> WALEntry:
        seq, type_len, ts = struct.unpack(">QHQ", raw[:18])
        entry_type = raw[18:18 + type_len].decode()
        data = raw[18 + type_len:]
        return cls(sequence=seq, entry_type=entry_type, data=data, timestamp=ts)


class L2PersistentStateStore:
    """LMDB-backed L2 state store with overlay pattern.

    Drop-in replacement for L2StateStore. Provides:
    - Transparent dict-like state access (overlay → LMDB fallback)
    - Batch/proof persistence
    - Metadata persistence (batch counters, nonces)
    - WAL for crash recovery
    - Snapshot/rollback via overlay copies (LMDB immutable between flushes)
    """

    def __init__(self, data_dir: Path, map_size: int = 256 * 1024 * 1024,
                 initial_state: Optional[dict] = None) -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._env = lmdb.open(
            str(self._data_dir / "l2.lmdb"),
            map_size=map_size,
            max_dbs=5,
            create=True,
        )

        self._db_state = self._env.open_db(b"l2_state")
        self._db_batches = self._env.open_db(b"l2_batches")
        self._db_proofs = self._env.open_db(b"l2_proofs")
        self._db_meta = self._env.open_db(b"l2_meta")
        self._db_wal = self._env.open_db(b"l2_wal")

        self._state = L2PersistentState(self._env, self._db_state, initial_state)
        self._snapshots: list[L2PersistentState] = []
        self._wal_sequence = self._get_max_wal_sequence()

    def close(self) -> None:
        """Close the LMDB environment."""
        self._env.close()

    @property
    def state(self) -> L2PersistentState:
        return self._state

    @state.setter
    def state(self, new_state: L2PersistentState) -> None:
        self._state = new_state

    def compute_state_root(self) -> bytes:
        """Compute Merkle root from overlay + LMDB merged state."""
        trie = Trie()
        for key in sorted(self._state.keys()):
            k_bytes = _encode_key(key)
            v_bytes = _encode_value(self._state[key])
            trie.put(k_bytes, v_bytes)
        return trie.root_hash

    def snapshot(self) -> int:
        """Save a snapshot and return its index."""
        self._snapshots.append(self._state.snapshot())
        return len(self._snapshots) - 1

    def rollback(self, snapshot_id: Optional[int] = None) -> None:
        """Rollback to a snapshot."""
        if not self._snapshots:
            return
        if snapshot_id is None:
            snapshot_id = len(self._snapshots) - 1
        if snapshot_id < 0 or snapshot_id >= len(self._snapshots):
            raise IndexError(f"Invalid snapshot_id {snapshot_id}, have {len(self._snapshots)} snapshots")
        self._state = self._snapshots[snapshot_id]
        self._snapshots = self._snapshots[:snapshot_id]

    def commit(self) -> None:
        """Discard all snapshots (commit current state)."""
        self._snapshots.clear()

    def flush(self) -> None:
        """Flush overlay to LMDB (persistent commit)."""
        self._state.flush_to_lmdb()

    # ── Batch persistence ──

    def put_batch(self, batch: Batch) -> None:
        key = struct.pack(">Q", batch.number)
        with self._env.begin(db=self._db_batches, write=True) as txn:
            txn.put(key, batch.encode())

    def get_batch(self, batch_number: int) -> Optional[Batch]:
        key = struct.pack(">Q", batch_number)
        with self._env.begin(db=self._db_batches) as txn:
            raw = txn.get(key)
        if raw is None:
            return None
        batch = Batch.decode(raw)
        batch.sealed = True
        return batch

    def get_all_batches(self) -> list[Batch]:
        batches = []
        with self._env.begin(db=self._db_batches) as txn:
            cursor = txn.cursor()
            for _, raw in cursor:
                batch = Batch.decode(raw)
                batch.sealed = True
                batches.append(batch)
        return batches

    # ── Proof persistence ──

    def put_proof(self, batch_number: int, proof_data: bytes) -> None:
        key = struct.pack(">Q", batch_number)
        with self._env.begin(db=self._db_proofs, write=True) as txn:
            txn.put(key, proof_data)

    def get_proof(self, batch_number: int) -> Optional[bytes]:
        key = struct.pack(">Q", batch_number)
        with self._env.begin(db=self._db_proofs) as txn:
            return txn.get(key)

    # ── Metadata ──

    def _get_meta(self, key: str) -> Optional[bytes]:
        with self._env.begin(db=self._db_meta) as txn:
            return txn.get(key.encode())

    def _put_meta(self, key: str, value: bytes) -> None:
        with self._env.begin(db=self._db_meta, write=True) as txn:
            txn.put(key.encode(), value)

    def get_last_batch_number(self) -> int:
        raw = self._get_meta("last_batch_number")
        if raw is None:
            return 0
        return struct.unpack(">Q", raw)[0]

    def set_last_batch_number(self, n: int) -> None:
        self._put_meta("last_batch_number", struct.pack(">Q", n))

    def get_last_submitted_batch(self) -> int:
        raw = self._get_meta("last_submitted_batch")
        if raw is None:
            return -1
        return struct.unpack(">q", raw)[0]

    def set_last_submitted_batch(self, n: int) -> None:
        self._put_meta("last_submitted_batch", struct.pack(">q", n))

    def get_nonces(self) -> dict[bytes, int]:
        raw = self._get_meta("nonces")
        if raw is None:
            return {}
        data = json.loads(raw)
        return {bytes.fromhex(k): v for k, v in data.items()}

    def put_nonces(self, nonces: dict[bytes, int]) -> None:
        data = {k.hex(): v for k, v in nonces.items()}
        self._put_meta("nonces", json.dumps(data).encode())

    def get_pre_batch_root(self) -> Optional[bytes]:
        return self._get_meta("pre_batch_root")

    def set_pre_batch_root(self, root: bytes) -> None:
        self._put_meta("pre_batch_root", root)

    # ── WAL (Write-Ahead Log) ──

    def _get_max_wal_sequence(self) -> int:
        with self._env.begin(db=self._db_wal) as txn:
            cursor = txn.cursor()
            if cursor.last():
                key = cursor.key()
                return struct.unpack(">Q", key)[0]
        return 0

    def wal_append(self, entry: WALEntry) -> None:
        self._wal_sequence += 1
        entry.sequence = self._wal_sequence
        key = struct.pack(">Q", entry.sequence)
        with self._env.begin(db=self._db_wal, write=True) as txn:
            txn.put(key, entry.encode())

    def wal_replay(self) -> list[WALEntry]:
        entries = []
        with self._env.begin(db=self._db_wal) as txn:
            cursor = txn.cursor()
            for _, raw in cursor:
                entries.append(WALEntry.decode(raw))
        return entries

    def wal_truncate(self, up_to: int) -> None:
        """Remove WAL entries up to (inclusive) the given sequence number."""
        with self._env.begin(db=self._db_wal, write=True) as txn:
            cursor = txn.cursor()
            if not cursor.first():
                return
            to_delete = []
            for key, raw in cursor:
                seq = struct.unpack(">Q", key)[0]
                if seq <= up_to:
                    to_delete.append(key)
                else:
                    break
            for key in to_delete:
                txn.delete(key)
