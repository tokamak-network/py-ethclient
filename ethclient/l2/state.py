"""L2 state management with Trie-based state root computation."""

from __future__ import annotations

from typing import Optional

from ethclient.common.crypto import keccak256
from ethclient.common.trie import Trie
from ethclient.common import rlp
from ethclient.l2.types import L2State


class L2StateStore:
    """Manages L2 state and computes Merkle state roots."""

    def __init__(self, initial_state: Optional[dict] = None) -> None:
        self._state = L2State(initial_state or {})
        self._snapshots: list[L2State] = []

    @property
    def state(self) -> L2State:
        return self._state

    @state.setter
    def state(self, new_state: L2State) -> None:
        self._state = new_state

    def compute_state_root(self) -> bytes:
        """Compute Merkle root from current state."""
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
        self._state = self._snapshots[snapshot_id]
        self._snapshots = self._snapshots[:snapshot_id]

    def commit(self) -> None:
        """Discard all snapshots (commit current state)."""
        self._snapshots.clear()


def _encode_key(key) -> bytes:
    """Encode a state key to bytes for the trie."""
    if isinstance(key, bytes):
        return key
    return str(key).encode()


def _encode_value(value) -> bytes:
    """Encode a state value to bytes for the trie."""
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
