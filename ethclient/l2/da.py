"""Local DA (Data Availability) provider — in-memory dict backend."""

from __future__ import annotations

from typing import Optional

from ethclient.common.crypto import keccak256
from ethclient.l2.interfaces import DAProvider


class LocalDAProvider(DAProvider):
    """In-memory data availability provider using a dict.

    Commitments are keccak256(batch_number || data).
    """

    def __init__(self) -> None:
        self._store: dict[int, bytes] = {}
        self._commitments: dict[int, bytes] = {}

    def store_batch(self, batch_number: int, data: bytes) -> bytes:
        commitment = keccak256(batch_number.to_bytes(8, "big") + data)
        self._store[batch_number] = data
        self._commitments[batch_number] = commitment
        return commitment

    def retrieve_batch(self, batch_number: int) -> Optional[bytes]:
        return self._store.get(batch_number)

    def verify_commitment(self, batch_number: int, commitment: bytes) -> bool:
        data = self._store.get(batch_number)
        if data is None:
            return False
        expected = keccak256(batch_number.to_bytes(8, "big") + data)
        return expected == commitment

    @property
    def batch_count(self) -> int:
        return len(self._store)
