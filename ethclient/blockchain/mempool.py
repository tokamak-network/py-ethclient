"""
Transaction mempool (txpool).

Manages pending and queued transactions with per-sender nonce ordering.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from ethclient.common.types import Transaction


@dataclass(order=True)
class _PendingTx:
    """Wrapper for priority queue ordering.

    Ordered by: effective_gas_price (descending), then arrival time.
    """
    sort_key: tuple = field(compare=True)
    tx: Transaction = field(compare=False)
    arrival: float = field(compare=False, default_factory=time.time)

    @staticmethod
    def make(tx: Transaction, base_fee: int = 0) -> _PendingTx:
        price = tx.effective_gas_price(base_fee)
        return _PendingTx(
            sort_key=(-price, time.time()),
            tx=tx,
        )


class Mempool:
    """Transaction pool with pending/queued management.

    - pending: transactions with consecutive nonces ready for inclusion
    - queued: transactions with future nonces (gap in sequence)
    """

    def __init__(
        self,
        max_pending: int = 4096,
        max_queued: int = 1024,
    ) -> None:
        self.max_pending = max_pending
        self.max_queued = max_queued

        # sender -> {nonce -> Transaction}
        self._by_sender: dict[bytes, dict[int, Transaction]] = {}

        # All known tx hashes for dedup
        self._known: set[bytes] = set()

        # Current base fee (updated on new head)
        self.base_fee: int = 0

        self._lock = threading.Lock()

    def add(
        self,
        tx: Transaction,
        sender: bytes,
        current_nonce: int,
        sender_balance: int,
    ) -> tuple[bool, Optional[str]]:
        """Add a transaction to the pool.

        Args:
            tx: the transaction
            sender: recovered sender address
            current_nonce: sender's current on-chain nonce
            sender_balance: sender's current balance

        Returns:
            (accepted, error_message)
        """
        with self._lock:
            tx_hash = tx.tx_hash()

            # Dedup
            if tx_hash in self._known:
                return False, "Already known"

            # Nonce too low
            if tx.nonce < current_nonce:
                return False, f"Nonce too low: tx={tx.nonce}, current={current_nonce}"

            # Balance check
            cost = tx.gas_limit * tx.effective_gas_price(self.base_fee) + tx.value
            if sender_balance < cost:
                return False, "Insufficient balance"

            # Gas price must cover base fee
            effective_price = tx.effective_gas_price(self.base_fee)
            if effective_price < self.base_fee:
                return False, "Gas price below base fee"

            # Pool limits
            total = sum(len(v) for v in self._by_sender.values())
            if total >= self.max_pending + self.max_queued:
                return False, "Pool full"

            # Add to sender map
            if sender not in self._by_sender:
                self._by_sender[sender] = {}
            sender_txs = self._by_sender[sender]

            # Check for replacement (same nonce, higher gas price)
            if tx.nonce in sender_txs:
                existing = sender_txs[tx.nonce]
                existing_price = existing.effective_gas_price(self.base_fee)
                new_price = tx.effective_gas_price(self.base_fee)
                # Must be at least 10% higher to replace
                if new_price <= existing_price * 110 // 100:
                    return False, "Replacement gas price too low"
                # Remove old
                old_hash = existing.tx_hash()
                self._known.discard(old_hash)

            sender_txs[tx.nonce] = tx
            self._known.add(tx_hash)
            return True, None

    def get_pending(self, sender: Optional[bytes] = None, current_nonces: Optional[dict[bytes, int]] = None) -> list[Transaction]:
        """Get pending transactions (ready for inclusion), ordered by gas price.

        If current_nonces is provided, only return txs with consecutive nonces.
        """
        with self._lock:
            result: list[_PendingTx] = []

            senders = [sender] if sender else list(self._by_sender.keys())

            for s in senders:
                txs = self._by_sender.get(s, {})
                if not txs:
                    continue

                if current_nonces:
                    nonce = current_nonces.get(s, 0)
                else:
                    nonce = min(txs.keys()) if txs else 0

                # Collect consecutive nonces
                while nonce in txs:
                    result.append(_PendingTx.make(txs[nonce], self.base_fee))
                    nonce += 1

            result.sort()
            return [pt.tx for pt in result]

    def remove_committed(self, sender: bytes, committed_nonce: int) -> int:
        """Remove all transactions for sender with nonce < committed_nonce.

        Call this after a block is committed to prune included txs.
        Returns number of transactions removed.
        """
        with self._lock:
            txs = self._by_sender.get(sender)
            if txs is None:
                return 0

            removed = 0
            for nonce in list(txs.keys()):
                if nonce < committed_nonce:
                    tx = txs.pop(nonce)
                    self._known.discard(tx.tx_hash())
                    removed += 1

            if not txs:
                del self._by_sender[sender]

            return removed

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._known)

    def clear(self) -> None:
        with self._lock:
            self._by_sender.clear()
            self._known.clear()
