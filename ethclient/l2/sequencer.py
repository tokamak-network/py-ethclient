"""L2 Sequencer — mempool management, STF execution, and batch assembly."""

from __future__ import annotations

import logging
from typing import Optional

from ethclient.l2.interfaces import DAProvider, StateTransitionFunction
from ethclient.l2.state import L2StateStore
from ethclient.l2.types import Batch, L2Tx, STFResult
from ethclient.l2.config import L2Config

logger = logging.getLogger(__name__)


class Sequencer:
    """Sequences transactions, executes STF, and assembles batches."""

    def __init__(
        self,
        stf: StateTransitionFunction,
        state_store: L2StateStore,
        da: Optional[DAProvider] = None,
        config: Optional[L2Config] = None,
    ) -> None:
        self._stf = stf
        self._state_store = state_store
        self._da = da
        self._config = config or L2Config()
        self._mempool: list[L2Tx] = []
        self._current_batch_txs: list[L2Tx] = []
        self._batch_counter = 0
        self._sealed_batches: list[Batch] = []
        self._nonces: dict[bytes, int] = {}  # sender -> next expected nonce
        self._pre_batch_root: bytes = state_store.compute_state_root()

    @property
    def mempool(self) -> list[L2Tx]:
        return list(self._mempool)

    @property
    def sealed_batches(self) -> list[Batch]:
        return list(self._sealed_batches)

    @property
    def pending_tx_count(self) -> int:
        return len(self._mempool)

    @property
    def current_batch_size(self) -> int:
        return len(self._current_batch_txs)

    def submit_tx(self, tx: L2Tx) -> Optional[str]:
        """Submit a transaction. Returns error string or None on success."""
        error = self._stf.validate_tx(self._state_store.state, tx)
        if error:
            return error

        expected_nonce = self._nonces.get(tx.sender, 0)
        if tx.nonce < expected_nonce:
            return f"nonce too low: got {tx.nonce}, expected {expected_nonce}"
        if tx.nonce > expected_nonce:
            return f"nonce too high: got {tx.nonce}, expected {expected_nonce}"

        self._mempool.append(tx)
        self._nonces[tx.sender] = tx.nonce + 1
        return None

    def tick(self) -> list[STFResult]:
        """Process pending transactions and assemble into current batch."""
        results = []
        remaining: list[L2Tx] = []

        for tx in self._mempool:
            if len(self._current_batch_txs) >= self._config.max_txs_per_batch:
                remaining.append(tx)
                continue

            snap = self._state_store.snapshot()
            result = self._stf.apply_tx(self._state_store.state, tx)

            if result.success:
                self._state_store.commit()
                self._current_batch_txs.append(tx)
                self._nonces[tx.sender] = tx.nonce + 1
            else:
                self._state_store.rollback(snap)

            results.append(result)

        self._mempool = remaining

        if len(self._current_batch_txs) >= self._config.max_txs_per_batch:
            self._seal_batch()

        return results

    def force_seal(self) -> Optional[Batch]:
        """Force-seal the current batch even if not full."""
        if not self._current_batch_txs:
            return None
        return self._seal_batch()

    def _seal_batch(self) -> Batch:
        """Seal the current batch with state root and DA commitment."""
        old_root = self._pre_batch_root
        new_root = self._state_store.compute_state_root()

        batch = Batch(
            number=self._batch_counter,
            transactions=list(self._current_batch_txs),
            old_state_root=old_root,
            new_state_root=new_root,
            sealed=True,
        )

        if self._da is not None:
            commitment = self._da.store_batch(batch.number, batch.encode())
            batch.da_commitment = commitment

        self._sealed_batches.append(batch)
        self._current_batch_txs = []
        self._batch_counter += 1
        self._pre_batch_root = new_root

        logger.info("Sealed batch #%d with %d txs", batch.number, len(batch.transactions))
        return batch
