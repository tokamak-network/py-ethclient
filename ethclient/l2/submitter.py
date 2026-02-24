"""BatchSubmitter — orchestrates prove -> submit -> verify pipeline."""

from __future__ import annotations

import logging
from typing import Optional

from ethclient.l2.interfaces import L1Backend, ProofBackend
from ethclient.l2.types import Batch, BatchReceipt

logger = logging.getLogger(__name__)


class BatchSubmitter:
    """Orchestrates the prove -> submit -> verify pipeline for batches."""

    def __init__(self, prover: ProofBackend, l1: L1Backend) -> None:
        self._prover = prover
        self._l1 = l1

    def prove_batch(self, batch: Batch) -> Batch:
        """Generate a ZK proof for a sealed batch."""
        if not batch.sealed:
            raise ValueError("Cannot prove an unsealed batch")

        proof = self._prover.prove(
            old_state_root=batch.old_state_root,
            new_state_root=batch.new_state_root,
            transactions=batch.transactions,
            tx_commitment=batch.tx_commitment(),
        )
        batch.proof = proof
        batch.proven = True
        logger.info("Batch #%d proven", batch.number)
        return batch

    def submit_batch(self, batch: Batch) -> BatchReceipt:
        """Submit a proven batch to L1."""
        if not batch.proven or batch.proof is None:
            raise ValueError("Cannot submit an unproven batch")

        l1_tx_hash = self._l1.submit_batch(
            batch_number=batch.number,
            old_root=batch.old_state_root,
            new_root=batch.new_state_root,
            proof=batch.proof,
            tx_commitment=batch.tx_commitment(),
            da_commitment=batch.da_commitment,
        )

        batch.submitted = True
        verified = self._l1.is_batch_verified(batch.number)
        batch.verified = verified

        receipt = BatchReceipt(
            batch_number=batch.number,
            l1_tx_hash=l1_tx_hash,
            verified=verified,
            state_root=batch.new_state_root,
        )
        logger.info("Batch #%d submitted, verified=%s", batch.number, verified)
        return receipt

    def process_batch(self, batch: Batch) -> BatchReceipt:
        """Prove and submit a batch in one step."""
        self.prove_batch(batch)
        return self.submit_batch(batch)
