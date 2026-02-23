"""InMemoryL1Backend — simulates L1 verification using MemoryBackend + groth16.verify."""

from __future__ import annotations

import logging
from typing import Optional

from ethclient.common.crypto import keccak256
from ethclient.l2.interfaces import L1Backend
from ethclient.l2.prover import _to_field
from ethclient.zk import groth16
from ethclient.zk.types import Proof, VerificationKey

logger = logging.getLogger(__name__)


class InMemoryL1Backend(L1Backend):
    """In-memory L1 simulation that verifies Groth16 proofs directly."""

    def __init__(self) -> None:
        self._vk: Optional[VerificationKey] = None
        self._verifier_address: Optional[bytes] = None
        self._verified_batches: dict[int, bytes] = {}  # batch_number -> state_root
        self._latest_root: Optional[bytes] = None
        self._l1_tx_counter = 0

    def deploy_verifier(self, vk: VerificationKey) -> bytes:
        self._vk = vk
        self._verifier_address = keccak256(b"l2-verifier")[:20]
        logger.info("Deployed verifier at %s", self._verifier_address.hex())
        return self._verifier_address

    def submit_batch(
        self,
        batch_number: int,
        old_root: bytes,
        new_root: bytes,
        proof: Proof,
        tx_commitment: bytes,
        da_commitment: bytes = b"",
    ) -> bytes:
        if self._vk is None:
            raise RuntimeError("Verifier not deployed. Call deploy_verifier() first.")

        old_root_int = _to_field(old_root)
        new_root_int = _to_field(new_root)
        tx_commit_int = _to_field(tx_commitment)

        public_inputs = [old_root_int, new_root_int, tx_commit_int]
        valid = groth16.verify(self._vk, proof, public_inputs)

        self._l1_tx_counter += 1
        l1_tx_hash = keccak256(
            b"l1-tx" + batch_number.to_bytes(8, "big") + self._l1_tx_counter.to_bytes(8, "big")
        )

        if valid:
            self._verified_batches[batch_number] = new_root
            self._latest_root = new_root
            logger.info("Batch #%d verified on L1", batch_number)
        else:
            logger.warning("Batch #%d verification FAILED", batch_number)

        return l1_tx_hash

    def is_batch_verified(self, batch_number: int) -> bool:
        return batch_number in self._verified_batches

    def get_verified_state_root(self) -> Optional[bytes]:
        return self._latest_root
