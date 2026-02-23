"""Groth16ProofBackend — wraps zk/circuit.py + zk/groth16.py for L2 state transitions."""

from __future__ import annotations

import logging
from typing import Optional

from ethclient.common.crypto import keccak256
from ethclient.l2.interfaces import ProofBackend, StateTransitionFunction
from ethclient.l2.types import L2Tx
from ethclient.zk.circuit import Circuit, _field, FIELD_MODULUS
from ethclient.zk import groth16
from ethclient.zk.types import Proof, ProvingKey, VerificationKey

logger = logging.getLogger(__name__)

# Use 128-bit truncation to stay safely inside BN128 scalar field
TRUNCATION_BITS = 128
TRUNCATION_MASK = (1 << TRUNCATION_BITS) - 1


def _truncate_to_field(data: bytes) -> int:
    """Truncate a 32-byte hash to 128-bit integer (safe for BN128 field)."""
    val = int.from_bytes(data[:16], "big")  # first 16 bytes = 128 bits
    return val & TRUNCATION_MASK


class Groth16ProofBackend(ProofBackend):
    """ZK proof backend using Groth16 over BN128.

    Circuit structure (public: 3, private: 3):
        Public:  old_state_root, new_state_root, tx_commitment (128-bit each)
        Private: old_state_hash, new_state_hash, delta
        Constraints:
            1. old_state_hash * 1 = old_state_root   (binding)
            2. new_state_hash * 1 = new_state_root   (binding)
            3. delta * old_state_hash = new_state_hash * tx_commitment  (transition integrity)
    """

    def __init__(self) -> None:
        self._pk: Optional[ProvingKey] = None
        self._vk: Optional[VerificationKey] = None
        self._circuit: Optional[Circuit] = None
        self._is_setup = False

    def setup(self, stf: StateTransitionFunction, max_txs_per_batch: int) -> None:
        circuit = self._build_circuit()
        self._circuit = circuit
        self._pk, self._vk = groth16.setup(circuit)
        self._is_setup = True
        logger.info("Groth16 setup complete: %d constraints", circuit.num_constraints)

    def _build_circuit(self) -> Circuit:
        """Build the state-transition circuit."""
        c = Circuit()

        # Public inputs
        old_root = c.public("old_state_root")
        new_root = c.public("new_state_root")
        tx_commit = c.public("tx_commitment")

        # Private witnesses
        old_hash = c.private("old_state_hash")
        new_hash = c.private("new_state_hash")
        delta = c.private("delta")

        # Constraint 1: old_state_hash == old_state_root (binding)
        c.constrain(old_hash, old_root)

        # Constraint 2: new_state_hash == new_state_root (binding)
        c.constrain(new_hash, new_root)

        # Constraint 3: delta * old_state_hash == new_state_hash * tx_commitment
        c.constrain(delta * old_hash, new_hash * tx_commit)

        return c

    def prove(
        self,
        old_state_root: bytes,
        new_state_root: bytes,
        transactions: list[L2Tx],
        tx_commitment: bytes,
    ) -> Proof:
        if not self._is_setup:
            raise RuntimeError("Must call setup() before prove()")

        old_root_int = _truncate_to_field(old_state_root)
        new_root_int = _truncate_to_field(new_state_root)
        tx_commit_int = _truncate_to_field(tx_commitment)

        # Compute delta: delta * old = new * tx_commit
        # delta = (new * tx_commit) / old   (in field arithmetic)
        if old_root_int == 0:
            delta_int = 0
        else:
            old_inv = pow(old_root_int, FIELD_MODULUS - 2, FIELD_MODULUS)
            delta_int = _field(new_root_int * tx_commit_int * old_inv)

        public = {
            "old_state_root": old_root_int,
            "new_state_root": new_root_int,
            "tx_commitment": tx_commit_int,
        }
        private = {
            "old_state_hash": old_root_int,
            "new_state_hash": new_root_int,
            "delta": delta_int,
        }

        proof = groth16.prove(self._pk, private=private, public=public, circuit=self._circuit)
        logger.info("Generated Groth16 proof")
        return proof

    def verify(
        self,
        proof: Proof,
        old_state_root: bytes,
        new_state_root: bytes,
        tx_commitment: bytes,
    ) -> bool:
        if not self._is_setup:
            raise RuntimeError("Must call setup() before verify()")

        old_root_int = _truncate_to_field(old_state_root)
        new_root_int = _truncate_to_field(new_state_root)
        tx_commit_int = _truncate_to_field(tx_commitment)

        public_inputs = [old_root_int, new_root_int, tx_commit_int]
        return groth16.verify(self._vk, proof, public_inputs)

    @property
    def verification_key(self) -> VerificationKey:
        if self._vk is None:
            raise RuntimeError("Must call setup() before accessing verification_key")
        return self._vk
