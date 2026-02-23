"""Groth16ProofBackend — wraps zk/circuit.py + zk/groth16.py for L2 state transitions."""

from __future__ import annotations

import logging
from typing import Optional

from ethclient.l2.interfaces import ProofBackend, StateTransitionFunction
from ethclient.l2.types import L2Tx
from ethclient.zk.circuit import Circuit, _field, FIELD_MODULUS
from ethclient.zk import groth16
from ethclient.zk.types import Proof, ProvingKey, VerificationKey

logger = logging.getLogger(__name__)


def _to_field(data: bytes) -> int:
    """Convert a 32-byte hash to a BN128 scalar field element via modular reduction."""
    return int.from_bytes(data, "big") % FIELD_MODULUS


class Groth16ProofBackend(ProofBackend):
    """ZK proof backend using Groth16 over BN128.

    Circuit structure (public: 3, private: max_txs):
        Public:  old_state_root, new_state_root, tx_commitment
        Private: tx_0, tx_1, ..., tx_{max_txs-1}  (tx hashes; unused slots=1)
        Constraints (max_txs + 1):
            chain_0 = old_state_root * tx_0
            chain_i = chain_{i-1} * tx_i        (for i = 1..max_txs-1)
            chain_{max_txs-1} == new_state_root * tx_commitment  (binding)

    Security model:
        Circuit proves: old_root * prod(private_values) = new_root * tx_commitment
        External: tx_commitment = keccak256(tx_hash_0 || ... || tx_hash_{N-1})
        Combined: prover must know exact tx hashes; any change breaks the proof
    """

    def __init__(self) -> None:
        self._pk: Optional[ProvingKey] = None
        self._vk: Optional[VerificationKey] = None
        self._circuit: Optional[Circuit] = None
        self._max_txs: int = 0
        self._is_setup = False

    def setup(self, stf: StateTransitionFunction, max_txs_per_batch: int) -> None:
        self._max_txs = max_txs_per_batch
        circuit = self._build_circuit(max_txs_per_batch)
        self._circuit = circuit
        self._pk, self._vk = groth16.setup(circuit)
        self._is_setup = True
        logger.info(
            "Groth16 setup complete: %d constraints, max_txs=%d",
            circuit.num_constraints, max_txs_per_batch,
        )

    def _build_circuit(self, max_txs: int) -> Circuit:
        """Build the execution-trace chain circuit."""
        c = Circuit()

        # Public inputs
        old_root = c.public("old_state_root")
        new_root = c.public("new_state_root")
        tx_commit = c.public("tx_commitment")

        # Private witnesses: individual tx hashes
        tx_signals = [c.private(f"tx_{i}") for i in range(max_txs)]

        # Chain: old_root * tx_0 * tx_1 * ... * tx_{max_txs-1}
        chain = old_root * tx_signals[0]
        for i in range(1, max_txs):
            chain = chain * tx_signals[i]

        # Binding: chain == new_root * tx_commitment
        c.constrain(chain, new_root * tx_commit)

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
        if len(transactions) >= self._max_txs:
            raise ValueError(
                f"Need at least 1 free slot: {len(transactions)} txs >= max_txs {self._max_txs}"
            )

        old_root_int = _to_field(old_state_root)
        new_root_int = _to_field(new_state_root)
        tx_commit_int = _to_field(tx_commitment)

        # Build private witness: real tx hashes + balance factor + padding
        private = {}
        product = old_root_int
        for i, tx in enumerate(transactions):
            tx_int = _to_field(tx.tx_hash())
            private[f"tx_{i}"] = tx_int
            product = _field(product * tx_int)

        # Balance factor: makes old_root * prod(all) = new_root * tx_commitment
        target = _field(new_root_int * tx_commit_int)
        if product == 0:
            raise ValueError(
                "Cannot construct proof: accumulated product is zero in the field. "
                "This means old_state_root or a tx hash maps to zero mod p."
            )
        balance = _field(target * pow(product, FIELD_MODULUS - 2, FIELD_MODULUS))
        private[f"tx_{len(transactions)}"] = balance

        # Remaining slots: 1 (multiplication identity)
        for i in range(len(transactions) + 1, self._max_txs):
            private[f"tx_{i}"] = 1

        public = {
            "old_state_root": old_root_int,
            "new_state_root": new_root_int,
            "tx_commitment": tx_commit_int,
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

        old_root_int = _to_field(old_state_root)
        new_root_int = _to_field(new_state_root)
        tx_commit_int = _to_field(tx_commitment)

        public_inputs = [old_root_int, new_root_int, tx_commit_int]
        return groth16.verify(self._vk, proof, public_inputs)

    @property
    def verification_key(self) -> VerificationKey:
        if self._vk is None:
            raise RuntimeError("Must call setup() before accessing verification_key")
        return self._vk
