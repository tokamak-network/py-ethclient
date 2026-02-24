"""Pluggable interfaces for the L2 rollup framework (4 ABCs)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from ethclient.l2.types import L2State, L2Tx, STFResult, Batch
from ethclient.zk.types import Proof, VerificationKey


class StateTransitionFunction(ABC):
    """Defines how L2 state transitions in response to transactions."""

    @abstractmethod
    def apply_tx(self, state: L2State, tx: L2Tx) -> STFResult:
        ...

    def validate_tx(self, state: L2State, tx: L2Tx) -> Optional[str]:
        """Return an error string if tx is invalid, else None."""
        return None

    def genesis_state(self) -> dict[str, Any]:
        """Return the initial state for the rollup."""
        return {}


class DAProvider(ABC):
    """Data availability layer for batch data."""

    @abstractmethod
    def store_batch(self, batch_number: int, data: bytes) -> bytes:
        """Store batch data. Returns a commitment."""
        ...

    @abstractmethod
    def retrieve_batch(self, batch_number: int) -> Optional[bytes]:
        """Retrieve stored batch data."""
        ...

    @abstractmethod
    def verify_commitment(self, batch_number: int, commitment: bytes) -> bool:
        """Verify that the commitment matches stored data."""
        ...


class L1Backend(ABC):
    """Interface to L1 for verification and state anchoring."""

    @abstractmethod
    def deploy_verifier(self, vk: VerificationKey) -> bytes:
        """Deploy the on-chain verifier. Returns contract address."""
        ...

    @abstractmethod
    def submit_batch(
        self,
        batch_number: int,
        old_root: bytes,
        new_root: bytes,
        proof: Proof,
        tx_commitment: bytes,
        da_commitment: bytes = b"",
    ) -> bytes:
        """Submit a proven batch to L1. Returns L1 tx hash."""
        ...

    @abstractmethod
    def is_batch_verified(self, batch_number: int) -> bool:
        """Check if a batch has been verified on L1."""
        ...

    @abstractmethod
    def get_verified_state_root(self) -> Optional[bytes]:
        """Get the latest verified state root on L1."""
        ...


class ProofBackend(ABC):
    """ZK proof generation and verification."""

    @abstractmethod
    def setup(self, stf: StateTransitionFunction, max_txs_per_batch: int) -> None:
        """Initialize the proving system (trusted setup)."""
        ...

    @abstractmethod
    def prove(
        self,
        old_state_root: bytes,
        new_state_root: bytes,
        transactions: list[L2Tx],
        tx_commitment: bytes,
    ) -> Proof:
        """Generate a proof for a state transition."""
        ...

    @abstractmethod
    def verify(
        self,
        proof: Proof,
        old_state_root: bytes,
        new_state_root: bytes,
        tx_commitment: bytes,
    ) -> bool:
        """Verify a proof."""
        ...

    @property
    @abstractmethod
    def verification_key(self) -> VerificationKey:
        """Return the verification key."""
        ...
