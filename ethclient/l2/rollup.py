"""Rollup — main user-facing orchestrator for the L2 rollup framework."""

from __future__ import annotations

import logging
from typing import Callable, Optional

from ethclient.l2.config import L2Config
from ethclient.l2.da import LocalDAProvider
from ethclient.l2.interfaces import DAProvider, L1Backend, ProofBackend, StateTransitionFunction
from ethclient.l2.l1_backend import InMemoryL1Backend
from ethclient.l2.prover import Groth16ProofBackend
from ethclient.l2.runtime import PythonRuntime
from ethclient.l2.sequencer import Sequencer
from ethclient.l2.state import L2StateStore
from ethclient.l2.submitter import BatchSubmitter
from ethclient.l2.types import Batch, BatchReceipt, L2State, L2Tx, STFResult

logger = logging.getLogger(__name__)


class Rollup:
    """Main orchestrator for the application-specific ZK rollup.

    Usage::

        def my_stf(state, tx):
            state["count"] = state.get("count", 0) + 1
            return STFResult(success=True)

        rollup = Rollup(stf=my_stf)
        rollup.setup()

        rollup.submit_tx(L2Tx(sender=b"\\x01"*20, nonce=0, data={"op": "inc"}))
        batch = rollup.produce_batch()
        receipt = rollup.prove_and_submit(batch)
        assert receipt.verified
    """

    def __init__(
        self,
        stf: StateTransitionFunction | Callable | None = None,
        da: Optional[DAProvider] = None,
        l1: Optional[L1Backend] = None,
        prover: Optional[ProofBackend] = None,
        config: Optional[L2Config] = None,
    ) -> None:
        self._config = config or L2Config()

        # Wrap callable as PythonRuntime
        if stf is None:
            self._stf: StateTransitionFunction = PythonRuntime(lambda state, tx: STFResult(success=True))
        elif isinstance(stf, StateTransitionFunction):
            self._stf = stf
        elif callable(stf):
            self._stf = PythonRuntime(stf)
        else:
            raise TypeError(f"stf must be callable or StateTransitionFunction, got {type(stf)}")

        self._da = da or LocalDAProvider()
        self._l1 = l1 or InMemoryL1Backend()
        self._prover = prover or Groth16ProofBackend()

        # Initialize state from STF genesis
        genesis = self._stf.genesis_state()
        self._state_store = L2StateStore(genesis)

        # Build sequencer
        self._sequencer = Sequencer(
            stf=self._stf,
            state_store=self._state_store,
            da=self._da,
            config=self._config,
        )

        self._submitter: Optional[BatchSubmitter] = None
        self._initial_root: Optional[bytes] = None
        self._is_setup = False

    @property
    def state(self) -> L2State:
        return self._state_store.state

    @property
    def state_root(self) -> bytes:
        return self._state_store.compute_state_root()

    @property
    def is_setup(self) -> bool:
        return self._is_setup

    def setup(self) -> None:
        """Perform trusted setup (ZK circuit setup + verifier deployment)."""
        self._initial_root = self._state_store.compute_state_root()
        self._prover.setup(self._stf, self._config.max_txs_per_batch)
        self._l1.deploy_verifier(self._prover.verification_key)
        self._submitter = BatchSubmitter(self._prover, self._l1)
        self._is_setup = True
        logger.info("Rollup setup complete: %s", self._config.name)

    def submit_tx(self, tx: L2Tx) -> Optional[str]:
        """Submit a transaction to the sequencer."""
        return self._sequencer.submit_tx(tx)

    def produce_batch(self) -> Batch:
        """Process pending txs and produce a sealed batch."""
        self._sequencer.tick()
        batch = self._sequencer.force_seal()
        if batch is None:
            raise RuntimeError("No transactions to batch")
        return batch

    def prove_and_submit(self, batch: Batch) -> BatchReceipt:
        """Prove a batch and submit to L1."""
        if self._submitter is None:
            raise RuntimeError("Must call setup() before prove_and_submit()")
        return self._submitter.process_batch(batch)

    def get_sealed_batches(self) -> list[Batch]:
        """Return all sealed batches."""
        return self._sequencer.sealed_batches

    def get_batch(self, batch_number: int) -> Optional[Batch]:
        """Find a sealed batch by number."""
        for batch in self._sequencer.sealed_batches:
            if batch.number == batch_number:
                return batch
        return None

    def prove_batch(self, batch: Batch) -> Batch:
        """Prove a single batch (without submitting)."""
        if self._submitter is None:
            raise RuntimeError("Must call setup() before prove_batch()")
        return self._submitter.prove_batch(batch)

    def submit_batch(self, batch: Batch) -> BatchReceipt:
        """Submit a proven batch to L1."""
        if self._submitter is None:
            raise RuntimeError("Must call setup() before submit_batch()")
        return self._submitter.submit_batch(batch)

    def chain_info(self) -> dict:
        """Return info about the rollup chain."""
        return {
            "name": self._config.name,
            "chain_id": self._config.chain_id,
            "state_root": self._state_store.compute_state_root().hex(),
            "is_setup": self._is_setup,
            "pending_txs": self._sequencer.pending_tx_count,
            "sealed_batches": len(self._sequencer.sealed_batches),
        }
