"""Rollup — main user-facing orchestrator for the L2 rollup framework."""

from __future__ import annotations

import json
import logging
import time
from typing import Callable, Optional

from ethclient.l2.config import L2Config, resolve_hash_function
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
        self._l1 = l1 or self._create_l1_backend()
        self._prover = prover or self._create_prover_backend()
        self._hash_fn = resolve_hash_function(self._config.hash_function)

        # Initialize state from STF genesis
        genesis = self._stf.genesis_state()
        self._state_store = self._create_state_store(genesis)

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
        # WAL: nonce checkpoint after seal
        self._wal_write("nonce_checkpoint",
                        json.dumps({k.hex(): v for k, v in self._sequencer._nonces.items()}).encode())
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
        result = self._submitter.prove_batch(batch)
        # WAL: record proof (batch_number as 8 bytes + proof marker)
        proof_marker = b"proven"
        self._wal_write("batch_proven", batch.number.to_bytes(8, "big") + proof_marker)
        return result

    def submit_batch(self, batch: Batch) -> BatchReceipt:
        """Submit a proven batch to L1."""
        if self._submitter is None:
            raise RuntimeError("Must call setup() before submit_batch()")
        return self._submitter.submit_batch(batch)

    def chain_info(self) -> dict:
        """Return info about the rollup chain."""
        info = {
            "name": self._config.name,
            "chain_id": self._config.chain_id,
            "state_root": self._state_store.compute_state_root().hex(),
            "is_setup": self._is_setup,
            "pending_txs": self._sequencer.pending_tx_count,
            "sealed_batches": len(self._sequencer.sealed_batches),
            "sequencer_alive": self._sequencer.is_alive,
            "last_activity_seconds_ago": round(self._sequencer.last_activity_age, 2),
        }
        return info

    def _create_state_store(self, genesis: dict):
        """Create state store based on config."""
        hash_fn = self._hash_fn if self._config.hash_function != "keccak256" else None
        if self._config.state_backend == "lmdb":
            from pathlib import Path
            from ethclient.l2.persistent_state import L2PersistentStateStore
            return L2PersistentStateStore(Path(self._config.data_dir), initial_state=genesis, hash_fn=hash_fn)
        return L2StateStore(genesis, hash_fn=hash_fn)

    def _create_l1_backend(self) -> L1Backend:
        """Create L1 backend based on config."""
        if self._config.l1_backend == "eth_rpc":
            from ethclient.l2.eth_l1_backend import EthL1Backend
            pk = bytes.fromhex(self._config.l1_private_key) if self._config.l1_private_key else b""
            return EthL1Backend(
                rpc_url=self._config.l1_rpc_url,
                private_key=pk,
                chain_id=self._config.l1_chain_id,
                confirmations=self._config.l1_confirmations,
            )
        return InMemoryL1Backend()

    def _create_prover_backend(self) -> ProofBackend:
        """Create prover backend based on config."""
        if self._config.prover_backend == "native":
            from ethclient.l2.native_prover import NativeProverBackend
            return NativeProverBackend(
                prover_binary=self._config.prover_binary,
                working_dir=self._config.prover_working_dir or None,
            )
        return Groth16ProofBackend()

    def _wal_write(self, entry_type: str, data: bytes) -> None:
        """Write a WAL entry if using LMDB state backend."""
        from ethclient.l2.persistent_state import L2PersistentStateStore, WALEntry
        if isinstance(self._state_store, L2PersistentStateStore):
            entry = WALEntry(sequence=0, entry_type=entry_type, data=data,
                             timestamp=int(time.time()))
            self._state_store.wal_append(entry)

    def recover(self) -> None:
        """Replay WAL entries for crash recovery (requires LMDB state backend)."""
        from ethclient.l2.persistent_state import L2PersistentStateStore
        if not isinstance(self._state_store, L2PersistentStateStore):
            return
        entries = self._state_store.wal_replay()
        if not entries:
            return
        max_seq = 0
        for entry in entries:
            self._apply_wal_entry(entry)
            max_seq = max(max_seq, entry.sequence)
        self._state_store.wal_truncate(max_seq)

    def _apply_wal_entry(self, entry) -> None:
        """Apply a single WAL entry during recovery."""
        if entry.entry_type == "batch_sealed":
            batch = Batch.decode(entry.data)
            self._sequencer._sealed_batches.append(batch)
        elif entry.entry_type == "batch_submitted":
            batch_number = int.from_bytes(entry.data[:8], "big")
            for b in self._sequencer._sealed_batches:
                if b.number == batch_number:
                    b.submitted = True
                    break
        elif entry.entry_type == "batch_proven":
            batch_number = int.from_bytes(entry.data[:8], "big")
            proof_data = entry.data[8:]
            for b in self._sequencer._sealed_batches:
                if b.number == batch_number:
                    b.proven = True
                    break
            # Also persist proof data
            from ethclient.l2.persistent_state import L2PersistentStateStore
            if isinstance(self._state_store, L2PersistentStateStore) and proof_data:
                self._state_store.put_proof(batch_number, proof_data)
        elif entry.entry_type == "nonce_checkpoint":
            nonce_data = json.loads(entry.data)
            recovered = {bytes.fromhex(k): v for k, v in nonce_data.items()}
            self._sequencer._nonces.update(recovered)
