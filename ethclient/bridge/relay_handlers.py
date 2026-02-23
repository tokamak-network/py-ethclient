"""Pluggable relay handlers for cross-domain message execution.

Each handler implements a different strategy for applying state changes
when a message is relayed from one domain to another:

- EVMRelayHandler:      Execute calldata in EVM (default, backward-compatible)
- MerkleProofHandler:   Verify Merkle proof against trusted root, then apply state
- ZKProofHandler:       Verify Groth16 proof, then apply state
- DirectStateHandler:   Trusted relayer — apply state updates directly
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.common.types import Account
from ethclient.common.trie import Trie, verify_proof
from ethclient.storage.store import Store

from ethclient.bridge.types import CrossDomainMessage, RelayResult


# ---------------------------------------------------------------------------
# StateUpdate — common data structure for non-EVM handlers
# ---------------------------------------------------------------------------

@dataclass
class StateUpdate:
    """A single account state update to apply on the target domain."""

    address: bytes  # 20-byte address
    balance: Optional[int] = None
    nonce: Optional[int] = None
    storage: dict[int, int] = field(default_factory=dict)

    def encode(self) -> bytes:
        """RLP-encode this state update."""
        storage_list = [
            [key.to_bytes(32, "big"), val.to_bytes(32, "big")]
            for key, val in sorted(self.storage.items())
        ]
        return rlp.encode([
            self.address,
            self.balance if self.balance is not None else b"",
            self.nonce if self.nonce is not None else b"",
            storage_list,
        ])

    @classmethod
    def decode(cls, data: bytes) -> StateUpdate:
        """Decode an RLP-encoded state update."""
        items = rlp.decode(data)
        address = items[0]
        balance = _decode_optional_int(items[1])
        nonce = _decode_optional_int(items[2])
        storage: dict[int, int] = {}
        for pair in items[3]:
            key = int.from_bytes(pair[0], "big")
            val = int.from_bytes(pair[1], "big")
            storage[key] = val
        return cls(address=address, balance=balance, nonce=nonce, storage=storage)


def _decode_optional_int(val: bytes) -> Optional[int]:
    """Decode an RLP integer that may be empty (representing None)."""
    if not val:
        return None
    return int.from_bytes(val, "big")


def encode_state_updates(updates: list[StateUpdate]) -> bytes:
    """RLP-encode a list of state updates for use in msg.data."""
    encoded_items = [u.encode() for u in updates]
    return rlp.encode(encoded_items)


def decode_state_updates(data: bytes) -> list[StateUpdate]:
    """Decode an RLP-encoded list of state updates from msg.data."""
    items = rlp.decode(data)
    return [StateUpdate.decode(item) for item in items]


# ---------------------------------------------------------------------------
# RelayHandler ABC
# ---------------------------------------------------------------------------

class RelayHandler(ABC):
    """Abstract base class for relay execution strategies."""

    @abstractmethod
    def execute(
        self,
        msg: CrossDomainMessage,
        store: Store,
        block_number: int,
        chain_id: int,
    ) -> RelayResult:
        """Execute a cross-domain message and return the result.

        Args:
            msg:          The message to relay
            store:        Target domain's state store
            block_number: Current block number on target domain
            chain_id:     Target domain's chain ID
        """
        ...


# ---------------------------------------------------------------------------
# EVMRelayHandler — default, backward-compatible
# ---------------------------------------------------------------------------

class EVMRelayHandler(RelayHandler):
    """Execute message calldata in the EVM (original behavior)."""

    def execute(
        self,
        msg: CrossDomainMessage,
        store: Store,
        block_number: int,
        chain_id: int,
    ) -> RelayResult:
        from ethclient.vm.evm import ExecutionEnvironment, run_bytecode, CallFrame
        from ethclient.vm.precompiles import PRECOMPILES
        from ethclient.vm.hooks import DefaultHook
        from ethclient.bridge.messenger import (
            MESSENGER_ADDRESS,
            _bind_env_to_store,
            _sync_env_to_store,
        )

        env = ExecutionEnvironment()
        env.block_number = block_number
        env.chain_id = chain_id
        env.gas_limit = 30_000_000
        env.hook = DefaultHook()

        _bind_env_to_store(env, store)

        env.access_sets.mark_warm_address(MESSENGER_ADDRESS)
        env.access_sets.mark_warm_address(msg.target)
        for pa in PRECOMPILES:
            env.access_sets.mark_warm_address(pa)

        if msg.value > 0:
            env.add_balance(msg.target, msg.value)

        code = env.get_code(msg.target)
        frame = CallFrame(
            caller=MESSENGER_ADDRESS,
            address=msg.target,
            code_address=msg.target,
            origin=MESSENGER_ADDRESS,
            code=code,
            gas=msg.gas_limit,
            value=msg.value,
            calldata=msg.data,
            depth=0,
        )

        if code:
            success, return_data = run_bytecode(frame, env)
        else:
            success = True
            return_data = b""

        if success:
            _sync_env_to_store(env, store)

        return RelayResult(
            message=msg,
            success=success,
            return_data=return_data,
            gas_used=frame.gas_used,
            error=None if success else "execution reverted",
        )


# ---------------------------------------------------------------------------
# MerkleProofHandler — verify Merkle proof against trusted state root
# ---------------------------------------------------------------------------

class MerkleProofHandler(RelayHandler):
    """Verify a Merkle proof against a trusted L1 state root, then apply state.

    msg.data format (RLP):
        [state_root, address, account_rlp, [proof_nodes...], [storage_proofs...]]

    storage_proofs is a list of:
        [slot_key(32B), slot_value(32B), [proof_nodes...]]
    """

    def __init__(self) -> None:
        self._trusted_roots: set[bytes] = set()

    def add_trusted_root(self, root: bytes) -> None:
        """Register a state root as trusted (typically committed from L1)."""
        self._trusted_roots.add(root)

    def execute(
        self,
        msg: CrossDomainMessage,
        store: Store,
        block_number: int,
        chain_id: int,
    ) -> RelayResult:
        try:
            items = rlp.decode(msg.data)
            state_root = items[0]
            address = items[1]
            account_rlp = items[2]
            proof_nodes = items[3]
            storage_proofs = items[4] if len(items) > 4 else []
        except Exception as e:
            return RelayResult(
                message=msg, success=False,
                error=f"invalid merkle proof data: {e}",
            )

        # Check trusted root
        if state_root not in self._trusted_roots:
            return RelayResult(
                message=msg, success=False,
                error="state root not trusted",
            )

        # Verify account proof
        key = keccak256(address)
        verified_value = verify_proof(state_root, key, proof_nodes)
        if verified_value is None:
            return RelayResult(
                message=msg, success=False,
                error="merkle proof verification failed",
            )

        if verified_value != account_rlp:
            return RelayResult(
                message=msg, success=False,
                error="account RLP does not match proof",
            )

        # Decode account and apply
        acc_fields = rlp.decode(account_rlp)
        balance = int.from_bytes(acc_fields[1], "big") if acc_fields[1] else 0
        nonce = int.from_bytes(acc_fields[0], "big") if acc_fields[0] else 0

        update = StateUpdate(address=address, balance=balance, nonce=nonce)

        # Verify and collect storage proofs
        # Storage root is acc_fields[2]
        storage_root = acc_fields[2] if len(acc_fields) > 2 else b""
        for sp in storage_proofs:
            slot_key = sp[0]
            slot_value = sp[1]
            sp_nodes = sp[2]

            hashed_slot = keccak256(slot_key)
            verified_slot = verify_proof(storage_root, hashed_slot, sp_nodes)
            if verified_slot is None:
                return RelayResult(
                    message=msg, success=False,
                    error=f"storage proof failed for slot {slot_key.hex()}",
                )
            if verified_slot != slot_value:
                return RelayResult(
                    message=msg, success=False,
                    error=f"storage value mismatch for slot {slot_key.hex()}",
                )
            k = int.from_bytes(slot_key, "big")
            v_decoded = rlp.decode(slot_value)
            v = int.from_bytes(v_decoded, "big") if v_decoded else 0
            update.storage[k] = v

        _apply_state_update(store, update)

        return RelayResult(
            message=msg, success=True,
            return_data=b"",
            gas_used=0,
        )


# ---------------------------------------------------------------------------
# ZKProofHandler — verify Groth16 proof, then apply state
# ---------------------------------------------------------------------------

class ZKProofHandler(RelayHandler):
    """Verify a Groth16 proof and apply the proven state updates.

    msg.data format (RLP):
        [proof_a(64B), proof_b(128B), proof_c(64B), [public_inputs...], [state_updates...]]

    The circuit proves: old_balance + amount = new_balance
    Public inputs: [old_balance, amount, new_balance]
    """

    def __init__(self, vk: object) -> None:
        """Initialize with a Groth16 VerificationKey."""
        self._vk = vk

    def execute(
        self,
        msg: CrossDomainMessage,
        store: Store,
        block_number: int,
        chain_id: int,
    ) -> RelayResult:
        from ethclient.zk.types import G1Point, G2Point, Proof as ZKProof
        from ethclient.zk import groth16

        try:
            items = rlp.decode(msg.data)
            proof_a_bytes = items[0]   # 64 bytes
            proof_b_bytes = items[1]   # 128 bytes
            proof_c_bytes = items[2]   # 64 bytes
            public_inputs_raw = items[3]
            state_updates_raw = items[4]
        except Exception as e:
            return RelayResult(
                message=msg, success=False,
                error=f"invalid ZK proof data: {e}",
            )

        # Decode proof points
        try:
            proof_a = G1Point(
                x=int.from_bytes(proof_a_bytes[:32], "big"),
                y=int.from_bytes(proof_a_bytes[32:64], "big"),
            )
            proof_b = G2Point(
                x_imag=int.from_bytes(proof_b_bytes[:32], "big"),
                x_real=int.from_bytes(proof_b_bytes[32:64], "big"),
                y_imag=int.from_bytes(proof_b_bytes[64:96], "big"),
                y_real=int.from_bytes(proof_b_bytes[96:128], "big"),
            )
            proof_c = G1Point(
                x=int.from_bytes(proof_c_bytes[:32], "big"),
                y=int.from_bytes(proof_c_bytes[32:64], "big"),
            )
            zk_proof = ZKProof(a=proof_a, b=proof_b, c=proof_c)
        except Exception as e:
            return RelayResult(
                message=msg, success=False,
                error=f"invalid proof point encoding: {e}",
            )

        # Decode public inputs
        public_inputs = []
        for inp in public_inputs_raw:
            public_inputs.append(int.from_bytes(inp, "big") if inp else 0)

        # Verify proof
        try:
            valid = groth16.verify(self._vk, zk_proof, public_inputs)
        except Exception as e:
            return RelayResult(
                message=msg, success=False,
                error=f"proof verification error: {e}",
            )

        if not valid:
            return RelayResult(
                message=msg, success=False,
                error="ZK proof verification failed",
            )

        # Apply state updates
        for raw_update in state_updates_raw:
            update = StateUpdate.decode(rlp.encode(raw_update))
            _apply_state_update(store, update)

        return RelayResult(
            message=msg, success=True,
            return_data=b"",
            gas_used=0,
        )


# ---------------------------------------------------------------------------
# DirectStateHandler — trusted relayer, apply state updates directly
# ---------------------------------------------------------------------------

class DirectStateHandler(RelayHandler):
    """Trusted relayer mode: apply state updates directly without proof.

    msg.data format (RLP):
        [state_update_rlp_1, state_update_rlp_2, ...]
    """

    def execute(
        self,
        msg: CrossDomainMessage,
        store: Store,
        block_number: int,
        chain_id: int,
    ) -> RelayResult:
        try:
            updates = decode_state_updates(msg.data)
        except Exception as e:
            return RelayResult(
                message=msg, success=False,
                error=f"invalid state update data: {e}",
            )

        for update in updates:
            _apply_state_update(store, update)

        return RelayResult(
            message=msg, success=True,
            return_data=b"",
            gas_used=0,
        )


# ---------------------------------------------------------------------------
# TinyDBHandler — document DB backend for non-EVM state
# ---------------------------------------------------------------------------

class TinyDBHandler(RelayHandler):
    """Store ZK-verified state in TinyDB instead of Ethereum Store.

    Demonstrates that with proof-based relay, L2 can use *any* runtime
    and storage backend — not just the EVM. State updates are stored as
    JSON documents in TinyDB.

    msg.data format (RLP):
        [state_update_rlp_1, state_update_rlp_2, ...]

    Each update is written to TinyDB as:
        {"address": "0x...", "balance": 123, "nonce": 0, "storage": {"1": 42}}
    """

    def __init__(self, db: object | None = None) -> None:
        """Initialize with optional TinyDB instance.

        If not provided, creates an in-memory TinyDB.
        """
        from tinydb import TinyDB
        from tinydb.storages import MemoryStorage

        if db is None:
            self._db = TinyDB(storage=MemoryStorage)
        else:
            self._db = db

    @property
    def db(self):
        """Access the underlying TinyDB instance."""
        return self._db

    def execute(
        self,
        msg: CrossDomainMessage,
        store: Store,
        block_number: int,
        chain_id: int,
    ) -> RelayResult:
        from tinydb import where

        try:
            updates = decode_state_updates(msg.data)
        except Exception as e:
            return RelayResult(
                message=msg, success=False,
                error=f"invalid state update data: {e}",
            )

        for update in updates:
            addr_hex = "0x" + update.address.hex()

            # Build document
            doc: dict = {"address": addr_hex}
            if update.balance is not None:
                doc["balance"] = update.balance
            if update.nonce is not None:
                doc["nonce"] = update.nonce
            if update.storage:
                doc["storage"] = {
                    str(k): v for k, v in update.storage.items()
                }

            # Upsert: update existing or insert new
            existing = self._db.search(where("address") == addr_hex)
            if existing:
                # Merge fields
                merged = existing[0].copy()
                if "balance" in doc:
                    merged["balance"] = doc["balance"]
                if "nonce" in doc:
                    merged["nonce"] = doc["nonce"]
                if "storage" in doc:
                    old_storage = merged.get("storage", {})
                    old_storage.update(doc["storage"])
                    merged["storage"] = old_storage
                self._db.update(merged, where("address") == addr_hex)
            else:
                self._db.insert(doc)

        return RelayResult(
            message=msg, success=True,
            return_data=b"",
            gas_used=0,
        )

    def get_account(self, address: bytes) -> dict | None:
        """Query an account from TinyDB by address."""
        from tinydb import where
        addr_hex = "0x" + address.hex()
        results = self._db.search(where("address") == addr_hex)
        return results[0] if results else None


# ---------------------------------------------------------------------------
# Shared helper: apply a StateUpdate to a Store
# ---------------------------------------------------------------------------

def _apply_state_update(store: Store, update: StateUpdate) -> None:
    """Apply a single StateUpdate to the store."""
    acc = store.get_account(update.address)
    if acc is None:
        acc = Account()
    if update.balance is not None:
        acc.balance = update.balance
    if update.nonce is not None:
        acc.nonce = update.nonce
    store.put_account(update.address, acc)

    for key, val in update.storage.items():
        store.put_storage(update.address, key, val)
