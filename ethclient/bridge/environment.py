"""BridgeEnvironment — unified L1 + L2 + Watcher for prototyping and testing.

Bundles two independent stores, two messengers, and a watcher into a single
object. Provides convenience methods for the common deposit/withdraw/relay
cycle.

In production, L1 and L2 would be separate nodes. This environment simulates
both in one process for rapid iteration.
"""

from __future__ import annotations

from ethclient.storage.memory_backend import MemoryBackend
from ethclient.bridge.messenger import CrossDomainMessenger
from ethclient.bridge.watcher import BridgeWatcher
from ethclient.bridge.types import (
    BatchRelayResult,
    CrossDomainMessage,
    Domain,
    ForceInclusionEntry,
    RelayResult,
)
from ethclient.bridge.relay_handlers import (
    RelayHandler,
    EVMRelayHandler,
    MerkleProofHandler,
    ZKProofHandler,
    DirectStateHandler,
)


class BridgeEnvironment:
    """L1 + L2 + Watcher in a single process.

    Usage:
        env = BridgeEnvironment()

        # L1 → L2: send a message
        msg = env.send_l1(sender=alice, target=l2_contract, data=calldata)
        result = env.relay()    # watcher relays L1→L2

        # L2 → L1: send back
        msg = env.send_l2(sender=l2_contract, target=alice, data=response)
        result = env.relay()    # watcher relays L2→L1
    """

    def __init__(
        self,
        l1_chain_id: int = 1,
        l2_chain_id: int = 42170,
        l1_handler: RelayHandler | None = None,
        l2_handler: RelayHandler | None = None,
    ) -> None:
        # Independent stores for each domain
        self.l1_store = MemoryBackend()
        self.l2_store = MemoryBackend()

        # Messengers (with pluggable relay handlers)
        self.l1_messenger = CrossDomainMessenger(
            Domain.L1, self.l1_store, chain_id=l1_chain_id,
            relay_handler=l1_handler,
        )
        self.l2_messenger = CrossDomainMessenger(
            Domain.L2, self.l2_store, chain_id=l2_chain_id,
            relay_handler=l2_handler,
        )

        # Watcher
        self.watcher = BridgeWatcher(self.l1_messenger, self.l2_messenger)

    # ------------------------------------------------------------------
    # Factory classmethods for common relay modes
    # ------------------------------------------------------------------

    @classmethod
    def with_evm(cls, **kwargs) -> "BridgeEnvironment":
        """Create environment with default EVM relay (both domains)."""
        return cls(**kwargs)

    @classmethod
    def with_merkle_proof(cls, **kwargs) -> "BridgeEnvironment":
        """Create environment with Merkle proof relay on L2."""
        handler = MerkleProofHandler()
        env = cls(l2_handler=handler, **kwargs)
        return env

    @classmethod
    def with_zk_proof(cls, vk: object, **kwargs) -> "BridgeEnvironment":
        """Create environment with ZK proof relay on L2.

        Args:
            vk: Groth16 VerificationKey for proof verification
        """
        handler = ZKProofHandler(vk)
        return cls(l2_handler=handler, **kwargs)

    @classmethod
    def with_direct_state(cls, **kwargs) -> "BridgeEnvironment":
        """Create environment with trusted direct state relay on L2."""
        handler = DirectStateHandler()
        return cls(l2_handler=handler, **kwargs)

    # ------------------------------------------------------------------
    # Send messages
    # ------------------------------------------------------------------

    def send_l1(
        self,
        sender: bytes,
        target: bytes,
        data: bytes = b"",
        value: int = 0,
        gas_limit: int = 1_000_000,
    ) -> CrossDomainMessage:
        """Send a message from L1 → L2 (queued until relay)."""
        return self.l1_messenger.send_message(
            sender=sender, target=target, data=data,
            value=value, gas_limit=gas_limit,
        )

    def send_l2(
        self,
        sender: bytes,
        target: bytes,
        data: bytes = b"",
        value: int = 0,
        gas_limit: int = 1_000_000,
    ) -> CrossDomainMessage:
        """Send a message from L2 → L1 (queued until relay)."""
        return self.l2_messenger.send_message(
            sender=sender, target=target, data=data,
            value=value, gas_limit=gas_limit,
        )

    # ------------------------------------------------------------------
    # Relay
    # ------------------------------------------------------------------

    def relay(self) -> BatchRelayResult:
        """Run one watcher tick: relay all pending messages both directions."""
        return self.watcher.tick()

    # ------------------------------------------------------------------
    # Force Inclusion + Escape Hatch
    # ------------------------------------------------------------------

    def force_include(self, msg: CrossDomainMessage) -> ForceInclusionEntry:
        """Register a censored L1→L2 message for force inclusion."""
        return self.l1_messenger.force_include(msg)

    def force_relay(self, msg: CrossDomainMessage) -> RelayResult:
        """Force-relay after inclusion window elapsed."""
        return self.l1_messenger.force_relay(msg, self.l2_messenger)

    def escape_hatch(self, msg: CrossDomainMessage) -> RelayResult:
        """Last resort: recover value on L1."""
        return self.l1_messenger.escape_hatch(msg)

    def advance_l1_block(self, n: int = 1) -> None:
        """Simulate L1 block progression (for force inclusion window)."""
        self.l1_messenger.block_number += n

    # ------------------------------------------------------------------
    # State root commitment (for proof-based relay)
    # ------------------------------------------------------------------

    def commit_l1_root(self) -> bytes:
        """Compute L1 state root and register it as trusted on L2's handler.

        Returns the committed root. Only works if L2 uses MerkleProofHandler.
        """
        root = self.l1_store.compute_state_root()
        handler = self.l2_messenger.relay_handler
        if isinstance(handler, MerkleProofHandler):
            handler.add_trusted_root(root)
        return root

    def commit_l2_root(self) -> bytes:
        """Compute L2 state root and register it as trusted on L1's handler.

        Returns the committed root. Only works if L1 uses MerkleProofHandler.
        """
        root = self.l2_store.compute_state_root()
        handler = self.l1_messenger.relay_handler
        if isinstance(handler, MerkleProofHandler):
            handler.add_trusted_root(root)
        return root

    # ------------------------------------------------------------------
    # State inspection
    # ------------------------------------------------------------------

    def l1_balance(self, address: bytes) -> int:
        return self.l1_store.get_balance(address)

    def l2_balance(self, address: bytes) -> int:
        return self.l2_store.get_balance(address)

    def l1_storage(self, address: bytes, key: int) -> int:
        return self.l1_store.get_storage(address, key)

    def l2_storage(self, address: bytes, key: int) -> int:
        return self.l2_store.get_storage(address, key)

    def l1_state_root(self) -> bytes:
        return self.l1_store.compute_state_root()

    def l2_state_root(self) -> bytes:
        return self.l2_store.compute_state_root()
