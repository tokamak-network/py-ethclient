"""CrossDomainMessenger — send and relay arbitrary messages between L1 and L2.

The messenger is the only bridge primitive. It sends arbitrary bytes to any
target address. On relay, the message is executed via a pluggable RelayHandler.

The default EVMRelayHandler preserves the original behavior: calldata is
executed in the EVM. Alternative handlers (MerkleProofHandler, ZKProofHandler,
DirectStateHandler) allow proof-based or trust-based relay without EVM.

This is the Optimism CrossDomainMessenger pattern: the messenger itself is
permissionless. Anyone can send a message, and any contract on the receiving
side can decode and apply the data however it wants.
"""

from __future__ import annotations

from typing import Any

from ethclient.common.crypto import keccak256
from ethclient.common import rlp
from ethclient.storage.store import Store

from ethclient.bridge.types import (
    CrossDomainMessage,
    Domain,
    ForceInclusionEntry,
    RelayResult,
    FORCE_INCLUSION_WINDOW,
)
from ethclient.bridge.relay_handlers import RelayHandler, EVMRelayHandler


# Sentinel address for the messenger itself (system sender for relayed msgs)
MESSENGER_ADDRESS = b"\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42"


class CrossDomainMessenger:
    """Send and relay cross-domain messages via a pluggable RelayHandler.

    Each domain (L1 or L2) has its own messenger instance backed by its own
    Store. Messages are sent to the outbox; the BridgeWatcher picks them up
    and calls relay_message() on the other domain's messenger.

    On relay, execution is delegated to the configured RelayHandler.
    Default: EVMRelayHandler (backward-compatible EVM execution).
    """

    def __init__(
        self,
        domain: Domain,
        store: Store,
        chain_id: int = 1,
        relay_handler: RelayHandler | None = None,
    ) -> None:
        self.domain = domain
        self.store = store
        self.chain_id = chain_id
        self.relay_handler: RelayHandler = relay_handler or EVMRelayHandler()

        self._nonce: int = 0
        self.outbox: list[CrossDomainMessage] = []
        self._relayed: dict[bytes, bool] = {}  # message_hash → relayed

        # Force inclusion queue (L1-side only, keyed by message_hash)
        self._force_queue: dict[bytes, ForceInclusionEntry] = {}

        # Escape hatch: value recovered on L1 (message_hash → True)
        self._escaped: dict[bytes, bool] = {}

        # Current block number (incremented by environment)
        self.block_number: int = 0

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    def send_message(
        self,
        sender: bytes,
        target: bytes,
        data: bytes,
        value: int = 0,
        gas_limit: int = 1_000_000,
    ) -> CrossDomainMessage:
        """Queue a message to be relayed to the other domain.

        Args:
            sender:    20-byte address of the message originator
            target:    20-byte address on the *other* domain to call
            data:      arbitrary calldata (the target contract decodes this)
            value:     ETH value to transfer (minted on the target domain)
            gas_limit: gas budget for execution on the target domain

        Returns:
            The queued CrossDomainMessage with nonce and hash populated.
        """
        msg = CrossDomainMessage(
            nonce=self._nonce,
            sender=sender,
            target=target,
            data=data,
            value=value,
            gas_limit=gas_limit,
            source_domain=self.domain,
            block_number=self.block_number,
        )
        msg.message_hash = _hash_message(msg)
        self._nonce += 1
        self.outbox.append(msg)
        return msg

    # ------------------------------------------------------------------
    # Relay (execute on this domain's EVM)
    # ------------------------------------------------------------------

    def relay_message(self, msg: CrossDomainMessage) -> RelayResult:
        """Relay a cross-domain message: execute msg.data on this domain's EVM.

        This is the core of the bridge. The message data is treated as calldata
        to msg.target, executed with real state changes in this domain's store.

        Replay protection: each message_hash can only be relayed once.

        Returns:
            RelayResult with execution outcome.
        """
        # Replay protection
        if self._relayed.get(msg.message_hash):
            return RelayResult(
                message=msg, success=False, error="message already relayed"
            )

        # Execute in EVM
        result = self._execute(msg)

        # Mark as relayed only if execution succeeded
        if result.success:
            self._relayed[msg.message_hash] = True

        return result

    # ------------------------------------------------------------------
    # State inspection
    # ------------------------------------------------------------------

    def pending_count(self) -> int:
        """Number of messages in outbox waiting to be relayed."""
        return len(self.outbox)

    def drain_outbox(self) -> list[CrossDomainMessage]:
        """Remove and return all pending messages from outbox."""
        msgs = self.outbox[:]
        self.outbox.clear()
        return msgs

    def is_relayed(self, msg: CrossDomainMessage) -> bool:
        """Check if a message has already been relayed."""
        return self._relayed.get(msg.message_hash, False)

    # ------------------------------------------------------------------
    # Force Inclusion (anti-censorship)
    # ------------------------------------------------------------------

    def force_include(self, msg: CrossDomainMessage) -> ForceInclusionEntry:
        """Register a message for force inclusion on L1.

        When the L2 operator censors a message (doesn't relay it), the user
        can register it here. After FORCE_INCLUSION_WINDOW blocks, anyone
        can call force_relay() to execute it on L2, bypassing the operator.

        Must be called on the L1 messenger (the trust anchor).
        """
        if msg.message_hash in self._force_queue:
            return self._force_queue[msg.message_hash]

        entry = ForceInclusionEntry(
            message=msg,
            registered_block=self.block_number,
        )
        self._force_queue[msg.message_hash] = entry
        return entry

    def force_relay(
        self, msg: CrossDomainMessage, target_messenger: "CrossDomainMessenger"
    ) -> RelayResult:
        """Force-relay a message after the inclusion window has passed.

        Bypasses the operator's watcher. Anyone can call this once the
        FORCE_INCLUSION_WINDOW has elapsed since force_include().

        Args:
            msg: The message to force-relay
            target_messenger: The other domain's messenger to execute on
        """
        entry = self._force_queue.get(msg.message_hash)
        if entry is None:
            return RelayResult(
                message=msg, success=False,
                error="message not in force queue",
            )

        if entry.resolved:
            return RelayResult(
                message=msg, success=False,
                error="force inclusion already resolved",
            )

        elapsed = self.block_number - entry.registered_block
        if elapsed < FORCE_INCLUSION_WINDOW:
            return RelayResult(
                message=msg, success=False,
                error=f"force inclusion window not elapsed "
                      f"({elapsed}/{FORCE_INCLUSION_WINDOW} blocks)",
            )

        # Execute on target domain, bypassing operator
        result = target_messenger.relay_message(msg)
        if result.success:
            entry.resolved = True

        return result

    def get_force_queue(self) -> list[ForceInclusionEntry]:
        """Return all pending (unresolved) force inclusion entries."""
        return [e for e in self._force_queue.values() if not e.resolved]

    # ------------------------------------------------------------------
    # Escape Hatch (last resort)
    # ------------------------------------------------------------------

    def escape_hatch(self, msg: CrossDomainMessage) -> RelayResult:
        """Last resort: recover value directly on L1 when L2 is unresponsive.

        If a force-included message still can't be relayed (L2 is completely
        down or malicious), the sender can recover the deposited value on L1.

        Conditions:
          - Message must be in force queue
          - FORCE_INCLUSION_WINDOW must have elapsed
          - Message must not have been relayed or already escaped
          - Only works for messages with value > 0
          - Value is credited to msg.sender on this domain's store
        """
        entry = self._force_queue.get(msg.message_hash)
        if entry is None:
            return RelayResult(
                message=msg, success=False,
                error="message not in force queue",
            )

        if entry.resolved:
            return RelayResult(
                message=msg, success=False,
                error="already resolved (relayed or escaped)",
            )

        elapsed = self.block_number - entry.registered_block
        if elapsed < FORCE_INCLUSION_WINDOW:
            return RelayResult(
                message=msg, success=False,
                error=f"force inclusion window not elapsed "
                      f"({elapsed}/{FORCE_INCLUSION_WINDOW} blocks)",
            )

        if self._escaped.get(msg.message_hash):
            return RelayResult(
                message=msg, success=False,
                error="already escaped",
            )

        if msg.value == 0:
            return RelayResult(
                message=msg, success=False,
                error="no value to recover (escape hatch is for value recovery)",
            )

        # Credit value back to sender on this domain
        from ethclient.common.types import Account
        acc = self.store.get_account(msg.sender)
        if acc is None:
            acc = Account()
        acc.balance += msg.value
        self.store.put_account(msg.sender, acc)

        entry.resolved = True
        self._escaped[msg.message_hash] = True

        return RelayResult(
            message=msg, success=True,
            return_data=b"",
            gas_used=0,
            error=None,
        )

    # ------------------------------------------------------------------
    # Internal: delegate to relay handler
    # ------------------------------------------------------------------

    def _execute(self, msg: CrossDomainMessage) -> RelayResult:
        """Execute a message via the configured relay handler."""
        return self.relay_handler.execute(
            msg, self.store, self.block_number, self.chain_id,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_message(msg: CrossDomainMessage) -> bytes:
    """Compute a unique hash for a cross-domain message."""
    payload = rlp.encode([
        msg.nonce,
        msg.sender,
        msg.target,
        msg.data,
        msg.value,
        msg.gas_limit,
        msg.source_domain.value.encode(),
    ])
    return keccak256(payload)


def _bind_env_to_store(env: Any, store: Store) -> None:
    """Copy store state into EVM environment."""
    env._balances = {}
    env._nonces = {}
    env._code = {}
    env._storage = {}
    env._original_storage = {}

    for addr, acc in store.iter_accounts():
        env._balances[addr] = acc.balance
        env._nonces[addr] = acc.nonce
        code = store.get_account_code(addr)
        if code:
            env._code[addr] = code
    for (addr, key), val in store.iter_storage():
        env._storage[(addr, key)] = val
    for (addr, key), val in store.iter_original_storage():
        env._original_storage[(addr, key)] = val


def _sync_env_to_store(env: Any, store: Store) -> None:
    """Sync EVM state mutations back to store."""
    from ethclient.common.types import Account

    all_addrs = set(env._balances.keys()) | set(env._nonces.keys())
    for addr in all_addrs:
        acc = store.get_account(addr)
        if acc is None:
            acc = Account()
        if addr in env._balances:
            acc.balance = env._balances[addr]
        if addr in env._nonces:
            acc.nonce = env._nonces[addr]
        store.put_account(addr, acc)

    for (addr, key), val in env._storage.items():
        store.put_storage(addr, key, val)

    for addr in env.selfdestructs:
        store.delete_account(addr)
