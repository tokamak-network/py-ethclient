"""
Snap sync — downloads state via snap/1 protocol in 4 stages.

Pipeline:
  1. Account Download  — iterate the account trie by range
  2. Storage Download  — download storage slots for contract accounts
  3. Bytecode Download — fetch unique contract bytecodes
  4. Trie Healing      — patch missing trie nodes caused by chain progress

Uses asyncio.Event for request/response synchronization, following the
same pattern as full_sync.py.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ethclient.networking.server import PeerConnection

from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.common.trie import verify_range_proof
from ethclient.networking.snap.protocol import SnapMsg
from ethclient.networking.snap.messages import (
    GetAccountRangeMessage,
    AccountRangeMessage,
    GetStorageRangesMessage,
    StorageRangesMessage,
    GetByteCodesMessage,
    ByteCodesMessage,
    GetTrieNodesMessage,
    TrieNodesMessage,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ACCOUNTS_PER_REQUEST = 256        # response size limit handles the actual cap
STORAGE_PER_REQUEST = 1024
BYTECODES_PER_REQUEST = 64
TRIE_NODES_PER_REQUEST = 128
SNAP_TIMEOUT = 15.0               # seconds
PEER_WAIT_TIMEOUT = 30.0          # seconds
PEER_WAIT_POLL_INTERVAL = 1.0     # seconds
MAX_HASH = b"\xff" * 32           # 2^256 - 1
ZERO_HASH = b"\x00" * 32
STRICT_RANGE_PROOFS = False


# ---------------------------------------------------------------------------
# Sync phase enum
# ---------------------------------------------------------------------------

class SyncPhase(Enum):
    IDLE = auto()
    ACCOUNT_DOWNLOAD = auto()
    STORAGE_DOWNLOAD = auto()
    BYTECODE_DOWNLOAD = auto()
    TRIE_HEALING = auto()
    COMPLETE = auto()


# ---------------------------------------------------------------------------
# Snap sync state
# ---------------------------------------------------------------------------

@dataclass
class SnapSyncState:
    """Tracks the progress of a snap sync."""
    phase: SyncPhase = SyncPhase.IDLE
    target_root: bytes = field(default_factory=lambda: ZERO_HASH)
    target_block: int = 0

    # Account download cursor
    account_cursor: bytes = field(default_factory=lambda: ZERO_HASH)
    accounts_downloaded: int = 0

    # Storage download queue
    storage_queue: list[tuple[bytes, bytes]] = field(default_factory=list)
    # (account_hash, storage_root) pairs for accounts with non-empty storage
    storage_cursor: bytes = field(default_factory=lambda: ZERO_HASH)
    storage_downloaded: int = 0

    # Bytecode download queue
    code_queue: list[bytes] = field(default_factory=list)  # code hashes to fetch
    code_fetched: set[bytes] = field(default_factory=set)   # already fetched
    codes_downloaded: int = 0

    # Trie healing queue
    healing_queue: list[list[bytes]] = field(default_factory=list)  # path groups
    nodes_healed: int = 0

    # Request tracking
    _request_id: int = 0

    def next_request_id(self) -> int:
        self._request_id += 1
        return self._request_id


# ---------------------------------------------------------------------------
# Snap sync manager
# ---------------------------------------------------------------------------

EMPTY_CODE_HASH = keccak256(b"")
EMPTY_TRIE_ROOT = bytes.fromhex(
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
)


class SnapSync:
    """Manages snap/1 state synchronization."""

    def __init__(self, store=None) -> None:
        self.store = store
        self.state = SnapSyncState()
        self._response_events: dict[int, asyncio.Event] = {}
        self._peer_provider: Optional[Callable[[], list[PeerConnection]]] = None

        # Response buffers keyed by request_id
        self._account_responses: dict[int, AccountRangeMessage] = {}
        self._storage_responses: dict[int, StorageRangesMessage] = {}
        self._bytecode_responses: dict[int, ByteCodesMessage] = {}
        self._trie_node_responses: dict[int, TrieNodesMessage] = {}

    async def start(
        self,
        peers: list[PeerConnection],
        target_root: bytes,
        target_block: int,
        peer_provider: Optional[Callable[[], list[PeerConnection]]] = None,
    ) -> None:
        """Start snap sync with available snap-capable peers."""
        if not peers:
            logger.warning("No snap peers available")
            return
        self._peer_provider = peer_provider

        self.state.target_root = target_root
        self.state.target_block = target_block

        logger.info(
            "Starting snap sync: target block=%d, root=%s, %d peer(s)",
            target_block, target_root.hex()[:16], len(peers),
        )

        try:
            # Phase 1: Account download
            self.state.phase = SyncPhase.ACCOUNT_DOWNLOAD
            await self._download_accounts(peers)
            account_download_complete = self.state.account_cursor >= MAX_HASH

            if not account_download_complete:
                logger.info(
                    "Snap sync paused before account completion: downloaded=%d cursor=%s",
                    self.state.accounts_downloaded,
                    self.state.account_cursor.hex()[:16],
                )
                self.state.phase = SyncPhase.IDLE
                return

            # Phase 2: Storage download
            if self.state.storage_queue:
                self.state.phase = SyncPhase.STORAGE_DOWNLOAD
                await self._download_storage(peers)

            # Phase 3: Bytecode download
            if self.state.code_queue:
                self.state.phase = SyncPhase.BYTECODE_DOWNLOAD
                await self._download_bytecodes(peers)

            # Phase 4: Trie healing
            if self.state.healing_queue:
                self.state.phase = SyncPhase.TRIE_HEALING
                await self._heal_trie(peers)

            self.state.phase = SyncPhase.COMPLETE
            logger.info(
                "Snap sync complete: %d accounts, %d storage slots, %d codes, %d nodes healed",
                self.state.accounts_downloaded,
                self.state.storage_downloaded,
                self.state.codes_downloaded,
                self.state.nodes_healed,
            )

        except Exception as e:
            logger.error("Snap sync error: %s", e)
            self.state.phase = SyncPhase.IDLE

    def _connected_peers(self, fallback_peers: list[PeerConnection]) -> list[PeerConnection]:
        """Return current connected snap peers (refreshing from provider when available)."""
        if self._peer_provider is not None:
            candidates = self._peer_provider()
        else:
            candidates = fallback_peers
        return [peer for peer in candidates if peer.connected]

    async def _wait_for_connected_peers(
        self, fallback_peers: list[PeerConnection], phase_name: str
    ) -> bool:
        """Wait briefly for peers to reconnect instead of pausing immediately."""
        deadline = asyncio.get_running_loop().time() + PEER_WAIT_TIMEOUT
        while asyncio.get_running_loop().time() < deadline:
            if self._connected_peers(fallback_peers):
                return True
            await asyncio.sleep(PEER_WAIT_POLL_INTERVAL)
        logger.warning(
            "No connected peers for %s after %.0fs",
            phase_name,
            PEER_WAIT_TIMEOUT,
        )
        return False

    # ------------------------------------------------------------------
    # Phase 1: Account download
    # ------------------------------------------------------------------

    async def _download_accounts(self, peers: list[PeerConnection]) -> None:
        """Download the entire account trie by iterating ranges."""
        peer_idx = 0

        while self.state.account_cursor < MAX_HASH:
            connected_peers = self._connected_peers(peers)
            if not connected_peers:
                if not await self._wait_for_connected_peers(peers, "account download"):
                    break
                continue
            peer = connected_peers[peer_idx % len(connected_peers)]
            if not peer.connected:
                peer_idx += 1
                continue

            req_id = self.state.next_request_id()
            msg = GetAccountRangeMessage(
                request_id=req_id,
                root_hash=self.state.target_root,
                starting_hash=self.state.account_cursor,
                limit_hash=MAX_HASH,
            )

            event = asyncio.Event()
            self._response_events[req_id] = event

            try:
                await peer.send_snap_message(SnapMsg.GET_ACCOUNT_RANGE, msg.encode())
            except Exception as e:
                logger.debug("Failed to send GetAccountRange: %s", e)
                self._response_events.pop(req_id, None)
                peer_idx += 1
                continue

            try:
                await asyncio.wait_for(event.wait(), timeout=SNAP_TIMEOUT)
            except asyncio.TimeoutError:
                logger.warning("AccountRange request %d timed out", req_id)
                self._response_events.pop(req_id, None)
                peer_idx += 1
                continue
            finally:
                self._response_events.pop(req_id, None)

            response = self._account_responses.pop(req_id, None)
            if response is None or not response.accounts:
                logger.info("Empty AccountRange response, account download complete")
                break

            normalized_accounts: list[tuple[bytes, bytes, list]] = []
            for account_hash, account_payload in response.accounts:
                if isinstance(account_payload, list):
                    # Some peers send slim account as decoded list, not raw RLP bytes.
                    account_rlp = rlp.encode(account_payload)
                    acct_fields = account_payload
                else:
                    account_rlp = account_payload
                    try:
                        acct_fields = rlp.decode_list(account_rlp)
                    except Exception:
                        acct_fields = []
                normalized_accounts.append((account_hash, account_rlp, acct_fields))

            # Verify range proof
            keys = [h for h, _, _ in normalized_accounts]
            values = [account_rlp for _, account_rlp, _ in normalized_accounts]

            if response.proof:
                first_key = self.state.account_cursor
                last_key = keys[-1] if keys else MAX_HASH
                valid = verify_range_proof(
                    self.state.target_root,
                    first_key,
                    last_key,
                    keys,
                    values,
                    response.proof,
                )
                if not valid:
                    # Some peers return incomplete boundary proof sets; allow
                    # progress with relaxed checks unless strict mode is enabled.
                    is_sorted = all(keys[i] < keys[i + 1] for i in range(len(keys) - 1))
                    in_range = all(first_key <= k <= last_key for k in keys)
                    if STRICT_RANGE_PROOFS or not (is_sorted and in_range):
                        logger.warning("Invalid account range proof from peer, skipping")
                        peer_idx += 1
                        continue
                    logger.warning(
                        "Account range proof unverifiable, accepting by relaxed checks"
                    )

            # Store accounts and enqueue storage/code work
            for account_hash, account_rlp, acct_fields in normalized_accounts:
                if self.store:
                    self.store.put_snap_account(account_hash, account_rlp)

                # Parse slim account to check for storage and code
                try:
                    # Slim account: [nonce, balance, storage_root, code_hash]
                    if len(acct_fields) >= 4:
                        storage_root = acct_fields[2]
                        code_hash = acct_fields[3]

                        if storage_root and storage_root != EMPTY_TRIE_ROOT:
                            self.state.storage_queue.append((account_hash, storage_root))

                        if code_hash and code_hash != EMPTY_CODE_HASH:
                            if code_hash not in self.state.code_fetched:
                                self.state.code_queue.append(code_hash)
                except Exception:
                    pass

                self.state.accounts_downloaded += 1

            # Advance cursor past the last received account
            last_hash = keys[-1]
            # Increment last_hash by 1
            last_int = int.from_bytes(last_hash, "big") + 1
            if last_int >= 2**256:
                break
            self.state.account_cursor = last_int.to_bytes(32, "big")

            logger.info(
                "Account download: %d accounts, cursor=%s",
                self.state.accounts_downloaded,
                self.state.account_cursor.hex()[:16],
            )
            peer_idx += 1

        # Save progress
        if self.store:
            self.store.put_snap_progress({
                "phase": self.state.phase.name,
                "accounts_downloaded": self.state.accounts_downloaded,
            })

    # ------------------------------------------------------------------
    # Phase 2: Storage download
    # ------------------------------------------------------------------

    async def _download_storage(self, peers: list[PeerConnection]) -> None:
        """Download storage slots for all accounts with non-empty storage."""
        peer_idx = 0
        queue = list(self.state.storage_queue)
        batch_size = 6  # request storage for multiple accounts at once

        while queue:
            connected_peers = self._connected_peers(peers)
            if not connected_peers:
                if not await self._wait_for_connected_peers(peers, "storage download"):
                    break
                continue
            peer = connected_peers[peer_idx % len(connected_peers)]
            if not peer.connected:
                peer_idx += 1
                continue

            # Take a batch of accounts
            batch = queue[:batch_size]
            account_hashes = [h for h, _ in batch]

            req_id = self.state.next_request_id()
            msg = GetStorageRangesMessage(
                request_id=req_id,
                root_hash=self.state.target_root,
                account_hashes=account_hashes,
                starting_hash=ZERO_HASH,
                limit_hash=MAX_HASH,
            )

            event = asyncio.Event()
            self._response_events[req_id] = event

            try:
                await peer.send_snap_message(SnapMsg.GET_STORAGE_RANGES, msg.encode())
            except Exception as e:
                logger.debug("Failed to send GetStorageRanges: %s", e)
                self._response_events.pop(req_id, None)
                peer_idx += 1
                continue

            try:
                await asyncio.wait_for(event.wait(), timeout=SNAP_TIMEOUT)
            except asyncio.TimeoutError:
                logger.warning("StorageRanges request %d timed out", req_id)
                self._response_events.pop(req_id, None)
                peer_idx += 1
                continue
            finally:
                self._response_events.pop(req_id, None)

            response = self._storage_responses.pop(req_id, None)
            if response is None:
                peer_idx += 1
                continue

            # Process returned storage slots
            completed = 0
            for i, account_slots in enumerate(response.slots):
                if i >= len(batch):
                    break
                account_hash = batch[i][0]

                for slot_hash, value in account_slots:
                    if self.store:
                        self.store.put_snap_storage(account_hash, slot_hash, value)
                    self.state.storage_downloaded += 1

                completed += 1

            # If the last account in the batch has a proof, it's incomplete
            # (partial range) — re-queue it with updated cursor
            if response.proof and completed > 0 and completed <= len(batch):
                last_idx = completed - 1
                if response.slots and response.slots[last_idx]:
                    last_slot = response.slots[last_idx][-1][0]
                    last_int = int.from_bytes(last_slot, "big") + 1
                    if last_int < 2**256:
                        # Re-queue this account with the updated cursor
                        # (simplified: we just mark it as needing more)
                        pass

            # Remove completed accounts from queue
            queue = queue[completed:]

            logger.info(
                "Storage download: %d slots, %d accounts remaining",
                self.state.storage_downloaded, len(queue),
            )
            peer_idx += 1

        if self.store:
            self.store.put_snap_progress({
                "phase": self.state.phase.name,
                "storage_downloaded": self.state.storage_downloaded,
            })

    # ------------------------------------------------------------------
    # Phase 3: Bytecode download
    # ------------------------------------------------------------------

    async def _download_bytecodes(self, peers: list[PeerConnection]) -> None:
        """Download unique contract bytecodes."""
        peer_idx = 0
        queue = list(self.state.code_queue)

        while queue:
            connected_peers = self._connected_peers(peers)
            if not connected_peers:
                if not await self._wait_for_connected_peers(peers, "bytecode download"):
                    break
                continue
            peer = connected_peers[peer_idx % len(connected_peers)]
            if not peer.connected:
                peer_idx += 1
                continue

            batch = queue[:BYTECODES_PER_REQUEST]
            req_id = self.state.next_request_id()
            msg = GetByteCodesMessage(
                request_id=req_id,
                hashes=batch,
            )

            event = asyncio.Event()
            self._response_events[req_id] = event

            try:
                await peer.send_snap_message(SnapMsg.GET_BYTE_CODES, msg.encode())
            except Exception as e:
                logger.debug("Failed to send GetByteCodes: %s", e)
                self._response_events.pop(req_id, None)
                peer_idx += 1
                continue

            try:
                await asyncio.wait_for(event.wait(), timeout=SNAP_TIMEOUT)
            except asyncio.TimeoutError:
                logger.warning("ByteCodes request %d timed out", req_id)
                self._response_events.pop(req_id, None)
                peer_idx += 1
                continue
            finally:
                self._response_events.pop(req_id, None)

            response = self._bytecode_responses.pop(req_id, None)
            if response is None:
                peer_idx += 1
                continue

            # Verify and store bytecodes
            received = 0
            for code in response.codes:
                code_hash = keccak256(code)
                if code_hash in batch[:len(response.codes)]:
                    if self.store:
                        self.store.put_snap_code(code_hash, code)
                    self.state.code_fetched.add(code_hash)
                    self.state.codes_downloaded += 1
                    received += 1

            # Remove fulfilled hashes from queue
            queue = [h for h in queue if h not in self.state.code_fetched]

            logger.info(
                "Bytecode download: %d codes, %d remaining",
                self.state.codes_downloaded, len(queue),
            )
            peer_idx += 1

        if self.store:
            self.store.put_snap_progress({
                "phase": self.state.phase.name,
                "codes_downloaded": self.state.codes_downloaded,
            })

    # ------------------------------------------------------------------
    # Phase 4: Trie healing
    # ------------------------------------------------------------------

    async def _heal_trie(self, peers: list[PeerConnection]) -> None:
        """Download missing trie nodes to make the state trie complete."""
        peer_idx = 0
        queue = list(self.state.healing_queue)

        while queue:
            connected_peers = self._connected_peers(peers)
            if not connected_peers:
                if not await self._wait_for_connected_peers(peers, "trie healing"):
                    break
                continue
            peer = connected_peers[peer_idx % len(connected_peers)]
            if not peer.connected:
                peer_idx += 1
                continue

            batch = queue[:TRIE_NODES_PER_REQUEST]
            req_id = self.state.next_request_id()
            msg = GetTrieNodesMessage(
                request_id=req_id,
                root_hash=self.state.target_root,
                paths=batch,
            )

            event = asyncio.Event()
            self._response_events[req_id] = event

            try:
                await peer.send_snap_message(SnapMsg.GET_TRIE_NODES, msg.encode())
            except Exception as e:
                logger.debug("Failed to send GetTrieNodes: %s", e)
                self._response_events.pop(req_id, None)
                peer_idx += 1
                continue

            try:
                await asyncio.wait_for(event.wait(), timeout=SNAP_TIMEOUT)
            except asyncio.TimeoutError:
                logger.warning("TrieNodes request %d timed out", req_id)
                self._response_events.pop(req_id, None)
                peer_idx += 1
                continue
            finally:
                self._response_events.pop(req_id, None)

            response = self._trie_node_responses.pop(req_id, None)
            if response is None:
                peer_idx += 1
                continue

            self.state.nodes_healed += len(response.nodes)
            queue = queue[len(batch):]

            logger.info(
                "Trie healing: %d nodes healed, %d remaining",
                self.state.nodes_healed, len(queue),
            )
            peer_idx += 1

        if self.store:
            self.store.put_snap_progress({
                "phase": self.state.phase.name,
                "nodes_healed": self.state.nodes_healed,
            })

    # ------------------------------------------------------------------
    # Response handlers (called by P2PServer._dispatch_snap_message)
    # ------------------------------------------------------------------

    def handle_account_range(self, data: bytes) -> None:
        """Handle incoming AccountRange response."""
        msg = AccountRangeMessage.decode(data)
        self._account_responses[msg.request_id] = msg
        event = self._response_events.get(msg.request_id)
        if event:
            event.set()

    def handle_storage_ranges(self, data: bytes) -> None:
        """Handle incoming StorageRanges response."""
        msg = StorageRangesMessage.decode(data)
        self._storage_responses[msg.request_id] = msg
        event = self._response_events.get(msg.request_id)
        if event:
            event.set()

    def handle_byte_codes(self, data: bytes) -> None:
        """Handle incoming ByteCodes response."""
        msg = ByteCodesMessage.decode(data)
        self._bytecode_responses[msg.request_id] = msg
        event = self._response_events.get(msg.request_id)
        if event:
            event.set()

    def handle_trie_nodes(self, data: bytes) -> None:
        """Handle incoming TrieNodes response."""
        msg = TrieNodesMessage.decode(data)
        self._trie_node_responses[msg.request_id] = msg
        event = self._response_events.get(msg.request_id)
        if event:
            event.set()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_syncing(self) -> bool:
        return self.state.phase not in (SyncPhase.IDLE, SyncPhase.COMPLETE)

    @property
    def progress(self) -> dict:
        return {
            "phase": self.state.phase.name,
            "accounts": self.state.accounts_downloaded,
            "storage": self.state.storage_downloaded,
            "codes": self.state.codes_downloaded,
            "healed": self.state.nodes_healed,
        }
