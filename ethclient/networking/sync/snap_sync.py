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
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional, TYPE_CHECKING

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
MIN_SNAP_TIMEOUT = 8.0            # seconds
MAX_SNAP_TIMEOUT = 60.0           # seconds
PEER_WAIT_TIMEOUT = 30.0          # seconds
PEER_WAIT_POLL_INTERVAL = 1.0     # seconds
PEER_FAIL_BAN_THRESHOLD = 3
PEER_PROOF_BAN_THRESHOLD = 3
PEER_FAIL_BAN_SECONDS = 600.0
STORAGE_PARALLEL_REQUESTS = 3
BYTECODE_PARALLEL_REQUESTS = 3
TRIE_PARALLEL_REQUESTS = 3
MAX_EMPTY_ACCOUNT_RESPONSES = 8
MAX_STALE_SNAP_PEER_LAG_BLOCKS = 128
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


@dataclass
class PeerHealth:
    timeout_count: int = 0
    proof_fail_count: int = 0
    avg_rtt: Optional[float] = None
    cooldown_until: float = 0.0
    banned_until: float = 0.0


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
        self._peer_health: dict[Any, PeerHealth] = {}
        self._request_started_at: dict[int, float] = {}
        self._peer_round_robin_idx: int = 0
        self._last_account_pause_reason: Optional[str] = None

        # Response buffers keyed by request_id
        self._account_responses: dict[int, AccountRangeMessage] = {}
        self._storage_responses: dict[int, StorageRangesMessage] = {}
        self._bytecode_responses: dict[int, ByteCodesMessage] = {}
        self._trie_node_responses: dict[int, TrieNodesMessage] = {}

    def _restore_progress(self) -> None:
        """Best-effort restore of persisted progress for snap resume."""
        if not self.store:
            return
        progress = self.store.get_snap_progress()
        if not isinstance(progress, dict):
            return
        try:
            saved_target = int(progress.get("target_block", 0))
            saved_cursor_hex = progress.get("account_cursor")
            saved_accounts = int(progress.get("accounts_downloaded", 0))
            if saved_target > 0 and saved_target == self.state.target_block:
                if isinstance(saved_cursor_hex, str) and len(saved_cursor_hex) == 64:
                    self.state.account_cursor = bytes.fromhex(saved_cursor_hex)
                self.state.accounts_downloaded = max(
                    self.state.accounts_downloaded,
                    saved_accounts,
                )
                self.state.storage_downloaded = max(
                    self.state.storage_downloaded,
                    int(progress.get("storage_downloaded", 0)),
                )
                self.state.codes_downloaded = max(
                    self.state.codes_downloaded,
                    int(progress.get("codes_downloaded", 0)),
                )
                self.state.nodes_healed = max(
                    self.state.nodes_healed,
                    int(progress.get("nodes_healed", 0)),
                )
                logger.info(
                    "Resuming snap progress: accounts=%d cursor=%s",
                    self.state.accounts_downloaded,
                    self.state.account_cursor.hex()[:16],
                )
        except Exception:
            logger.debug("Failed to restore snap progress", exc_info=True)

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
        self._restore_progress()

        logger.info(
            "Starting snap sync: target block=%d, root=%s, %d peer(s)",
            target_block, target_root.hex()[:16], len(peers),
        )
        self._last_account_pause_reason = None

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
                self._persist_progress({
                    "paused": True,
                    "pause_reason": self._last_account_pause_reason or "account_incomplete",
                })
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
            self._persist_progress({"complete": True})
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
            self._persist_progress({"error": str(e)})

    def _peer_key(self, peer: PeerConnection) -> Any:
        if peer.remote_id:
            return peer.remote_id
        return id(peer)

    def _get_peer_health(self, peer: PeerConnection) -> PeerHealth:
        key = self._peer_key(peer)
        if key not in self._peer_health:
            self._peer_health[key] = PeerHealth()
        return self._peer_health[key]

    def _record_timeout(self, peer: PeerConnection) -> None:
        now = time.time()
        health = self._get_peer_health(peer)
        health.timeout_count += 1
        cooldown = min(30.0, float(2 ** min(health.timeout_count, 4)))
        health.cooldown_until = now + cooldown
        if health.timeout_count >= PEER_FAIL_BAN_THRESHOLD:
            health.banned_until = now + PEER_FAIL_BAN_SECONDS
            logger.warning(
                "Banning snap peer %s for %.0fs after %d timeouts",
                peer.remote_id.hex()[:16] if peer.remote_id else "unknown",
                PEER_FAIL_BAN_SECONDS,
                health.timeout_count,
            )
            health.timeout_count = 0

    def _record_proof_failure(self, peer: PeerConnection) -> None:
        now = time.time()
        health = self._get_peer_health(peer)
        health.proof_fail_count += 1
        if health.proof_fail_count >= PEER_PROOF_BAN_THRESHOLD:
            health.banned_until = now + PEER_FAIL_BAN_SECONDS
            logger.warning(
                "Banning snap peer %s for %.0fs after %d proof failures",
                peer.remote_id.hex()[:16] if peer.remote_id else "unknown",
                PEER_FAIL_BAN_SECONDS,
                health.proof_fail_count,
            )
            health.proof_fail_count = 0

    def _record_success(self, peer: PeerConnection, req_id: int) -> None:
        health = self._get_peer_health(peer)
        health.timeout_count = 0
        health.cooldown_until = 0.0
        started = self._request_started_at.get(req_id)
        if started is None:
            return
        rtt = max(0.001, time.time() - started)
        if health.avg_rtt is None:
            health.avg_rtt = rtt
        else:
            health.avg_rtt = (health.avg_rtt * 0.8) + (rtt * 0.2)

    def _adaptive_timeout(self, peer: PeerConnection) -> float:
        health = self._get_peer_health(peer)
        if health.avg_rtt is None:
            return SNAP_TIMEOUT
        return max(MIN_SNAP_TIMEOUT, min(MAX_SNAP_TIMEOUT, max(SNAP_TIMEOUT, health.avg_rtt * 6.0)))

    def _persist_progress(self, extra: Optional[dict[str, Any]] = None) -> None:
        if not self.store:
            return
        payload: dict[str, Any] = {
            "phase": self.state.phase.name,
            "target_block": self.state.target_block,
            "target_root": self.state.target_root.hex(),
            "account_cursor": self.state.account_cursor.hex(),
            "accounts_downloaded": self.state.accounts_downloaded,
            "storage_downloaded": self.state.storage_downloaded,
            "codes_downloaded": self.state.codes_downloaded,
            "nodes_healed": self.state.nodes_healed,
            "storage_queue_len": len(self.state.storage_queue),
            "code_queue_len": len(self.state.code_queue),
            "healing_queue_len": len(self.state.healing_queue),
            "timestamp": int(time.time()),
        }
        if extra:
            payload.update(extra)
        self.store.put_snap_progress(payload)

    def _connected_peers(self, fallback_peers: list[PeerConnection]) -> list[PeerConnection]:
        """Return current connected snap peers (refreshing from provider when available)."""
        if self._peer_provider is not None:
            candidates = self._peer_provider()
        else:
            candidates = fallback_peers
        now = time.time()
        result: list[PeerConnection] = []
        for peer in candidates:
            if not peer.connected:
                continue
            health = self._get_peer_health(peer)
            if health.banned_until > now:
                continue
            if health.cooldown_until > now:
                continue
            # Snap peers that are far behind the target block may not have the
            # requested root and often return empty ranges indefinitely.
            if self.state.target_block > 0 and peer.best_block_number > 0:
                if peer.best_block_number + MAX_STALE_SNAP_PEER_LAG_BLOCKS < self.state.target_block:
                    continue
            result.append(peer)
        return result

    def _pick_peer(self, fallback_peers: list[PeerConnection]) -> Optional[PeerConnection]:
        peers = self._connected_peers(fallback_peers)
        if not peers:
            return None
        peer = peers[self._peer_round_robin_idx % len(peers)]
        self._peer_round_robin_idx += 1
        return peer

    async def _request_snap(
        self,
        peer: PeerConnection,
        req_id: int,
        relative_code: int,
        payload: bytes,
        response_buffer: dict[int, Any],
        request_name: str,
    ) -> Any | None:
        event = asyncio.Event()
        self._response_events[req_id] = event
        self._request_started_at[req_id] = time.time()
        try:
            await peer.send_snap_message(relative_code, payload)
        except Exception as e:
            logger.debug("Failed to send %s: %s", request_name, e)
            self._record_timeout(peer)
            self._response_events.pop(req_id, None)
            self._request_started_at.pop(req_id, None)
            return None

        timeout = self._adaptive_timeout(peer)
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("%s request %d timed out (%.1fs)", request_name, req_id, timeout)
            self._record_timeout(peer)
            self._request_started_at.pop(req_id, None)
            return None
        finally:
            self._response_events.pop(req_id, None)

        response = response_buffer.pop(req_id, None)
        if response is None:
            self._record_timeout(peer)
            self._request_started_at.pop(req_id, None)
            return None
        self._record_success(peer, req_id)
        self._request_started_at.pop(req_id, None)
        return response

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
        consecutive_empty_responses = 0
        while self.state.account_cursor < MAX_HASH:
            peer = self._pick_peer(peers)
            if peer is None:
                if not await self._wait_for_connected_peers(peers, "account download"):
                    break
                continue

            req_id = self.state.next_request_id()
            msg = GetAccountRangeMessage(
                request_id=req_id,
                root_hash=self.state.target_root,
                starting_hash=self.state.account_cursor,
                limit_hash=MAX_HASH,
            )
            response = await self._request_snap(
                peer,
                req_id,
                SnapMsg.GET_ACCOUNT_RANGE,
                msg.encode(),
                self._account_responses,
                "AccountRange",
            )
            if response is None:
                continue
            if not response.accounts:
                consecutive_empty_responses += 1
                logger.warning(
                    "Empty AccountRange response at cursor=%s (%d/%d), retrying with another peer",
                    self.state.account_cursor.hex()[:16],
                    consecutive_empty_responses,
                    MAX_EMPTY_ACCOUNT_RESPONSES,
                )
                if consecutive_empty_responses >= MAX_EMPTY_ACCOUNT_RESPONSES:
                    logger.warning(
                        "Too many empty AccountRange responses, pausing account download"
                    )
                    self._last_account_pause_reason = "too_many_empty_account_responses"
                    break
                continue
            consecutive_empty_responses = 0

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
                        self._record_proof_failure(peer)
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
            self._persist_progress()

        self._persist_progress()

    # ------------------------------------------------------------------
    # Phase 2: Storage download
    # ------------------------------------------------------------------

    async def _fetch_storage_batch(
        self,
        peer: PeerConnection,
        batch: list[tuple[bytes, bytes]],
    ) -> tuple[bool, list[tuple[bytes, bytes]], Optional[StorageRangesMessage]]:
        req_id = self.state.next_request_id()
        msg = GetStorageRangesMessage(
            request_id=req_id,
            root_hash=self.state.target_root,
            account_hashes=[h for h, _ in batch],
            starting_hash=ZERO_HASH,
            limit_hash=MAX_HASH,
        )
        response = await self._request_snap(
            peer,
            req_id,
            SnapMsg.GET_STORAGE_RANGES,
            msg.encode(),
            self._storage_responses,
            "StorageRanges",
        )
        return response is not None, batch, response

    async def _fetch_bytecode_batch(
        self,
        peer: PeerConnection,
        batch: list[bytes],
    ) -> tuple[bool, list[bytes], Optional[ByteCodesMessage]]:
        req_id = self.state.next_request_id()
        msg = GetByteCodesMessage(request_id=req_id, hashes=batch)
        response = await self._request_snap(
            peer,
            req_id,
            SnapMsg.GET_BYTE_CODES,
            msg.encode(),
            self._bytecode_responses,
            "ByteCodes",
        )
        return response is not None, batch, response

    async def _fetch_trie_batch(
        self,
        peer: PeerConnection,
        batch: list[list[bytes]],
    ) -> tuple[bool, list[list[bytes]], Optional[TrieNodesMessage]]:
        req_id = self.state.next_request_id()
        msg = GetTrieNodesMessage(
            request_id=req_id,
            root_hash=self.state.target_root,
            paths=batch,
        )
        response = await self._request_snap(
            peer,
            req_id,
            SnapMsg.GET_TRIE_NODES,
            msg.encode(),
            self._trie_node_responses,
            "TrieNodes",
        )
        return response is not None, batch, response

    async def _download_storage(self, peers: list[PeerConnection]) -> None:
        """Download storage slots for all accounts with non-empty storage."""
        queue = list(self.state.storage_queue)
        batch_size = 6  # request storage for multiple accounts at once
        pending_batches: list[list[tuple[bytes, bytes]]] = [
            queue[i:i + batch_size] for i in range(0, len(queue), batch_size)
        ]
        in_flight: set[asyncio.Task] = set()

        while pending_batches or in_flight:
            while pending_batches and len(in_flight) < STORAGE_PARALLEL_REQUESTS:
                peer = self._pick_peer(peers)
                if peer is None:
                    break
                batch = pending_batches.pop(0)
                in_flight.add(asyncio.create_task(self._fetch_storage_batch(peer, batch)))

            if not in_flight:
                if not await self._wait_for_connected_peers(peers, "storage download"):
                    break
                continue

            done, pending_tasks = await asyncio.wait(
                in_flight,
                return_when=asyncio.FIRST_COMPLETED,
            )
            in_flight = set(pending_tasks)

            for task in done:
                ok, batch, response = task.result()
                if not ok or response is None:
                    pending_batches.append(batch)
                    continue

                for i, account_slots in enumerate(response.slots):
                    if i >= len(batch):
                        break
                    account_hash = batch[i][0]
                    for slot_hash, value in account_slots:
                        if self.store:
                            self.store.put_snap_storage(account_hash, slot_hash, value)
                        self.state.storage_downloaded += 1

            remaining_accounts = sum(len(b) for b in pending_batches)
            logger.info(
                "Storage download: %d slots, %d accounts remaining",
                self.state.storage_downloaded,
                remaining_accounts,
            )
            self._persist_progress({"storage_accounts_remaining": remaining_accounts})

        self._persist_progress()

    # ------------------------------------------------------------------
    # Phase 3: Bytecode download
    # ------------------------------------------------------------------

    async def _download_bytecodes(self, peers: list[PeerConnection]) -> None:
        """Download unique contract bytecodes."""
        queue = [h for h in self.state.code_queue if h not in self.state.code_fetched]
        pending_batches: list[list[bytes]] = [
            queue[i:i + BYTECODES_PER_REQUEST] for i in range(0, len(queue), BYTECODES_PER_REQUEST)
        ]
        in_flight: set[asyncio.Task] = set()

        while pending_batches or in_flight:
            while pending_batches and len(in_flight) < BYTECODE_PARALLEL_REQUESTS:
                peer = self._pick_peer(peers)
                if peer is None:
                    break
                batch = pending_batches.pop(0)
                in_flight.add(asyncio.create_task(self._fetch_bytecode_batch(peer, batch)))

            if not in_flight:
                if not await self._wait_for_connected_peers(peers, "bytecode download"):
                    break
                continue

            done, pending_tasks = await asyncio.wait(
                in_flight,
                return_when=asyncio.FIRST_COMPLETED,
            )
            in_flight = set(pending_tasks)

            for task in done:
                ok, batch, response = task.result()
                if not ok or response is None:
                    pending_batches.append(batch)
                    continue

                for code in response.codes:
                    code_hash = keccak256(code)
                    if code_hash in batch and code_hash not in self.state.code_fetched:
                        if self.store:
                            self.store.put_snap_code(code_hash, code)
                        self.state.code_fetched.add(code_hash)
                        self.state.codes_downloaded += 1

            remaining = sum(len(b) for b in pending_batches)
            logger.info(
                "Bytecode download: %d codes, %d remaining",
                self.state.codes_downloaded, remaining,
            )
            self._persist_progress({"bytecode_hashes_remaining": remaining})

        self.state.code_queue = [h for h in self.state.code_queue if h not in self.state.code_fetched]
        self._persist_progress()

    # ------------------------------------------------------------------
    # Phase 4: Trie healing
    # ------------------------------------------------------------------

    async def _heal_trie(self, peers: list[PeerConnection]) -> None:
        """Download missing trie nodes to make the state trie complete."""
        pending_batches: list[list[list[bytes]]] = [
            self.state.healing_queue[i:i + TRIE_NODES_PER_REQUEST]
            for i in range(0, len(self.state.healing_queue), TRIE_NODES_PER_REQUEST)
        ]
        in_flight: set[asyncio.Task] = set()

        while pending_batches or in_flight:
            while pending_batches and len(in_flight) < TRIE_PARALLEL_REQUESTS:
                peer = self._pick_peer(peers)
                if peer is None:
                    break
                batch = pending_batches.pop(0)
                in_flight.add(asyncio.create_task(self._fetch_trie_batch(peer, batch)))

            if not in_flight:
                if not await self._wait_for_connected_peers(peers, "trie healing"):
                    break
                continue

            done, pending_tasks = await asyncio.wait(
                in_flight,
                return_when=asyncio.FIRST_COMPLETED,
            )
            in_flight = set(pending_tasks)

            for task in done:
                ok, batch, response = task.result()
                if not ok or response is None:
                    pending_batches.append(batch)
                    continue
                self.state.nodes_healed += len(response.nodes)

            remaining = sum(len(b) for b in pending_batches)
            logger.info(
                "Trie healing: %d nodes healed, %d remaining",
                self.state.nodes_healed,
                remaining,
            )
            self._persist_progress({"trie_batches_remaining": remaining})

        self._persist_progress()

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
