"""
Full sync — downloads headers and bodies from peers, executes blocks sequentially.

Pipeline:
  1. Request headers from best peer
  2. Download bodies for received headers
  3. Execute blocks and update state
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import Executor
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from ethclient.networking.server import PeerConnection

from ethclient.common.types import BlockHeader
from ethclient.networking.eth.protocol import EthMsg
from ethclient.networking.eth.messages import (
    GetBlockHeadersMessage,
    BlockHeadersMessage,
    GetBlockBodiesMessage,
    BlockBodiesMessage,
)

logger = logging.getLogger(__name__)


def _decode_block_headers_message(data: bytes) -> BlockHeadersMessage:
    return BlockHeadersMessage.decode(data)


def _decode_block_bodies_message(data: bytes) -> BlockBodiesMessage:
    return BlockBodiesMessage.decode(data)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HEADERS_PER_REQUEST = 192   # max headers per request
BODIES_PER_REQUEST = 64     # max bodies per request
SYNC_TIMEOUT = 20.0         # seconds
HEADER_RETRY_BACKOFF = 1.0  # seconds
PEER_TIMEOUT_PENALTY_SECONDS = 30.0
SYNC_EXECUTION_YIELD_INTERVAL = 16  # yield to event loop every N executed headers
MAX_HEADER_FAILURES = 2
MAX_BODY_FAILURES = 2
MAX_PEER_TIMEOUT_STRIKES = 6
MAX_SYNC_TIMEOUT_SECONDS = 45.0
MIN_BODIES_PER_REQUEST = 8
HEDGE_HEADER_ATTEMPTS = 2
HEDGE_BODY_ATTEMPTS = 2


# ---------------------------------------------------------------------------
# Sync state
# ---------------------------------------------------------------------------

@dataclass
class SyncState:
    """Tracks the progress of a full sync."""
    target_block: int = 0
    current_block: int = 0
    syncing: bool = False
    best_peer: Optional[PeerConnection] = None
    _request_id: int = 0

    def next_request_id(self) -> int:
        self._request_id += 1
        return self._request_id


# ---------------------------------------------------------------------------
# Full sync manager
# ---------------------------------------------------------------------------

class FullSync:
    """Manages full block synchronization."""

    def __init__(
        self,
        store=None,
        chain=None,
        decode_executor: Optional[Executor] = None,
        peer_provider: Optional[Callable[[], list["PeerConnection"]]] = None,
    ) -> None:
        self.store = store
        self.chain = chain
        self._decode_executor = decode_executor
        self._peer_provider = peer_provider
        self.state = SyncState()
        self._candidate_peers: list[PeerConnection] = []
        self._header_responses: dict[int, list[BlockHeader]] = {}
        self._body_responses: dict[int, list[tuple[list, list]]] = {}
        self._response_events: dict[int, asyncio.Event] = {}
        self._peer_retry_after: dict[bytes, float] = {}
        self._peer_timeout_strikes: dict[bytes, int] = {}
        self._peer_timeout_seconds: dict[bytes, float] = {}
        self._peer_body_chunk_size: dict[bytes, int] = {}

    def _live_connected_peers(self) -> list[PeerConnection]:
        if self._peer_provider is not None:
            try:
                return [p for p in self._peer_provider() if p.connected]
            except Exception:
                return [p for p in self._candidate_peers if p.connected]
        return [p for p in self._candidate_peers if p.connected]

    def _hedge_peers(self, primary: PeerConnection) -> list[PeerConnection]:
        now = time.time()
        candidates = []
        for p in self._live_connected_peers():
            if p is primary:
                continue
            if p.remote_id and self._peer_retry_after.get(p.remote_id, 0.0) > now:
                continue
            candidates.append(p)
        candidates.sort(key=lambda p: (p.best_block_number, -self._peer_strikes(p)), reverse=True)
        return candidates

    def _peer_id(self, peer: PeerConnection) -> Optional[bytes]:
        if peer.remote_id:
            return peer.remote_id
        return None

    def _peer_strikes(self, peer: PeerConnection) -> int:
        peer_id = self._peer_id(peer)
        if peer_id is None:
            return 0
        return self._peer_timeout_strikes.get(peer_id, 0)

    def _timeout_for_peer(self, peer: PeerConnection) -> float:
        peer_id = self._peer_id(peer)
        if peer_id is None:
            return SYNC_TIMEOUT
        return self._peer_timeout_seconds.get(peer_id, SYNC_TIMEOUT)

    def _body_chunk_size_for_peer(self, peer: PeerConnection) -> int:
        peer_id = self._peer_id(peer)
        if peer_id is None:
            return BODIES_PER_REQUEST
        return self._peer_body_chunk_size.get(peer_id, BODIES_PER_REQUEST)

    def _record_peer_success(self, peer: PeerConnection) -> None:
        peer_id = self._peer_id(peer)
        if peer_id is None:
            return
        current_timeout = self._peer_timeout_seconds.get(peer_id, SYNC_TIMEOUT)
        if current_timeout > SYNC_TIMEOUT:
            self._peer_timeout_seconds[peer_id] = max(SYNC_TIMEOUT, current_timeout - 2.0)
        current_chunk = self._peer_body_chunk_size.get(peer_id, BODIES_PER_REQUEST)
        if current_chunk < BODIES_PER_REQUEST:
            self._peer_body_chunk_size[peer_id] = min(BODIES_PER_REQUEST, current_chunk + 8)

    def _penalize_peer(self, peer: PeerConnection, *, severe: bool = False) -> None:
        peer_id = self._peer_id(peer)
        if peer_id is None:
            return
        strikes = self._peer_timeout_strikes.get(peer_id, 0)
        if severe:
            strikes = MAX_PEER_TIMEOUT_STRIKES
        else:
            strikes = min(MAX_PEER_TIMEOUT_STRIKES, strikes + 1)
        self._peer_timeout_strikes[peer_id] = strikes
        penalty_seconds = PEER_TIMEOUT_PENALTY_SECONDS * max(1, strikes)
        self._peer_retry_after[peer_id] = time.time() + penalty_seconds
        current_timeout = self._peer_timeout_seconds.get(peer_id, SYNC_TIMEOUT)
        self._peer_timeout_seconds[peer_id] = min(MAX_SYNC_TIMEOUT_SECONDS, current_timeout + 5.0)
        current_chunk = self._peer_body_chunk_size.get(peer_id, BODIES_PER_REQUEST)
        self._peer_body_chunk_size[peer_id] = max(MIN_BODIES_PER_REQUEST, current_chunk // 2)

    def _record_peer_timeout(self, peer: PeerConnection) -> None:
        self._penalize_peer(peer)

    async def discover_head_header(self, peer: PeerConnection) -> Optional[BlockHeader]:
        """Fetch the current head header from a peer using peer.best_hash."""
        if not peer.best_hash or peer.best_hash == b"\x00" * 32:
            return None

        req_id = self.state.next_request_id()
        msg = GetBlockHeadersMessage(
            request_id=req_id,
            origin=peer.best_hash,
            amount=1,
        )

        event = asyncio.Event()
        self._response_events[req_id] = event
        await peer.send_eth_message(EthMsg.GET_BLOCK_HEADERS, msg.encode())

        try:
            await asyncio.wait_for(event.wait(), timeout=SYNC_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning("Head discovery timed out")
            return None
        finally:
            self._response_events.pop(req_id, None)

        headers = self._header_responses.pop(req_id, [])
        if not headers:
            return None

        return headers[0]

    async def _discover_head(self, peer: PeerConnection) -> int:
        """Discover peer's head block number by requesting the header for best_hash."""
        header = await self.discover_head_header(peer)
        if header is None:
            return 0
        logger.info("Discovered peer head: block #%d", header.number)
        return header.number

    async def start(self, peers: list[PeerConnection]) -> None:
        """Start full sync with available peers."""
        connected_peers = [p for p in peers if p.connected]
        if not connected_peers:
            logger.warning("No peers available for sync")
            return
        self._candidate_peers = peers

        best, best_head = await self._select_best_peer(connected_peers)
        if best is None:
            logger.warning("No suitable peer available for full sync")
            return

        self.state.best_peer = best
        self.state.target_block = best_head
        self.state.syncing = True

        if self.store:
            head = self.store.get_latest_block_number()
            self.state.current_block = head if head is not None else 0

        logger.info(
            "Starting full sync: %d -> %d from peer %s",
            self.state.current_block, self.state.target_block,
            best.remote_id.hex()[:16] if best.remote_id else "unknown",
        )

        try:
            await self._sync_loop()
        except Exception as e:
            logger.error("Sync error: %s", e)
        finally:
            self.state.syncing = False

    async def _select_best_peer(
        self, peers: list[PeerConnection], exclude: Optional[PeerConnection] = None
    ) -> tuple[Optional[PeerConnection], int]:
        """Select best connected peer and estimate its head block."""
        now = time.time()
        connected_peers = [p for p in peers if p.connected and p is not exclude]
        if not connected_peers:
            return None, 0
        eligible_peers = [
            p for p in connected_peers
            if not p.remote_id or self._peer_retry_after.get(p.remote_id, 0.0) <= now
        ]
        if not eligible_peers:
            # If all peers are in penalty window, continue with connected peers.
            eligible_peers = connected_peers

        # Prefer peers that already announced a head number (eth/69).
        best = max(
            eligible_peers,
            key=lambda p: (p.best_block_number, -self._peer_strikes(p)),
        )
        best_head = best.best_block_number
        if best_head > 0:
            return best, best_head

        # Fallback for peers without block number (eth/68) or stale status.
        discovered_best = 0
        discovered_peer: Optional[PeerConnection] = None
        for peer in eligible_peers:
            try:
                head_number = await self._discover_head(peer)
            except Exception:
                continue
            if head_number > discovered_best:
                discovered_best = head_number
                discovered_peer = peer

        if discovered_peer is not None:
            discovered_peer.best_block_number = discovered_best
            return discovered_peer, discovered_best

        return best, best_head

    async def _failover_peer(self) -> bool:
        """Switch to another connected peer when current sync peer fails."""
        current = self.state.best_peer
        candidate_peers = self._live_connected_peers() or self._candidate_peers
        new_peer, new_head = await self._select_best_peer(candidate_peers, exclude=current)
        if new_peer is None and current is not None and current.connected:
            # No alternative peer found; keep current if still alive.
            return True
        if new_peer is None:
            return False

        self.state.best_peer = new_peer
        if new_head > self.state.target_block:
            self.state.target_block = new_head
        logger.info(
            "Switched full sync peer to %s (target=%d)",
            new_peer.remote_id.hex()[:16] if new_peer.remote_id else "unknown",
            self.state.target_block,
        )
        return True

    def _refresh_target_block(self) -> None:
        """Refresh target block from current connected peers."""
        connected_peers = self._live_connected_peers()
        if not connected_peers:
            return
        announced_best = max((p.best_block_number for p in connected_peers), default=0)
        if announced_best > self.state.target_block:
            self.state.target_block = announced_best

    async def _fetch_sync_batch(
        self, peer: PeerConnection, start: int
    ) -> tuple[Optional[list[BlockHeader]], Optional[list[tuple[list, list]]]]:
        """Fetch one sync batch: headers then corresponding bodies."""
        headers = await self._fetch_headers(peer, start, HEADERS_PER_REQUEST)
        if headers is None:
            return None, None
        if not headers:
            return [], []
        hashes = [h.block_hash() for h in headers]
        bodies = await self._fetch_bodies(peer, hashes)
        if bodies is None:
            return headers, None
        return headers, bodies

    async def _execute_headers(
        self, headers: list[BlockHeader], bodies: list[tuple[list, list]]
    ) -> None:
        """Execute/persist synced headers."""
        for i, header in enumerate(headers, start=1):
            if self.chain and self.store:
                body = bodies[i - 1] if (i - 1) < len(bodies) else ([], [])
                try:
                    # Offload heavy block execution to worker pool while keeping
                    # sequential ordering for deterministic state transitions.
                    await asyncio.to_thread(self.chain.execute_block, header, body)
                    block_hash = header.block_hash()
                    self.store.put_block_header(header)
                    self.store.put_canonical_hash(header.number, block_hash)
                    self.state.current_block = header.number
                except Exception as e:
                    logger.error("Block execution failed at %d: %s", header.number, e)
                    raise
            else:
                self._persist_headers_locally([header])
            if i % SYNC_EXECUTION_YIELD_INTERVAL == 0:
                await asyncio.sleep(0)

    def _persist_headers_locally(self, headers: list[BlockHeader]) -> None:
        """Persist headers to local store in canonical order."""
        if not self.store:
            if headers:
                self.state.current_block = headers[-1].number
            return
        for header in headers:
            block_hash = header.block_hash()
            self.store.put_block_header(header)
            self.store.put_canonical_hash(header.number, block_hash)
            self.state.current_block = header.number

    async def _sync_loop(self) -> None:
        """Main sync loop — fetch headers, then bodies, then execute."""
        header_failures = 0
        body_failures = 0
        prefetched_task: Optional[asyncio.Task] = None
        prefetched_start = self.state.current_block + 1
        while self.state.syncing and self.state.current_block < self.state.target_block:
            peer = self.state.best_peer
            if peer is None or not peer.connected:
                if prefetched_task is not None:
                    prefetched_task.cancel()
                    prefetched_task = None
                logger.warning("Sync peer disconnected")
                if not await self._failover_peer():
                    break
                header_failures = 0
                body_failures = 0
                prefetched_start = self.state.current_block + 1
                await asyncio.sleep(HEADER_RETRY_BACKOFF)
                continue

            # Step 1/2: Download headers+bodies, allowing one-batch lookahead prefetch.
            if prefetched_task is None:
                prefetched_start = self.state.current_block + 1
                prefetched_task = asyncio.create_task(
                    self._fetch_sync_batch(peer, prefetched_start)
                )
            headers, bodies = await prefetched_task
            prefetched_task = None

            if headers is None:
                header_failures += 1
                logger.warning(
                    "Header fetch failed from peer %s (%d/%d)",
                    peer.remote_id.hex()[:16] if peer.remote_id else "unknown",
                    header_failures,
                    MAX_HEADER_FAILURES,
                )
                if header_failures >= MAX_HEADER_FAILURES:
                    self._penalize_peer(peer, severe=True)
                    if not await self._failover_peer():
                        break
                    header_failures = 0
                    body_failures = 0
                prefetched_start = self.state.current_block + 1
                await asyncio.sleep(HEADER_RETRY_BACKOFF)
                continue
            if bodies is None:
                body_failures += 1
                logger.warning(
                    "Body fetch failed from peer %s (%d/%d)",
                    peer.remote_id.hex()[:16] if peer.remote_id else "unknown",
                    body_failures,
                    MAX_BODY_FAILURES,
                )
                if body_failures >= MAX_BODY_FAILURES:
                    self._penalize_peer(peer, severe=True)
                    if not await self._failover_peer():
                        break
                    header_failures = 0
                    body_failures = 0
                prefetched_start = self.state.current_block + 1
                await asyncio.sleep(HEADER_RETRY_BACKOFF)
                continue

            if not headers:
                self._refresh_target_block()
                if self.state.current_block >= self.state.target_block:
                    logger.info("No more headers, sync reached target")
                    break
                if not await self._failover_peer():
                    logger.warning("No header response but no failover peer available")
                    await asyncio.sleep(HEADER_RETRY_BACKOFF)
                header_failures = 0
                body_failures = 0
                prefetched_start = self.state.current_block + 1
                continue
            header_failures = 0
            body_failures = 0

            # Start next batch prefetch while executing current batch.
            next_start = headers[-1].number + 1
            if next_start <= self.state.target_block and peer.connected:
                prefetched_start = next_start
                prefetched_task = asyncio.create_task(
                    self._fetch_sync_batch(peer, prefetched_start)
                )

            # Step 3: Execute blocks
            try:
                await self._execute_headers(headers, bodies)
            except Exception:
                return
            self._refresh_target_block()

            logger.info("Synced to block %d / %d", self.state.current_block, self.state.target_block)

    async def _fetch_headers(
        self, peer: PeerConnection, start: int, count: int,
    ) -> Optional[list[BlockHeader]]:
        """Request block headers from peer with limited hedge attempts."""
        attempts = [peer] + self._hedge_peers(peer)[: max(0, HEDGE_HEADER_ATTEMPTS - 1)]
        for idx, attempt_peer in enumerate(attempts):
            headers = await self._fetch_headers_from_single_peer(attempt_peer, start, count)
            if headers is not None:
                if idx > 0:
                    logger.info(
                        "Header request recovered via hedge peer %s",
                        attempt_peer.remote_id.hex()[:16] if attempt_peer.remote_id else "unknown",
                    )
                return headers
        return None

    async def _fetch_headers_from_single_peer(
        self, peer: PeerConnection, start: int, count: int,
    ) -> Optional[list[BlockHeader]]:
        """Request block headers from a single peer."""
        req_id = self.state.next_request_id()
        msg = GetBlockHeadersMessage(
            request_id=req_id,
            origin=start,
            amount=count,
        )

        event = asyncio.Event()
        self._response_events[req_id] = event

        try:
            await peer.send_eth_message(EthMsg.GET_BLOCK_HEADERS, msg.encode())
        except Exception as e:
            logger.warning("Header request %d send failed: %s", req_id, e)
            self._response_events.pop(req_id, None)
            return None

        try:
            await asyncio.wait_for(event.wait(), timeout=self._timeout_for_peer(peer))
        except asyncio.TimeoutError:
            logger.warning("Header request %d timed out", req_id)
            self._record_peer_timeout(peer)
            return None
        finally:
            self._response_events.pop(req_id, None)

        headers = self._header_responses.pop(req_id, [])
        if headers:
            self._record_peer_success(peer)
        return headers

    async def _fetch_bodies(
        self, peer: PeerConnection, hashes: list[bytes],
    ) -> Optional[list[tuple[list, list]]]:
        """Request block bodies with limited hedge attempts."""
        attempts = [peer] + self._hedge_peers(peer)[: max(0, HEDGE_BODY_ATTEMPTS - 1)]
        for idx, attempt_peer in enumerate(attempts):
            bodies = await self._fetch_bodies_from_single_peer(attempt_peer, hashes)
            if bodies is not None:
                if idx > 0:
                    logger.info(
                        "Body request recovered via hedge peer %s",
                        attempt_peer.remote_id.hex()[:16] if attempt_peer.remote_id else "unknown",
                    )
                return bodies
        return None

    async def _fetch_bodies_from_single_peer(
        self, peer: PeerConnection, hashes: list[bytes],
    ) -> Optional[list[tuple[list, list]]]:
        """Request block bodies from a single peer."""
        all_bodies: list[tuple[list, list]] = []

        chunk_size = self._body_chunk_size_for_peer(peer)
        for i in range(0, len(hashes), chunk_size):
            chunk = hashes[i:i + chunk_size]
            req_id = self.state.next_request_id()
            msg = GetBlockBodiesMessage(request_id=req_id, hashes=chunk)

            event = asyncio.Event()
            self._response_events[req_id] = event

            try:
                await peer.send_eth_message(EthMsg.GET_BLOCK_BODIES, msg.encode())
            except Exception as e:
                logger.warning("Body request %d send failed: %s", req_id, e)
                self._response_events.pop(req_id, None)
                self._record_peer_timeout(peer)
                return None

            try:
                await asyncio.wait_for(event.wait(), timeout=self._timeout_for_peer(peer))
            except asyncio.TimeoutError:
                logger.warning("Body request %d timed out", req_id)
                self._record_peer_timeout(peer)
                return None
            finally:
                self._response_events.pop(req_id, None)

            bodies = self._body_responses.pop(req_id, [])
            all_bodies.extend(bodies)
            if bodies:
                self._record_peer_success(peer)

        return all_bodies

    def handle_block_headers(self, data: bytes) -> None:
        """Handle incoming BlockHeaders response."""
        msg = BlockHeadersMessage.decode(data)
        self._store_block_headers_response(msg)

    async def handle_block_headers_async(self, data: bytes) -> None:
        """Handle incoming BlockHeaders response with decode offloaded to worker pool."""
        loop = asyncio.get_running_loop()
        msg = await loop.run_in_executor(
            self._decode_executor, _decode_block_headers_message, data
        )
        self._store_block_headers_response(msg)

    def _store_block_headers_response(self, msg: BlockHeadersMessage) -> None:
        self._header_responses[msg.request_id] = msg.headers
        event = self._response_events.get(msg.request_id)
        if event:
            event.set()

    async def handle_block_bodies_async(self, data: bytes) -> None:
        """Handle incoming BlockBodies response with decode offloaded to worker pool."""
        loop = asyncio.get_running_loop()
        msg = await loop.run_in_executor(
            self._decode_executor, _decode_block_bodies_message, data
        )
        self._store_block_bodies_response(msg)

    def _store_block_bodies_response(self, msg: BlockBodiesMessage) -> None:
        self._body_responses[msg.request_id] = msg.bodies
        event = self._response_events.get(msg.request_id)
        if event:
            event.set()

    @property
    def is_syncing(self) -> bool:
        return self.state.syncing

    @property
    def progress(self) -> tuple[int, int]:
        return self.state.current_block, self.state.target_block
