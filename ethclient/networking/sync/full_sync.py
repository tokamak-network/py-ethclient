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
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HEADERS_PER_REQUEST = 192   # max headers per request
BODIES_PER_REQUEST = 64     # max bodies per request
SYNC_TIMEOUT = 15.0         # seconds
HEADER_RETRY_BACKOFF = 1.0  # seconds
MAX_HEADER_FAILURES = 2     # per peer before failover


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

    def __init__(self, store=None, chain=None) -> None:
        self.store = store
        self.chain = chain
        self.state = SyncState()
        self._candidate_peers: list[PeerConnection] = []
        self._header_responses: dict[int, list[BlockHeader]] = {}
        self._body_responses: dict[int, list[tuple[list, list]]] = {}
        self._response_events: dict[int, asyncio.Event] = {}

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
        connected_peers = [p for p in peers if p.connected and p is not exclude]
        if not connected_peers:
            return None, 0

        # Prefer peers that already announced a head number (eth/69).
        best = max(connected_peers, key=lambda p: p.best_block_number)
        best_head = best.best_block_number
        if best_head > 0:
            return best, best_head

        # Fallback for peers without block number (eth/68) or stale status.
        discovered_best = 0
        discovered_peer: Optional[PeerConnection] = None
        for peer in connected_peers:
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
        new_peer, new_head = await self._select_best_peer(self._candidate_peers, exclude=current)
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
        connected_peers = [p for p in self._candidate_peers if p.connected]
        if not connected_peers:
            return
        announced_best = max((p.best_block_number for p in connected_peers), default=0)
        if announced_best > self.state.target_block:
            self.state.target_block = announced_best

    async def _sync_loop(self) -> None:
        """Main sync loop — fetch headers, then bodies, then execute."""
        header_failures = 0
        while self.state.syncing and self.state.current_block < self.state.target_block:
            peer = self.state.best_peer
            if peer is None or not peer.connected:
                logger.warning("Sync peer disconnected")
                if not await self._failover_peer():
                    break
                header_failures = 0
                await asyncio.sleep(HEADER_RETRY_BACKOFF)
                continue

            # Step 1: Download headers
            headers = await self._fetch_headers(
                peer,
                self.state.current_block + 1,
                HEADERS_PER_REQUEST,
            )
            if headers is None:
                header_failures += 1
                logger.warning(
                    "Header fetch failed from peer %s (%d/%d)",
                    peer.remote_id.hex()[:16] if peer.remote_id else "unknown",
                    header_failures,
                    MAX_HEADER_FAILURES,
                )
                if header_failures >= MAX_HEADER_FAILURES:
                    if not await self._failover_peer():
                        break
                    header_failures = 0
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
                continue
            header_failures = 0

            # Step 2: Download bodies
            hashes = [h.block_hash() for h in headers]
            bodies = await self._fetch_bodies(peer, hashes)

            # Step 3: Execute blocks
            for i, header in enumerate(headers):
                if self.chain and self.store:
                    body = bodies[i] if i < len(bodies) else ([], [])
                    try:
                        self.chain.execute_block(header, body)
                        block_hash = header.block_hash()
                        self.store.put_block_header(header)
                        self.store.put_canonical_hash(header.number, block_hash)
                        self.state.current_block = header.number
                    except Exception as e:
                        logger.error("Block execution failed at %d: %s", header.number, e)
                        return
                else:
                    if self.store:
                        block_hash = header.block_hash()
                        self.store.put_block_header(header)
                        self.store.put_canonical_hash(header.number, block_hash)
                    self.state.current_block = header.number
            self._refresh_target_block()

            logger.info("Synced to block %d / %d", self.state.current_block, self.state.target_block)

    async def _fetch_headers(
        self, peer: PeerConnection, start: int, count: int,
    ) -> Optional[list[BlockHeader]]:
        """Request block headers from peer."""
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
            await asyncio.wait_for(event.wait(), timeout=SYNC_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning("Header request %d timed out", req_id)
            return None
        finally:
            self._response_events.pop(req_id, None)

        return self._header_responses.pop(req_id, [])

    async def _fetch_bodies(
        self, peer: PeerConnection, hashes: list[bytes],
    ) -> list[tuple[list, list]]:
        """Request block bodies from peer."""
        all_bodies: list[tuple[list, list]] = []

        for i in range(0, len(hashes), BODIES_PER_REQUEST):
            chunk = hashes[i:i + BODIES_PER_REQUEST]
            req_id = self.state.next_request_id()
            msg = GetBlockBodiesMessage(request_id=req_id, hashes=chunk)

            event = asyncio.Event()
            self._response_events[req_id] = event

            await peer.send_eth_message(EthMsg.GET_BLOCK_BODIES, msg.encode())

            try:
                await asyncio.wait_for(event.wait(), timeout=SYNC_TIMEOUT)
            except asyncio.TimeoutError:
                logger.warning("Body request %d timed out", req_id)
                break
            finally:
                self._response_events.pop(req_id, None)

            bodies = self._body_responses.pop(req_id, [])
            all_bodies.extend(bodies)

        return all_bodies

    def handle_block_headers(self, data: bytes) -> None:
        """Handle incoming BlockHeaders response."""
        msg = BlockHeadersMessage.decode(data)
        self._header_responses[msg.request_id] = msg.headers
        event = self._response_events.get(msg.request_id)
        if event:
            event.set()

    def handle_block_bodies(self, data: bytes) -> None:
        """Handle incoming BlockBodies response."""
        msg = BlockBodiesMessage.decode(data)
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
