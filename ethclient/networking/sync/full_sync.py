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
        self._header_responses: dict[int, list[BlockHeader]] = {}
        self._body_responses: dict[int, list[tuple[list, list]]] = {}
        self._response_events: dict[int, asyncio.Event] = {}

    async def _discover_head(self, peer: PeerConnection) -> int:
        """Discover peer's head block number by requesting the header for best_hash."""
        if not peer.best_hash or peer.best_hash == b"\x00" * 32:
            return 0

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
            return 0
        finally:
            self._response_events.pop(req_id, None)

        headers = self._header_responses.pop(req_id, [])
        if headers:
            head_number = headers[0].number
            logger.info("Discovered peer head: block #%d", head_number)
            return head_number
        return 0

    async def start(self, peers: list[PeerConnection]) -> None:
        """Start full sync with available peers."""
        if not peers:
            logger.warning("No peers available for sync")
            return

        # Find best peer (highest total difficulty)
        best = max(peers, key=lambda p: p.total_difficulty)
        self.state.best_peer = best

        # Discover head block number from best_hash (eth/68 Status has no block number)
        head_number = await self._discover_head(best)
        if head_number > 0:
            best.best_block_number = head_number
        self.state.target_block = best.best_block_number
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

    async def _sync_loop(self) -> None:
        """Main sync loop — fetch headers, then bodies, then execute."""
        while self.state.syncing and self.state.current_block < self.state.target_block:
            peer = self.state.best_peer
            if peer is None or not peer.connected:
                logger.warning("Sync peer disconnected")
                break

            # Step 1: Download headers
            headers = await self._fetch_headers(
                peer,
                self.state.current_block + 1,
                HEADERS_PER_REQUEST,
            )
            if not headers:
                logger.info("No more headers, sync may be complete")
                break

            # Step 2: Download bodies
            hashes = [h.block_hash() for h in headers]
            bodies = await self._fetch_bodies(peer, hashes)

            # Step 3: Execute blocks
            for i, header in enumerate(headers):
                if self.chain and self.store:
                    body = bodies[i] if i < len(bodies) else ([], [])
                    try:
                        self.chain.execute_block(header, body)
                        self.state.current_block = header.number
                    except Exception as e:
                        logger.error("Block execution failed at %d: %s", header.number, e)
                        return
                else:
                    self.state.current_block = header.number

            logger.info("Synced to block %d / %d", self.state.current_block, self.state.target_block)

    async def _fetch_headers(
        self, peer: PeerConnection, start: int, count: int,
    ) -> list[BlockHeader]:
        """Request block headers from peer."""
        req_id = self.state.next_request_id()
        msg = GetBlockHeadersMessage(
            request_id=req_id,
            origin=start,
            amount=count,
        )

        event = asyncio.Event()
        self._response_events[req_id] = event

        await peer.send_eth_message(EthMsg.GET_BLOCK_HEADERS, msg.encode())

        try:
            await asyncio.wait_for(event.wait(), timeout=SYNC_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning("Header request %d timed out", req_id)
            return []
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
