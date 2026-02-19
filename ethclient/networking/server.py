"""
P2P server — manages peer connections, message routing, and the main event loop.

Coordinates RLPx connections, eth sub-protocol, snap sub-protocol, discovery,
and sync.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from coincurve import PrivateKey

from ethclient.networking.rlpx.connection import RLPxConnection
from ethclient.networking.eth.protocol import (
    P2PMsg,
    EthMsg,
    DisconnectReason,
    ETH_VERSION,
    ETH_VERSION_FALLBACK,
)
from ethclient.networking.eth.messages import (
    HelloMessage,
    DisconnectMessage,
    StatusMessage,
    GetBlockHeadersMessage,
    BlockHeadersMessage,
    GetBlockBodiesMessage,
    BlockBodiesMessage,
    GetReceiptsMessage,
    ReceiptsMessage,
    TransactionsMessage,
    NewPooledTransactionHashesMessage,
    NewBlockHashesMessage,
    encode_ping,
    encode_pong,
)
from ethclient.networking.snap.protocol import SnapMsg, SNAP_VERSION
from ethclient.networking.protocol_registry import (
    Capability,
    NegotiatedCapabilities,
    negotiate_capabilities,
)
from ethclient.networking.discv4.routing import Node
from ethclient.networking.discv4.discovery import DiscoveryProtocol, start_discovery
from ethclient.networking.sync.full_sync import FullSync

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_PEERS = 25
PING_INTERVAL = 15.0   # seconds between pings
DIAL_INTERVAL = 10.0   # seconds between dial attempts
CLEANUP_INTERVAL = 30.0
DIAL_COOLDOWN_SECONDS = 30.0
DIAL_MAX_ATTEMPTS_PER_TICK = 6
DIAL_PONG_FRESHNESS_SECONDS = 300.0


# ---------------------------------------------------------------------------
# Local capabilities
# ---------------------------------------------------------------------------

LOCAL_CAPS_ETH_ONLY = [Capability("eth", ETH_VERSION), Capability("eth", ETH_VERSION_FALLBACK)]
LOCAL_CAPS_WITH_SNAP = [Capability("eth", ETH_VERSION), Capability("eth", ETH_VERSION_FALLBACK), Capability("snap", SNAP_VERSION)]


# ---------------------------------------------------------------------------
# Peer connection state
# ---------------------------------------------------------------------------

@dataclass
class PeerConnection:
    """Represents a connected peer with protocol state."""
    conn: RLPxConnection
    remote_id: bytes = b""         # 64-byte public key
    remote_client: str = ""
    eth_version: int = 0
    total_difficulty: int = 0
    best_hash: bytes = b""
    best_block_number: int = 0
    genesis_hash: bytes = b""
    connected: bool = False
    last_ping: float = 0.0
    last_pong: float = 0.0
    snap_supported: bool = False
    capabilities: Optional[NegotiatedCapabilities] = field(default=None, repr=False)

    async def send_p2p_message(self, msg_code: int, payload: bytes) -> None:
        await self.conn.send_message(msg_code, payload)

    async def send_eth_message(self, msg_code: int, payload: bytes) -> None:
        await self.conn.send_message(msg_code, payload)

    async def send_snap_message(self, relative_code: int, payload: bytes) -> None:
        """Send a snap sub-protocol message using the negotiated offset."""
        if self.capabilities is None or not self.capabilities.supports("snap"):
            raise RuntimeError("Peer does not support snap protocol")
        abs_code = self.capabilities.absolute_code("snap", relative_code)
        await self.conn.send_message(abs_code, payload)


# ---------------------------------------------------------------------------
# P2P Server
# ---------------------------------------------------------------------------

class P2PServer:
    """Main P2P server managing peer connections and protocol."""

    def __init__(
        self,
        private_key: bytes,
        listen_port: int = 30303,
        max_peers: int = MAX_PEERS,
        boot_nodes: Optional[list[Node]] = None,
        bootnode_only: bool = False,
        network_id: int = 1,
        genesis_hash: bytes = b"\x00" * 32,
        fork_id: tuple[bytes, int] = (b"\x00" * 4, 0),
        store=None,
        chain=None,
        enable_snap: bool = True,
    ) -> None:
        self.private_key = private_key
        self.listen_port = listen_port
        self.max_peers = max_peers
        self.boot_nodes = boot_nodes or []
        self.bootnode_only = bootnode_only
        self.network_id = network_id
        self.genesis_hash = genesis_hash
        self.fork_id = fork_id
        self.store = store
        self.chain = chain
        self.enable_snap = enable_snap

        pk = PrivateKey(private_key)
        self.public_key = pk.public_key.format(compressed=False)[1:]  # 64 bytes
        self.local_node = Node(
            id=self.public_key,
            ip="0.0.0.0",
            udp_port=listen_port,
            tcp_port=listen_port,
        )

        self.peers: dict[bytes, PeerConnection] = {}  # pubkey -> PeerConnection
        self.syncer = FullSync(store=store, chain=chain)
        self.snap_syncer = None  # set externally when snap sync is active
        self._discovery: Optional[DiscoveryProtocol] = None
        self._discovery_transport: Optional[asyncio.DatagramTransport] = None
        self._tcp_server: Optional[asyncio.Server] = None
        self._running = False
        self._dial_retry_after: dict[bytes, float] = {}
        self._boot_node_ids: set[bytes] = {node.id for node in self.boot_nodes if node.id}
        self._snap_bootstrap_attempts = 0

        # Local capabilities for Hello message
        self._local_caps = LOCAL_CAPS_WITH_SNAP if enable_snap else LOCAL_CAPS_ETH_ONLY

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the P2P server."""
        self._running = True
        logger.info(
            "Starting P2P server on port %d, node ID: %s...",
            self.listen_port, self.public_key.hex()[:32],
        )

        # Start TCP listener
        self._tcp_server = await asyncio.start_server(
            self._handle_incoming,
            "0.0.0.0",
            self.listen_port,
        )

        # Start discovery
        try:
            self._discovery_transport, self._discovery = await start_discovery(
                self.private_key,
                self.local_node,
                self.boot_nodes,
                self.listen_port,
            )
        except Exception as e:
            logger.warning("Could not start discovery: %s", e)

        # Start background tasks
        asyncio.create_task(self._dial_loop())
        asyncio.create_task(self._ping_loop())
        asyncio.create_task(self._cleanup_loop())

        # Bootstrap discovery
        if self._discovery:
            asyncio.create_task(self._discovery.bootstrap())

        logger.info("P2P server started (snap=%s)", self.enable_snap)

    async def stop(self) -> None:
        """Gracefully stop the server."""
        self._running = False

        # Disconnect all peers
        for peer in list(self.peers.values()):
            await self._disconnect_peer(peer, DisconnectReason.CLIENT_QUIT)

        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()

        if self._discovery_transport:
            self._discovery_transport.close()

        logger.info("P2P server stopped")

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------

    async def _handle_incoming(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming TCP connection."""
        if len(self.peers) >= self.max_peers:
            writer.close()
            return

        conn = RLPxConnection(self.private_key, reader, writer)
        if not await conn.accept_handshake():
            reason = conn.last_handshake_error or "unknown error"
            logger.info("Incoming RLPx handshake failed: %s", reason)
            conn.close()
            return

        peer = PeerConnection(conn=conn)
        if conn.remote_pubkey:
            peer.remote_id = conn.remote_pubkey[1:] if len(conn.remote_pubkey) == 65 else conn.remote_pubkey

        # Perform protocol handshake
        if not await self._do_protocol_handshake(peer):
            conn.close()
            return

        self.peers[peer.remote_id] = peer
        peer.connected = True
        logger.info("Incoming peer connected: %s (snap=%s)", peer.remote_client, peer.snap_supported)

        await self._handle_peer(peer)

    async def connect_to_peer(self, node: Node) -> Optional[PeerConnection]:
        """Initiate connection to a peer."""
        if node.id in self.peers:
            return self.peers[node.id]

        if len(self.peers) >= self.max_peers:
            return None

        now = time.time()
        retry_after = self._dial_retry_after.get(node.id, 0.0)
        if retry_after > now:
            return None

        logger.info("Connecting to %s:%d ...", node.ip, node.tcp_port or node.udp_port)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(node.ip, node.tcp_port or node.udp_port),
                timeout=10.0,
            )
        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            logger.info("TCP connect failed to %s:%d: %s", node.ip, node.tcp_port, e)
            self._dial_retry_after[node.id] = now + DIAL_COOLDOWN_SECONDS
            return None

        logger.info("TCP connected, starting RLPx handshake...")
        remote_pubkey = b"\x04" + node.id  # add uncompressed prefix
        conn = RLPxConnection(self.private_key, reader, writer)
        if not await conn.initiate_handshake(remote_pubkey):
            reason = conn.last_handshake_error or "unknown error"
            logger.info("RLPx handshake failed with %s: %s", node.ip, reason)
            conn.close()
            self._dial_retry_after[node.id] = now + DIAL_COOLDOWN_SECONDS
            return None

        logger.info("RLPx handshake OK, starting protocol handshake...")
        peer = PeerConnection(conn=conn, remote_id=node.id)

        if not await self._do_protocol_handshake(peer):
            logger.info("Protocol handshake failed with %s", node.ip)
            conn.close()
            self._dial_retry_after[node.id] = now + DIAL_COOLDOWN_SECONDS
            return None

        self.peers[peer.remote_id] = peer
        peer.connected = True
        self._dial_retry_after.pop(node.id, None)
        logger.info("Peer connected: %s (%s:%d, snap=%s)",
                     peer.remote_client, node.ip, node.tcp_port, peer.snap_supported)

        asyncio.create_task(self._handle_peer(peer))
        return peer

    async def _do_protocol_handshake(self, peer: PeerConnection) -> bool:
        """Exchange Hello and Status messages."""
        # Send Hello with our capabilities
        hello_caps = [(c.name, c.version) for c in self._local_caps]
        hello = HelloMessage(
            node_id=self.public_key,
            listen_port=self.listen_port,
            capabilities=hello_caps,
        )
        await peer.send_p2p_message(P2PMsg.HELLO, hello.encode())
        logger.debug("Sent Hello message with caps=%s", hello_caps)

        # Receive Hello
        result = await peer.conn.recv_message(timeout=15.0)
        if result is None:
            logger.debug("No Hello response received")
            return False

        msg_code, payload = result
        if msg_code == P2PMsg.DISCONNECT:
            try:
                disc = DisconnectMessage.decode(payload)
                logger.info("Peer sent Disconnect during Hello: reason=%d", disc.reason)
            except Exception:
                logger.info("Peer sent Disconnect during Hello")
            return False
        if msg_code != P2PMsg.HELLO:
            logger.debug("Expected Hello (0x00), got 0x%02x", msg_code)
            return False

        remote_hello = HelloMessage.decode(payload)
        peer.remote_client = remote_hello.client_id
        logger.info("Remote Hello: %s, caps=%s", remote_hello.client_id,
                     remote_hello.capabilities)

        # Negotiate capabilities
        remote_caps = [Capability(name, ver) for name, ver in remote_hello.capabilities]
        negotiated = negotiate_capabilities(self._local_caps, remote_caps)
        peer.capabilities = negotiated

        # Check eth capability
        if not negotiated.supports("eth"):
            logger.info("Peer lacks eth protocol, disconnecting")
            await self._disconnect_peer(peer, DisconnectReason.INCOMPATIBLE_VERSION)
            return False

        # Find eth version from negotiated caps
        eth_cap = next((c for c in negotiated.caps if c.name == "eth"), None)
        peer.eth_version = eth_cap.version if eth_cap else 0

        # Check snap support
        peer.snap_supported = negotiated.supports("snap")
        if peer.snap_supported:
            logger.info("Peer supports snap/1")

        # Send Status (wrapped in try/except to catch connection failures)
        try:
            return await self._exchange_status(peer)
        except Exception as e:
            logger.info("Status exchange error: %s: %s", type(e).__name__, e)
            return False

    async def _exchange_status(self, peer: PeerConnection) -> bool:
        """Exchange eth Status messages. Separated for clean error handling."""
        total_difficulty = 0
        best_hash = self.genesis_hash
        head_number = 0
        if self.store:
            head = self.store.get_latest_block_number()
            if head is not None:
                head_number = head
                header = self.store.get_block_header_by_number(head)
                if header:
                    best_hash = header.block_hash()

        status = StatusMessage(
            protocol_version=peer.eth_version or ETH_VERSION,
            network_id=self.network_id,
            total_difficulty=total_difficulty,
            best_hash=best_hash,
            genesis_hash=self.genesis_hash,
            fork_id=self.fork_id,
            earliest_block=0,
            latest_block=head_number,
            latest_block_hash=best_hash,
        )
        try:
            await peer.send_eth_message(EthMsg.STATUS, status.encode())
        except (ConnectionError, OSError) as e:
            logger.info("Failed to send Status: %s", e)
            return False

        # Receive Status
        result = await peer.conn.recv_message(timeout=15.0)
        if result is None:
            logger.info("No Status response received")
            return False

        msg_code, payload = result
        if msg_code == P2PMsg.DISCONNECT:
            try:
                disc = DisconnectMessage.decode(payload)
                logger.info("Peer Disconnect during Status: reason=%d", disc.reason)
            except Exception:
                logger.info("Peer Disconnect during Status")
            return False
        if msg_code != EthMsg.STATUS:
            logger.info("Expected Status (0x10), got 0x%02x", msg_code)
            return False

        try:
            remote_status = StatusMessage.decode(payload)
        except Exception as e:
            logger.info("Failed to decode Status: %s", e)
            return False

        logger.info("Remote Status: network=%d, version=%d, td=%d, latest=%d, genesis=%s, fork_id=(%s, %d)",
                     remote_status.network_id, remote_status.protocol_version, remote_status.total_difficulty,
                     remote_status.latest_block,
                     remote_status.genesis_hash.hex()[:16],
                     remote_status.fork_id[0].hex(), remote_status.fork_id[1])

        # Verify genesis hash and network ID
        if remote_status.genesis_hash != self.genesis_hash:
            logger.info("Genesis mismatch — ours=%s remote=%s",
                         self.genesis_hash.hex()[:16], remote_status.genesis_hash.hex()[:16])
            await self._disconnect_peer(peer, DisconnectReason.SUBPROTOCOL_ERROR)
            return False
        if remote_status.network_id != self.network_id:
            logger.info("Network ID mismatch — ours=%d remote=%d",
                         self.network_id, remote_status.network_id)
            await self._disconnect_peer(peer, DisconnectReason.SUBPROTOCOL_ERROR)
            return False

        peer.total_difficulty = remote_status.total_difficulty
        if remote_status.protocol_version >= 69:
            peer.best_hash = remote_status.latest_block_hash
            peer.best_block_number = remote_status.latest_block
        else:
            peer.best_hash = remote_status.best_hash
        peer.genesis_hash = remote_status.genesis_hash

        return True

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

    async def _handle_peer(self, peer: PeerConnection) -> None:
        """Main loop for handling messages from a peer."""
        try:
            while self._running and peer.connected:
                result = await peer.conn.recv_message()
                if result is None:
                    break

                msg_code, payload = result
                await self._dispatch_message(peer, msg_code, payload)

        except Exception as e:
            logger.debug("Peer error: %s", e)
        finally:
            peer.connected = False
            self.peers.pop(peer.remote_id, None)
            if peer.remote_id:
                self._dial_retry_after[peer.remote_id] = time.time() + DIAL_COOLDOWN_SECONDS
            peer.conn.close()
            logger.info("Peer disconnected: %s", peer.remote_client)

    async def _dispatch_message(
        self, peer: PeerConnection, msg_code: int, payload: bytes,
    ) -> None:
        """Dispatch a received message to the appropriate handler."""
        # p2p base messages
        if msg_code == P2PMsg.PING:
            await peer.send_p2p_message(P2PMsg.PONG, encode_pong())
            return
        if msg_code == P2PMsg.PONG:
            peer.last_pong = time.time()
            return
        if msg_code == P2PMsg.DISCONNECT:
            try:
                disc = DisconnectMessage.decode(payload)
                logger.info("Peer disconnecting: reason=%s", disc.reason.name)
            except Exception:
                pass
            peer.connected = False
            return

        # Use protocol registry to resolve sub-protocol messages
        if peer.capabilities:
            try:
                protocol, relative_code = peer.capabilities.resolve_msg_code(msg_code)
            except ValueError:
                logger.debug("Unhandled message code: 0x%02x", msg_code)
                return

            if protocol == "eth":
                await self._dispatch_eth_message(peer, msg_code, payload)
            elif protocol == "snap":
                await self._dispatch_snap_message(peer, relative_code, payload)
            else:
                logger.debug("Unhandled protocol: %s, code: 0x%02x", protocol, msg_code)
        else:
            # Fallback: treat as eth message (legacy path)
            await self._dispatch_eth_message(peer, msg_code, payload)

    async def _dispatch_eth_message(
        self, peer: PeerConnection, msg_code: int, payload: bytes,
    ) -> None:
        """Dispatch an eth sub-protocol message."""
        if msg_code == EthMsg.BLOCK_HEADERS:
            self.syncer.handle_block_headers(payload)
        elif msg_code == EthMsg.BLOCK_BODIES:
            self.syncer.handle_block_bodies(payload)
        elif msg_code == EthMsg.GET_BLOCK_HEADERS:
            await self._handle_get_block_headers(peer, payload)
        elif msg_code == EthMsg.GET_BLOCK_BODIES:
            await self._handle_get_block_bodies(peer, payload)
        elif msg_code == EthMsg.GET_RECEIPTS:
            await self._handle_get_receipts(peer, payload)
        elif msg_code == EthMsg.RECEIPTS:
            logger.debug("Received receipts response")
        elif msg_code == EthMsg.TRANSACTIONS:
            self._handle_transactions(payload)
        elif msg_code == EthMsg.NEW_POOLED_TX_HASHES:
            self._handle_new_pooled_tx_hashes(payload)
        elif msg_code == EthMsg.NEW_BLOCK_HASHES:
            self._handle_new_block_hashes(payload)
        elif msg_code == EthMsg.BLOCK_RANGE_UPDATE:
            logger.debug("Received BlockRangeUpdate")
        else:
            logger.debug("Unhandled eth message code: 0x%02x", msg_code)

    async def _dispatch_snap_message(
        self, peer: PeerConnection, relative_code: int, payload: bytes,
    ) -> None:
        """Dispatch a snap sub-protocol message."""
        if self.snap_syncer is None:
            logger.debug("Received snap message but no snap syncer active (code=%d)", relative_code)
            return

        if relative_code == SnapMsg.ACCOUNT_RANGE:
            self.snap_syncer.handle_account_range(payload)
        elif relative_code == SnapMsg.STORAGE_RANGES:
            self.snap_syncer.handle_storage_ranges(payload)
        elif relative_code == SnapMsg.BYTE_CODES:
            self.snap_syncer.handle_byte_codes(payload)
        elif relative_code == SnapMsg.TRIE_NODES:
            self.snap_syncer.handle_trie_nodes(payload)
        else:
            logger.debug("Unhandled snap message code: %d", relative_code)

    async def _handle_get_block_headers(
        self, peer: PeerConnection, data: bytes,
    ) -> None:
        """Respond to GetBlockHeaders request."""
        msg = GetBlockHeadersMessage.decode(data)
        headers: list = []

        if self.store:
            origin = msg.origin
            for i in range(msg.amount):
                if isinstance(origin, int):
                    block_num = origin + (i if not msg.reverse else -i) * (msg.skip + 1)
                    if block_num < 0:
                        break
                    header = self.store.get_block_header_by_number(block_num)
                else:
                    header = self.store.get_block_header_by_hash(origin)
                if header:
                    headers.append(header)

        response = BlockHeadersMessage(request_id=msg.request_id, headers=headers)
        await peer.send_eth_message(EthMsg.BLOCK_HEADERS, response.encode())

    async def _handle_get_block_bodies(
        self, peer: PeerConnection, data: bytes,
    ) -> None:
        """Respond to GetBlockBodies request."""
        msg = GetBlockBodiesMessage.decode(data)
        bodies: list[tuple[list, list]] = []

        if self.store:
            for block_hash in msg.hashes:
                body = self.store.get_block_body(block_hash)
                if body:
                    bodies.append(body)
                else:
                    bodies.append(([], []))

        response = BlockBodiesMessage(request_id=msg.request_id, bodies=bodies)
        await peer.send_eth_message(EthMsg.BLOCK_BODIES, response.encode())

    async def _handle_get_receipts(
        self, peer: PeerConnection, data: bytes,
    ) -> None:
        """Respond to GetReceipts request."""
        msg = GetReceiptsMessage.decode(data)
        payload_receipts: list[list] = []

        if self.store:
            for block_hash in msg.hashes:
                receipts = self.store.get_receipts(block_hash)
                payload_receipts.append(receipts or [])

        response = ReceiptsMessage(
            request_id=msg.request_id,
            receipts=payload_receipts,
            protocol_version=peer.eth_version or ETH_VERSION,
        )
        await peer.send_eth_message(EthMsg.RECEIPTS, response.encode())

    def _handle_transactions(self, data: bytes) -> None:
        """Handle broadcast transactions."""
        msg = TransactionsMessage.decode(data)
        logger.debug("Received %d transactions", len(msg.transactions))

    def _handle_new_pooled_tx_hashes(self, data: bytes) -> None:
        """Handle new pooled transaction hash announcements."""
        msg = NewPooledTransactionHashesMessage.decode(data)
        logger.debug("Received %d new pooled tx hashes", len(msg.hashes))

    def _handle_new_block_hashes(self, data: bytes) -> None:
        """Handle new block hash announcements."""
        msg = NewBlockHashesMessage.decode(data)
        logger.debug("Received %d new block hashes", len(msg.hashes))

    # ------------------------------------------------------------------
    # TX broadcast
    # ------------------------------------------------------------------

    async def broadcast_transactions(self, tx_data: list[bytes]) -> None:
        """Broadcast transactions to all connected peers."""
        if not tx_data:
            return

        msg = TransactionsMessage(transactions=tx_data)
        payload = msg.encode()

        for peer in list(self.peers.values()):
            if peer.connected:
                try:
                    await peer.send_eth_message(EthMsg.TRANSACTIONS, payload)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Background tasks
    # ------------------------------------------------------------------

    async def _dial_loop(self) -> None:
        """Periodically try to connect to discovered peers."""
        while self._running:
            await asyncio.sleep(DIAL_INTERVAL)

            if len(self.peers) >= self.max_peers:
                continue

            if self._discovery:
                now = time.time()
                nodes = self._discovery.table.all_nodes()
                if not nodes:
                    continue

                def _is_eligible(node: Node) -> bool:
                    if node.id in self.peers or node.tcp_port <= 0:
                        return False
                    if self.bootnode_only and self._boot_node_ids and node.id not in self._boot_node_ids:
                        return False
                    # Always allow configured bootnodes.
                    if node.id in self._boot_node_ids:
                        return True
                    # For non-bootnodes, require recent liveness (pong) to reduce dial churn.
                    if node.last_pong <= 0:
                        return False
                    return (now - node.last_pong) <= DIAL_PONG_FRESHNESS_SECONDS

                candidates = [n for n in nodes if _is_eligible(n)]
                if not candidates:
                    continue

                # Prioritize bootnodes, then recently alive peers.
                candidates.sort(
                    key=lambda n: ((0 if n.id in self._boot_node_ids else 1), -n.last_pong)
                )
                dial_budget = min(DIAL_MAX_ATTEMPTS_PER_TICK, self.max_peers - len(self.peers))
                for node in candidates[:dial_budget]:
                    try:
                        await self.connect_to_peer(node)
                    except Exception as e:
                        logger.debug("Dial error: %s", e)
                    if len(self.peers) >= self.max_peers:
                        break

    async def _ping_loop(self) -> None:
        """Periodically ping connected peers."""
        while self._running:
            await asyncio.sleep(PING_INTERVAL)

            for peer in list(self.peers.values()):
                if peer.connected:
                    try:
                        peer.last_ping = time.time()
                        await peer.send_p2p_message(P2PMsg.PING, encode_ping())
                    except Exception:
                        peer.connected = False

    async def _cleanup_loop(self) -> None:
        """Remove dead peers."""
        while self._running:
            await asyncio.sleep(CLEANUP_INTERVAL)

            now = time.time()
            for pubkey, peer in list(self.peers.items()):
                if not peer.connected:
                    self.peers.pop(pubkey, None)
                    continue
                # If we pinged but no pong for > 30s, disconnect
                if peer.last_ping > 0 and peer.last_pong < peer.last_ping:
                    if now - peer.last_ping > 30:
                        logger.info("Peer timed out: %s", peer.remote_client)
                        await self._disconnect_peer(peer, DisconnectReason.TIMEOUT)

            # Cleanup discovery pending pings
            if self._discovery:
                self._discovery.cleanup_pending()
            # Cleanup expired dial cooldown entries
            expired = [node_id for node_id, ts in self._dial_retry_after.items() if ts <= now]
            for node_id in expired:
                self._dial_retry_after.pop(node_id, None)

    async def _disconnect_peer(
        self, peer: PeerConnection, reason: DisconnectReason,
    ) -> None:
        """Send disconnect and close connection."""
        try:
            msg = DisconnectMessage(reason=reason)
            await peer.send_p2p_message(P2PMsg.DISCONNECT, msg.encode())
        except Exception:
            pass
        peer.connected = False
        peer.conn.close()
        self.peers.pop(peer.remote_id, None)

    # ------------------------------------------------------------------
    # Sync control
    # ------------------------------------------------------------------

    async def start_sync(self) -> None:
        """Start block synchronization."""
        if self.syncer.is_syncing or (self.snap_syncer is not None and self.snap_syncer.is_syncing):
            logger.debug("Sync already in progress, skipping start")
            return
        peers = [p for p in self.peers.values() if p.connected]
        if not peers:
            return

        if self.enable_snap and self.snap_syncer is not None:
            snap_peers = [p for p in peers if p.snap_supported]
            if snap_peers:
                local_head = self.store.get_latest_block_number() if self.store else 0
                if local_head == 0:
                    self._snap_bootstrap_attempts += 1
                else:
                    self._snap_bootstrap_attempts = 0

                # If snap keeps restarting while local head stays at genesis,
                # periodically bootstrap via full sync to advance block height.
                if self._snap_bootstrap_attempts >= 3:
                    logger.info(
                        "Snap bootstrap stalled at block 0, running full sync bootstrap"
                    )
                    self._snap_bootstrap_attempts = 0
                    await self.syncer.start(peers)
                    return

                best_snap_peer = max(snap_peers, key=lambda p: p.best_block_number)
                head_header = None
                try:
                    head_header = await self.syncer.discover_head_header(best_snap_peer)
                except Exception as exc:
                    logger.debug("snap head discovery failed: %s", exc)

                if head_header is not None and head_header.state_root != b"\x00" * 32:
                    await self.start_snap_sync(head_header.state_root, head_header.number)
                    return

                logger.warning("Could not determine snap target from peer, falling back to full sync")

        await self.syncer.start(peers)

    async def start_snap_sync(self, target_root: bytes, target_block: int) -> None:
        """Start snap synchronization if snap syncer is set and peers support it."""
        if self.snap_syncer is None:
            logger.warning("No snap syncer configured")
            return
        snap_peers = [p for p in self.peers.values() if p.connected and p.snap_supported]
        if not snap_peers:
            logger.warning("No snap-capable peers, falling back to full sync")
            await self.start_sync()
            return
        await self.snap_syncer.start(
            snap_peers,
            target_root,
            target_block,
            peer_provider=lambda: [
                p for p in self.peers.values() if p.connected and p.snap_supported
            ],
        )

    @property
    def peer_count(self) -> int:
        return len(self.peers)

    @property
    def is_syncing(self) -> bool:
        return self.syncer.is_syncing or (
            self.snap_syncer is not None and self.snap_syncer.is_syncing
        )
