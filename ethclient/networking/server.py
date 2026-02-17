"""
P2P server — manages peer connections, message routing, and the main event loop.

Coordinates RLPx connections, eth sub-protocol, discovery, and sync.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional

from coincurve import PrivateKey

from ethclient.networking.rlpx.connection import RLPxConnection
from ethclient.networking.eth.protocol import (
    P2PMsg,
    EthMsg,
    DisconnectReason,
    ETH_VERSION,
)
from ethclient.networking.eth.messages import (
    HelloMessage,
    DisconnectMessage,
    StatusMessage,
    GetBlockHeadersMessage,
    BlockHeadersMessage,
    GetBlockBodiesMessage,
    BlockBodiesMessage,
    TransactionsMessage,
    NewPooledTransactionHashesMessage,
    NewBlockHashesMessage,
    encode_ping,
    encode_pong,
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

    async def send_p2p_message(self, msg_code: int, payload: bytes) -> None:
        await self.conn.send_message(msg_code, payload)

    async def send_eth_message(self, msg_code: int, payload: bytes) -> None:
        await self.conn.send_message(msg_code, payload)


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
        network_id: int = 1,
        genesis_hash: bytes = b"\x00" * 32,
        store=None,
        chain=None,
    ) -> None:
        self.private_key = private_key
        self.listen_port = listen_port
        self.max_peers = max_peers
        self.boot_nodes = boot_nodes or []
        self.network_id = network_id
        self.genesis_hash = genesis_hash
        self.store = store
        self.chain = chain

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
        self._discovery: Optional[DiscoveryProtocol] = None
        self._discovery_transport: Optional[asyncio.DatagramTransport] = None
        self._tcp_server: Optional[asyncio.Server] = None
        self._running = False

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
        asyncio.ensure_future(self._dial_loop())
        asyncio.ensure_future(self._ping_loop())
        asyncio.ensure_future(self._cleanup_loop())

        # Bootstrap discovery
        if self._discovery:
            asyncio.ensure_future(self._discovery.bootstrap())

        logger.info("P2P server started")

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
        logger.info("Incoming peer connected: %s", peer.remote_client)

        await self._handle_peer(peer)

    async def connect_to_peer(self, node: Node) -> Optional[PeerConnection]:
        """Initiate connection to a peer."""
        if node.id in self.peers:
            return self.peers[node.id]

        if len(self.peers) >= self.max_peers:
            return None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(node.ip, node.tcp_port or node.udp_port),
                timeout=5.0,
            )
        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            logger.debug("Failed to connect to %s:%d: %s", node.ip, node.tcp_port, e)
            return None

        remote_pubkey = b"\x04" + node.id  # add uncompressed prefix
        conn = RLPxConnection(self.private_key, reader, writer)
        if not await conn.initiate_handshake(remote_pubkey):
            conn.close()
            return None

        peer = PeerConnection(conn=conn, remote_id=node.id)

        if not await self._do_protocol_handshake(peer):
            conn.close()
            return None

        self.peers[peer.remote_id] = peer
        peer.connected = True
        logger.info("Connected to peer: %s (%s)", peer.remote_client, node.ip)

        asyncio.ensure_future(self._handle_peer(peer))
        return peer

    async def _do_protocol_handshake(self, peer: PeerConnection) -> bool:
        """Exchange Hello and Status messages."""
        # Send Hello
        hello = HelloMessage(node_id=self.public_key)
        await peer.send_p2p_message(P2PMsg.HELLO, hello.encode())

        # Receive Hello
        result = await peer.conn.recv_message()
        if result is None:
            return False

        msg_code, payload = result
        if msg_code != P2PMsg.HELLO:
            return False

        remote_hello = HelloMessage.decode(payload)
        peer.remote_client = remote_hello.client_id

        # Check eth capability
        has_eth = any(cap == "eth" and ver >= 67 for cap, ver in remote_hello.capabilities)
        if not has_eth:
            await self._disconnect_peer(peer, DisconnectReason.INCOMPATIBLE_VERSION)
            return False

        peer.eth_version = max(
            ver for cap, ver in remote_hello.capabilities if cap == "eth"
        )

        # Send Status
        total_difficulty = 0
        best_hash = self.genesis_hash
        if self.store:
            head = self.store.get_latest_block_number()
            if head is not None:
                header = self.store.get_block_header(head)
                if header:
                    best_hash = header.block_hash()
                td = self.store.get_total_difficulty(best_hash)
                if td is not None:
                    total_difficulty = td

        status = StatusMessage(
            protocol_version=ETH_VERSION,
            network_id=self.network_id,
            total_difficulty=total_difficulty,
            best_hash=best_hash,
            genesis_hash=self.genesis_hash,
        )
        await peer.send_eth_message(EthMsg.STATUS, status.encode())

        # Receive Status
        result = await peer.conn.recv_message()
        if result is None:
            return False

        msg_code, payload = result
        if msg_code != EthMsg.STATUS:
            return False

        remote_status = StatusMessage.decode(payload)

        # Verify genesis hash and network ID
        if remote_status.genesis_hash != self.genesis_hash:
            await self._disconnect_peer(peer, DisconnectReason.SUBPROTOCOL_ERROR)
            return False
        if remote_status.network_id != self.network_id:
            await self._disconnect_peer(peer, DisconnectReason.SUBPROTOCOL_ERROR)
            return False

        peer.total_difficulty = remote_status.total_difficulty
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
            peer.conn.close()
            logger.info("Peer disconnected: %s", peer.remote_client)

    async def _dispatch_message(
        self, peer: PeerConnection, msg_code: int, payload: bytes,
    ) -> None:
        """Dispatch a received message to the appropriate handler."""
        # p2p base messages
        if msg_code == P2PMsg.PING:
            await peer.send_p2p_message(P2PMsg.PONG, encode_pong())
        elif msg_code == P2PMsg.PONG:
            peer.last_pong = time.time()
        elif msg_code == P2PMsg.DISCONNECT:
            try:
                disc = DisconnectMessage.decode(payload)
                logger.info("Peer disconnecting: reason=%s", disc.reason.name)
            except Exception:
                pass
            peer.connected = False

        # eth messages
        elif msg_code == EthMsg.BLOCK_HEADERS:
            self.syncer.handle_block_headers(payload)
        elif msg_code == EthMsg.BLOCK_BODIES:
            self.syncer.handle_block_bodies(payload)
        elif msg_code == EthMsg.GET_BLOCK_HEADERS:
            await self._handle_get_block_headers(peer, payload)
        elif msg_code == EthMsg.GET_BLOCK_BODIES:
            await self._handle_get_block_bodies(peer, payload)
        elif msg_code == EthMsg.TRANSACTIONS:
            self._handle_transactions(payload)
        elif msg_code == EthMsg.NEW_POOLED_TX_HASHES:
            self._handle_new_pooled_tx_hashes(payload)
        elif msg_code == EthMsg.NEW_BLOCK_HASHES:
            self._handle_new_block_hashes(payload)
        else:
            logger.debug("Unhandled message code: 0x%02x", msg_code)

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
                    header = self.store.get_block_header(block_num)
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

    def _handle_transactions(self, data: bytes) -> None:
        """Handle broadcast transactions."""
        msg = TransactionsMessage.decode(data)
        logger.debug("Received %d transactions", len(msg.transactions))
        # TODO: forward to mempool

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
                nodes = self._discovery.table.all_nodes()
                for node in nodes:
                    if node.id not in self.peers and node.tcp_port > 0:
                        try:
                            await self.connect_to_peer(node)
                        except Exception:
                            pass
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
        peers = [p for p in self.peers.values() if p.connected]
        if peers:
            await self.syncer.start(peers)

    @property
    def peer_count(self) -> int:
        return len(self.peers)

    @property
    def is_syncing(self) -> bool:
        return self.syncer.is_syncing
