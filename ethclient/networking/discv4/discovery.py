"""
Discovery v4 protocol — UDP-based peer discovery using Kademlia-like lookups.

Packet types:
  0x01 Ping
  0x02 Pong
  0x03 FindNeighbours (FindNode)
  0x04 Neighbours (Nodes)

Packet structure:
  hash(32) || signature(65) || packet-type(1) || rlp-data(...)
  hash = keccak256(signature || packet-type || rlp-data)
"""

from __future__ import annotations

import asyncio
import time
import logging
from dataclasses import dataclass
from typing import Optional

from coincurve import PrivateKey, PublicKey

from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.networking.discv4.routing import (
    Node,
    RoutingTable,
    ALPHA,
    BUCKET_SIZE,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Packet types
# ---------------------------------------------------------------------------

PING = 0x01
PONG = 0x02
FIND_NEIGHBOURS = 0x03
NEIGHBOURS = 0x04

# Expiration window (60 seconds)
EXPIRATION_WINDOW = 60

# Max neighbours per packet
MAX_NEIGHBOURS_PER_PACKET = 12


# ---------------------------------------------------------------------------
# Packet encoding/decoding
# ---------------------------------------------------------------------------

@dataclass
class Endpoint:
    ip: str
    udp_port: int
    tcp_port: int = 0

    def encode(self) -> list:
        ip_bytes = bytes(int(x) for x in self.ip.split(".")) if self.ip else b"\x00\x00\x00\x00"
        return [ip_bytes, self.udp_port, self.tcp_port]

    @classmethod
    def decode(cls, items: list) -> Endpoint:
        ip_bytes = items[0] if isinstance(items[0], bytes) else items[0]
        if isinstance(ip_bytes, bytes) and len(ip_bytes) == 4:
            ip = ".".join(str(b) for b in ip_bytes)
        else:
            ip = "0.0.0.0"
        udp_port = rlp.decode_uint(items[1]) if isinstance(items[1], bytes) else items[1]
        tcp_port = rlp.decode_uint(items[2]) if isinstance(items[2], bytes) else items[2]
        return cls(ip=ip, udp_port=udp_port, tcp_port=tcp_port)


def _encode_packet(private_key: bytes, packet_type: int, data: bytes) -> bytes:
    """Encode a discovery packet: hash || signature || type || data."""
    pk = PrivateKey(private_key)
    type_byte = bytes([packet_type])
    sig_input = type_byte + data
    sig = pk.sign_recoverable(keccak256(sig_input), hasher=None)
    packet_hash = keccak256(sig + sig_input)
    return packet_hash + sig + sig_input


def _decode_packet(data: bytes) -> Optional[tuple[int, bytes, bytes, bytes]]:
    """Decode a discovery packet.

    Returns (packet_type, payload, node_pubkey_64, packet_hash) or None.
    """
    if len(data) < 32 + 65 + 1:
        return None

    packet_hash = data[:32]
    sig = data[32:97]
    packet_type = data[97]
    payload = data[98:]

    # Verify hash
    expected_hash = keccak256(data[32:])
    if packet_hash != expected_hash:
        return None

    # Recover public key from signature
    try:
        sig_input = data[97:]
        msg_hash = keccak256(sig_input)
        pubkey = PublicKey.from_signature_and_message(sig, msg_hash, hasher=None)
        pubkey_bytes = pubkey.format(compressed=False)[1:]  # 64 bytes
    except Exception:
        return None

    return packet_type, payload, pubkey_bytes, packet_hash


# ---------------------------------------------------------------------------
# Ping / Pong / FindNeighbours / Neighbours
# ---------------------------------------------------------------------------

def encode_ping(
    private_key: bytes,
    from_ep: Endpoint,
    to_ep: Endpoint,
    expiration: Optional[int] = None,
) -> bytes:
    """Encode a Ping packet."""
    if expiration is None:
        expiration = int(time.time()) + EXPIRATION_WINDOW
    data = rlp.encode([
        4,  # version
        from_ep.encode(),
        to_ep.encode(),
        expiration,
    ])
    return _encode_packet(private_key, PING, data)


def decode_ping(payload: bytes) -> tuple[int, Endpoint, Endpoint, int]:
    """Decode Ping payload -> (version, from, to, expiration)."""
    items = rlp.decode_list(payload)
    version = rlp.decode_uint(items[0])
    from_ep = Endpoint.decode(items[1])
    to_ep = Endpoint.decode(items[2])
    expiration = rlp.decode_uint(items[3])
    return version, from_ep, to_ep, expiration


def encode_pong(
    private_key: bytes,
    to_ep: Endpoint,
    ping_hash: bytes,
    expiration: Optional[int] = None,
) -> bytes:
    """Encode a Pong packet."""
    if expiration is None:
        expiration = int(time.time()) + EXPIRATION_WINDOW
    data = rlp.encode([
        to_ep.encode(),
        ping_hash,
        expiration,
    ])
    return _encode_packet(private_key, PONG, data)


def decode_pong(payload: bytes) -> tuple[Endpoint, bytes, int]:
    """Decode Pong payload -> (to, ping_hash, expiration)."""
    items = rlp.decode_list(payload)
    to_ep = Endpoint.decode(items[0])
    ping_hash = items[1]
    expiration = rlp.decode_uint(items[2])
    return to_ep, ping_hash, expiration


def encode_find_neighbours(
    private_key: bytes,
    target: bytes,
    expiration: Optional[int] = None,
) -> bytes:
    """Encode a FindNeighbours packet."""
    if expiration is None:
        expiration = int(time.time()) + EXPIRATION_WINDOW
    data = rlp.encode([target, expiration])
    return _encode_packet(private_key, FIND_NEIGHBOURS, data)


def decode_find_neighbours(payload: bytes) -> tuple[bytes, int]:
    """Decode FindNeighbours payload -> (target, expiration)."""
    items = rlp.decode_list(payload)
    target = items[0]
    expiration = rlp.decode_uint(items[1])
    return target, expiration


def encode_neighbours(
    private_key: bytes,
    nodes: list[Node],
    expiration: Optional[int] = None,
) -> bytes:
    """Encode a Neighbours packet."""
    if expiration is None:
        expiration = int(time.time()) + EXPIRATION_WINDOW
    node_list = []
    for node in nodes:
        ip_bytes = bytes(int(x) for x in node.ip.split(".")) if node.ip else b"\x00\x00\x00\x00"
        node_list.append([
            ip_bytes,
            node.udp_port,
            node.tcp_port,
            node.id,
        ])
    data = rlp.encode([node_list, expiration])
    return _encode_packet(private_key, NEIGHBOURS, data)


def decode_neighbours(payload: bytes) -> tuple[list[Node], int]:
    """Decode Neighbours payload -> (nodes, expiration)."""
    items = rlp.decode_list(payload)
    nodes = []
    for entry in items[0]:
        ip_bytes = entry[0]
        if isinstance(ip_bytes, bytes) and len(ip_bytes) == 4:
            ip = ".".join(str(b) for b in ip_bytes)
        else:
            ip = "0.0.0.0"
        nodes.append(Node(
            id=entry[3],
            ip=ip,
            udp_port=rlp.decode_uint(entry[1]) if isinstance(entry[1], bytes) else entry[1],
            tcp_port=rlp.decode_uint(entry[2]) if isinstance(entry[2], bytes) else entry[2],
        ))
    expiration = rlp.decode_uint(items[1])
    return nodes, expiration


# ---------------------------------------------------------------------------
# Discovery v4 service
# ---------------------------------------------------------------------------

class DiscoveryProtocol(asyncio.DatagramProtocol):
    """UDP-based discovery v4 protocol handler."""

    def __init__(
        self,
        private_key: bytes,
        local_node: Node,
        routing_table: RoutingTable,
        boot_nodes: Optional[list[Node]] = None,
    ) -> None:
        self.private_key = private_key
        self.local_node = local_node
        self.table = routing_table
        self.boot_nodes = boot_nodes or []
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._pending_pings: dict[bytes, tuple[Node, float]] = {}  # ping_hash -> (node, timestamp)
        self._pending_find: dict[str, float] = {}  # endpoint_key -> timestamp

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        logger.info("Discovery UDP server started")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Handle incoming UDP packet."""
        result = _decode_packet(data)
        if result is None:
            return

        packet_type, payload, pubkey, packet_hash = result

        if packet_type == PING:
            self._handle_ping(payload, pubkey, packet_hash, addr)
        elif packet_type == PONG:
            self._handle_pong(payload, pubkey, addr)
        elif packet_type == FIND_NEIGHBOURS:
            self._handle_find_neighbours(payload, pubkey, addr)
        elif packet_type == NEIGHBOURS:
            self._handle_neighbours(payload, pubkey, addr)

    def _handle_ping(
        self, payload: bytes, pubkey: bytes, packet_hash: bytes, addr: tuple[str, int],
    ) -> None:
        """Respond to Ping with Pong and add sender to routing table."""
        try:
            version, from_ep, to_ep, expiration = decode_ping(payload)
        except Exception:
            return

        if expiration < int(time.time()):
            return

        # Send Pong
        to_endpoint = Endpoint(ip=addr[0], udp_port=addr[1])
        pong = encode_pong(self.private_key, to_endpoint, packet_hash)
        if self.transport:
            self.transport.sendto(pong, addr)

        # Add to routing table
        node = Node(
            id=pubkey,
            ip=addr[0],
            udp_port=addr[1],
            tcp_port=from_ep.tcp_port,
            last_seen=time.time(),
            last_pong=time.time(),
        )
        self.table.add_node(node)

    def _handle_pong(
        self, payload: bytes, pubkey: bytes, addr: tuple[str, int],
    ) -> None:
        """Handle Pong response."""
        try:
            to_ep, ping_hash, expiration = decode_pong(payload)
        except Exception:
            return

        if expiration < int(time.time()):
            return

        # Mark node as alive
        if ping_hash in self._pending_pings:
            node, _ = self._pending_pings.pop(ping_hash)
            node.last_pong = time.time()
            self.table.add_node(node)

        # Also try to add by pubkey
        node = Node(
            id=pubkey,
            ip=addr[0],
            udp_port=addr[1],
            last_seen=time.time(),
            last_pong=time.time(),
        )
        self.table.add_node(node)

    def _handle_find_neighbours(
        self, payload: bytes, pubkey: bytes, addr: tuple[str, int],
    ) -> None:
        """Respond with closest nodes to requested target."""
        try:
            target, expiration = decode_find_neighbours(payload)
        except Exception:
            return

        if expiration < int(time.time()):
            return

        target_id = keccak256(target) if len(target) == 64 else target
        closest = self.table.closest_nodes(target_id, BUCKET_SIZE)

        # Send in chunks
        for i in range(0, len(closest), MAX_NEIGHBOURS_PER_PACKET):
            chunk = closest[i:i + MAX_NEIGHBOURS_PER_PACKET]
            packet = encode_neighbours(self.private_key, chunk)
            if self.transport:
                self.transport.sendto(packet, addr)

    def _handle_neighbours(
        self, payload: bytes, pubkey: bytes, addr: tuple[str, int],
    ) -> None:
        """Handle Neighbours response — add nodes to routing table."""
        try:
            nodes, expiration = decode_neighbours(payload)
        except Exception:
            return

        if expiration < int(time.time()):
            return

        for node in nodes:
            if node.id != self.local_node.id:
                self.table.add_node(node)

    # ------------------------------------------------------------------
    # Active operations
    # ------------------------------------------------------------------

    def send_ping(self, node: Node) -> bytes:
        """Send a Ping to a node. Returns the ping hash."""
        from_ep = Endpoint(
            ip=self.local_node.ip,
            udp_port=self.local_node.udp_port,
            tcp_port=self.local_node.tcp_port,
        )
        to_ep = Endpoint(ip=node.ip, udp_port=node.udp_port, tcp_port=node.tcp_port)
        packet = encode_ping(self.private_key, from_ep, to_ep)
        ping_hash = packet[:32]

        self._pending_pings[ping_hash] = (node, time.time())

        if self.transport:
            self.transport.sendto(packet, (node.ip, node.udp_port))

        return ping_hash

    def send_find_neighbours(self, node: Node, target: bytes) -> None:
        """Send FindNeighbours to a node."""
        packet = encode_find_neighbours(self.private_key, target)
        if self.transport:
            self.transport.sendto(packet, (node.ip, node.udp_port))

    async def bootstrap(self) -> None:
        """Ping boot nodes and perform initial lookup."""
        for node in self.boot_nodes:
            self.send_ping(node)

        # Wait for pongs
        await asyncio.sleep(1.0)

        # Lookup ourselves to populate routing table
        await self.lookup(self.local_node.id)

    async def lookup(self, target: bytes) -> list[Node]:
        """Perform a Kademlia lookup for the target.

        Returns the closest nodes found.
        """
        target_id = keccak256(target) if len(target) == 64 else target

        # Start with closest known nodes
        closest = self.table.closest_nodes(target_id, ALPHA)
        if not closest:
            return []

        asked: set[bytes] = set()
        seen: set[bytes] = {self.local_node.id}
        result: list[Node] = list(closest)

        for _ in range(8):  # max iterations
            to_ask = [n for n in result if n.id not in asked][:ALPHA]
            if not to_ask:
                break

            for node in to_ask:
                asked.add(node.id)
                self.send_find_neighbours(node, target)

            # Wait for responses
            await asyncio.sleep(0.5)

            # Collect new closest
            new_closest = self.table.closest_nodes(target_id, BUCKET_SIZE)
            for node in new_closest:
                if node.id not in seen:
                    seen.add(node.id)
                    result.append(node)

            # Sort by distance
            result.sort(key=lambda n: int.from_bytes(n.node_id, "big") ^ int.from_bytes(target_id, "big"))
            result = result[:BUCKET_SIZE]

        return result

    def cleanup_pending(self, timeout: float = 10.0) -> None:
        """Remove expired pending pings."""
        now = time.time()
        expired = [h for h, (_, ts) in self._pending_pings.items() if now - ts > timeout]
        for h in expired:
            del self._pending_pings[h]


async def start_discovery(
    private_key: bytes,
    local_node: Node,
    boot_nodes: list[Node],
    listen_port: int = 30303,
) -> tuple[asyncio.DatagramTransport, DiscoveryProtocol]:
    """Start the discovery v4 UDP server."""
    table = RoutingTable(local_node)
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DiscoveryProtocol(private_key, local_node, table, boot_nodes),
        local_addr=("0.0.0.0", listen_port),
    )
    return transport, protocol
