"""
Discovery v4 Kademlia-like routing table.

Each bucket holds up to K=16 nodes at a particular log-distance from
the local node. Distance is defined as keccak256(pubkey_a) XOR keccak256(pubkey_b).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from ethclient.common.crypto import keccak256


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BUCKET_SIZE = 16      # k-bucket capacity
NUM_BUCKETS = 256     # one per bit of the 256-bit node ID
ALPHA = 3             # concurrency parameter for lookups
MAX_REPLACEMENTS = 10 # replacement list size per bucket


# ---------------------------------------------------------------------------
# Node representation
# ---------------------------------------------------------------------------

@dataclass
class Node:
    """A node in the discovery network."""
    id: bytes          # 64-byte public key (uncompressed, without 0x04 prefix)
    ip: str = ""
    udp_port: int = 0
    tcp_port: int = 0
    last_seen: float = 0.0
    last_pong: float = 0.0

    @property
    def node_id(self) -> bytes:
        """32-byte node ID = keccak256(pubkey)."""
        return keccak256(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Node):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)


# ---------------------------------------------------------------------------
# Distance utilities
# ---------------------------------------------------------------------------

def log_distance(a: bytes, b: bytes) -> int:
    """Compute the log2 distance between two 32-byte node IDs.

    Returns 0 if identical, otherwise 1..256.
    """
    dist = int.from_bytes(a, "big") ^ int.from_bytes(b, "big")
    if dist == 0:
        return 0
    return dist.bit_length()


def distance(a: bytes, b: bytes) -> int:
    """Raw XOR distance as integer."""
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


# ---------------------------------------------------------------------------
# Routing table
# ---------------------------------------------------------------------------

@dataclass
class Bucket:
    """A single k-bucket."""
    entries: list[Node] = field(default_factory=list)
    replacements: list[Node] = field(default_factory=list)

    def contains(self, node: Node) -> bool:
        return any(n.id == node.id for n in self.entries)

    def find(self, node_id: bytes) -> Optional[Node]:
        for n in self.entries:
            if n.id == node_id:
                return n
        return None


class RoutingTable:
    """Kademlia-style routing table with 256 k-buckets."""

    def __init__(self, local_node: Node) -> None:
        self.local_node = local_node
        self.local_id = local_node.node_id
        self.buckets: list[Bucket] = [Bucket() for _ in range(NUM_BUCKETS)]

    def bucket_index(self, node_id: bytes) -> int:
        """Get the bucket index for a given 32-byte node ID."""
        d = log_distance(self.local_id, node_id)
        if d == 0:
            return 0
        return d - 1  # bucket 0 = distance 1, bucket 255 = distance 256

    def add_node(self, node: Node) -> Optional[Node]:
        """Add a node to the table.

        Returns None if added successfully or the bucket was updated.
        Returns the least-recently-seen node if the bucket is full
        (caller should ping that node and evict if unresponsive).
        """
        if node.id == self.local_node.id:
            return None

        idx = self.bucket_index(node.node_id)
        bucket = self.buckets[idx]

        # Already in bucket — move to tail (most recent)
        for i, existing in enumerate(bucket.entries):
            if existing.id == node.id:
                bucket.entries.pop(i)
                node.last_seen = time.time()
                bucket.entries.append(node)
                return None

        # Bucket not full — add to tail
        if len(bucket.entries) < BUCKET_SIZE:
            node.last_seen = time.time()
            bucket.entries.append(node)
            return None

        # Bucket full — add to replacement list, return head for ping check
        if node not in bucket.replacements:
            if len(bucket.replacements) >= MAX_REPLACEMENTS:
                bucket.replacements.pop(0)
            bucket.replacements.append(node)

        return bucket.entries[0]  # least recently seen

    def remove_node(self, node: Node) -> None:
        """Remove a node and promote a replacement if available."""
        idx = self.bucket_index(node.node_id)
        bucket = self.buckets[idx]

        bucket.entries = [n for n in bucket.entries if n.id != node.id]

        # Promote from replacement list
        if bucket.replacements and len(bucket.entries) < BUCKET_SIZE:
            replacement = bucket.replacements.pop()
            replacement.last_seen = time.time()
            bucket.entries.append(replacement)

    def closest_nodes(self, target_id: bytes, count: int = BUCKET_SIZE) -> list[Node]:
        """Find the `count` closest nodes to a target ID."""
        all_nodes: list[tuple[int, Node]] = []
        for bucket in self.buckets:
            for node in bucket.entries:
                d = distance(node.node_id, target_id)
                all_nodes.append((d, node))

        all_nodes.sort(key=lambda x: x[0])
        return [node for _, node in all_nodes[:count]]

    def total_nodes(self) -> int:
        """Total number of nodes in the table."""
        return sum(len(b.entries) for b in self.buckets)

    def all_nodes(self) -> list[Node]:
        """Return all nodes in the table."""
        result: list[Node] = []
        for bucket in self.buckets:
            result.extend(bucket.entries)
        return result
