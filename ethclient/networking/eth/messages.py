"""
eth sub-protocol message encoding/decoding.

Each message type has encode/decode methods using RLP.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ethclient.common import rlp
from ethclient.common.types import BlockHeader
from ethclient.networking.eth.protocol import (
    P2P_VERSION,
    ETH_VERSION,
    CLIENT_NAME,
    DisconnectReason,
)


# ---------------------------------------------------------------------------
# p2p base protocol messages
# ---------------------------------------------------------------------------

@dataclass
class HelloMessage:
    """p2p Hello message exchanged after handshake."""
    p2p_version: int = P2P_VERSION
    client_id: str = CLIENT_NAME
    capabilities: list[tuple[str, int]] = field(default_factory=lambda: [("eth", ETH_VERSION)])
    listen_port: int = 30303
    node_id: bytes = b""  # 64-byte public key (without 0x04 prefix)

    def encode(self) -> bytes:
        caps = [[cap.encode(), ver] for cap, ver in self.capabilities]
        return rlp.encode([
            self.p2p_version,
            self.client_id,
            caps,
            self.listen_port,
            self.node_id,
        ])

    @classmethod
    def decode(cls, data: bytes) -> HelloMessage:
        items = rlp.decode_list(data)
        caps = [(cap[0].decode(), rlp.decode_uint(cap[1])) for cap in items[2]]
        return cls(
            p2p_version=rlp.decode_uint(items[0]),
            client_id=items[1].decode(),
            capabilities=caps,
            listen_port=rlp.decode_uint(items[3]),
            node_id=items[4],
        )


@dataclass
class DisconnectMessage:
    reason: DisconnectReason = DisconnectReason.REQUESTED

    def encode(self) -> bytes:
        return rlp.encode([self.reason])

    @classmethod
    def decode(cls, data: bytes) -> DisconnectMessage:
        items = rlp.decode_list(data)
        reason = rlp.decode_uint(items[0]) if items else 0
        return cls(reason=DisconnectReason(reason))


# Ping/Pong have empty payload
def encode_ping() -> bytes:
    return rlp.encode([])

def encode_pong() -> bytes:
    return rlp.encode([])


# ---------------------------------------------------------------------------
# eth protocol messages
# ---------------------------------------------------------------------------

@dataclass
class StatusMessage:
    """eth Status message — exchanged after Hello."""
    protocol_version: int = ETH_VERSION
    network_id: int = 1
    total_difficulty: int = 0
    best_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    genesis_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    fork_id: tuple[bytes, int] = field(default_factory=lambda: (b"\x00" * 4, 0))

    def encode(self) -> bytes:
        return rlp.encode([
            self.protocol_version,
            self.network_id,
            self.total_difficulty,
            self.best_hash,
            self.genesis_hash,
            [self.fork_id[0], self.fork_id[1]],
        ])

    @classmethod
    def decode(cls, data: bytes) -> StatusMessage:
        items = rlp.decode_list(data)
        fork_id = (items[5][0], rlp.decode_uint(items[5][1])) if len(items) > 5 else (b"\x00" * 4, 0)
        return cls(
            protocol_version=rlp.decode_uint(items[0]),
            network_id=rlp.decode_uint(items[1]),
            total_difficulty=rlp.decode_uint(items[2]),
            best_hash=items[3],
            genesis_hash=items[4],
            fork_id=fork_id,
        )


@dataclass
class GetBlockHeadersMessage:
    """Request block headers."""
    request_id: int = 0
    origin: int | bytes = 0  # block number or hash
    amount: int = 1
    skip: int = 0
    reverse: bool = False

    def encode(self) -> bytes:
        if isinstance(self.origin, int):
            origin = self.origin
        else:
            origin = self.origin
        return rlp.encode([
            self.request_id,
            [origin, self.amount, self.skip, 1 if self.reverse else 0],
        ])

    @classmethod
    def decode(cls, data: bytes) -> GetBlockHeadersMessage:
        items = rlp.decode_list(data)
        req_id = rlp.decode_uint(items[0])
        params = items[1]
        origin = params[0]
        if len(origin) <= 8:
            origin = rlp.decode_uint(origin)
        return cls(
            request_id=req_id,
            origin=origin,
            amount=rlp.decode_uint(params[1]),
            skip=rlp.decode_uint(params[2]),
            reverse=rlp.decode_uint(params[3]) != 0,
        )


@dataclass
class BlockHeadersMessage:
    """Response with block headers."""
    request_id: int = 0
    headers: list[BlockHeader] = field(default_factory=list)

    def encode(self) -> bytes:
        return rlp.encode([
            self.request_id,
            [h.to_rlp_list() for h in self.headers],
        ])

    @classmethod
    def decode(cls, data: bytes) -> BlockHeadersMessage:
        items = rlp.decode_list(data)
        req_id = rlp.decode_uint(items[0])
        headers = [BlockHeader.from_rlp_list(h) for h in items[1]]
        return cls(request_id=req_id, headers=headers)


@dataclass
class GetBlockBodiesMessage:
    """Request block bodies by hash."""
    request_id: int = 0
    hashes: list[bytes] = field(default_factory=list)

    def encode(self) -> bytes:
        return rlp.encode([self.request_id, self.hashes])

    @classmethod
    def decode(cls, data: bytes) -> GetBlockBodiesMessage:
        items = rlp.decode_list(data)
        return cls(
            request_id=rlp.decode_uint(items[0]),
            hashes=items[1],
        )


@dataclass
class BlockBodiesMessage:
    """Response with block bodies (transactions + ommers)."""
    request_id: int = 0
    bodies: list[tuple[list, list]] = field(default_factory=list)  # [(txs_rlp, ommers_rlp), ...]

    def encode(self) -> bytes:
        return rlp.encode([
            self.request_id,
            [[txs, ommers] for txs, ommers in self.bodies],
        ])

    @classmethod
    def decode(cls, data: bytes) -> BlockBodiesMessage:
        items = rlp.decode_list(data)
        req_id = rlp.decode_uint(items[0])
        bodies = [(body[0], body[1]) for body in items[1]]
        return cls(request_id=req_id, bodies=bodies)


@dataclass
class TransactionsMessage:
    """Broadcast transactions."""
    transactions: list[bytes] = field(default_factory=list)  # RLP-encoded txs

    def encode(self) -> bytes:
        return rlp.encode(self.transactions)

    @classmethod
    def decode(cls, data: bytes) -> TransactionsMessage:
        items = rlp.decode_list(data)
        return cls(transactions=items)


@dataclass
class NewPooledTransactionHashesMessage:
    """Announce new pooled transaction hashes (eth/68)."""
    types: list[int] = field(default_factory=list)
    sizes: list[int] = field(default_factory=list)
    hashes: list[bytes] = field(default_factory=list)

    def encode(self) -> bytes:
        return rlp.encode([
            bytes(self.types),
            self.sizes,
            self.hashes,
        ])

    @classmethod
    def decode(cls, data: bytes) -> NewPooledTransactionHashesMessage:
        items = rlp.decode_list(data)
        types_bytes = items[0]
        return cls(
            types=list(types_bytes),
            sizes=[rlp.decode_uint(s) for s in items[1]],
            hashes=items[2],
        )


@dataclass
class NewBlockHashesMessage:
    """Announce new block hashes."""
    hashes: list[tuple[bytes, int]] = field(default_factory=list)  # (hash, number)

    def encode(self) -> bytes:
        return rlp.encode([[h, n] for h, n in self.hashes])

    @classmethod
    def decode(cls, data: bytes) -> NewBlockHashesMessage:
        items = rlp.decode_list(data)
        return cls(hashes=[(item[0], rlp.decode_uint(item[1])) for item in items])
