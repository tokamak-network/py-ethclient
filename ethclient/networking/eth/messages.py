"""
eth sub-protocol message encoding/decoding.

Each message type has encode/decode methods using RLP.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ethclient.common import rlp
from ethclient.common.types import BlockHeader, Receipt, Log, TxType, logs_bloom
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
    # eth/68 fields
    total_difficulty: int = 0
    best_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    # common field
    genesis_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    fork_id: tuple[bytes, int] = field(default_factory=lambda: (b"\x00" * 4, 0))
    # eth/69 fields
    earliest_block: int = 0
    latest_block: int = 0
    latest_block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)

    def encode(self) -> bytes:
        if self.protocol_version >= 69:
            return rlp.encode([
                self.protocol_version,
                self.network_id,
                self.genesis_hash,
                [self.fork_id[0], self.fork_id[1]],
                self.earliest_block,
                self.latest_block,
                self.latest_block_hash,
            ])
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
        protocol_version = rlp.decode_uint(items[0])
        network_id = rlp.decode_uint(items[1])

        # eth/69 Status format:
        # [version, networkid, genesis, forkid, earliest, latest, latest_hash]
        if protocol_version >= 69:
            fork_id = (items[3][0], rlp.decode_uint(items[3][1])) if len(items) > 3 else (b"\x00" * 4, 0)
            return cls(
                protocol_version=protocol_version,
                network_id=network_id,
                genesis_hash=items[2],
                fork_id=fork_id,
                earliest_block=rlp.decode_uint(items[4]) if len(items) > 4 else 0,
                latest_block=rlp.decode_uint(items[5]) if len(items) > 5 else 0,
                latest_block_hash=items[6] if len(items) > 6 else b"\x00" * 32,
            )

        # eth/68 (and older) Status format:
        # [version, networkid, td, besthash, genesis, forkid]
        fork_id = (items[5][0], rlp.decode_uint(items[5][1])) if len(items) > 5 else (b"\x00" * 4, 0)
        return cls(
            protocol_version=protocol_version,
            network_id=network_id,
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
    """Response with block bodies (transactions + ommers + optional withdrawals)."""
    request_id: int = 0
    bodies: list[tuple] = field(default_factory=list)  # [(txs_rlp, ommers_rlp, [withdrawals_rlp]), ...]

    def encode(self) -> bytes:
        encoded_bodies = []
        for body in self.bodies:
            if len(body) > 2 and body[2] is not None:
                encoded_bodies.append([body[0], body[1], body[2]])
            else:
                encoded_bodies.append([body[0], body[1]])
        return rlp.encode([self.request_id, encoded_bodies])

    @classmethod
    def decode(cls, data: bytes) -> BlockBodiesMessage:
        items = rlp.decode_list(data)
        req_id = rlp.decode_uint(items[0])
        bodies = []
        for body in items[1]:
            if len(body) > 2:
                bodies.append((body[0], body[1], body[2]))
            else:
                bodies.append((body[0], body[1], []))
        return cls(request_id=req_id, bodies=bodies)


@dataclass
class GetReceiptsMessage:
    """Request receipts by block hash list."""
    request_id: int = 0
    hashes: list[bytes] = field(default_factory=list)

    def encode(self) -> bytes:
        return rlp.encode([self.request_id, self.hashes])

    @classmethod
    def decode(cls, data: bytes) -> GetReceiptsMessage:
        items = rlp.decode_list(data)
        return cls(
            request_id=rlp.decode_uint(items[0]),
            hashes=items[1],
        )


def _encode_receipt_v2(receipt: Receipt) -> list:
    """eth/69 receipt object without logs bloom."""
    return [
        int(receipt.tx_type),
        b"\x01" if receipt.succeeded else b"",
        receipt.cumulative_gas_used,
        [log.to_rlp_list() for log in receipt.logs],
    ]


def _decode_receipt_v2(item: list) -> Receipt:
    tx_type = TxType(rlp.decode_uint(item[0]))
    status_raw = item[1]
    logs = [Log.from_rlp_list(l) for l in item[3]]
    return Receipt(
        succeeded=status_raw == b"\x01",
        cumulative_gas_used=rlp.decode_uint(item[2]),
        logs_bloom=logs_bloom(logs),
        logs=logs,
        tx_type=tx_type,
    )


@dataclass
class ReceiptsMessage:
    """Receipts response, version-aware for eth/68 and eth/69."""
    request_id: int = 0
    receipts: list[list[Receipt]] = field(default_factory=list)
    protocol_version: int = ETH_VERSION

    def encode(self) -> bytes:
        encoded_receipts: list[list] = []
        for block_receipts in self.receipts:
            if self.protocol_version >= 69:
                encoded_receipts.append([_encode_receipt_v2(r) for r in block_receipts])
            else:
                encoded_receipts.append([r.encode_rlp() for r in block_receipts])
        return rlp.encode([self.request_id, encoded_receipts])

    @classmethod
    def decode(cls, data: bytes, protocol_version: int = ETH_VERSION) -> ReceiptsMessage:
        items = rlp.decode_list(data)
        req_id = rlp.decode_uint(items[0])
        all_receipts: list[list[Receipt]] = []
        for block_items in items[1]:
            decoded_block: list[Receipt] = []
            for raw in block_items:
                if protocol_version >= 69 and isinstance(raw, list):
                    decoded_block.append(_decode_receipt_v2(raw))
                elif isinstance(raw, bytes):
                    decoded_block.append(Receipt.decode_rlp(raw))
                elif isinstance(raw, list):
                    decoded_block.append(Receipt.from_rlp_list(raw, TxType.LEGACY))
            all_receipts.append(decoded_block)
        return cls(request_id=req_id, receipts=all_receipts, protocol_version=protocol_version)


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
