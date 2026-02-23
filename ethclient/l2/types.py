"""L2 Rollup core types."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

from ethclient.common.crypto import keccak256
from ethclient.common import rlp


class L2TxType(IntEnum):
    CALL = 0
    DEPOSIT = 1
    WITHDRAWAL = 2


@dataclass
class L2Tx:
    """A Layer-2 transaction."""

    sender: bytes  # 20-byte address
    nonce: int = 0
    data: dict = field(default_factory=dict)
    value: int = 0
    tx_type: L2TxType = L2TxType.CALL
    signature: bytes = b""
    timestamp: int = 0

    def __post_init__(self) -> None:
        if self.timestamp == 0:
            self.timestamp = int(time.time())

    def tx_hash(self) -> bytes:
        return keccak256(self.encode())

    def encode(self) -> bytes:
        data_bytes = rlp.encode(_dict_to_rlp(self.data))
        items = [
            int(self.tx_type).to_bytes(1, "big"),
            self.sender,
            rlp.encode_uint(self.nonce),
            data_bytes,
            rlp.encode_uint(self.value),
            self.signature,
            rlp.encode_uint(self.timestamp),
        ]
        return rlp.encode(items)

    @classmethod
    def decode(cls, raw: bytes) -> L2Tx:
        items = rlp.decode(raw)
        data_rlp = rlp.decode(items[3])
        return cls(
            tx_type=L2TxType(int.from_bytes(items[0], "big")),
            sender=items[1],
            nonce=rlp.decode_uint(items[2]),
            data=_rlp_to_dict(data_rlp),
            value=rlp.decode_uint(items[4]),
            signature=items[5],
            timestamp=rlp.decode_uint(items[6]),
        )


def _dict_to_rlp(d: dict) -> list:
    """Convert a dict to RLP-compatible list of [key, value] pairs."""
    result = []
    for k, v in sorted(d.items()):
        key_bytes = str(k).encode()
        if isinstance(v, int):
            val_bytes = b"\x01" + rlp.encode_uint(v)
        elif isinstance(v, bytes):
            val_bytes = b"\x02" + v
        elif isinstance(v, str):
            val_bytes = b"\x03" + v.encode()
        elif isinstance(v, dict):
            val_bytes = b"\x04" + rlp.encode(_dict_to_rlp(v))
        else:
            val_bytes = b"\x03" + str(v).encode()
        result.append([key_bytes, val_bytes])
    return result


def _rlp_to_dict(items: list) -> dict:
    """Convert RLP pairs back to dict."""
    result = {}
    for pair in items:
        key = pair[0].decode()
        val_bytes = pair[1]
        tag = val_bytes[0:1]
        payload = val_bytes[1:]
        if tag == b"\x01":
            result[key] = rlp.decode_uint(payload)
        elif tag == b"\x02":
            result[key] = payload
        elif tag == b"\x03":
            result[key] = payload.decode()
        elif tag == b"\x04":
            result[key] = _rlp_to_dict(rlp.decode(payload))
        else:
            result[key] = payload.decode()
    return result


class L2State(dict):
    """L2 state as a dict with snapshot support."""

    def snapshot(self) -> L2State:
        import copy
        return L2State(copy.deepcopy(dict(self)))

    @classmethod
    def from_dict(cls, d: dict) -> L2State:
        import copy
        return cls(copy.deepcopy(d))


@dataclass
class STFResult:
    """Result of applying a state transition function."""

    success: bool
    output: dict = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class Batch:
    """A batch of L2 transactions."""

    number: int
    transactions: list[L2Tx] = field(default_factory=list)
    old_state_root: bytes = b"\x00" * 32
    new_state_root: bytes = b"\x00" * 32
    da_commitment: bytes = b""
    proof: Any = None

    sealed: bool = False
    proven: bool = False
    submitted: bool = False
    verified: bool = False

    def tx_commitment(self) -> bytes:
        if not self.transactions:
            return keccak256(b"empty")
        parts = b""
        for tx in self.transactions:
            parts += tx.tx_hash()
        return keccak256(parts)

    def encode(self) -> bytes:
        tx_list = [tx.encode() for tx in self.transactions]
        items = [
            rlp.encode_uint(self.number),
            rlp.encode(tx_list),
            self.old_state_root,
            self.new_state_root,
            self.da_commitment,
        ]
        return rlp.encode(items)

    @classmethod
    def decode(cls, raw: bytes) -> Batch:
        items = rlp.decode(raw)
        tx_list = rlp.decode(items[1])
        txs = [L2Tx.decode(tx_raw) for tx_raw in tx_list]
        return cls(
            number=rlp.decode_uint(items[0]),
            transactions=txs,
            old_state_root=items[2],
            new_state_root=items[3],
            da_commitment=items[4],
            sealed=True,
        )


@dataclass
class BatchReceipt:
    """Receipt for a submitted batch."""

    batch_number: int
    l1_tx_hash: bytes = b""
    verified: bool = False
    state_root: bytes = b"\x00" * 32
