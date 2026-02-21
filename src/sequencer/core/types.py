"""Minimal type wrappers for sequencer."""

from dataclasses import dataclass
from typing import Optional

from .crypto import keccak256
from .constants import EMPTY_ROOT, EMPTY_CODE_HASH


@dataclass
class Account:
    nonce: int
    balance: int
    storage_root: bytes
    code_hash: bytes

    @classmethod
    def empty(cls) -> "Account":
        return cls(nonce=0, balance=0, storage_root=EMPTY_ROOT, code_hash=EMPTY_CODE_HASH)

    def to_rlp(self) -> bytes:
        from rlp import encode
        result = encode([self.nonce, self.balance, self.storage_root, self.code_hash])
        return bytes(result)

    @classmethod
    def from_rlp(cls, data: bytes) -> "Account":
        from rlp import decode
        nonce, balance, storage_root, code_hash = decode(data)
        return cls(nonce, balance, storage_root, code_hash)


@dataclass
class BlockHeader:
    parent_hash: bytes
    ommers_hash: bytes
    coinbase: bytes
    state_root: bytes
    transactions_root: bytes
    receipts_root: bytes
    logs_bloom: bytes
    difficulty: int = 0
    number: int = 0
    gas_limit: int = 30_000_000
    gas_used: int = 0
    timestamp: int = 0
    extra_data: bytes = b""
    prev_randao: bytes = b"\x00" * 32
    nonce: bytes = b"\x00" * 8
    base_fee_per_gas: Optional[int] = None

    def hash(self) -> bytes:
        from rlp import encode
        return keccak256(encode(self._to_rlp_list()))

    def _to_rlp_list(self) -> list:
        return [
            self.parent_hash,
            self.ommers_hash,
            self.coinbase,
            self.state_root,
            self.transactions_root,
            self.receipts_root,
            self.logs_bloom,
            self.difficulty,
            self.number,
            self.gas_limit,
            self.gas_used,
            self.timestamp,
            self.extra_data,
            self.prev_randao,
            self.nonce,
            self.base_fee_per_gas if self.base_fee_per_gas else b"",
        ]


@dataclass
class Block:
    header: BlockHeader
    transactions: list

    @property
    def hash(self) -> bytes:
        return self.header.hash()

    @property
    def number(self) -> int:
        return self.header.number


@dataclass
class Receipt:
    status: int
    cumulative_gas_used: int
    logs: list
    contract_address: Optional[bytes] = None

    def to_rlp(self) -> bytes:
        from rlp import encode
        return encode([self.status, self.cumulative_gas_used, self.logs])


