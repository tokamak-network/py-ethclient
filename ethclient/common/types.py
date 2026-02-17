"""
Core Ethereum types: Block, BlockHeader, Transaction, Receipt, Account, Bloom.

All types support RLP serialization via to_rlp_list() / from_rlp_list() patterns
and direct encode/decode via the rlp module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from ethclient.common import rlp
from ethclient.common.crypto import keccak256


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EMPTY_TRIE_ROOT = bytes.fromhex(
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
)
EMPTY_CODE_HASH = keccak256(b"")

ZERO_HASH = b"\x00" * 32
ZERO_ADDRESS = b"\x00" * 20
BLOOM_BYTE_SIZE = 256


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------

@dataclass
class Account:
    nonce: int = 0
    balance: int = 0
    storage_root: bytes = field(default_factory=lambda: EMPTY_TRIE_ROOT)
    code_hash: bytes = field(default_factory=lambda: EMPTY_CODE_HASH)

    def to_rlp_list(self) -> list:
        return [
            self.nonce,
            self.balance,
            self.storage_root,
            self.code_hash,
        ]

    @classmethod
    def from_rlp_list(cls, items: list) -> Account:
        return cls(
            nonce=rlp.decode_uint(items[0]),
            balance=rlp.decode_uint(items[1]),
            storage_root=items[2],
            code_hash=items[3],
        )

    def encode_rlp(self) -> bytes:
        return rlp.encode(self.to_rlp_list())

    @classmethod
    def decode_rlp(cls, data: bytes) -> Account:
        return cls.from_rlp_list(rlp.decode_list(data))

    def is_empty(self) -> bool:
        return (
            self.nonce == 0
            and self.balance == 0
            and self.code_hash == EMPTY_CODE_HASH
        )


# ---------------------------------------------------------------------------
# Transaction types
# ---------------------------------------------------------------------------

class TxType(IntEnum):
    LEGACY = 0
    ACCESS_LIST = 1   # EIP-2930
    FEE_MARKET = 2    # EIP-1559
    BLOB = 3          # EIP-4844


@dataclass
class AccessListEntry:
    address: bytes  # 20 bytes
    storage_keys: list[bytes] = field(default_factory=list)  # list of 32-byte keys

    def to_rlp_list(self) -> list:
        return [self.address, self.storage_keys]

    @classmethod
    def from_rlp_list(cls, items: list) -> AccessListEntry:
        return cls(
            address=items[0],
            storage_keys=items[1],
        )


@dataclass
class Transaction:
    """Unified transaction type supporting Legacy, EIP-2930, EIP-1559, EIP-4844."""
    tx_type: TxType = TxType.LEGACY

    # Common fields
    nonce: int = 0
    gas_limit: int = 0
    to: Optional[bytes] = None  # None for contract creation
    value: int = 0
    data: bytes = b""

    # Legacy / EIP-2930
    gas_price: int = 0

    # EIP-1559 / EIP-4844
    max_fee_per_gas: int = 0
    max_priority_fee_per_gas: int = 0

    # EIP-2930 / EIP-1559 / EIP-4844
    chain_id: int = 1
    access_list: list[AccessListEntry] = field(default_factory=list)

    # EIP-4844
    max_fee_per_blob_gas: int = 0
    blob_versioned_hashes: list[bytes] = field(default_factory=list)

    # Signature
    v: int = 0
    r: int = 0
    s: int = 0

    def to_rlp_list(self) -> list:
        to_bytes = self.to if self.to is not None else b""
        al = [e.to_rlp_list() for e in self.access_list]

        if self.tx_type == TxType.LEGACY:
            return [
                self.nonce,
                self.gas_price,
                self.gas_limit,
                to_bytes,
                self.value,
                self.data,
                self.v,
                self.r,
                self.s,
            ]
        elif self.tx_type == TxType.ACCESS_LIST:
            return [
                self.chain_id,
                self.nonce,
                self.gas_price,
                self.gas_limit,
                to_bytes,
                self.value,
                self.data,
                al,
                self.v,
                self.r,
                self.s,
            ]
        elif self.tx_type == TxType.FEE_MARKET:
            return [
                self.chain_id,
                self.nonce,
                self.max_priority_fee_per_gas,
                self.max_fee_per_gas,
                self.gas_limit,
                to_bytes,
                self.value,
                self.data,
                al,
                self.v,
                self.r,
                self.s,
            ]
        elif self.tx_type == TxType.BLOB:
            return [
                self.chain_id,
                self.nonce,
                self.max_priority_fee_per_gas,
                self.max_fee_per_gas,
                self.gas_limit,
                to_bytes,
                self.value,
                self.data,
                al,
                self.max_fee_per_blob_gas,
                self.blob_versioned_hashes,
                self.v,
                self.r,
                self.s,
            ]
        raise ValueError(f"Unknown tx type: {self.tx_type}")

    @classmethod
    def from_rlp_list(cls, items: list, tx_type: TxType = TxType.LEGACY) -> Transaction:
        def parse_to(raw: bytes) -> Optional[bytes]:
            return raw if len(raw) == 20 else None

        def parse_al(raw: list) -> list[AccessListEntry]:
            return [AccessListEntry.from_rlp_list(e) for e in raw]

        if tx_type == TxType.LEGACY:
            return cls(
                tx_type=TxType.LEGACY,
                nonce=rlp.decode_uint(items[0]),
                gas_price=rlp.decode_uint(items[1]),
                gas_limit=rlp.decode_uint(items[2]),
                to=parse_to(items[3]),
                value=rlp.decode_uint(items[4]),
                data=items[5],
                v=rlp.decode_uint(items[6]),
                r=rlp.decode_uint(items[7]),
                s=rlp.decode_uint(items[8]),
            )
        elif tx_type == TxType.ACCESS_LIST:
            return cls(
                tx_type=TxType.ACCESS_LIST,
                chain_id=rlp.decode_uint(items[0]),
                nonce=rlp.decode_uint(items[1]),
                gas_price=rlp.decode_uint(items[2]),
                gas_limit=rlp.decode_uint(items[3]),
                to=parse_to(items[4]),
                value=rlp.decode_uint(items[5]),
                data=items[6],
                access_list=parse_al(items[7]),
                v=rlp.decode_uint(items[8]),
                r=rlp.decode_uint(items[9]),
                s=rlp.decode_uint(items[10]),
            )
        elif tx_type == TxType.FEE_MARKET:
            return cls(
                tx_type=TxType.FEE_MARKET,
                chain_id=rlp.decode_uint(items[0]),
                nonce=rlp.decode_uint(items[1]),
                max_priority_fee_per_gas=rlp.decode_uint(items[2]),
                max_fee_per_gas=rlp.decode_uint(items[3]),
                gas_limit=rlp.decode_uint(items[4]),
                to=parse_to(items[5]),
                value=rlp.decode_uint(items[6]),
                data=items[7],
                access_list=parse_al(items[8]),
                v=rlp.decode_uint(items[9]),
                r=rlp.decode_uint(items[10]),
                s=rlp.decode_uint(items[11]),
            )
        elif tx_type == TxType.BLOB:
            return cls(
                tx_type=TxType.BLOB,
                chain_id=rlp.decode_uint(items[0]),
                nonce=rlp.decode_uint(items[1]),
                max_priority_fee_per_gas=rlp.decode_uint(items[2]),
                max_fee_per_gas=rlp.decode_uint(items[3]),
                gas_limit=rlp.decode_uint(items[4]),
                to=parse_to(items[5]),
                value=rlp.decode_uint(items[6]),
                data=items[7],
                access_list=parse_al(items[8]),
                max_fee_per_blob_gas=rlp.decode_uint(items[9]),
                blob_versioned_hashes=items[10],
                v=rlp.decode_uint(items[11]),
                r=rlp.decode_uint(items[12]),
                s=rlp.decode_uint(items[13]),
            )
        raise ValueError(f"Unknown tx type: {tx_type}")

    def encode_rlp(self) -> bytes:
        """Encode transaction to RLP bytes (with type prefix for typed txs)."""
        payload = rlp.encode(self.to_rlp_list())
        if self.tx_type == TxType.LEGACY:
            return payload
        return bytes([self.tx_type]) + payload

    @classmethod
    def decode_rlp(cls, data: bytes) -> Transaction:
        """Decode transaction from RLP bytes (handles typed tx prefix)."""
        if len(data) == 0:
            raise rlp.RLPDecodingError("Empty transaction data")

        if data[0] < 0x80:
            # Typed transaction: first byte is tx type
            tx_type = TxType(data[0])
            items = rlp.decode_list(data[1:])
            return cls.from_rlp_list(items, tx_type)
        else:
            # Legacy transaction
            items = rlp.decode_list(data)
            return cls.from_rlp_list(items, TxType.LEGACY)

    def signing_hash(self, chain_id: Optional[int] = None) -> bytes:
        """Compute the hash to be signed (pre-signature)."""
        to_bytes = self.to if self.to is not None else b""
        al = [e.to_rlp_list() for e in self.access_list]

        if self.tx_type == TxType.LEGACY:
            if chain_id is not None:
                # EIP-155
                items = [
                    self.nonce, self.gas_price, self.gas_limit,
                    to_bytes, self.value, self.data,
                    chain_id, 0, 0,
                ]
            else:
                items = [
                    self.nonce, self.gas_price, self.gas_limit,
                    to_bytes, self.value, self.data,
                ]
            return keccak256(rlp.encode(items))
        elif self.tx_type == TxType.ACCESS_LIST:
            items = [
                self.chain_id, self.nonce, self.gas_price, self.gas_limit,
                to_bytes, self.value, self.data, al,
            ]
            return keccak256(bytes([0x01]) + rlp.encode(items))
        elif self.tx_type == TxType.FEE_MARKET:
            items = [
                self.chain_id, self.nonce, self.max_priority_fee_per_gas,
                self.max_fee_per_gas, self.gas_limit,
                to_bytes, self.value, self.data, al,
            ]
            return keccak256(bytes([0x02]) + rlp.encode(items))
        elif self.tx_type == TxType.BLOB:
            items = [
                self.chain_id, self.nonce, self.max_priority_fee_per_gas,
                self.max_fee_per_gas, self.gas_limit,
                to_bytes, self.value, self.data, al,
                self.max_fee_per_blob_gas, self.blob_versioned_hashes,
            ]
            return keccak256(bytes([0x03]) + rlp.encode(items))
        raise ValueError(f"Unknown tx type: {self.tx_type}")

    def tx_hash(self) -> bytes:
        """Compute transaction hash."""
        return keccak256(self.encode_rlp())

    def effective_gas_price(self, base_fee: int = 0) -> int:
        if self.tx_type in (TxType.FEE_MARKET, TxType.BLOB):
            return min(
                self.max_fee_per_gas,
                base_fee + self.max_priority_fee_per_gas,
            )
        return self.gas_price

    def sender(self) -> bytes:
        """Recover sender address from signature."""
        from ethclient.common.crypto import ecdsa_recover, pubkey_to_address

        if self.tx_type == TxType.LEGACY:
            # EIP-155: v = chain_id * 2 + 35 + recovery_id
            if self.v >= 35:
                chain_id = (self.v - 35) // 2
                recovery_id = self.v - 35 - 2 * chain_id
                msg_hash = self.signing_hash(chain_id)
            else:
                recovery_id = self.v - 27
                msg_hash = self.signing_hash()
        else:
            recovery_id = self.v
            msg_hash = self.signing_hash()

        pubkey = ecdsa_recover(msg_hash, recovery_id, self.r, self.s)
        return pubkey_to_address(pubkey)


# ---------------------------------------------------------------------------
# Withdrawal (post-Shanghai)
# ---------------------------------------------------------------------------

@dataclass
class Withdrawal:
    index: int = 0
    validator_index: int = 0
    address: bytes = field(default_factory=lambda: ZERO_ADDRESS)
    amount: int = 0  # in Gwei

    def to_rlp_list(self) -> list:
        return [self.index, self.validator_index, self.address, self.amount]

    @classmethod
    def from_rlp_list(cls, items: list) -> Withdrawal:
        return cls(
            index=rlp.decode_uint(items[0]),
            validator_index=rlp.decode_uint(items[1]),
            address=items[2],
            amount=rlp.decode_uint(items[3]),
        )


# ---------------------------------------------------------------------------
# Block Header
# ---------------------------------------------------------------------------

@dataclass
class BlockHeader:
    parent_hash: bytes = field(default_factory=lambda: ZERO_HASH)
    ommers_hash: bytes = field(default_factory=lambda: ZERO_HASH)
    coinbase: bytes = field(default_factory=lambda: ZERO_ADDRESS)
    state_root: bytes = field(default_factory=lambda: ZERO_HASH)
    transactions_root: bytes = field(default_factory=lambda: EMPTY_TRIE_ROOT)
    receipts_root: bytes = field(default_factory=lambda: EMPTY_TRIE_ROOT)
    logs_bloom: bytes = field(default_factory=lambda: b"\x00" * BLOOM_BYTE_SIZE)
    difficulty: int = 0
    number: int = 0
    gas_limit: int = 0
    gas_used: int = 0
    timestamp: int = 0
    extra_data: bytes = b""
    mix_hash: bytes = field(default_factory=lambda: ZERO_HASH)
    nonce: bytes = field(default_factory=lambda: b"\x00" * 8)

    # Post-London (EIP-1559)
    base_fee_per_gas: Optional[int] = None
    # Post-Shanghai
    withdrawals_root: Optional[bytes] = None
    # Post-Cancun (EIP-4844)
    blob_gas_used: Optional[int] = None
    excess_blob_gas: Optional[int] = None
    parent_beacon_block_root: Optional[bytes] = None

    def to_rlp_list(self) -> list:
        items: list = [
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
            self.mix_hash,
            self.nonce,
        ]
        if self.base_fee_per_gas is not None:
            items.append(self.base_fee_per_gas)
        if self.withdrawals_root is not None:
            items.append(self.withdrawals_root)
        if self.blob_gas_used is not None:
            items.append(self.blob_gas_used)
        if self.excess_blob_gas is not None:
            items.append(self.excess_blob_gas)
        if self.parent_beacon_block_root is not None:
            items.append(self.parent_beacon_block_root)
        return items

    @classmethod
    def from_rlp_list(cls, items: list) -> BlockHeader:
        header = cls(
            parent_hash=items[0],
            ommers_hash=items[1],
            coinbase=items[2],
            state_root=items[3],
            transactions_root=items[4],
            receipts_root=items[5],
            logs_bloom=items[6],
            difficulty=rlp.decode_uint(items[7]),
            number=rlp.decode_uint(items[8]),
            gas_limit=rlp.decode_uint(items[9]),
            gas_used=rlp.decode_uint(items[10]),
            timestamp=rlp.decode_uint(items[11]),
            extra_data=items[12],
            mix_hash=items[13],
            nonce=items[14],
        )
        n = len(items)
        if n > 15:
            header.base_fee_per_gas = rlp.decode_uint(items[15])
        if n > 16:
            header.withdrawals_root = items[16]
        if n > 17:
            header.blob_gas_used = rlp.decode_uint(items[17])
        if n > 18:
            header.excess_blob_gas = rlp.decode_uint(items[18])
        if n > 19:
            header.parent_beacon_block_root = items[19]
        return header

    def encode_rlp(self) -> bytes:
        return rlp.encode(self.to_rlp_list())

    @classmethod
    def decode_rlp(cls, data: bytes) -> BlockHeader:
        return cls.from_rlp_list(rlp.decode_list(data))

    def block_hash(self) -> bytes:
        return keccak256(self.encode_rlp())


# ---------------------------------------------------------------------------
# Log & Receipt
# ---------------------------------------------------------------------------

@dataclass
class Log:
    address: bytes = field(default_factory=lambda: ZERO_ADDRESS)
    topics: list[bytes] = field(default_factory=list)
    data: bytes = b""

    def to_rlp_list(self) -> list:
        return [self.address, self.topics, self.data]

    @classmethod
    def from_rlp_list(cls, items: list) -> Log:
        return cls(address=items[0], topics=items[1], data=items[2])


@dataclass
class Receipt:
    succeeded: bool = True
    cumulative_gas_used: int = 0
    logs_bloom: bytes = field(default_factory=lambda: b"\x00" * BLOOM_BYTE_SIZE)
    logs: list[Log] = field(default_factory=list)
    tx_type: TxType = TxType.LEGACY

    def to_rlp_list(self) -> list:
        return [
            b"\x01" if self.succeeded else b"",
            self.cumulative_gas_used,
            self.logs_bloom,
            [log.to_rlp_list() for log in self.logs],
        ]

    @classmethod
    def from_rlp_list(cls, items: list, tx_type: TxType = TxType.LEGACY) -> Receipt:
        status_bytes = items[0]
        return cls(
            succeeded=status_bytes == b"\x01",
            cumulative_gas_used=rlp.decode_uint(items[1]),
            logs_bloom=items[2],
            logs=[Log.from_rlp_list(l) for l in items[3]],
            tx_type=tx_type,
        )

    def encode_rlp(self) -> bytes:
        payload = rlp.encode(self.to_rlp_list())
        if self.tx_type == TxType.LEGACY:
            return payload
        return bytes([self.tx_type]) + payload

    @classmethod
    def decode_rlp(cls, data: bytes) -> Receipt:
        if data[0] < 0x80:
            tx_type = TxType(data[0])
            return cls.from_rlp_list(rlp.decode_list(data[1:]), tx_type)
        return cls.from_rlp_list(rlp.decode_list(data), TxType.LEGACY)


# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------

@dataclass
class Block:
    header: BlockHeader = field(default_factory=BlockHeader)
    transactions: list[Transaction] = field(default_factory=list)
    ommers: list[BlockHeader] = field(default_factory=list)
    withdrawals: Optional[list[Withdrawal]] = None

    def encode_rlp(self) -> bytes:
        items: list = [
            self.header.to_rlp_list(),
            [tx.to_rlp_list() for tx in self.transactions],
            [o.to_rlp_list() for o in self.ommers],
        ]
        if self.withdrawals is not None:
            items.append([w.to_rlp_list() for w in self.withdrawals])
        return rlp.encode(items)

    @classmethod
    def decode_rlp(cls, data: bytes) -> Block:
        items = rlp.decode_list(data)
        header = BlockHeader.from_rlp_list(items[0])
        transactions = [
            Transaction.from_rlp_list(tx_items)
            for tx_items in items[1]
        ]
        ommers = [BlockHeader.from_rlp_list(o) for o in items[2]]
        withdrawals = None
        if len(items) > 3:
            withdrawals = [Withdrawal.from_rlp_list(w) for w in items[3]]
        return cls(
            header=header,
            transactions=transactions,
            ommers=ommers,
            withdrawals=withdrawals,
        )

    def block_hash(self) -> bytes:
        return self.header.block_hash()


# ---------------------------------------------------------------------------
# Bloom filter utilities
# ---------------------------------------------------------------------------

def bloom_add(bloom: bytearray, data: bytes) -> None:
    """Add data to a 2048-bit bloom filter (256 bytes)."""
    h = keccak256(data)
    for i in range(3):
        bit = (h[i * 2] << 8 | h[i * 2 + 1]) & 0x7FF
        byte_idx = BLOOM_BYTE_SIZE - 1 - (bit // 8)
        bit_idx = bit % 8
        bloom[byte_idx] |= 1 << bit_idx


def bloom_contains(bloom: bytes, data: bytes) -> bool:
    """Check if data might be in the bloom filter."""
    h = keccak256(data)
    for i in range(3):
        bit = (h[i * 2] << 8 | h[i * 2 + 1]) & 0x7FF
        byte_idx = BLOOM_BYTE_SIZE - 1 - (bit // 8)
        bit_idx = bit % 8
        if not (bloom[byte_idx] & (1 << bit_idx)):
            return False
    return True


def logs_bloom(logs: list[Log]) -> bytes:
    """Compute the bloom filter for a list of logs."""
    bloom = bytearray(BLOOM_BYTE_SIZE)
    for log in logs:
        bloom_add(bloom, log.address)
        for topic in log.topics:
            bloom_add(bloom, topic)
    return bytes(bloom)
