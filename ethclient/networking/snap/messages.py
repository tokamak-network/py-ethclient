"""
snap/1 sub-protocol message encoding/decoding.

Each message type has encode/decode methods using RLP, following the same
pattern as eth/messages.py.

Wire format reference: https://github.com/ethereum/devp2p/blob/master/caps/snap.md

All request messages include a response_bytes soft limit (default 512 KiB).
All response messages include the matching request_id.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ethclient.common import rlp


# Default soft response size limit (512 KiB)
SNAP_RESPONSE_BYTES = 512 * 1024


# ---------------------------------------------------------------------------
# GetAccountRange / AccountRange
# ---------------------------------------------------------------------------

@dataclass
class GetAccountRangeMessage:
    """Request a range of accounts from the state trie."""
    request_id: int = 0
    root_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    starting_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    limit_hash: bytes = field(default_factory=lambda: b"\xff" * 32)
    response_bytes: int = SNAP_RESPONSE_BYTES

    def encode(self) -> bytes:
        return rlp.encode([
            self.request_id,
            self.root_hash,
            self.starting_hash,
            self.limit_hash,
            self.response_bytes,
        ])

    @classmethod
    def decode(cls, data: bytes) -> GetAccountRangeMessage:
        items = rlp.decode_list(data)
        return cls(
            request_id=rlp.decode_uint(items[0]),
            root_hash=items[1],
            starting_hash=items[2],
            limit_hash=items[3],
            response_bytes=rlp.decode_uint(items[4]),
        )


@dataclass
class AccountRangeMessage:
    """Response with a range of accounts and a Merkle proof.

    accounts: list of (account_hash, slim_account_rlp) tuples
    proof: list of trie node bytes forming the range proof
    """
    request_id: int = 0
    accounts: list[tuple[bytes, bytes]] = field(default_factory=list)
    proof: list[bytes] = field(default_factory=list)

    def encode(self) -> bytes:
        encoded_accounts = [[h, rlp_data] for h, rlp_data in self.accounts]
        return rlp.encode([
            self.request_id,
            encoded_accounts,
            self.proof,
        ])

    @classmethod
    def decode(cls, data: bytes) -> AccountRangeMessage:
        items = rlp.decode_list(data)
        accounts = [(acc[0], acc[1]) for acc in items[1]]
        proof = list(items[2])
        return cls(
            request_id=rlp.decode_uint(items[0]),
            accounts=accounts,
            proof=proof,
        )


# ---------------------------------------------------------------------------
# GetStorageRanges / StorageRanges
# ---------------------------------------------------------------------------

@dataclass
class GetStorageRangesMessage:
    """Request storage slot ranges for one or more accounts."""
    request_id: int = 0
    root_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    account_hashes: list[bytes] = field(default_factory=list)
    starting_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    limit_hash: bytes = field(default_factory=lambda: b"\xff" * 32)
    response_bytes: int = SNAP_RESPONSE_BYTES

    def encode(self) -> bytes:
        return rlp.encode([
            self.request_id,
            self.root_hash,
            self.account_hashes,
            self.starting_hash,
            self.limit_hash,
            self.response_bytes,
        ])

    @classmethod
    def decode(cls, data: bytes) -> GetStorageRangesMessage:
        items = rlp.decode_list(data)
        return cls(
            request_id=rlp.decode_uint(items[0]),
            root_hash=items[1],
            account_hashes=list(items[2]),
            starting_hash=items[3],
            limit_hash=items[4],
            response_bytes=rlp.decode_uint(items[5]),
        )


@dataclass
class StorageRangesMessage:
    """Response with storage slot ranges and proof.

    slots: list of lists of (slot_hash, value) tuples — one inner list per
           requested account.
    proof: Merkle proof for the *last* account's storage trie (only present
           if the range is incomplete for the last account).
    """
    request_id: int = 0
    slots: list[list[tuple[bytes, bytes]]] = field(default_factory=list)
    proof: list[bytes] = field(default_factory=list)

    def encode(self) -> bytes:
        encoded_slots = [
            [[h, v] for h, v in account_slots]
            for account_slots in self.slots
        ]
        return rlp.encode([
            self.request_id,
            encoded_slots,
            self.proof,
        ])

    @classmethod
    def decode(cls, data: bytes) -> StorageRangesMessage:
        items = rlp.decode_list(data)
        slots = [
            [(slot[0], slot[1]) for slot in account_slots]
            for account_slots in items[1]
        ]
        proof = list(items[2])
        return cls(
            request_id=rlp.decode_uint(items[0]),
            slots=slots,
            proof=proof,
        )


# ---------------------------------------------------------------------------
# GetByteCodes / ByteCodes
# ---------------------------------------------------------------------------

@dataclass
class GetByteCodesMessage:
    """Request contract bytecodes by their keccak256 hashes."""
    request_id: int = 0
    hashes: list[bytes] = field(default_factory=list)
    response_bytes: int = SNAP_RESPONSE_BYTES

    def encode(self) -> bytes:
        return rlp.encode([
            self.request_id,
            self.hashes,
            self.response_bytes,
        ])

    @classmethod
    def decode(cls, data: bytes) -> GetByteCodesMessage:
        items = rlp.decode_list(data)
        return cls(
            request_id=rlp.decode_uint(items[0]),
            hashes=list(items[1]),
            response_bytes=rlp.decode_uint(items[2]),
        )


@dataclass
class ByteCodesMessage:
    """Response with contract bytecodes."""
    request_id: int = 0
    codes: list[bytes] = field(default_factory=list)

    def encode(self) -> bytes:
        return rlp.encode([
            self.request_id,
            self.codes,
        ])

    @classmethod
    def decode(cls, data: bytes) -> ByteCodesMessage:
        items = rlp.decode_list(data)
        return cls(
            request_id=rlp.decode_uint(items[0]),
            codes=list(items[1]),
        )


# ---------------------------------------------------------------------------
# GetTrieNodes / TrieNodes
# ---------------------------------------------------------------------------

@dataclass
class GetTrieNodesMessage:
    """Request trie nodes by their paths (for trie healing).

    paths: list of path groups. Each group is a list of byte-encoded paths:
      - For account trie: [[account_path]]
      - For storage trie: [[account_path, slot_path_1, slot_path_2, ...]]
    """
    request_id: int = 0
    root_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    paths: list[list[bytes]] = field(default_factory=list)
    response_bytes: int = SNAP_RESPONSE_BYTES

    def encode(self) -> bytes:
        return rlp.encode([
            self.request_id,
            self.root_hash,
            self.paths,
            self.response_bytes,
        ])

    @classmethod
    def decode(cls, data: bytes) -> GetTrieNodesMessage:
        items = rlp.decode_list(data)
        paths = [list(group) for group in items[2]]
        return cls(
            request_id=rlp.decode_uint(items[0]),
            root_hash=items[1],
            paths=paths,
            response_bytes=rlp.decode_uint(items[3]),
        )


@dataclass
class TrieNodesMessage:
    """Response with trie nodes."""
    request_id: int = 0
    nodes: list[bytes] = field(default_factory=list)

    def encode(self) -> bytes:
        return rlp.encode([
            self.request_id,
            self.nodes,
        ])

    @classmethod
    def decode(cls, data: bytes) -> TrieNodesMessage:
        items = rlp.decode_list(data)
        return cls(
            request_id=rlp.decode_uint(items[0]),
            nodes=list(items[1]),
        )
