"""
In-memory storage backend.

Dict-based implementation of the Store interface for testing and development.
Includes state trie computation and block-level snapshots.
"""

from __future__ import annotations

import copy
from typing import Optional

from ethclient.common.types import (
    Account,
    Block,
    BlockHeader,
    Transaction,
    Receipt,
    Withdrawal,
    EMPTY_CODE_HASH,
    EMPTY_TRIE_ROOT,
)
from ethclient.common.trie import Trie, EMPTY_ROOT
from ethclient.common.crypto import keccak256
from ethclient.common import rlp
from ethclient.storage.store import Store


class MemoryBackend(Store):
    """In-memory storage backend using Python dicts."""

    def __init__(self) -> None:
        # Account state
        self._accounts: dict[bytes, Account] = {}
        self._code: dict[bytes, bytes] = {}  # code_hash -> code
        self._storage: dict[tuple[bytes, int], int] = {}  # (addr, key) -> value

        # Original storage values at start of block (for SSTORE gas)
        self._original_storage: dict[tuple[bytes, int], int] = {}

        # Block data
        self._headers: dict[bytes, BlockHeader] = {}  # block_hash -> header
        self._bodies: dict[bytes, tuple[list[Transaction], list[BlockHeader], Optional[list[Withdrawal]]]] = {}
        self._receipts: dict[bytes, list[Receipt]] = {}  # block_hash -> receipts

        # Canonical chain: number -> block_hash
        self._canonical: dict[int, bytes] = {}
        self._latest_block: int = -1

        # Transaction index: tx_hash -> (block_hash, tx_index)
        self._tx_index: dict[bytes, tuple[bytes, int]] = {}

        # Snapshots
        self._snapshots: list[dict] = []

    # -----------------------------------------------------------------
    # Account state
    # -----------------------------------------------------------------

    def get_account(self, address: bytes) -> Optional[Account]:
        return self._accounts.get(address)

    def put_account(self, address: bytes, account: Account) -> None:
        self._accounts[address] = account

    def delete_account(self, address: bytes) -> None:
        self._accounts.pop(address, None)
        # Clean up storage for this address
        keys_to_remove = [k for k in self._storage if k[0] == address]
        for k in keys_to_remove:
            del self._storage[k]

    def account_exists(self, address: bytes) -> bool:
        acc = self._accounts.get(address)
        if acc is None:
            return False
        return not acc.is_empty()

    def get_balance(self, address: bytes) -> int:
        acc = self._accounts.get(address)
        return acc.balance if acc else 0

    def set_balance(self, address: bytes, balance: int) -> None:
        acc = self._accounts.get(address)
        if acc is None:
            acc = Account()
            self._accounts[address] = acc
        acc.balance = balance

    def get_nonce(self, address: bytes) -> int:
        acc = self._accounts.get(address)
        return acc.nonce if acc else 0

    def set_nonce(self, address: bytes, nonce: int) -> None:
        acc = self._accounts.get(address)
        if acc is None:
            acc = Account()
            self._accounts[address] = acc
        acc.nonce = nonce

    def increment_nonce(self, address: bytes) -> None:
        self.set_nonce(address, self.get_nonce(address) + 1)

    # -----------------------------------------------------------------
    # Code
    # -----------------------------------------------------------------

    def get_code(self, code_hash: bytes) -> Optional[bytes]:
        return self._code.get(code_hash)

    def put_code(self, code_hash: bytes, code: bytes) -> None:
        self._code[code_hash] = code

    def get_account_code(self, address: bytes) -> bytes:
        acc = self._accounts.get(address)
        if acc is None or acc.code_hash == EMPTY_CODE_HASH:
            return b""
        return self._code.get(acc.code_hash, b"")

    def set_account_code(self, address: bytes, code: bytes) -> None:
        """Store code for an account, updating account's code_hash."""
        acc = self._accounts.get(address)
        if acc is None:
            acc = Account()
            self._accounts[address] = acc
        if code:
            code_hash = keccak256(code)
            acc.code_hash = code_hash
            self._code[code_hash] = code
        else:
            acc.code_hash = EMPTY_CODE_HASH

    # -----------------------------------------------------------------
    # Storage
    # -----------------------------------------------------------------

    def get_storage(self, address: bytes, key: int) -> int:
        return self._storage.get((address, key), 0)

    def put_storage(self, address: bytes, key: int, value: int) -> None:
        if value == 0:
            self._storage.pop((address, key), None)
        else:
            self._storage[(address, key)] = value

    def get_original_storage(self, address: bytes, key: int) -> int:
        return self._original_storage.get((address, key), 0)

    def commit_original_storage(self) -> None:
        """Snapshot current storage as 'original' for next block's SSTORE gas calc."""
        self._original_storage = dict(self._storage)

    # -----------------------------------------------------------------
    # Block headers
    # -----------------------------------------------------------------

    def get_block_header(self, block_hash: bytes) -> Optional[BlockHeader]:
        return self._headers.get(block_hash)

    def get_block_header_by_number(self, number: int) -> Optional[BlockHeader]:
        bh = self._canonical.get(number)
        if bh is None:
            return None
        return self._headers.get(bh)

    def put_block_header(self, header: BlockHeader) -> None:
        block_hash = header.block_hash()
        self._headers[block_hash] = header

    # -----------------------------------------------------------------
    # Block bodies
    # -----------------------------------------------------------------

    def get_block_body(
        self, block_hash: bytes
    ) -> Optional[tuple[list[Transaction], list[BlockHeader], Optional[list[Withdrawal]]]]:
        return self._bodies.get(block_hash)

    def put_block_body(
        self,
        block_hash: bytes,
        transactions: list[Transaction],
        ommers: list[BlockHeader],
        withdrawals: Optional[list[Withdrawal]] = None,
    ) -> None:
        self._bodies[block_hash] = (transactions, ommers, withdrawals)

    # -----------------------------------------------------------------
    # Block (combined)
    # -----------------------------------------------------------------

    def get_block(self, block_hash: bytes) -> Optional[Block]:
        header = self._headers.get(block_hash)
        if header is None:
            return None
        body = self._bodies.get(block_hash)
        if body is None:
            return Block(header=header)
        txs, ommers, withdrawals = body
        return Block(header=header, transactions=txs, ommers=ommers, withdrawals=withdrawals)

    def get_block_by_number(self, number: int) -> Optional[Block]:
        bh = self._canonical.get(number)
        if bh is None:
            return None
        return self.get_block(bh)

    def put_block(self, block: Block) -> None:
        block_hash = block.header.block_hash()
        self._headers[block_hash] = block.header
        self._bodies[block_hash] = (
            block.transactions,
            block.ommers,
            block.withdrawals,
        )
        # Index transactions
        for i, tx in enumerate(block.transactions):
            tx_hash = tx.tx_hash()
            self._tx_index[tx_hash] = (block_hash, i)

    # -----------------------------------------------------------------
    # Receipts
    # -----------------------------------------------------------------

    def get_receipts(self, block_hash: bytes) -> Optional[list[Receipt]]:
        return self._receipts.get(block_hash)

    def put_receipts(self, block_hash: bytes, receipts: list[Receipt]) -> None:
        self._receipts[block_hash] = receipts

    def get_transaction_receipt(
        self, tx_hash: bytes
    ) -> Optional[tuple[Receipt, bytes, int]]:
        idx = self._tx_index.get(tx_hash)
        if idx is None:
            return None
        block_hash, tx_index = idx
        receipts = self._receipts.get(block_hash)
        if receipts is None or tx_index >= len(receipts):
            return None
        return receipts[tx_index], block_hash, tx_index

    # -----------------------------------------------------------------
    # Canonical chain
    # -----------------------------------------------------------------

    def get_canonical_hash(self, number: int) -> Optional[bytes]:
        return self._canonical.get(number)

    def put_canonical_hash(self, number: int, block_hash: bytes) -> None:
        self._canonical[number] = block_hash
        if number > self._latest_block:
            self._latest_block = number

    def get_latest_block_number(self) -> int:
        return max(self._latest_block, 0)

    # -----------------------------------------------------------------
    # State root computation
    # -----------------------------------------------------------------

    def compute_state_root(self) -> bytes:
        """Compute MPT root from all accounts and their storage."""
        if not self._accounts:
            return EMPTY_ROOT

        state_trie = Trie()

        for address, account in self._accounts.items():
            if account.is_empty() and self.get_account_code(address) == b"":
                continue

            # Compute storage root for this account
            storage_root = self._compute_storage_root(address)
            account.storage_root = storage_root

            # RLP-encode the account and insert into state trie
            account_rlp = account.encode_rlp()
            state_trie.put(address, account_rlp)

        return state_trie.root_hash

    def _compute_storage_root(self, address: bytes) -> bytes:
        """Compute the storage trie root for a single account."""
        storage_trie = Trie()
        has_storage = False

        for (addr, key), value in self._storage.items():
            if addr != address or value == 0:
                continue
            has_storage = True
            # Key: keccak256(uint256 key as 32 bytes)
            key_bytes = key.to_bytes(32, "big")
            # Value: RLP-encoded non-zero value (with leading zeros stripped)
            value_rlp = rlp.encode(rlp.encode_uint(value))
            storage_trie.put(key_bytes, value_rlp)

        if not has_storage:
            return EMPTY_TRIE_ROOT

        return storage_trie.root_hash

    # -----------------------------------------------------------------
    # State snapshots
    # -----------------------------------------------------------------

    def snapshot(self) -> int:
        snap = {
            "accounts": {k: copy.copy(v) for k, v in self._accounts.items()},
            "code": dict(self._code),
            "storage": dict(self._storage),
            "canonical": dict(self._canonical),
            "latest_block": self._latest_block,
            "headers": dict(self._headers),
            "bodies": dict(self._bodies),
            "receipts": dict(self._receipts),
            "tx_index": dict(self._tx_index),
        }
        self._snapshots.append(snap)
        return len(self._snapshots) - 1

    def rollback(self, snapshot_id: int) -> None:
        if snapshot_id >= len(self._snapshots):
            return
        snap = self._snapshots[snapshot_id]
        self._accounts = snap["accounts"]
        self._code = snap["code"]
        self._storage = snap["storage"]
        self._canonical = snap["canonical"]
        self._latest_block = snap["latest_block"]
        self._headers = snap["headers"]
        self._bodies = snap["bodies"]
        self._receipts = snap["receipts"]
        self._tx_index = snap["tx_index"]
        self._snapshots = self._snapshots[:snapshot_id]

    def commit(self, snapshot_id: int) -> None:
        self._snapshots = self._snapshots[:snapshot_id]

    # -----------------------------------------------------------------
    # Transaction index
    # -----------------------------------------------------------------

    def get_transaction_by_hash(
        self, tx_hash: bytes
    ) -> Optional[tuple[Transaction, bytes, int]]:
        idx = self._tx_index.get(tx_hash)
        if idx is None:
            return None
        block_hash, tx_index = idx
        body = self._bodies.get(block_hash)
        if body is None or tx_index >= len(body[0]):
            return None
        return body[0][tx_index], block_hash, tx_index

    # -----------------------------------------------------------------
    # Convenience: initialize from genesis
    # -----------------------------------------------------------------

    def init_from_genesis(self, genesis) -> bytes:
        """Initialize state from a Genesis object. Returns genesis block hash."""
        from ethclient.common.config import Genesis

        for alloc in genesis.alloc:
            acc = Account(
                nonce=alloc.nonce,
                balance=alloc.balance,
            )
            self._accounts[alloc.address] = acc

            if alloc.code:
                self.set_account_code(alloc.address, alloc.code)

            for key_bytes, val_bytes in alloc.storage.items():
                key = int.from_bytes(key_bytes, "big")
                val = int.from_bytes(val_bytes, "big")
                if val != 0:
                    self._storage[(alloc.address, key)] = val

        # Compute state root and create genesis block
        state_root = self.compute_state_root()
        block = genesis.to_block()
        block.header.state_root = state_root

        block_hash = block.header.block_hash()
        self.put_block(block)
        self.put_canonical_hash(0, block_hash)

        # Snapshot original storage
        self.commit_original_storage()

        return block_hash
