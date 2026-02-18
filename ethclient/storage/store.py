"""
Store interface — abstract storage layer for the Ethereum client.

Defines the contract for state (accounts, code, storage) and chain data
(block headers, bodies, receipts) persistence.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator, Optional

from ethclient.common.types import (
    Account,
    Block,
    BlockHeader,
    Transaction,
    Receipt,
    Withdrawal,
    EMPTY_CODE_HASH,
)
from ethclient.common.crypto import keccak256


class Store(ABC):
    """Abstract storage interface.

    Implementations can be in-memory (testing), LMDB, or other backends.
    """

    # -----------------------------------------------------------------
    # Account state
    # -----------------------------------------------------------------

    @abstractmethod
    def get_account(self, address: bytes) -> Optional[Account]:
        """Get account by address, or None if not found."""
        ...

    @abstractmethod
    def put_account(self, address: bytes, account: Account) -> None:
        """Store or update an account."""
        ...

    @abstractmethod
    def delete_account(self, address: bytes) -> None:
        """Remove an account."""
        ...

    @abstractmethod
    def account_exists(self, address: bytes) -> bool:
        """Check if account exists (non-empty)."""
        ...

    # -----------------------------------------------------------------
    # Convenience account methods (concrete — delegate to get/put_account)
    # -----------------------------------------------------------------

    def get_balance(self, address: bytes) -> int:
        acc = self.get_account(address)
        return acc.balance if acc else 0

    def set_balance(self, address: bytes, balance: int) -> None:
        acc = self.get_account(address)
        if acc is None:
            acc = Account()
        acc.balance = balance
        self.put_account(address, acc)

    def get_nonce(self, address: bytes) -> int:
        acc = self.get_account(address)
        return acc.nonce if acc else 0

    def set_nonce(self, address: bytes, nonce: int) -> None:
        acc = self.get_account(address)
        if acc is None:
            acc = Account()
        acc.nonce = nonce
        self.put_account(address, acc)

    def increment_nonce(self, address: bytes) -> None:
        self.set_nonce(address, self.get_nonce(address) + 1)

    def set_account_code(self, address: bytes, code: bytes) -> None:
        """Store code for an account, updating account's code_hash."""
        acc = self.get_account(address)
        if acc is None:
            acc = Account()
        if code:
            code_hash = keccak256(code)
            acc.code_hash = code_hash
            self.put_code(code_hash, code)
        else:
            acc.code_hash = EMPTY_CODE_HASH
        self.put_account(address, acc)

    # -----------------------------------------------------------------
    # Code
    # -----------------------------------------------------------------

    @abstractmethod
    def get_code(self, code_hash: bytes) -> Optional[bytes]:
        """Get contract code by its keccak256 hash."""
        ...

    @abstractmethod
    def put_code(self, code_hash: bytes, code: bytes) -> None:
        """Store contract code."""
        ...

    @abstractmethod
    def get_account_code(self, address: bytes) -> bytes:
        """Get contract code for an account address."""
        ...

    # -----------------------------------------------------------------
    # Storage
    # -----------------------------------------------------------------

    @abstractmethod
    def get_storage(self, address: bytes, key: int) -> int:
        """Get storage value at (address, key). Returns 0 if not set."""
        ...

    @abstractmethod
    def put_storage(self, address: bytes, key: int, value: int) -> None:
        """Set storage value at (address, key)."""
        ...

    @abstractmethod
    def get_original_storage(self, address: bytes, key: int) -> int:
        """Get storage value at the start of the transaction (for SSTORE gas calc)."""
        ...

    @abstractmethod
    def commit_original_storage(self) -> None:
        """Snapshot current storage as 'original' for next block's SSTORE gas calc."""
        ...

    # -----------------------------------------------------------------
    # Iterators (for _bind_env_to_store and compute_state_root)
    # -----------------------------------------------------------------

    @abstractmethod
    def iter_accounts(self) -> Iterator[tuple[bytes, Account]]:
        """Iterate over all (address, Account) pairs."""
        ...

    @abstractmethod
    def iter_storage(self) -> Iterator[tuple[tuple[bytes, int], int]]:
        """Iterate over all ((address, key), value) storage pairs."""
        ...

    @abstractmethod
    def iter_original_storage(self) -> Iterator[tuple[tuple[bytes, int], int]]:
        """Iterate over all ((address, key), value) original storage pairs."""
        ...

    # -----------------------------------------------------------------
    # Block headers
    # -----------------------------------------------------------------

    @abstractmethod
    def get_block_header(self, block_hash: bytes) -> Optional[BlockHeader]:
        """Get block header by hash."""
        ...

    @abstractmethod
    def get_block_header_by_number(self, number: int) -> Optional[BlockHeader]:
        """Get block header by block number (canonical chain)."""
        ...

    @abstractmethod
    def put_block_header(self, header: BlockHeader) -> None:
        """Store a block header."""
        ...

    # -----------------------------------------------------------------
    # Block bodies (transactions + ommers + withdrawals)
    # -----------------------------------------------------------------

    @abstractmethod
    def get_block_body(
        self, block_hash: bytes
    ) -> Optional[tuple[list[Transaction], list[BlockHeader], Optional[list[Withdrawal]]]]:
        """Get block body (transactions, ommers, withdrawals) by hash."""
        ...

    @abstractmethod
    def put_block_body(
        self,
        block_hash: bytes,
        transactions: list[Transaction],
        ommers: list[BlockHeader],
        withdrawals: Optional[list[Withdrawal]] = None,
    ) -> None:
        """Store block body."""
        ...

    # -----------------------------------------------------------------
    # Block (combined header + body)
    # -----------------------------------------------------------------

    @abstractmethod
    def get_block(self, block_hash: bytes) -> Optional[Block]:
        """Get full block by hash."""
        ...

    @abstractmethod
    def get_block_by_number(self, number: int) -> Optional[Block]:
        """Get full block by number (canonical chain)."""
        ...

    @abstractmethod
    def put_block(self, block: Block) -> None:
        """Store a full block."""
        ...

    # -----------------------------------------------------------------
    # Receipts
    # -----------------------------------------------------------------

    @abstractmethod
    def get_receipts(self, block_hash: bytes) -> Optional[list[Receipt]]:
        """Get receipts for a block."""
        ...

    @abstractmethod
    def put_receipts(self, block_hash: bytes, receipts: list[Receipt]) -> None:
        """Store receipts for a block."""
        ...

    @abstractmethod
    def get_transaction_receipt(
        self, tx_hash: bytes
    ) -> Optional[tuple[Receipt, bytes, int]]:
        """Get receipt by tx hash. Returns (receipt, block_hash, tx_index) or None."""
        ...

    # -----------------------------------------------------------------
    # Canonical chain mapping
    # -----------------------------------------------------------------

    @abstractmethod
    def get_canonical_hash(self, number: int) -> Optional[bytes]:
        """Get the block hash for a canonical block number."""
        ...

    @abstractmethod
    def put_canonical_hash(self, number: int, block_hash: bytes) -> None:
        """Set the canonical block hash for a number."""
        ...

    @abstractmethod
    def get_latest_block_number(self) -> int:
        """Get the highest known canonical block number."""
        ...

    # -----------------------------------------------------------------
    # State root
    # -----------------------------------------------------------------

    @abstractmethod
    def compute_state_root(self) -> bytes:
        """Compute the current state trie root hash."""
        ...

    # -----------------------------------------------------------------
    # State snapshots (for block-level rollback)
    # -----------------------------------------------------------------

    @abstractmethod
    def snapshot(self) -> int:
        """Take a snapshot of current state. Returns snapshot ID."""
        ...

    @abstractmethod
    def rollback(self, snapshot_id: int) -> None:
        """Rollback state to a previous snapshot."""
        ...

    @abstractmethod
    def commit(self, snapshot_id: int) -> None:
        """Commit changes since snapshot (discard rollback point)."""
        ...

    # -----------------------------------------------------------------
    # Transaction index
    # -----------------------------------------------------------------

    @abstractmethod
    def get_transaction_by_hash(
        self, tx_hash: bytes
    ) -> Optional[tuple[Transaction, bytes, int]]:
        """Get transaction by hash. Returns (tx, block_hash, tx_index) or None."""
        ...

    # -----------------------------------------------------------------
    # Snap sync state
    # -----------------------------------------------------------------

    def put_snap_account(self, account_hash: bytes, account_rlp: bytes) -> None:
        """Store a snap-synced account by its hash key."""
        ...

    def put_snap_storage(
        self, account_hash: bytes, slot_hash: bytes, value: bytes,
    ) -> None:
        """Store a snap-synced storage slot."""
        ...

    def put_snap_code(self, code_hash: bytes, code: bytes) -> None:
        """Store snap-synced contract bytecode."""
        ...

    def get_snap_progress(self) -> Optional[dict]:
        """Get snap sync progress state, or None if not started."""
        ...

    def put_snap_progress(self, progress: dict) -> None:
        """Persist snap sync progress for resumption."""
        ...

    # -----------------------------------------------------------------
    # Genesis initialization (concrete — uses abstract methods)
    # -----------------------------------------------------------------

    def init_from_genesis(self, genesis) -> bytes:
        """Initialize state from a Genesis object. Returns genesis block hash."""
        for alloc in genesis.alloc:
            acc = Account(
                nonce=alloc.nonce,
                balance=alloc.balance,
            )
            self.put_account(alloc.address, acc)

            if alloc.code:
                self.set_account_code(alloc.address, alloc.code)

            for key_bytes, val_bytes in alloc.storage.items():
                key = int.from_bytes(key_bytes, "big")
                val = int.from_bytes(val_bytes, "big")
                if val != 0:
                    self.put_storage(alloc.address, key, val)

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
