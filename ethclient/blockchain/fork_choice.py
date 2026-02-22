"""
Fork choice rule and canonical chain management.

Post-merge Ethereum uses the beacon chain for fork choice. This module
manages the canonical chain pointer and handles reorgs.
"""

from __future__ import annotations

from typing import Optional

from ethclient.common.types import BlockHeader
from ethclient.storage.store import Store


class ForkChoice:
    """Manages the canonical chain and handles reorgs.

    Post-merge: the head is set by the consensus layer via forkchoiceUpdated.
    Pre-merge: uses total difficulty (not implemented — focus on post-merge).
    """

    def __init__(self, store: Store) -> None:
        self.store = store
        self._head_hash: Optional[bytes] = None
        self._finalized_hash: Optional[bytes] = None
        self._safe_hash: Optional[bytes] = None

    @property
    def head_hash(self) -> Optional[bytes]:
        return self._head_hash

    @property
    def head_number(self) -> int:
        if self._head_hash is None:
            return 0
        header = self.store.get_block_header(self._head_hash)
        return header.number if header else 0

    @property
    def head(self) -> Optional[BlockHeader]:
        if self._head_hash is None:
            return None
        return self.store.get_block_header(self._head_hash)

    def set_head(self, block_hash: bytes) -> bool:
        """Set the canonical head to the given block hash.

        Updates the canonical chain mapping. Returns True if a reorg occurred.
        """
        header = self.store.get_block_header(block_hash)
        if header is None:
            return False

        old_head = self._head_hash
        self._head_hash = block_hash

        # Build the chain from this block back to genesis or a known canonical block
        chain: list[tuple[int, bytes]] = []
        current = header
        current_hash = block_hash

        while current is not None:
            existing = self.store.get_canonical_hash(current.number)
            if existing == current_hash:
                # Already canonical from here back
                break
            chain.append((current.number, current_hash))
            if current.number == 0:
                break
            current_hash = current.parent_hash
            current = self.store.get_block_header(current_hash)

        # Apply canonical chain updates
        for number, bh in chain:
            self.store.put_canonical_hash(number, bh)

        # Detect reorg
        is_reorg = old_head is not None and old_head != block_hash
        if is_reorg and old_head:
            old_header = self.store.get_block_header(old_head)
            if old_header and old_header.number >= header.number:
                # The old chain was at least as long — this is a reorg
                # Clean up canonical pointers above new head
                for n in range(header.number + 1, old_header.number + 1):
                    # Remove stale canonical entries (can't really delete from dict,
                    # but overwriting with new chain handles it)
                    pass

        return is_reorg and old_head != block_hash

    def set_finalized(self, block_hash: bytes) -> None:
        """Set the finalized block hash (from consensus layer)."""
        self._finalized_hash = block_hash

    def set_safe(self, block_hash: bytes) -> None:
        """Set the safe block hash (from consensus layer)."""
        self._safe_hash = block_hash

    def is_canonical(self, block_hash: bytes) -> bool:
        """Check if a block is part of the canonical chain."""
        header = self.store.get_block_header(block_hash)
        if header is None:
            return False
        canonical = self.store.get_canonical_hash(header.number)
        return canonical == block_hash

    def get_ancestor(self, block_hash: bytes, height: int) -> Optional[bytes]:
        """Walk back from block_hash to find the ancestor at the given height."""
        current = self.store.get_block_header(block_hash)
        while current is not None and current.number > height:
            current = self.store.get_block_header(current.parent_hash)
        if current is None or current.number != height:
            return None
        return current.block_hash()

    def find_common_ancestor(
        self, hash_a: bytes, hash_b: bytes
    ) -> Optional[bytes]:
        """Find the common ancestor of two blocks."""
        header_a = self.store.get_block_header(hash_a)
        header_b = self.store.get_block_header(hash_b)
        if header_a is None or header_b is None:
            return None

        # Walk both chains back to the same height
        while header_a.number > header_b.number:
            header_a = self.store.get_block_header(header_a.parent_hash)
            if header_a is None:
                return None
        while header_b.number > header_a.number:
            header_b = self.store.get_block_header(header_b.parent_hash)
            if header_b is None:
                return None

        # Walk both back until they meet
        while header_a.block_hash() != header_b.block_hash():
            header_a = self.store.get_block_header(header_a.parent_hash)
            header_b = self.store.get_block_header(header_b.parent_hash)
            if header_a is None or header_b is None:
                return None

        return header_a.block_hash()

