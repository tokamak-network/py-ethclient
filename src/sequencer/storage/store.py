"""In-memory storage for sequencer blocks and state."""

from typing import Optional
from dataclasses import dataclass

from sequencer.core.types import Block, Receipt


@dataclass
class StoredBlock:
    block: Block
    receipts: list[Receipt]


class InMemoryStore:
    def __init__(self):
        self._blocks: dict[int, StoredBlock] = {}
        self._block_by_hash: dict[bytes, StoredBlock] = {}
        self._latest_number: int = -1

    def get_block(self, number: int) -> Optional[Block]:
        stored = self._blocks.get(number)
        return stored.block if stored else None

    def get_block_by_hash(self, block_hash: bytes) -> Optional[Block]:
        stored = self._block_by_hash.get(block_hash)
        return stored.block if stored else None

    def get_receipts(self, block_number: int) -> list[Receipt]:
        stored = self._blocks.get(block_number)
        return stored.receipts if stored else []

    def get_latest_block(self) -> Optional[Block]:
        if self._latest_number < 0:
            return None
        return self.get_block(self._latest_number)

    def save_block(self, block: Block, receipts: list[Receipt]):
        stored = StoredBlock(block=block, receipts=receipts)
        self._blocks[block.number] = stored
        self._block_by_hash[block.hash] = stored
        self._latest_number = max(self._latest_number, block.number)

    def get_latest_number(self) -> int:
        return self._latest_number