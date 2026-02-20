"""In-memory storage for sequencer blocks and state."""

from typing import Optional
from dataclasses import dataclass

from sequencer.core.types import Block, Receipt


@dataclass
class StoredBlock:
    block: Block
    receipts: list[Receipt]
    tx_hashes: list[bytes]


class InMemoryStore:
    def __init__(self):
        self._blocks: dict[int, StoredBlock] = {}
        self._block_by_hash: dict[bytes, StoredBlock] = {}
        self._tx_to_receipt: dict[bytes, tuple[int, int, Receipt]] = {}
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

    def get_transaction_receipt(self, tx_hash: bytes) -> tuple[int, int, Receipt] | None:
        return self._tx_to_receipt.get(tx_hash)

    def get_transaction_by_hash(self, tx_hash: bytes) -> tuple[Block, int] | None:
        """Get transaction by hash. Returns (block, tx_index) or None."""
        receipt_info = self._tx_to_receipt.get(tx_hash)
        if not receipt_info:
            return None
        
        block_number, tx_index, _ = receipt_info
        block = self.get_block(block_number)
        if not block:
            return None
        
        return (block, tx_index)

    def get_latest_block(self) -> Optional[Block]:
        if self._latest_number < 0:
            return None
        return self.get_block(self._latest_number)

    def save_block(self, block: Block, receipts: list[Receipt], tx_hashes: list[bytes]):
        stored = StoredBlock(block=block, receipts=receipts, tx_hashes=tx_hashes)
        self._blocks[block.number] = stored
        self._block_by_hash[block.hash] = stored
        self._latest_number = max(self._latest_number, block.number)
        
        for i, (receipt, tx_hash) in enumerate(zip(receipts, tx_hashes)):
            self._tx_to_receipt[tx_hash] = (block.number, i, receipt)

    def get_latest_number(self) -> int:
        return self._latest_number

    def get_logs(
        self,
        from_block: int,
        to_block: int,
        address: bytes | list[bytes] | None = None,
        topics: list[bytes | list[bytes] | None] | None = None,
    ) -> list[dict]:
        """
        Get logs matching the filter criteria.
        
        Args:
            from_block: Starting block number (inclusive)
            to_block: Ending block number (inclusive)
            address: Contract address(es) to filter by
            topics: Topic filters (each element can be a single topic or list of alternatives)
        
        Returns:
            List of log entries matching the filter
        """
        logs = []
        
        for block_number in range(from_block, to_block + 1):
            stored = self._blocks.get(block_number)
            if not stored:
                continue
            
            block = stored.block
            receipts = stored.receipts
            tx_hashes = stored.tx_hashes
            
            for tx_index, (receipt, tx_hash) in enumerate(zip(receipts, tx_hashes)):
                if not receipt.logs:
                    continue
                
                for log_index, log in enumerate(receipt.logs):
                    # Parse log tuple: (address, topics, data)
                    if isinstance(log, tuple) and len(log) == 3:
                        log_address, log_topics, log_data = log
                    else:
                        continue
                    
                    # Convert topics to bytes format (py-evm may return int)
                    normalized_topics = []
                    for topic in log_topics:
                        if isinstance(topic, int):
                            normalized_topics.append(topic.to_bytes(32, 'big'))
                        else:
                            normalized_topics.append(topic)
                    
                    # Address filter
                    if address is not None:
                        if isinstance(address, list):
                            if log_address not in address:
                                continue
                        elif log_address != address:
                            continue
                    
                    # Topic filter
                    if topics is not None:
                        match = self._match_topics(normalized_topics, topics)
                        if not match:
                            continue
                    
                    # Build log entry
                    log_entry = {
                        "address": log_address,
                        "topics": normalized_topics,
                        "data": log_data,
                        "block_number": block_number,
                        "block_hash": block.hash,
                        "tx_hash": tx_hash,
                        "tx_index": tx_index,
                        "log_index": log_index,
                    }
                    logs.append(log_entry)
        
        return logs

    def _match_topics(
        self,
        log_topics: list[bytes],
        filter_topics: list[bytes | list[bytes] | None],
    ) -> bool:
        """
        Check if log topics match the filter.
        
        Each filter element can be:
        - None: Match any topic at this position
        - bytes: Match this exact topic
        - list[bytes]: Match any topic in the list
        """
        for i, filter_topic in enumerate(filter_topics):
            if i >= len(log_topics):
                return False
            
            if filter_topic is None:
                continue
            
            log_topic = log_topics[i]
            
            if isinstance(filter_topic, list):
                if log_topic not in filter_topic:
                    return False
            elif log_topic != filter_topic:
                return False
        
        return True