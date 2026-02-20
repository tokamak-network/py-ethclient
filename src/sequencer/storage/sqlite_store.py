"""SQLite-based persistent storage for sequencer blocks and state."""

import json
import sqlite3
from pathlib import Path
from typing import Optional

from sequencer.core.types import Block, BlockHeader, Receipt


class SQLiteStore:
    """SQLite-based persistent storage for blockchain data."""
    
    def __init__(self, db_path: str = "sequencer.db"):
        """
        Initialize SQLite storage.
        
        Args:
            db_path: Path to SQLite database file. Use ":memory:" for in-memory database.
        """
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._init_db()
    
    def _get_conn(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn
    
    def _init_db(self):
        """Initialize database tables."""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # Blocks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
                number INTEGER PRIMARY KEY,
                hash BLOB UNIQUE NOT NULL,
                parent_hash BLOB NOT NULL,
                ommers_hash BLOB NOT NULL,
                coinbase BLOB NOT NULL,
                state_root BLOB NOT NULL,
                transactions_root BLOB NOT NULL,
                receipts_root BLOB NOT NULL,
                logs_bloom BLOB NOT NULL,
                difficulty INTEGER NOT NULL,
                gas_limit INTEGER NOT NULL,
                gas_used INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                extra_data BLOB,
                prev_randao BLOB NOT NULL,
                nonce BLOB NOT NULL,
                base_fee_per_gas INTEGER,
                transactions BLOB
            )
        """)
        
        # Transactions table (for fast lookup by hash)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                hash BLOB PRIMARY KEY,
                block_number INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                FOREIGN KEY (block_number) REFERENCES blocks(number)
            )
        """)
        
        # Receipts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                block_number INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                status INTEGER NOT NULL,
                cumulative_gas_used INTEGER NOT NULL,
                logs BLOB,
                contract_address BLOB,
                PRIMARY KEY (block_number, tx_index),
                FOREIGN KEY (block_number) REFERENCES blocks(number)
            )
        """)
        
        # Create indexes for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_transactions_block ON transactions(block_number)
        """)
        
        conn.commit()
    
    def _block_to_row(self, block: Block, receipts: list[Receipt], tx_hashes: list[bytes]) -> dict:
        """Convert block to database row."""
        header = block.header
        tx_data = json.dumps([tx.hex() if isinstance(tx, bytes) else tx for tx in tx_hashes])
        
        return {
            "number": header.number,
            "hash": block.hash,
            "parent_hash": header.parent_hash,
            "ommers_hash": header.ommers_hash,
            "coinbase": header.coinbase,
            "state_root": header.state_root,
            "transactions_root": header.transactions_root,
            "receipts_root": header.receipts_root,
            "logs_bloom": header.logs_bloom,
            "difficulty": header.difficulty,
            "gas_limit": header.gas_limit,
            "gas_used": header.gas_used,
            "timestamp": header.timestamp,
            "extra_data": header.extra_data or b"",
            "prev_randao": header.prev_randao,
            "nonce": header.nonce,
            "base_fee_per_gas": header.base_fee_per_gas,
            "transactions": tx_data.encode(),
        }
    
    def _row_to_block(self, row: sqlite3.Row) -> Block:
        """Convert database row to Block object."""
        header = BlockHeader(
            parent_hash=row["parent_hash"],
            ommers_hash=row["ommers_hash"],
            coinbase=row["coinbase"],
            state_root=row["state_root"],
            transactions_root=row["transactions_root"],
            receipts_root=row["receipts_root"],
            logs_bloom=row["logs_bloom"],
            difficulty=row["difficulty"],
            number=row["number"],
            gas_limit=row["gas_limit"],
            gas_used=row["gas_used"],
            timestamp=row["timestamp"],
            extra_data=row["extra_data"] or b"",
            prev_randao=row["prev_randao"],
            nonce=row["nonce"],
            base_fee_per_gas=row["base_fee_per_gas"],
        )
        
        # Note: We don't store full transaction objects, just hashes
        # Transactions would need to be fetched separately if needed
        return Block(header=header, transactions=[])
    
    def _receipt_to_row(self, receipt: Receipt, block_number: int, tx_index: int) -> dict:
        """Convert receipt to database row."""
        # Serialize logs as JSON
        logs_data = []
        for log in receipt.logs:
            if isinstance(log, tuple) and len(log) == 3:
                addr, topics, data = log
                logs_data.append({
                    "address": addr.hex() if isinstance(addr, bytes) else addr,
                    "topics": [t.hex() if isinstance(t, bytes) else hex(t) for t in topics],
                    "data": data.hex() if isinstance(data, bytes) else data,
                })
        
        return {
            "block_number": block_number,
            "tx_index": tx_index,
            "status": receipt.status,
            "cumulative_gas_used": receipt.cumulative_gas_used,
            "logs": json.dumps(logs_data).encode(),
            "contract_address": receipt.contract_address,
        }
    
    def _row_to_receipt(self, row: sqlite3.Row) -> Receipt:
        """Convert database row to Receipt object."""
        logs_data = json.loads(row["logs"].decode()) if row["logs"] else []
        logs = []
        for log in logs_data:
            addr = bytes.fromhex(log["address"]) if isinstance(log["address"], str) else log["address"]
            topics = tuple(
                bytes.fromhex(t[2:].zfill(64)) if isinstance(t, str) and t.startswith("0x") else 
                bytes.fromhex(t.zfill(64)) if isinstance(t, str) else t 
                for t in log["topics"]
            )
            data = bytes.fromhex(log["data"][2:]) if isinstance(log["data"], str) and log["data"].startswith("0x") else log["data"]
            logs.append((addr, topics, data))
        
        return Receipt(
            status=row["status"],
            cumulative_gas_used=row["cumulative_gas_used"],
            logs=logs,
            contract_address=row["contract_address"],
        )
    
    def get_block(self, number: int) -> Optional[Block]:
        """Get block by number."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocks WHERE number = ?", (number,))
        row = cursor.fetchone()
        return self._row_to_block(row) if row else None
    
    def get_block_by_hash(self, block_hash: bytes) -> Optional[Block]:
        """Get block by hash."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocks WHERE hash = ?", (block_hash,))
        row = cursor.fetchone()
        return self._row_to_block(row) if row else None
    
    def get_receipts(self, block_number: int) -> list[Receipt]:
        """Get all receipts for a block."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM receipts WHERE block_number = ? ORDER BY tx_index",
            (block_number,)
        )
        rows = cursor.fetchall()
        return [self._row_to_receipt(row) for row in rows]
    
    def get_transaction_receipt(self, tx_hash: bytes) -> tuple[int, int, Receipt] | None:
        """Get transaction receipt by hash. Returns (block_number, tx_index, receipt) or None."""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # Find transaction
        cursor.execute(
            "SELECT block_number, tx_index FROM transactions WHERE hash = ?",
            (tx_hash,)
        )
        tx_row = cursor.fetchone()
        if not tx_row:
            return None
        
        block_number = tx_row["block_number"]
        tx_index = tx_row["tx_index"]
        
        # Get receipt
        cursor.execute(
            "SELECT * FROM receipts WHERE block_number = ? AND tx_index = ?",
            (block_number, tx_index)
        )
        receipt_row = cursor.fetchone()
        if not receipt_row:
            return None
        
        return (block_number, tx_index, self._row_to_receipt(receipt_row))
    
    def get_transaction_by_hash(self, tx_hash: bytes) -> tuple[Block, int] | None:
        """Get transaction by hash. Returns (block, tx_index) or None."""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT block_number, tx_index FROM transactions WHERE hash = ?",
            (tx_hash,)
        )
        tx_row = cursor.fetchone()
        if not tx_row:
            return None
        
        block = self.get_block(tx_row["block_number"])
        if not block:
            return None
        
        return (block, tx_row["tx_index"])
    
    def get_latest_block(self) -> Optional[Block]:
        """Get the latest block."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocks ORDER BY number DESC LIMIT 1")
        row = cursor.fetchone()
        return self._row_to_block(row) if row else None
    
    def save_block(self, block: Block, receipts: list[Receipt], tx_hashes: list[bytes]):
        """Save block with receipts and transaction hashes."""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # Insert block
        row = self._block_to_row(block, receipts, tx_hashes)
        cursor.execute("""
            INSERT OR REPLACE INTO blocks (
                number, hash, parent_hash, ommers_hash, coinbase,
                state_root, transactions_root, receipts_root, logs_bloom,
                difficulty, gas_limit, gas_used, timestamp, extra_data,
                prev_randao, nonce, base_fee_per_gas, transactions
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row["number"], row["hash"], row["parent_hash"], row["ommers_hash"],
            row["coinbase"], row["state_root"], row["transactions_root"],
            row["receipts_root"], row["logs_bloom"], row["difficulty"],
            row["gas_limit"], row["gas_used"], row["timestamp"], row["extra_data"],
            row["prev_randao"], row["nonce"], row["base_fee_per_gas"],
            row["transactions"]
        ))
        
        # Insert transactions
        for i, tx_hash in enumerate(tx_hashes):
            cursor.execute("""
                INSERT OR REPLACE INTO transactions (hash, block_number, tx_index)
                VALUES (?, ?, ?)
            """, (tx_hash, block.number, i))
        
        # Insert receipts
        for i, receipt in enumerate(receipts):
            receipt_row = self._receipt_to_row(receipt, block.number, i)
            cursor.execute("""
                INSERT OR REPLACE INTO receipts (
                    block_number, tx_index, status, cumulative_gas_used, logs, contract_address
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                receipt_row["block_number"], receipt_row["tx_index"],
                receipt_row["status"], receipt_row["cumulative_gas_used"],
                receipt_row["logs"], receipt_row["contract_address"]
            ))
        
        conn.commit()
    
    def get_latest_number(self) -> int:
        """Get the latest block number."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(number) as max_num FROM blocks")
        row = cursor.fetchone()
        return row["max_num"] if row and row["max_num"] is not None else -1
    
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
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # Query receipts for the block range
        cursor.execute(
            "SELECT * FROM receipts WHERE block_number >= ? AND block_number <= ?",
            (from_block, to_block)
        )
        
        for receipt_row in cursor.fetchall():
            block_number = receipt_row["block_number"]
            tx_index = receipt_row["tx_index"]
            
            # Get transaction hash
            cursor.execute(
                "SELECT hash FROM transactions WHERE block_number = ? AND tx_index = ?",
                (block_number, tx_index)
            )
            tx_row = cursor.fetchone()
            tx_hash = tx_row["hash"] if tx_row else b""
            
            # Get block hash
            block = self.get_block(block_number)
            block_hash = block.hash if block else b""
            
            # Parse logs from receipt
            receipt = self._row_to_receipt(receipt_row)
            
            for log_index, log in enumerate(receipt.logs):
                if isinstance(log, tuple) and len(log) == 3:
                    log_address, log_topics, log_data = log
                else:
                    continue
                
                # Convert topics to bytes format
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
                
                logs.append({
                    "address": log_address,
                    "topics": normalized_topics,
                    "data": log_data,
                    "block_number": block_number,
                    "block_hash": block_hash,
                    "tx_hash": tx_hash,
                    "tx_index": tx_index,
                    "log_index": log_index,
                })
        
        return logs
    
    def _match_topics(
        self,
        log_topics: list[bytes],
        filter_topics: list[bytes | list[bytes] | None],
    ) -> bool:
        """Check if log topics match the filter."""
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
    
    def close(self):
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
    
    def __del__(self):
        """Clean up database connection on object destruction."""
        self.close()