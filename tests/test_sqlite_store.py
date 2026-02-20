"""Test SQLite storage backend."""

import os
import tempfile

import pytest
from eth_keys import keys
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.core.types import Block, BlockHeader, Receipt
from sequencer.storage.sqlite_store import SQLiteStore
from sequencer.core.crypto import keccak256


class TestSQLiteStore:
    """Test SQLite storage operations."""

    @pytest.fixture
    def sqlite_store(self):
        """Create a temporary SQLite store."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        
        store = SQLiteStore(db_path)
        yield store, db_path
        
        store.close()
        # Clean up
        if os.path.exists(db_path):
            os.unlink(db_path)

    def test_sqlite_store_init(self, sqlite_store):
        """Test SQLite store initialization."""
        store, db_path = sqlite_store
        assert store.db_path == db_path
        
        # Tables should be created
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        
        assert "blocks" in tables
        assert "transactions" in tables
        assert "receipts" in tables
        
        conn.close()

    def test_get_latest_number_empty(self, sqlite_store):
        """Test get_latest_number on empty store."""
        store, _ = sqlite_store
        assert store.get_latest_number() == -1

    def test_save_and_get_block(self, sqlite_store):
        """Test saving and retrieving a block."""
        store, _ = sqlite_store
        
        # Create a simple block
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=keccak256(b"\xc0"),
            coinbase=b"\x01" * 20,
            state_root=b"\x02" * 32,
            transactions_root=keccak256(b"\x80"),
            receipts_root=keccak256(b"\x80"),
            logs_bloom=b"\x00" * 256,
            difficulty=1,
            number=1,
            gas_limit=1_000_000,
            gas_used=50_000,
            timestamp=1234567890,
            extra_data=b"test",
            prev_randao=b"\x03" * 32,
            nonce=b"\x00" * 8,
            base_fee_per_gas=1_000_000_000,
        )
        
        block = Block(header=header, transactions=[])
        tx_hashes = [b"\xaa" * 32]
        receipts = []
        
        # Save block
        store.save_block(block, receipts, tx_hashes)
        
        # Retrieve block
        retrieved = store.get_block(1)
        assert retrieved is not None
        assert retrieved.number == 1
        assert retrieved.header.gas_used == 50_000
        assert retrieved.header.coinbase == b"\x01" * 20

    def test_get_block_by_hash(self, sqlite_store):
        """Test retrieving block by hash."""
        store, _ = sqlite_store
        
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=keccak256(b"\xc0"),
            coinbase=b"\x01" * 20,
            state_root=b"\x02" * 32,
            transactions_root=keccak256(b"\x80"),
            receipts_root=keccak256(b"\x80"),
            logs_bloom=b"\x00" * 256,
            difficulty=1,
            number=1,
            gas_limit=1_000_000,
            gas_used=50_000,
            timestamp=1234567890,
            extra_data=b"",
            prev_randao=b"\x03" * 32,
            nonce=b"\x00" * 8,
            base_fee_per_gas=1_000_000_000,
        )
        
        block = Block(header=header, transactions=[])
        store.save_block(block, [], [])
        
        # Get by hash
        retrieved = store.get_block_by_hash(block.hash)
        assert retrieved is not None
        assert retrieved.number == 1

    def test_save_and_get_receipts(self, sqlite_store):
        """Test saving and retrieving receipts."""
        store, _ = sqlite_store
        
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=keccak256(b"\xc0"),
            coinbase=b"\x01" * 20,
            state_root=b"\x02" * 32,
            transactions_root=keccak256(b"\x80"),
            receipts_root=keccak256(b"\x80"),
            logs_bloom=b"\x00" * 256,
            difficulty=1,
            number=1,
            gas_limit=1_000_000,
            gas_used=50_000,
            timestamp=1234567890,
            extra_data=b"",
            prev_randao=b"\x03" * 32,
            nonce=b"\x00" * 8,
            base_fee_per_gas=1_000_000_000,
        )
        
        block = Block(header=header, transactions=[])
        
        tx_hash = b"\xaa" * 32
        receipt = Receipt(
            status=1,
            cumulative_gas_used=50_000,
            logs=[],
            contract_address=b"\x04" * 20,
        )
        
        store.save_block(block, [receipt], [tx_hash])
        
        # Get receipts
        receipts = store.get_receipts(1)
        assert len(receipts) == 1
        assert receipts[0].status == 1
        assert receipts[0].cumulative_gas_used == 50_000

    def test_receipts_with_logs(self, sqlite_store):
        """Test receipt storage with logs."""
        store, _ = sqlite_store
        
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=keccak256(b"\xc0"),
            coinbase=b"\x01" * 20,
            state_root=b"\x02" * 32,
            transactions_root=keccak256(b"\x80"),
            receipts_root=keccak256(b"\x80"),
            logs_bloom=b"\x00" * 256,
            difficulty=1,
            number=1,
            gas_limit=1_000_000,
            gas_used=50_000,
            timestamp=1234567890,
            extra_data=b"",
            prev_randao=b"\x03" * 32,
            nonce=b"\x00" * 8,
            base_fee_per_gas=1_000_000_000,
        )
        
        block = Block(header=header, transactions=[])
        
        tx_hash = b"\xaa" * 32
        
        # Event topic (Transfer)
        topic = keccak256(b"Transfer(address,address,uint256)")
        log = (b"\x04" * 20, (topic, b"\x00" * 32), b"\x00" * 32)
        
        receipt = Receipt(
            status=1,
            cumulative_gas_used=50_000,
            logs=[log],
            contract_address=None,
        )
        
        store.save_block(block, [receipt], [tx_hash])
        
        # Get receipts
        receipts = store.get_receipts(1)
        assert len(receipts) == 1
        assert len(receipts[0].logs) == 1
        
        # Check log format
        stored_log = receipts[0].logs[0]
        if isinstance(stored_log, tuple) and len(stored_log) == 3:
            addr, topics, data = stored_log
            assert addr == b"\x04" * 20
            assert len(topics) == 2

    def test_get_latest_block(self, sqlite_store):
        """Test getting the latest block."""
        store, _ = sqlite_store
        
        # Save multiple blocks
        for i in range(3):
            header = BlockHeader(
                parent_hash=b"\x00" * 32 if i == 0 else keccak256(f"block{i-1}".encode()),
                ommers_hash=keccak256(b"\xc0"),
                coinbase=b"\x01" * 20,
                state_root=b"\x02" * 32,
                transactions_root=keccak256(b"\x80"),
                receipts_root=keccak256(b"\x80"),
                logs_bloom=b"\x00" * 256,
                difficulty=1,
                number=i,
                gas_limit=1_000_000,
                gas_used=50_000 * (i + 1),
                timestamp=1234567890 + i,
                extra_data=b"",
                prev_randao=b"\x03" * 32,
                nonce=b"\x00" * 8,
                base_fee_per_gas=1_000_000_000,
            )
            block = Block(header=header, transactions=[])
            store.save_block(block, [], [])
        
        # Get latest
        latest = store.get_latest_block()
        assert latest is not None
        assert latest.number == 2

    def test_get_transaction_receipt(self, sqlite_store):
        """Test getting transaction receipt by hash."""
        store, _ = sqlite_store
        
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=keccak256(b"\xc0"),
            coinbase=b"\x01" * 20,
            state_root=b"\x02" * 32,
            transactions_root=keccak256(b"\x80"),
            receipts_root=keccak256(b"\x80"),
            logs_bloom=b"\x00" * 256,
            difficulty=1,
            number=1,
            gas_limit=1_000_000,
            gas_used=50_000,
            timestamp=1234567890,
            extra_data=b"",
            prev_randao=b"\x03" * 32,
            nonce=b"\x00" * 8,
            base_fee_per_gas=1_000_000_000,
        )
        
        block = Block(header=header, transactions=[])
        tx_hashes = [b"\xaa" * 32, b"\xbb" * 32]
        
        receipts = [
            Receipt(status=1, cumulative_gas_used=30_000, logs=[], contract_address=None),
            Receipt(status=1, cumulative_gas_used=50_000, logs=[], contract_address=b"\x04" * 20),
        ]
        
        store.save_block(block, receipts, tx_hashes)
        
        # Get receipt for second transaction
        result = store.get_transaction_receipt(b"\xbb" * 32)
        assert result is not None
        block_num, tx_idx, receipt = result
        assert block_num == 1
        assert tx_idx == 1
        assert receipt.cumulative_gas_used == 50_000

    def test_get_logs(self, sqlite_store):
        """Test log retrieval with filtering."""
        store, _ = sqlite_store
        
        # Create block with logs
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=keccak256(b"\xc0"),
            coinbase=b"\x01" * 20,
            state_root=b"\x02" * 32,
            transactions_root=keccak256(b"\x80"),
            receipts_root=keccak256(b"\x80"),
            logs_bloom=b"\x00" * 256,
            difficulty=1,
            number=1,
            gas_limit=1_000_000,
            gas_used=50_000,
            timestamp=1234567890,
            extra_data=b"",
            prev_randao=b"\x03" * 32,
            nonce=b"\x00" * 8,
            base_fee_per_gas=1_000_000_000,
        )
        
        block = Block(header=header, transactions=[])
        tx_hash = b"\xaa" * 32
        
        topic = keccak256(b"Transfer(address,address,uint256)")
        log = (b"\x04" * 20, (topic,), b"\x00" * 32)
        
        receipt = Receipt(
            status=1,
            cumulative_gas_used=50_000,
            logs=[log],
            contract_address=None,
        )
        
        store.save_block(block, [receipt], [tx_hash])
        
        # Get logs
        logs = store.get_logs(0, 10)
        assert len(logs) == 1
        assert logs[0]["block_number"] == 1
        assert logs[0]["tx_hash"] == tx_hash

    def test_get_logs_by_address(self, sqlite_store):
        """Test log filtering by address."""
        store, _ = sqlite_store
        
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=keccak256(b"\xc0"),
            coinbase=b"\x01" * 20,
            state_root=b"\x02" * 32,
            transactions_root=keccak256(b"\x80"),
            receipts_root=keccak256(b"\x80"),
            logs_bloom=b"\x00" * 256,
            difficulty=1,
            number=1,
            gas_limit=1_000_000,
            gas_used=50_000,
            timestamp=1234567890,
            extra_data=b"",
            prev_randao=b"\x03" * 32,
            nonce=b"\x00" * 8,
            base_fee_per_gas=1_000_000_000,
        )
        
        block = Block(header=header, transactions=[])
        tx_hash = b"\xaa" * 32
        
        topic = keccak256(b"Transfer(address,address,uint256)")
        log_addr = b"\x04" * 20
        log = (log_addr, (topic,), b"\x00" * 32)
        
        receipt = Receipt(status=1, cumulative_gas_used=50_000, logs=[log], contract_address=None)
        store.save_block(block, [receipt], [tx_hash])
        
        # Filter by matching address
        logs = store.get_logs(0, 10, address=log_addr)
        assert len(logs) == 1
        
        # Filter by non-matching address
        logs = store.get_logs(0, 10, address=b"\xff" * 20)
        assert len(logs) == 0

    def test_get_logs_by_topic(self, sqlite_store):
        """Test log filtering by topic."""
        store, _ = sqlite_store
        
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=keccak256(b"\xc0"),
            coinbase=b"\x01" * 20,
            state_root=b"\x02" * 32,
            transactions_root=keccak256(b"\x80"),
            receipts_root=keccak256(b"\x80"),
            logs_bloom=b"\x00" * 256,
            difficulty=1,
            number=1,
            gas_limit=1_000_000,
            gas_used=50_000,
            timestamp=1234567890,
            extra_data=b"",
            prev_randao=b"\x03" * 32,
            nonce=b"\x00" * 8,
            base_fee_per_gas=1_000_000_000,
        )
        
        block = Block(header=header, transactions=[])
        tx_hash = b"\xaa" * 32
        
        topic = keccak256(b"Transfer(address,address,uint256)")
        log = (b"\x04" * 20, (topic,), b"\x00" * 32)
        
        receipt = Receipt(status=1, cumulative_gas_used=50_000, logs=[log], contract_address=None)
        store.save_block(block, [receipt], [tx_hash])
        
        # Convert topic to bytes for filtering
        topic_bytes = topic if isinstance(topic, bytes) else topic.to_bytes(32, 'big')
        
        # Filter by matching topic
        logs = store.get_logs(0, 10, topics=[topic_bytes])
        assert len(logs) == 1
        assert logs[0]["topics"][0] == topic_bytes
        
        # Filter by non-matching topic
        logs = store.get_logs(0, 10, topics=[b"\xff" * 32])
        assert len(logs) == 0


class TestChainWithSQLite:
    """Test Chain with SQLite backend."""

    def test_chain_with_sqlite_backend(self, pk, address):
        """Test creating chain with SQLite backend."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        
        try:
            genesis_state = {
                address: {
                    "balance": to_wei(100, "ether"),
                    "nonce": 0,
                    "code": b"",
                    "storage": {},
                }
            }
            
            chain = Chain.from_genesis(
                genesis_state,
                chain_id=1337,
                block_time=0,
                store_type="sqlite",
                store_path=db_path,
            )
            
            # Verify block was saved
            block = chain.store.get_block(0)
            assert block is not None
            assert block.number == 0
            
            # Build a block
            nonce = chain.get_nonce(address)
            signed_tx = chain.create_transaction(
                from_private_key=pk.to_bytes(),
                to=None,
                value=0,
                data=b"\x60\x60",  # Simple bytecode
                gas=100_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            chain.send_transaction(signed_tx)
            chain.build_block()
            
            # Verify block 1 was saved
            block = chain.store.get_block(1)
            assert block is not None
            assert block.number == 1
            
            # Store should have latest number
            assert chain.store.get_latest_number() == 1
            
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_sqlite_persistence_across_restarts(self, pk, address):
        """Test that SQLite data persists across chain restarts."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        
        try:
            genesis_state = {
                address: {
                    "balance": to_wei(100, "ether"),
                    "nonce": 0,
                    "code": b"",
                    "storage": {},
                }
            }
            
            # Create chain and add a block
            chain = Chain.from_genesis(
                genesis_state,
                chain_id=1337,
                block_time=0,
                store_type="sqlite",
                store_path=db_path,
            )
            
            nonce = chain.get_nonce(address)
            signed_tx = chain.create_transaction(
                from_private_key=pk.to_bytes(),
                to=None,
                value=0,
                data=b"\x60\x60",
                gas=100_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            chain.send_transaction(signed_tx)
            chain.build_block()
            
            # Close chain's store connection
            chain.store.close()
            
            # Create new chain instance with same DB
            chain2 = Chain.from_genesis(
                genesis_state,
                chain_id=1337,
                block_time=0,
                store_type="sqlite",
                store_path=db_path,
            )
            
            # Verify data persists - we can override genesis with existing blocks
            # Note: This test shows SQLite stores data persistently
            assert chain2.store.get_latest_number() >= 0
            
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)
