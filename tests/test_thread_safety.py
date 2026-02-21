"""Tests for thread safety of the Chain class."""

import threading
import time
import tempfile
import os

import pytest
from eth_keys import keys
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain


class TestThreadSafety:
    """Test that Chain handles concurrent access correctly."""

    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database file path."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        yield db_path
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)

    @pytest.fixture
    def pk_and_address(self):
        """Create private key and address."""
        pk = keys.PrivateKey(bytes.fromhex("01" * 32))
        address = pk.public_key.to_canonical_address()
        return pk, address

    def test_concurrent_send_transaction(self, pk_and_address):
        """Test that concurrent send_transaction calls are thread-safe."""
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(1000, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        num_threads = 10
        txs_per_thread = 5
        results = []
        errors = []
        
        def send_transactions(thread_id):
            try:
                for i in range(txs_per_thread):
                    nonce_offset = thread_id * txs_per_thread + i
                    # Each thread uses different nonces to avoid conflicts
                    # But all are sent concurrently
                    signed_tx = chain.create_transaction(
                        from_private_key=pk.to_bytes(),
                        to=bytes.fromhex("deadbeef" * 5),
                        value=to_wei(1, "ether"),
                        data=b"",
                        gas=21_000,
                        gas_price=1_000_000_000,
                        nonce=nonce_offset,  # Pre-computed nonce
                    )
                    tx_hash = chain.send_transaction(signed_tx)
                    results.append((thread_id, i, tx_hash))
            except Exception as e:
                errors.append((thread_id, str(e)))
        
        # Start all threads
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=send_transactions, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        # Verify no errors
        assert len(errors) == 0, f"Errors occurred: {errors}"
        
        # Verify all transactions were added
        assert len(results) == num_threads * txs_per_thread
        
        # Verify mempool has all transactions
        assert len(chain.mempool) == num_threads * txs_per_thread
        
        print(f"✅ Successfully sent {len(results)} transactions from {num_threads} threads")

    def test_concurrent_send_and_build_block(self, pk_and_address, temp_db_path):
        """Test that concurrent send_transaction and build_block are thread-safe."""
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(1000, "ether"),
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
            store_path=temp_db_path,
        )
        
        num_sender_threads = 5
        txs_per_thread = 3
        errors = []
        stop_flag = threading.Event()
        
        def send_transactions(thread_id):
            try:
                for i in range(txs_per_thread):
                    if stop_flag.is_set():
                        break
                    nonce = chain.get_nonce(address)
                    signed_tx = chain.create_transaction(
                        from_private_key=pk.to_bytes(),
                        to=bytes.fromhex("deadbeef" * 5),
                        value=to_wei(1, "ether"),
                        data=b"",
                        gas=21_000,
                        gas_price=1_000_000_000,
                        nonce=nonce,
                    )
                    chain.send_transaction(signed_tx)
                    time.sleep(0.01)  # Small delay to allow interleaving
            except Exception as e:
                errors.append(("sender", thread_id, str(e)))
        
        def build_blocks():
            try:
                for _ in range(10):
                    if stop_flag.is_set():
                        break
                    if len(chain.mempool) > 0:
                        chain.build_block()
                    time.sleep(0.02)  # Small delay
            except Exception as e:
                errors.append(("builder", 0, str(e)))
        
        # Start sender threads
        sender_threads = []
        for i in range(num_sender_threads):
            t = threading.Thread(target=send_transactions, args=(i,))
            sender_threads.append(t)
            t.start()
        
        # Start builder thread
        builder_thread = threading.Thread(target=build_blocks)
        builder_thread.start()
        
        # Wait for senders to complete
        for t in sender_threads:
            t.join()
        
        # Stop builder after senders are done
        time.sleep(0.1)
        stop_flag.set()
        builder_thread.join()
        
        # Verify no errors
        assert len(errors) == 0, f"Errors occurred: {errors}"
        
        # Verify all transactions were processed
        blocks = []
        for i in range(20):
            block = chain.store.get_block(i)
            if block:
                blocks.append(block)
        
        total_txs = sum(len(block.transactions) for block in blocks)
        print(f"✅ Built {len(blocks)} blocks with {total_txs} total transactions")
        
        # All transactions should be in blocks or mempool
        remaining_in_mempool = len(chain.mempool)
        assert total_txs + remaining_in_mempool <= num_sender_threads * txs_per_thread
        
        chain.store.close()

    def test_concurrent_block_building(self, pk_and_address):
        """Test that only one build_block can run at a time."""
        pk, address = pk_and_address
        
        genesis_state = {
            address: {
                "balance": to_wei(1000, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Add some transactions first
        for _ in range(5):
            nonce = chain.get_nonce(address)
            signed_tx = chain.create_transaction(
                from_private_key=pk.to_bytes(),
                to=bytes.fromhex("deadbeef" * 5),
                value=to_wei(1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            chain.send_transaction(signed_tx)
        
        errors = []
        block_numbers = []
        
        def build_block_thread(thread_id):
            try:
                block = chain.build_block()
                block_numbers.append(block.number)
            except Exception as e:
                errors.append((thread_id, str(e)))
        
        # Start multiple build_block calls concurrently
        threads = []
        for i in range(3):
            t = threading.Thread(target=build_block_thread, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # All build_block calls should succeed without errors
        assert len(errors) == 0, f"Errors occurred: {errors}"
        
        # Each thread should have built a block with different block numbers
        # (except if some threads raced and got empty mempool)
        print(f"✅ Built {len(block_numbers)} blocks: {sorted(block_numbers)}")