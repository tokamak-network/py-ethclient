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
        
        # Create multiple addresses for concurrent transactions
        addresses = []
        private_keys = []
        for i in range(3):
            # Each thread gets its own address to avoid nonce conflicts
            test_pk = keys.PrivateKey(bytes.fromhex(f"{i+1:02d}" * 32))
            addresses.append(test_pk.public_key.to_canonical_address())
            private_keys.append(test_pk)
        
        genesis_state = {
            address: {
                "balance": to_wei(1000, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        # Give each test address some balance
        for addr in addresses:
            genesis_state[addr] = {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        
        chain = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
            store_type="sqlite",
            store_path=temp_db_path,
        )
        
        errors = []
        stop_flag = threading.Event()
        tx_sent_count = 0
        tx_sent_lock = threading.Lock()
        
        def send_transactions(thread_id):
            nonlocal tx_sent_count
            try:
                pk = private_keys[thread_id]
                addr = addresses[thread_id]
                for i in range(3):  # Only 3 transactions per thread
                    if stop_flag.is_set():
                        break
                    # Send transactions and wait for them to be included
                    nonce = chain.get_nonce(addr)
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
                    with tx_sent_lock:
                        tx_sent_count += 1
                    # Build block after each send to avoid nonce conflicts
                    chain.build_block()
                    time.sleep(0.02)
            except Exception as e:
                errors.append(("sender", thread_id, str(e)))
        
        def build_blocks():
            try:
                for _ in range(20):
                    if stop_flag.is_set():
                        break
                    if len(chain.mempool) > 0:
                        chain.build_block()
                    time.sleep(0.02)
            except Exception as e:
                errors.append(("builder", str(e)))
        
        # Start sender threads (each with its own address)
        sender_threads = []
        for i in range(3):
            t = threading.Thread(target=send_transactions, args=(i,))
            sender_threads.append(t)
            t.start()
        
        # Start builder thread
        builder_thread = threading.Thread(target=build_blocks)
        builder_thread.start()
        
        # Wait for senders to complete
        for t in sender_threads:
            t.join()
        
        # Build remaining blocks
        while len(chain.mempool) > 0:
            chain.build_block()
        
        stop_flag.set()
        builder_thread.join()
        
        # Verify no errors
        assert len(errors) == 0, f"Errors occurred: {errors}"
        
        # Count total transactions in blocks
        blocks = []
        for i in range(20):
            block = chain.store.get_block(i)
            if block:
                blocks.append(block)
        
        total_txs = sum(len(block.transactions) for block in blocks)
        print(f"✅ Built {len(blocks)} blocks with {total_txs} total transactions, sent {tx_sent_count}")
        
        # All sent transactions should be in blocks
        assert total_txs == tx_sent_count
        
        chain.store.close()

    def test_concurrent_block_building(self, pk_and_address):
        """Test that concurrent build_block calls are serialized correctly."""
        pk, address = pk_and_address
        
        # Use fresh state for this test to avoid conflicts
        pk1 = keys.PrivateKey(bytes.fromhex("aa" * 32))
        addr1 = pk1.public_key.to_canonical_address()
        pk2 = keys.PrivateKey(bytes.fromhex("bb" * 32))
        addr2 = pk2.public_key.to_canonical_address()
        
        genesis_state = {
            addr1: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            },
            addr2: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            },
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Add transactions from different addresses (use sequential nonces)
        for i in range(3):
            # From addr1 - nonce is 0, 1, 2
            signed_tx1 = chain.create_transaction(
                from_private_key=pk1.to_bytes(),
                to=bytes.fromhex("deadbeef" * 5),
                value=to_wei(1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=i,
            )
            chain.send_transaction(signed_tx1)
            
            # From addr2 - nonce is 0, 1, 2
            signed_tx2 = chain.create_transaction(
                from_private_key=pk2.to_bytes(),
                to=bytes.fromhex("deadbeef" * 5),
                value=to_wei(1, "ether"),
                data=b"",
                gas=21_000,
                gas_price=1_000_000_000,
                nonce=i,
            )
            chain.send_transaction(signed_tx2)
        
        # Now we have 6 transactions in the mempool
        assert len(chain.mempool) == 6
        
        errors = []
        results = []
        
        def build_block_thread(thread_id):
            try:
                # Try to build blocks concurrently
                if len(chain.mempool) > 0:
                    block = chain.build_block()
                    if block:
                        results.append((thread_id, block.number))
            except Exception as e:
                errors.append((thread_id, str(e)))
        
        # Start threads
        threads = []
        for i in range(3):
            t = threading.Thread(target=build_block_thread, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # All build_block calls should succeed without errors
        assert len(errors) == 0, f"Errors occurred: {errors}"
        
        # Verify blocks were built correctly
        block_numbers = sorted([r[1] for r in results])
        print(f"✅ Built {len(block_numbers)} blocks: {block_numbers}")
        
        # Build remaining blocks
        while len(chain.mempool) > 0:
            chain.build_block()
        
        # Verify all transactions were included
        total_txs = 0
        for i in range(10):
            block = chain.store.get_block(i + 1)  # Start from block 1
            if block:
                total_txs += len(block.transactions)
        
        print(f"✅ Total transactions in blocks: {total_txs}")
        assert total_txs == 6  # 3 from addr1 + 3 from addr2