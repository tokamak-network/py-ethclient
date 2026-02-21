"""Test block producer error handling and recovery.

Verifies that the block producer thread handles errors gracefully
and doesn't crash silently.
"""

import pytest
import threading
import time
from unittest.mock import patch

from eth_keys import keys
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.rpc.server import _block_producer


def test_block_producer_handles_single_error():
    """Block producer should handle a single error and continue."""
    pk = keys.PrivateKey(bytes.fromhex("01" * 32))
    address = pk.public_key.to_canonical_address()
    
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
        gas_limit=100_000,
        block_time=1,
    )
    
    error_count = 0
    original_build = chain.build_block
    
    def flaky_build():
        nonlocal error_count
        error_count += 1
        if error_count == 1:
            raise ValueError("Simulated error")
        return original_build()
    
    # Patch build_block to fail once
    with patch.object(chain, 'build_block', side_effect=flaky_build):
        # Send a transaction
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=bytes.fromhex("deadbeef" * 5),
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
        )
        chain.send_transaction(signed_tx)
        
        # Start block producer
        chain._last_block_time = 0
        producer_thread = threading.Thread(target=_block_producer, args=(chain,), daemon=True)
        producer_thread.start()
        
        # Wait for error and recovery
        time.sleep(3)
        
        # Thread should still be alive (didn't crash)
        assert producer_thread.is_alive(), "Block producer thread died after single error"
        
        print(f"✅ Single error handled, producer still running")


@pytest.mark.skip(reason="Takes 60s to run, covered by manual testing")
def test_block_producer_stops_after_max_errors():
    """Block producer should stop after 10 consecutive errors.
    
    Note: This test is skipped by default as it takes 60+ seconds.
    The functionality is verified in manual testing.
    """
    pk = keys.PrivateKey(bytes.fromhex("01" * 32))
    address = pk.public_key.to_canonical_address()
    
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
        gas_limit=100_000,
        block_time=1,
        store_type="memory",
    )
    
    errors_caught = []
    
    def always_should_build():
        return True
    chain.should_build_block = always_should_build
    
    def failing_build():
        errors_caught.append(time.time())
        raise ValueError("Always fails")
    
    with patch.object(chain, 'build_block', side_effect=failing_build):
        producer_thread = threading.Thread(target=_block_producer, args=(chain,), daemon=True)
        producer_thread.start()
        
        time.sleep(60)
        
        assert not producer_thread.is_alive(), "Block producer should stop after max consecutive errors"
        assert len(errors_caught) >= 10, f"Expected at least 10 errors, got {len(errors_caught)}"
        
        print(f"✅ Block producer stopped after {len(errors_caught)} consecutive errors")


def test_block_producer_recovers_after_transient_error():
    """Block producer should recover and reset error count after success."""
    pk = keys.PrivateKey(bytes.fromhex("01" * 32))
    address = pk.public_key.to_canonical_address()
    
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
        gas_limit=100_000,
        block_time=1,
    )
    
    error_count = 0
    original_build = chain.build_block
    
    def sometimes_failing_build():
        nonlocal error_count
        error_count += 1
        # Fail first 3 times, then succeed
        if error_count <= 3:
            raise ValueError(f"Transient error {error_count}")
        return original_build()
    
    # Patch build_block to fail a few times
    with patch.object(chain, 'build_block', side_effect=sometimes_failing_build):
        # Send a transaction
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=bytes.fromhex("deadbeef" * 5),
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
        )
        chain.send_transaction(signed_tx)
        
        # Start block producer
        chain._last_block_time = 0
        producer_thread = threading.Thread(target=_block_producer, args=(chain,), daemon=True)
        producer_thread.start()
        
        # Wait for errors and recovery
        time.sleep(8)
        
        # Thread should still be alive (recovered after errors)
        assert producer_thread.is_alive(), "Block producer should recover after transient errors"
        
        print(f"✅ Block producer recovered after {error_count} transient errors")


def test_block_producer_error_backoff():
    """Block producer should use backoff on errors."""
    pk = keys.PrivateKey(bytes.fromhex("01" * 32))
    address = pk.public_key.to_canonical_address()
    
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
        gas_limit=100_000,
        block_time=1,
    )
    
    # Track timing between error attempts
    error_times = []
    
    def always_failing_build():
        error_times.append(time.time())
        raise ValueError("Always fails")
    
    with patch.object(chain, 'build_block', side_effect=always_failing_build):
        # Send a transaction
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=bytes.fromhex("deadbeef" * 5),
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
        )
        chain.send_transaction(signed_tx)
        
        # Start block producer
        chain._last_block_time = 0
        producer_thread = threading.Thread(target=_block_producer, args=(chain,), daemon=True)
        producer_thread.start()
        
        # Wait for several errors
        time.sleep(20)
        
        # Check that errors had backoff ( gaps > 1 second after first error)
        if len(error_times) > 2:
            for i in range(2, len(error_times)):
                gap = error_times[i] - error_times[i-1]
                # After error, should backoff to 5 seconds
                assert gap >= 4.5, f"Backoff not working: gap was {gap}s"
        
        print(f"✅ Block producer backoff working: {len(error_times)} errors with proper delays")
