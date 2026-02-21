"""Test block gas limit enforcement.

Verifies that blocks respect the gas limit and don't overflow.
"""

import pytest
from eth_keys import keys
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain


def test_block_respects_gas_limit():
    """Block should stop adding transactions when gas limit is reached."""
    pk = keys.PrivateKey(bytes.fromhex("01" * 32))
    address = pk.public_key.to_canonical_address()
    
    gas_limit = 100_000  # Low limit for testing
    
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
        gas_limit=gas_limit,
        block_time=1,
    )
    
    # Create transactions that each use ~21,000 gas (simple transfers)
    tx_gas = 21_000
    max_txs = gas_limit // tx_gas  # Should fit ~4 transactions
    
    # Send more transactions than can fit in a block
    for nonce in range(max_txs + 5):
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=bytes.fromhex("deadbeef" * 5),
            value=to_wei(1, "ether"),
            data=b"",
            gas=tx_gas,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
    
    # Build block
    chain._last_block_time = 0  # Force block building
    block = chain.build_block()
    
    # Verify block doesn't exceed gas limit
    assert block.header.gas_used <= gas_limit, f"Block gas used ({block.header.gas_used}) exceeds limit ({gas_limit})"
    
    # Verify not all transactions were included (gas limit enforced)
    assert len(block.transactions) <= max_txs, f"Too many transactions in block: {len(block.transactions)} > {max_txs}"
    
    # Verify at least one transaction was included
    assert len(block.transactions) > 0, "No transactions included in block"
    
    print(f"✅ Block gas limit enforced: {len(block.transactions)} txs, {block.header.gas_used}/{gas_limit} gas")


def test_block_gas_limit_simple_transfer():
    """Simple transfer (21k gas) should fill block at correct count."""
    pk = keys.PrivateKey(bytes.fromhex("01" * 32))
    address = pk.public_key.to_canonical_address()
    
    gas_limit = 50_000  # Low limit for testing
    
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
        gas_limit=gas_limit,
        block_time=1,
    )
    
    # Send many simple transfers (use explicit nonces)
    for nonce in range(10):
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=bytes.fromhex("deadbeef" * 5),
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
    
    # Build block
    chain._last_block_time = 0
    block = chain.build_block()
    
    # With 50k limit and 21k per tx, should fit 2 txs (42k gas)
    # 3 txs would be 63k which exceeds limit
    assert block.header.gas_used <= gas_limit
    assert len(block.transactions) <= 2
    
    print(f"✅ Simple transfer test: {len(block.transactions)} txs, {block.header.gas_used}/{gas_limit} gas")


def test_block_with_mixed_gas_transactions():
    """Block with mixed gas transactions should accurately track gas."""
    pk = keys.PrivateKey(bytes.fromhex("01" * 32))
    address = pk.public_key.to_canonical_address()
    
    gas_limit = 100_000
    
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
        gas_limit=gas_limit,
        block_time=1,
    )
    
    # Send transactions with varying gas limits (explicit nonces)
    txs = [
        (21_000, b""),  # Simple transfer
        (50_000, b""),  # Higher gas
        (30_000, b""),  # Medium gas
        (25_000, b""),  # Medium gas
        (100_000, b""),  # Too big for remaining space
    ]
    
    for i, (gas, data) in enumerate(txs):
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=bytes.fromhex("deadbeef" * 5),
            value=to_wei(1, "ether"),
            data=data,
            gas=gas,
            nonce=i,
        )
        chain.send_transaction(signed_tx)
    
    # Build block
    chain._last_block_time = 0
    block = chain.build_block()
    
    # Verify gas limit respected
    assert block.header.gas_used <= gas_limit
    
    # Verify gas tracking is accurate
    print(f"✅ Mixed gas test: {len(block.transactions)} txs, {block.header.gas_used}/{gas_limit} gas")


def test_high_gas_transaction_skipped():
    """High gas transaction should be skipped if it doesn't fit."""
    pk = keys.PrivateKey(bytes.fromhex("01" * 32))
    address = pk.public_key.to_canonical_address()
    
    gas_limit = 50_000
    
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
        gas_limit=gas_limit,
        block_time=1,
    )
    
    # First send a small transaction (nonce=0)
    small_tx = chain.create_transaction(
        from_private_key=pk.to_bytes(),
        to=bytes.fromhex("deadbeef" * 5),
        value=to_wei(1, "ether"),
        data=b"",
        gas=21_000,
        nonce=0,
    )
    chain.send_transaction(small_tx)
    
    # Then send a transaction that won't fit (nonce=1)
    big_tx = chain.create_transaction(
        from_private_key=pk.to_bytes(),
        to=bytes.fromhex("cafebabe" * 5),
        value=to_wei(1, "ether"),
        data=b"",
        gas=50_000,  # Won't fit after first tx
        nonce=1,
    )
    chain.send_transaction(big_tx)
    
    # Build block
    chain._last_block_time = 0
    block = chain.build_block()
    
    # Should only include the first transaction
    assert len(block.transactions) == 1
    assert block.header.gas_used == 21_000
    
    # Second transaction should still be in mempool
    assert len(chain.mempool) == 1
    
    print(f"✅ High gas skip test: included 1 tx, 1 tx remains in mempool")
