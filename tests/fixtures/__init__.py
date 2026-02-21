"""Test fixtures for Ethereum Execution Layer tests."""

from .addresses import (
    ALICE_ADDRESS,
    BOB_ADDRESS,
    CHARLIE_ADDRESS,
    COINBASE_ADDRESS,
    ZERO_ADDRESS,
    TEST_ADDRESSES,
)
from .keys import (
    ALICE_PRIVATE_KEY,
    BOB_PRIVATE_KEY,
    CHARLIE_PRIVATE_KEY,
    TEST_PRIVATE_KEYS,
    get_keypair,
)
from .contracts import (
    SIMPLE_TRANSFER_BYTECODE,
    SIMPLE_STORAGE_BYTECODE,
    COUNTER_BYTECODE,
    PAYABLE_BYTECODE,
    REVERT_BYTECODE,
    TEST_CONTRACTS,
)

__all__ = [
    # Addresses
    "ALICE_ADDRESS",
    "BOB_ADDRESS",
    "CHARLIE_ADDRESS",
    "COINBASE_ADDRESS",
    "ZERO_ADDRESS",
    "TEST_ADDRESSES",
    # Keys
    "ALICE_PRIVATE_KEY",
    "BOB_PRIVATE_KEY",
    "CHARLIE_PRIVATE_KEY",
    "TEST_PRIVATE_KEYS",
    "get_keypair",
    # Contracts
    "SIMPLE_TRANSFER_BYTECODE",
    "SIMPLE_STORAGE_BYTECODE",
    "COUNTER_BYTECODE",
    "PAYABLE_BYTECODE",
    "REVERT_BYTECODE",
    "TEST_CONTRACTS",
]