"""Pytest configuration and shared fixtures for all tests."""

import pytest
from eth_keys import keys
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.core.constants import DEFAULT_CHAIN_ID, DEFAULT_GAS_LIMIT

# Import test fixtures
from tests.fixtures.addresses import (
    ALICE_ADDRESS,
    BOB_ADDRESS,
    CHARLIE_ADDRESS,
    ALICE_PRIVATE_KEY,
    BOB_PRIVATE_KEY,
    CHARLIE_PRIVATE_KEY,
    COINBASE_ADDRESS,
    ZERO_ADDRESS,
)
from tests.fixtures.contracts import (
    SIMPLE_STORAGE_BYTECODE,
    COUNTER_BYTECODE,
    PAYABLE_BYTECODE,
)
from tests.fixtures.keys import (
    derive_address,
    get_keypair,
)


# =============================================================================
# Core Fixtures - Private Keys and Addresses
# =============================================================================

@pytest.fixture
def alice_key():
    """Alice's private key (0x01...01)."""
    return ALICE_PRIVATE_KEY


@pytest.fixture
def alice_address():
    """Alice's address derived from her private key."""
    return ALICE_ADDRESS


@pytest.fixture
def bob_key():
    """Bob's private key (0x02...02)."""
    return BOB_PRIVATE_KEY


@pytest.fixture
def bob_address():
    """Bob's address."""
    return BOB_ADDRESS


@pytest.fixture
def charlie_key():
    """Charlie's private key (0x03...03)."""
    return CHARLIE_PRIVATE_KEY


@pytest.fixture
def charlie_address():
    """Charlie's address."""
    return CHARLIE_ADDRESS


@pytest.fixture
def coinbase_address():
    """Coinbase address (block producer)."""
    return COINBASE_ADDRESS


@pytest.fixture
def zero_address():
    """Zero address (0x00...00)."""
    return ZERO_ADDRESS


# =============================================================================
# Legacy Fixtures - Keep for backward compatibility
# =============================================================================

# Backward compatibility with existing tests
PRIVATE_KEY = ALICE_PRIVATE_KEY
RECIPIENT_ADDRESS = BOB_ADDRESS


@pytest.fixture
def private_key():
    """Primary test private key."""
    return PRIVATE_KEY


@pytest.fixture
def recipient_address():
    """Default recipient address for tests."""
    return RECIPIENT_ADDRESS


@pytest.fixture
def pk():
    """Private key object for signing."""
    return keys.PrivateKey(PRIVATE_KEY)


@pytest.fixture
def address(pk):
    """Address derived from private key."""
    return pk.public_key.to_canonical_address()


# =============================================================================
# Chain Fixtures
# =============================================================================

@pytest.fixture
def chain(address):
    """Create a chain with funded address (100 ETH)."""
    genesis_state = {
        address: {
            "balance": to_wei(100, "ether"),
            "nonce": 0,
            "code": b"",
            "storage": {},
        }
    }
    return Chain.from_genesis(genesis_state, chain_id=DEFAULT_CHAIN_ID)


@pytest.fixture
def chain_with_multiple_accounts(alice_address, bob_address, charlie_address):
    """Create a chain with multiple funded addresses."""
    genesis_state = {
        alice_address: {
            "balance": to_wei(100, "ether"),
            "nonce": 0,
            "code": b"",
            "storage": {},
        },
        bob_address: {
            "balance": to_wei(50, "ether"),
            "nonce": 0,
            "code": b"",
            "storage": {},
        },
        charlie_address: {
            "balance": to_wei(25, "ether"),
            "nonce": 0,
            "code": b"",
            "storage": {},
        },
    }
    return Chain.from_genesis(genesis_state, chain_id=DEFAULT_CHAIN_ID)


@pytest.fixture
def chain_with_nonce(address):
    """Factory fixture to create chain with custom nonce."""
    def _chain_with_nonce(nonce):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": nonce,
                "code": b"",
                "storage": {},
            }
        }
        return Chain.from_genesis(genesis_state, chain_id=DEFAULT_CHAIN_ID)
    return _chain_with_nonce


@pytest.fixture
def genesis_state_factory(address):
    """Factory fixture to create genesis state."""
    def _genesis_state(balance=to_wei(100, "ether"), nonce=0):
        return {
            address: {
                "balance": balance,
                "nonce": nonce,
                "code": b"",
                "storage": {},
            }
        }
    return _genesis_state


@pytest.fixture
def chain_factory():
    """Factory fixture to create chains with custom configurations."""
    def _chain_factory(
        genesis_state=None,
        chain_id=DEFAULT_CHAIN_ID,
        gas_limit=DEFAULT_GAS_LIMIT,
        coinbase=None,
        block_time=10,
        store_type="memory",
    ):
        return Chain.from_genesis(
            genesis_state or {},
            chain_id=chain_id,
            gas_limit=gas_limit,
            coinbase=coinbase or COINBASE_ADDRESS,
            block_time=block_time,
            store_type=store_type,
        )
    return _chain_factory


# =============================================================================
# Transaction Fixtures
# =============================================================================

@pytest.fixture
def legacy_tx_params(alice_address):
    """Default parameters for legacy transactions."""
    return {
        "from_private_key": ALICE_PRIVATE_KEY,
        "to": BOB_ADDRESS,
        "value": to_wei(1, "ether"),
        "data": b"",
        "gas": 21_000,
        "gas_price": 1_000_000_000,  # 1 Gwei
    }


@pytest.fixture
def eip1559_tx_params(alice_address):
    """Default parameters for EIP-1559 transactions."""
    return {
        "from_private_key": ALICE_PRIVATE_KEY,
        "to": BOB_ADDRESS,
        "value": to_wei(1, "ether"),
        "data": b"",
        "gas": 21_000,
        "max_priority_fee_per_gas": 1_000_000_000,  # 1 Gwei
        "max_fee_per_gas": 2_000_000_000,  # 2 Gwei
    }


# =============================================================================
# Contract Bytecode Fixtures
# =============================================================================

@pytest.fixture
def simple_storage_bytecode():
    """Bytecode for simple storage contract."""
    return SIMPLE_STORAGE_BYTECODE


@pytest.fixture
def counter_bytecode():
    """Bytecode for counter contract."""
    return COUNTER_BYTECODE


@pytest.fixture
def payable_bytecode():
    """Bytecode for payable contract."""
    return PAYABLE_BYTECODE