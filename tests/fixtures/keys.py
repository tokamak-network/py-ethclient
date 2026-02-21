"""Standard test private keys for Ethereum tests.

All keys are 32 bytes. These match common Ethereum test vectors.
"""

from eth_keys import keys
from typing import Tuple

# Standard test private keys
ALICE_PRIVATE_KEY = bytes.fromhex("01" * 32)
BOB_PRIVATE_KEY = bytes.fromhex("02" * 32)
CHARLIE_PRIVATE_KEY = bytes.fromhex("03" * 32)

# Additional test keys for various scenarios
TEST_KEY_4 = bytes.fromhex("04" * 32)
TEST_KEY_5 = bytes.fromhex("05" * 32)

# Known keypair from Ethereum tests (useful for signature verification)
# This key is commonly used in EF tests
KNOWN_TEST_KEY = bytes.fromhex(
    "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
)

# Dict of all test keys
TEST_PRIVATE_KEYS = {
    "alice": ALICE_PRIVATE_KEY,
    "bob": BOB_PRIVATE_KEY,
    "charlie": CHARLIE_PRIVATE_KEY,
    "test4": TEST_KEY_4,
    "test5": TEST_KEY_5,
    "known": KNOWN_TEST_KEY,
}


def get_keypair(private_key: bytes) -> Tuple[bytes, bytes]:
    """Get (private_key, address) tuple from a private key.
    
    Args:
        private_key: 32-byte private key
        
    Returns:
        Tuple of (private_key, address)
    """
    pk = keys.PrivateKey(private_key)
    address = pk.public_key.to_canonical_address()
    return (private_key, address)


def derive_address(private_key: bytes) -> bytes:
    """Derive Ethereum address from private key.
    
    Args:
        private_key: 32-byte private key
        
    Returns:
        20-byte canonical address
    """
    pk = keys.PrivateKey(private_key)
    return pk.public_key.to_canonical_address()


def sign_message(private_key: bytes, message: bytes) -> Tuple[int, int, int]:
    """Sign a message with a private key.
    
    Args:
        private_key: 32-byte private key
        message: Message bytes to sign
        
    Returns:
        Tuple of (v, r, s) signature components
    """
    from sequencer.core.crypto import keccak256
    pk = keys.PrivateKey(private_key)
    message_hash = keccak256(message)
    signature = pk.sign_msg_hash(message_hash)
    return (signature.v, signature.r, signature.s)


# Pre-computed addresses for convenience
ALICE_ADDRESS = derive_address(ALICE_PRIVATE_KEY)
BOB_ADDRESS = derive_address(BOB_PRIVATE_KEY)
CHARLIE_ADDRESS = derive_address(CHARLIE_PRIVATE_KEY)