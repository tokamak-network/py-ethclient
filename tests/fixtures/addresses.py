"""Standard test addresses for Ethereum tests.

These addresses match common test vectors used in Ethereum spec tests.
All addresses are 20 bytes (canonical form, not checksummed).
"""

from sequencer.core.crypto import keccak256

# Standard test addresses (derived from test private keys)
# Private key 0x01...01 -> Address
ALICE_PRIVATE_KEY = bytes.fromhex("01" * 32)
ALICE_ADDRESS = keccak256(
    bytes.fromhex("01") * 32  # Simplified derivation
)[12:][:20]  # Take last 20 bytes
# Actually compute properly
from eth_keys import keys
_pk = keys.PrivateKey(ALICE_PRIVATE_KEY)
ALICE_ADDRESS = _pk.public_key.to_canonical_address()

# Private key 0x02...02 -> Address
BOB_PRIVATE_KEY = bytes.fromhex("02" * 32)
_pk2 = keys.PrivateKey(BOB_PRIVATE_KEY)
BOB_ADDRESS = _pk2.public_key.to_canonical_address()

# Private key 0x03...03 -> Address
CHARLIE_PRIVATE_KEY = bytes.fromhex("03" * 32)
_pk3 = keys.PrivateKey(CHARLIE_PRIVATE_KEY)
CHARLIE_ADDRESS = _pk3.public_key.to_canonical_address()

# Coinbase address (block producer)
COINBASE_ADDRESS = bytes.fromhex("00" * 19 + "99")

# Zero address (for burns, etc.)
ZERO_ADDRESS = bytes.fromhex("00" * 20)

# Common test addresses from Ethereum tests
TEST_ADDRESS_1 = bytes.fromhex("00" * 19 + "01")
TEST_ADDRESS_2 = bytes.fromhex("00" * 19 + "02")
TEST_ADDRESS_3 = bytes.fromhex("00" * 19 + "03")
TEST_ADDRESS_4 = bytes.fromhex("00" * 19 + "04")
TEST_ADDRESS_5 = bytes.fromhex("00" * 19 + "05")

# Precompile addresses (1-9)
ECRECOVER_ADDRESS = bytes.fromhex("00" * 19 + "01")
SHA256_ADDRESS = bytes.fromhex("00" * 19 + "02")
RIPEMD160_ADDRESS = bytes.fromhex("00" * 19 + "03")
IDENTITY_ADDRESS = bytes.fromhex("00" * 19 + "04")
MODEXP_ADDRESS = bytes.fromhex("00" * 19 + "05")
BN128_ADD_ADDRESS = bytes.fromhex("00" * 19 + "06")
BN128_MUL_ADDRESS = bytes.fromhex("00" * 19 + "07")
BN128_PAIRING_ADDRESS = bytes.fromhex("00" * 19 + "08")
BLAKE2F_ADDRESS = bytes.fromhex("00" * 19 + "09")

# Dict of all test addresses for easy iteration
TEST_ADDRESSES = {
    "alice": ALICE_ADDRESS,
    "bob": BOB_ADDRESS,
    "charlie": CHARLIE_ADDRESS,
    "coinbase": COINBASE_ADDRESS,
    "zero": ZERO_ADDRESS,
    "test1": TEST_ADDRESS_1,
    "test2": TEST_ADDRESS_2,
    "test3": TEST_ADDRESS_3,
    "test4": TEST_ADDRESS_4,
    "test5": TEST_ADDRESS_5,
}