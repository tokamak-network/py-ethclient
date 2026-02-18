import pytest
from eth_keys import keys
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain


PRIVATE_KEY = bytes.fromhex("01" * 32)
RECIPIENT_ADDRESS = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
SIMPLE_STORAGE_BYTECODE = bytes.fromhex("602a60005260206000f3")


@pytest.fixture
def private_key():
    return PRIVATE_KEY


@pytest.fixture
def recipient_address():
    return RECIPIENT_ADDRESS


@pytest.fixture
def pk():
    return keys.PrivateKey(PRIVATE_KEY)


@pytest.fixture
def address(pk):
    return pk.public_key.to_canonical_address()


@pytest.fixture
def chain(address):
    genesis_state = {
        address: {
            "balance": to_wei(100, "ether"),
            "nonce": 0,
            "code": b"",
            "storage": {},
        }
    }
    return Chain.from_genesis(genesis_state, chain_id=1337)


@pytest.fixture
def chain_with_nonce(address):
    def _chain_with_nonce(nonce):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": nonce,
                "code": b"",
                "storage": {},
            }
        }
        return Chain.from_genesis(genesis_state, chain_id=1337)
    return _chain_with_nonce


@pytest.fixture
def genesis_state_factory(address):
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