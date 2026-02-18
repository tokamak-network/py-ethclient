import time

import pytest
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain
from tests.conftest import PRIVATE_KEY


class TestBlockTime:
    def test_block_time_prevents_immediate_mining(self, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=12)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
        )
        
        chain.add_transaction_to_pool(tx)
        
        assert len(chain.mempool) == 1
        assert chain.should_build_block() == False
        
        time.sleep(2)
        assert chain.should_build_block() == False
        
    def test_block_time_allows_mining_after_elapsed(self, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=2)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
        )
        
        chain.add_transaction_to_pool(tx)
        
        assert chain.should_build_block() == False
        
        time.sleep(2)
        
        assert chain.should_build_block() == True
        
        chain.build_block()
        assert len(chain.mempool) == 0
    
    def test_send_transaction_respects_block_time(self, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=5)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
        )
        
        chain.send_transaction(tx)
        
        assert len(chain.mempool) == 1
        latest = chain.get_latest_block()
        assert latest is not None
        assert latest.number == 0
        
        assert chain.should_build_block() == False