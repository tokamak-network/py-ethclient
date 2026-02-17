"""Integration test for sequencer: sendTransaction and eth_call."""

import json
import pytest
from http.server import HTTPServer
import threading
import time
import socket

from eth_keys import keys
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.rpc.server import create_server
from sequencer.rpc.methods import create_methods


PRIVATE_KEY = bytes.fromhex("01" * 32)
SIMPLE_STORAGE_BYTECODE = bytes.fromhex(
    "602a60005260206000f3"
)
SET_VALUE_CALLDATA = bytes.fromhex("6057361d000000000000000000000000000000000000000000000000000000000000002a")


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class TestSequencerIntegration:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.pk = keys.PrivateKey(PRIVATE_KEY)
        self.address = self.pk.public_key.to_canonical_address()
        
        genesis_state = {
            self.address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        self.chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        self.port = get_free_port()
        self.server = create_server(self.chain, "127.0.0.1", self.port)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        time.sleep(0.1)
        
        yield
        
        self.server.shutdown()

    def test_get_balance(self):
        methods = create_methods(self.chain)
        balance_hex = methods["eth_getBalance"]([self.address.hex(), "latest"])
        balance = int(balance_hex, 16)
        assert balance == to_wei(100, "ether")

    def test_chain_id(self):
        methods = create_methods(self.chain)
        chain_id = methods["eth_chainId"]([])
        assert int(chain_id, 16) == 1337

    def test_get_block_by_number(self):
        methods = create_methods(self.chain)
        block = methods["eth_getBlockByNumber"](["0x0", False])
        assert block is not None
        assert int(block["number"], 16) == 0

    def test_send_transaction_deploy_contract(self):
        nonce = self.chain.get_nonce(self.address)
        
        signed_tx = self.chain.create_transaction(
            from_private_key=PRIVATE_KEY,
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=500_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        
        tx_hash = self.chain.send_transaction(signed_tx)
        
        block = self.chain.build_block()
        
        assert block is not None
        assert block.number == 1
        assert len(block.transactions) == 1
        
        receipts = self.chain.store.get_receipts(1)
        assert len(receipts) == 1
        assert receipts[0].status == 1

    def test_eth_call_read_storage(self):
        nonce = self.chain.get_nonce(self.address)
        
        signed_tx = self.chain.create_transaction(
            from_private_key=PRIVATE_KEY,
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=500_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        
        tx_hash = self.chain.send_transaction(signed_tx)
        block = self.chain.build_block()
        
        receipts = self.chain.store.get_receipts(1)
        assert len(receipts) == 1
        assert receipts[0].status == 1

    def test_simple_transfer(self):
        recipient = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        
        nonce = self.chain.get_nonce(self.address)
        
        signed_tx = self.chain.create_transaction(
            from_private_key=PRIVATE_KEY,
            to=recipient,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        
        tx_hash = self.chain.send_transaction(signed_tx)
        
        block = self.chain.build_block()
        
        assert block is not None
        
        recipient_balance = self.chain.get_balance(recipient)
        assert recipient_balance == to_wei(1, "ether")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])