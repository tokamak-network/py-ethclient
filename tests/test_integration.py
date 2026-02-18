import socket
import threading
import time

import pytest
from eth_utils import to_wei

from sequencer.rpc.server import create_server
from sequencer.rpc.methods import create_methods
from tests.conftest import PRIVATE_KEY, SIMPLE_STORAGE_BYTECODE


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class TestSequencerIntegration:
    @pytest.fixture(autouse=True)
    def setup(self, pk, address, chain):
        self.pk = pk
        self.address = address
        self.chain = chain
        
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
        
        self.chain.send_transaction(signed_tx)
        self.chain.build_block()
        
        block = self.chain.get_latest_block()
        
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
        
        self.chain.send_transaction(signed_tx)
        self.chain.build_block()
        
        receipts = self.chain.store.get_receipts(1)
        assert len(receipts) == 1
        assert receipts[0].status == 1

    def test_simple_transfer(self, recipient_address):
        nonce = self.chain.get_nonce(self.address)
        
        signed_tx = self.chain.create_transaction(
            from_private_key=PRIVATE_KEY,
            to=recipient_address,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        
        self.chain.send_transaction(signed_tx)
        self.chain.build_block()
        
        block = self.chain.get_latest_block()
        
        assert block is not None
        
        recipient_balance = self.chain.get_balance(recipient_address)
        assert recipient_balance == to_wei(1, "ether")