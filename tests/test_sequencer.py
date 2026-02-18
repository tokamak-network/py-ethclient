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
        
        tx_hash = self.chain.send_transaction(signed_tx)
        
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
        
        block = self.chain.get_latest_block()
        
        assert block is not None
        
        recipient_balance = self.chain.get_balance(recipient)
        assert recipient_balance == to_wei(1, "ether")


class TestEIP1559:
    def test_calc_base_fee_same_as_target(self):
        from sequencer.sequencer.chain import calc_base_fee
        from sequencer.core.constants import INITIAL_BASE_FEE
        
        gas_limit = 30_000_000
        gas_target = gas_limit // 2
        result = calc_base_fee(gas_target, gas_limit, INITIAL_BASE_FEE)
        assert result == INITIAL_BASE_FEE
    
    def test_calc_base_fee_above_target(self):
        from sequencer.sequencer.chain import calc_base_fee
        from sequencer.core.constants import INITIAL_BASE_FEE, BASE_FEE_MAX_CHANGE_DENOMINATOR
        
        gas_limit = 30_000_000
        gas_target = gas_limit // 2
        gas_used = gas_target + 1_000_000
        
        expected_delta = max(INITIAL_BASE_FEE * 1_000_000 // gas_target // BASE_FEE_MAX_CHANGE_DENOMINATOR, 1)
        expected = INITIAL_BASE_FEE + expected_delta
        
        result = calc_base_fee(gas_used, gas_limit, INITIAL_BASE_FEE)
        assert result == expected
        assert result > INITIAL_BASE_FEE
    
    def test_calc_base_fee_below_target(self):
        from sequencer.sequencer.chain import calc_base_fee
        from sequencer.core.constants import INITIAL_BASE_FEE, BASE_FEE_MAX_CHANGE_DENOMINATOR
        
        gas_limit = 30_000_000
        gas_target = gas_limit // 2
        gas_used = gas_target - 1_000_000
        
        expected_delta = INITIAL_BASE_FEE * 1_000_000 // gas_target // BASE_FEE_MAX_CHANGE_DENOMINATOR
        expected = max(INITIAL_BASE_FEE - expected_delta, 1)
        
        result = calc_base_fee(gas_used, gas_limit, INITIAL_BASE_FEE)
        assert result == expected
        assert result < INITIAL_BASE_FEE
    
    def test_create_eip1559_transaction(self):
        pk = keys.PrivateKey(PRIVATE_KEY)
        address = pk.public_key.to_canonical_address()
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        recipient = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        
        signed_tx = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=recipient,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            max_priority_fee_per_gas=100_000_000,
            max_fee_per_gas=2_000_000_000,
        )
        
        assert hasattr(signed_tx, "max_fee_per_gas")
        assert hasattr(signed_tx, "max_priority_fee_per_gas")
        assert signed_tx.max_fee_per_gas == 2_000_000_000
        assert signed_tx.max_priority_fee_per_gas == 100_000_000
    
    def test_send_eip1559_transaction(self):
        pk = keys.PrivateKey(PRIVATE_KEY)
        address = pk.public_key.to_canonical_address()
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        recipient = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        
        signed_tx = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=recipient,
            value=to_wei(1, "ether"),
            data=b"",
            gas=21_000,
            max_priority_fee_per_gas=100_000_000,
            max_fee_per_gas=2_000_000_000,
        )
        
        tx_hash = chain.send_transaction(signed_tx)
        
        block = chain.get_latest_block()
        assert block is not None
        assert block.number == 1
        assert len(block.transactions) == 1
        
        recipient_balance = chain.get_balance(recipient)
        assert recipient_balance == to_wei(1, "ether")
    
    def test_base_fee_changes_after_block(self):
        pk = keys.PrivateKey(PRIVATE_KEY)
        address = pk.public_key.to_canonical_address()
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        genesis_block = chain.get_latest_block()
        assert genesis_block is not None
        initial_base_fee = genesis_block.header.base_fee_per_gas
        
        signed_tx = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
        )
        chain.send_transaction(signed_tx)
        
        block1 = chain.get_block_by_number(1)
        assert block1 is not None
        
        signed_tx2 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
        )
        chain.send_transaction(signed_tx2)
        
        block2 = chain.get_block_by_number(2)
        assert block2 is not None
        assert block2.header.base_fee_per_gas is not None
    
    def test_eth_sendTransaction_eip1559_via_rpc(self):
        pk = keys.PrivateKey(PRIVATE_KEY)
        address = pk.public_key.to_canonical_address()
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        methods = create_methods(chain)
        
        recipient = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        tx_params = {
            "from": "0x" + address.hex(),
            "to": recipient,
            "value": "0xde0b6b3a7640000",
            "gas": "0x5208",
            "maxFeePerGas": "0x77359400",
            "maxPriorityFeePerGas": "0x5f5e100",
            "_private_key": PRIVATE_KEY.hex(),
        }
        
        tx_hash_hex = methods["eth_sendTransaction"]([tx_params])
        assert tx_hash_hex.startswith("0x")
        
        block = chain.get_latest_block()
        assert block is not None
        assert len(block.transactions) == 1
        
        tx = block.transactions[0]
        assert hasattr(tx, "max_fee_per_gas")
        assert tx.max_fee_per_gas == 2_000_000_000
        assert tx.max_priority_fee_per_gas == 100_000_000


class TestFeeHistory:
    def test_fee_history_genesis_only(self):
        pk = keys.PrivateKey(PRIVATE_KEY)
        address = pk.public_key.to_canonical_address()
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        methods = create_methods(chain)
        
        result = methods["eth_feeHistory"]([1, "latest", []])
        
        assert "oldestBlock" in result
        assert "baseFeePerGas" in result
        assert "gasUsedRatio" in result
        assert int(result["oldestBlock"], 16) == 0
        assert len(result["baseFeePerGas"]) == 2
        assert len(result["gasUsedRatio"]) == 1
    
    def test_fee_history_after_transactions(self):
        pk = keys.PrivateKey(PRIVATE_KEY)
        address = pk.public_key.to_canonical_address()
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        for i in range(3):
            signed_tx = chain.create_eip1559_transaction(
                from_private_key=PRIVATE_KEY,
                to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
                value=to_wei(1, "ether"),
                gas=21_000,
            )
            chain.send_transaction(signed_tx)
        
        methods = create_methods(chain)
        result = methods["eth_feeHistory"]([3, "latest", []])
        
        assert int(result["oldestBlock"], 16) == 1
        assert len(result["baseFeePerGas"]) == 4
        assert len(result["gasUsedRatio"]) == 3
    
    def test_fee_history_with_reward_percentiles(self):
        pk = keys.PrivateKey(PRIVATE_KEY)
        address = pk.public_key.to_canonical_address()
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        signed_tx = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
        )
        chain.send_transaction(signed_tx)
        
        methods = create_methods(chain)
        result = methods["eth_feeHistory"]([1, "latest", [25, 50, 75]])
        
        assert "reward" in result
        assert len(result["reward"]) == 1
    
    def test_fee_history_base_fee_increases_with_high_gas(self):
        from sequencer.sequencer.chain import calc_base_fee
        from sequencer.core.constants import INITIAL_BASE_FEE
        
        pk = keys.PrivateKey(PRIVATE_KEY)
        address = pk.public_key.to_canonical_address()
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        for i in range(10):
            signed_tx = chain.create_eip1559_transaction(
                from_private_key=PRIVATE_KEY,
                to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
                value=to_wei(1, "ether"),
                gas=21_000,
            )
            chain.send_transaction(signed_tx)
        
        methods = create_methods(chain)
        result = methods["eth_feeHistory"]([5, "latest", []])
        
        base_fees = [int(fee, 16) for fee in result["baseFeePerGas"]]
        assert len(base_fees) == 6
        
        genesis_block = chain.get_block_by_number(0)
        genesis_fee = genesis_block.header.base_fee_per_gas if genesis_block else INITIAL_BASE_FEE
        
        block1 = chain.get_block_by_number(1)
        if block1 and block1.header.gas_used > block1.header.gas_limit // 2:
            block2 = chain.get_block_by_number(2)
            if block2:
                fee1 = block1.header.base_fee_per_gas or INITIAL_BASE_FEE
                fee2 = block2.header.base_fee_per_gas or INITIAL_BASE_FEE
                assert fee2 > fee1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])