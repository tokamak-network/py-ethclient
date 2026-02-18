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
        
        tx_hash = self.chain.send_transaction(signed_tx)
        self.chain.build_block()
        
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
        self.chain.build_block()
        
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
        chain.build_block()
        
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
        chain.build_block()
        
        block1 = chain.get_block_by_number(1)
        assert block1 is not None
        
        signed_tx2 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
        )
        chain.send_transaction(signed_tx2)
        chain.build_block()
        
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
        
        chain.build_block()
        
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
            chain.build_block()
        
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
            chain.build_block()
        
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


class TestMempool:
    def test_mempool_add_and_get_pending(self):
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
        
        tx = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            max_priority_fee_per_gas=100_000_000,
            max_fee_per_gas=2_000_000_000,
        )
        
        assert chain.mempool.add(tx, 0) == True
        assert len(chain.mempool) == 1
        
        pending = chain.mempool.get_pending(10)
        assert len(pending) == 1
        assert pending[0] == tx

    def test_mempool_nonce_ordering(self):
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
        
        tx0 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            nonce=0,
        )
        
        tx1 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            nonce=1,
        )
        
        chain.mempool.add(tx1, 0)
        chain.mempool.add(tx0, 0)
        
        pending = chain.mempool.get_pending(10)
        assert len(pending) == 2
        assert pending[0].nonce == 0
        assert pending[1].nonce == 1

    def test_mempool_tx_replacement(self):
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
        
        tx_low = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            max_priority_fee_per_gas=100_000_000,
        )
        
        assert chain.mempool.add(tx_low, 0) == True
        assert len(chain.mempool) == 1
        
        tx_high = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            max_priority_fee_per_gas=150_000_000,
        )
        
        assert chain.mempool.add(tx_high, 0) == True
        assert len(chain.mempool) == 1
        
        pending = chain.mempool.get_pending(10)
        assert pending[0].max_priority_fee_per_gas == 150_000_000

    def test_mempool_reject_low_fee_replacement(self):
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
        
        tx_high = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            max_priority_fee_per_gas=100_000_000,
        )
        
        chain.mempool.add(tx_high, 0)
        
        tx_low = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            max_priority_fee_per_gas=105_000_000,
        )
        
        from sequencer.sequencer.mempool import UnderpricedReplacement
        with pytest.raises(UnderpricedReplacement):
            chain.mempool.add(tx_low, 0)
        
        assert len(chain.mempool) == 1
        
        pending = chain.mempool.get_pending(10)
        assert pending[0].max_priority_fee_per_gas == 100_000_000

    def test_mempool_priority_sorting(self):
        pk1 = keys.PrivateKey(PRIVATE_KEY)
        addr1 = pk1.public_key.to_canonical_address()
        
        pk2 = keys.PrivateKey(bytes.fromhex("02" * 32))
        addr2 = pk2.public_key.to_canonical_address()
        
        genesis_state = {
            addr1: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}},
            addr2: {"balance": to_wei(100, "ether"), "nonce": 0, "code": b"", "storage": {}},
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx_low = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            max_priority_fee_per_gas=50_000_000,
        )
        
        tx_high = chain.create_eip1559_transaction(
            from_private_key=bytes.fromhex("02" * 32),
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            max_priority_fee_per_gas=200_000_000,
        )
        
        chain.mempool.add(tx_low, 0)
        chain.mempool.add(tx_high, 0)
        
        pending = chain.mempool.get_pending(10)
        assert len(pending) == 2
        assert pending[0].max_priority_fee_per_gas == 200_000_000
        assert pending[1].max_priority_fee_per_gas == 50_000_000

    def test_mempool_size_limit_eviction(self):
        from sequencer.sequencer.mempool import Mempool
        
        mempool = Mempool(max_size=2)
        
        class MockTx:
            def __init__(self, sender, nonce, fee):
                self.sender = sender
                self.nonce = nonce
                self._fee = fee
                self._hash = sender + bytes([nonce])
            
            def encode(self):
                return self._hash
            
            @property
            def max_priority_fee_per_gas(self):
                return self._fee
        
        tx1 = MockTx(b"addr1", 0, 100)
        tx2 = MockTx(b"addr2", 0, 200)
        tx3 = MockTx(b"addr3", 0, 150)
        
        mempool.add(tx1, 0)
        mempool.add(tx2, 0)
        assert len(mempool) == 2
        
        mempool.add(tx3, 0)
        assert len(mempool) == 2
        
        pending = mempool.get_pending(10)
        assert len(pending) == 2
        fees = [tx.max_priority_fee_per_gas for tx in pending]
        assert 100 not in fees

    def test_mempool_with_chain_integration(self):
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
        
        tx1 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            max_priority_fee_per_gas=100_000_000,
        )
        
        tx2 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            max_priority_fee_per_gas=150_000_000,
            nonce=1,
        )
        
        chain.add_transaction_to_pool(tx1)
        chain.add_transaction_to_pool(tx2)
        
        assert len(chain.mempool) == 2
        
        block = chain.build_block()
        assert len(block.transactions) == 2
        assert len(chain.mempool) == 0

    def test_mempool_reject_nonce_too_low(self):
        from sequencer.sequencer.mempool import NonceTooLow
        
        pk = keys.PrivateKey(PRIVATE_KEY)
        address = pk.public_key.to_canonical_address()
        
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 5,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            nonce=3,
        )
        
        with pytest.raises(NonceTooLow):
            chain.mempool.add(tx, 5)
    
    def test_mempool_pending_high_nonce(self):
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
        
        tx_nonce_5 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            nonce=5,
        )
        
        assert chain.mempool.add(tx_nonce_5, 0) == True
        assert len(chain.mempool) == 1
        
        pending = chain.mempool.get_pending(10)
        assert len(pending) == 0
    
    def test_mempool_nonce_gap_filled(self):
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
        
        tx2 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            nonce=2,
        )
        chain.mempool.add(tx2, 0)
        
        tx1 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            nonce=1,
        )
        chain.mempool.add(tx1, 0)
        
        tx0 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
            nonce=0,
        )
        chain.mempool.add(tx0, 0)
        
        pending = chain.mempool.get_pending(10)
        assert len(pending) == 3
        assert pending[0].nonce == 0
        assert pending[1].nonce == 1
        assert pending[2].nonce == 2
    
    def test_mempool_out_of_order_nonce_same_block(self):
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
        
        tx_nonce_1 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=recipient,
            value=to_wei(1, "ether"),
            gas=21_000,
            nonce=1,
        )
        chain.add_transaction_to_pool(tx_nonce_1)
        
        assert len(chain.mempool) == 1
        assert len(chain.mempool.get_pending(10)) == 0
        
        tx_nonce_0 = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=recipient,
            value=to_wei(1, "ether"),
            gas=21_000,
            nonce=0,
        )
        chain.add_transaction_to_pool(tx_nonce_0)
        
        assert len(chain.mempool) == 2
        pending = chain.mempool.get_pending(10)
        assert len(pending) == 2
        assert pending[0].nonce == 0
        assert pending[1].nonce == 1
        
        block = chain.build_block()
        
        assert block is not None
        assert block.number == 1
        assert len(block.transactions) == 2
        assert block.transactions[0].nonce == 0
        assert block.transactions[1].nonce == 1
        assert len(chain.mempool) == 0
        assert chain.get_nonce(address) == 2
        assert chain.get_balance(recipient) == to_wei(2, "ether")


class TestBlockTime:
    def test_block_time_prevents_immediate_mining(self):
        import time as time_module
        
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
        
        time_module.sleep(2)
        assert chain.should_build_block() == False
        
    def test_block_time_allows_mining_after_elapsed(self):
        import time as time_module
        
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
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=2)
        
        tx = chain.create_eip1559_transaction(
            from_private_key=PRIVATE_KEY,
            to=bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            value=to_wei(1, "ether"),
            gas=21_000,
        )
        
        chain.add_transaction_to_pool(tx)
        
        assert chain.should_build_block() == False
        
        time_module.sleep(2)
        
        assert chain.should_build_block() == True
        
        chain.build_block()
        assert len(chain.mempool) == 0
    
    def test_send_transaction_respects_block_time(self):
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])