import pytest
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.sequencer.mempool import Mempool, NonceTooLow, UnderpricedReplacement
from tests.conftest import PRIVATE_KEY


class TestMempool:
    def test_mempool_add_and_get_pending(self, chain):
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

    def test_mempool_nonce_ordering(self, chain):
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

    def test_mempool_tx_replacement(self, chain):
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

    def test_mempool_reject_low_fee_replacement(self, chain):
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
        
        with pytest.raises(UnderpricedReplacement):
            chain.mempool.add(tx_low, 0)
        
        assert len(chain.mempool) == 1
        
        pending = chain.mempool.get_pending(10)
        assert pending[0].max_priority_fee_per_gas == 100_000_000

    def test_mempool_priority_sorting(self, pk):
        from eth_keys import keys
        
        addr1 = pk.public_key.to_canonical_address()
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

    def test_mempool_with_chain_integration(self, chain):
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

    def test_mempool_reject_nonce_too_low(self, pk):
        genesis_state = {
            pk.public_key.to_canonical_address(): {
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
    
    def test_mempool_pending_high_nonce(self, chain):
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
    
    def test_mempool_nonce_gap_filled(self, chain):
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
    
    def test_mempool_out_of_order_nonce_same_block(self, chain, address):
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