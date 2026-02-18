from eth_utils import to_wei

from sequencer.sequencer.chain import Chain, calc_base_fee
from sequencer.core.constants import INITIAL_BASE_FEE, BASE_FEE_MAX_CHANGE_DENOMINATOR
from sequencer.rpc.methods import create_methods
from tests.conftest import PRIVATE_KEY


class TestEIP1559:
    def test_calc_base_fee_same_as_target(self):
        gas_limit = 30_000_000
        gas_target = gas_limit // 2
        result = calc_base_fee(gas_target, gas_limit, INITIAL_BASE_FEE)
        assert result == INITIAL_BASE_FEE
    
    def test_calc_base_fee_above_target(self):
        gas_limit = 30_000_000
        gas_target = gas_limit // 2
        gas_used = gas_target + 1_000_000
        
        expected_delta = max(INITIAL_BASE_FEE * 1_000_000 // gas_target // BASE_FEE_MAX_CHANGE_DENOMINATOR, 1)
        expected = INITIAL_BASE_FEE + expected_delta
        
        result = calc_base_fee(gas_used, gas_limit, INITIAL_BASE_FEE)
        assert result == expected
        assert result > INITIAL_BASE_FEE
    
    def test_calc_base_fee_below_target(self):
        gas_limit = 30_000_000
        gas_target = gas_limit // 2
        gas_used = gas_target - 1_000_000
        
        expected_delta = INITIAL_BASE_FEE * 1_000_000 // gas_target // BASE_FEE_MAX_CHANGE_DENOMINATOR
        expected = max(INITIAL_BASE_FEE - expected_delta, 1)
        
        result = calc_base_fee(gas_used, gas_limit, INITIAL_BASE_FEE)
        assert result == expected
        assert result < INITIAL_BASE_FEE
    
    def test_create_eip1559_transaction(self, pk, address):
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
    
    def test_send_eip1559_transaction(self, pk, address):
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
        
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        block = chain.get_latest_block()
        assert block is not None
        assert block.number == 1
        assert len(block.transactions) == 1
        
        recipient_balance = chain.get_balance(recipient)
        assert recipient_balance == to_wei(1, "ether")
    
    def test_base_fee_changes_after_block(self, pk, address):
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
    
    def test_eth_sendTransaction_eip1559_via_rpc(self, pk, address):
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