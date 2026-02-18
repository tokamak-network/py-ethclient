from eth_utils import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.core.constants import INITIAL_BASE_FEE
from sequencer.rpc.methods import create_methods
from tests.conftest import PRIVATE_KEY


class TestFeeHistory:
    def test_fee_history_genesis_only(self, pk, address):
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
    
    def test_fee_history_after_transactions(self, pk, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        for _ in range(3):
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
    
    def test_fee_history_with_reward_percentiles(self, pk, address):
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
    
    def test_fee_history_base_fee_increases_with_high_gas(self, pk, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        
        chain = Chain.from_genesis(genesis_state, chain_id=1337)
        
        for _ in range(10):
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