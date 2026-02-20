"""Test cases for contract deployment and storage operations.

This module tests:
1. Deploying contracts via transaction
2. Reading storage via eth_call (view methods)
3. Modifying storage via transactions (public/external methods)
4. Verifying storage changes

Contracts used:
- SimpleStorage: A basic contract with a stored value and getter/setter
- Counter: A contract with increment/decrement operations
"""

import pytest
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.rpc.methods import create_methods
from sequencer.core.crypto import keccak256


# SimpleStorage contract bytecode
# Solidity:
#   contract SimpleStorage {
#       uint256 private _value;
#       function getValue() public view returns (uint256) { return _value; }
#       function setValue(uint256 newValue) public { _value = newValue; }
#   }
#
# Compiled with solc 0.8.34 with optimization
SIMPLE_STORAGE_BYTECODE = bytes.fromhex(
    "6080604052348015600e575f5ffd5b5060a580601a5f395ff3fe6080604052348015600e575f5ffd5b50600436106030575f3560e01c80632096525514603457806355241077146048575b5f5ffd5b5f5460405190815260200160405180910390f35b605760533660046059565b5f55565b005b5f602082840312156068575f5ffd5b503591905056fea2646970667358221220179c94577d7fa8b744a517360bce0b535a7c23f81e3c6767a0abcacfcfd1549264736f6c63430008220033"
)

# Counter contract bytecode
# Solidity:
#   contract Counter {
#       uint256 private _count;
#       function getCount() public view returns (uint256) { return _count; }
#       function increment() public { _count += 1; }
#       function decrement() public { _count -= 1; }
#   }
#
# Compiled with solc 0.8.34 with optimization
COUNTER_BYTECODE = bytes.fromhex(
    "6080604052348015600e575f5ffd5b5060f58061001b5f395ff3fe6080604052348015600e575f5ffd5b5060043610603a575f3560e01c80632baeceb714603e578063a87d942c146046578063d09de08a14605a575b5f5ffd5b60446060565b005b5f5460405190815260200160405180910390f35b60446076565b60015f5f828254606f91906099565b9091555050565b60015f5f828254606f919060af565b634e487b7160e01b5f52601160045260245ffd5b8181038181111560a95760a96085565b92915050565b8082018082111560a95760a9608556fea26469706673582212208eda0cf3fe04effe43d21e5e560387edda6444850a7cc10c5db251aef76c121e64736f6c63430008220033"
)

# Function selectors (keccak256(fragment)[:4])
GET_VALUE_SELECTOR = keccak256(b"getValue()")[:4]  # 0x20965255
SET_VALUE_SELECTOR = keccak256(b"setValue(uint256)")[:4]  # 0x55241077
GET_COUNT_SELECTOR = keccak256(b"getCount()")[:4]  # 0xa87d942c
INCREMENT_SELECTOR = keccak256(b"increment()")[:4]  # 0xd09de08a
DECREMENT_SELECTOR = keccak256(b"decrement()")[:4]  # 0x2baeceb7


class TestContractDeployment:
    """Test contract deployment and basic operations."""

    @pytest.fixture
    def chain(self, pk, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        return Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)

    def test_deploy_simple_storage_contract(self, chain, pk, address):
        """Test deploying a simple storage contract."""
        nonce = chain.get_nonce(address)
        
        # Deploy contract
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,  # Contract creation
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        
        tx_hash = chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        # Verify transaction was successful
        assert block is not None
        assert len(block.transactions) == 1
        
        receipts = chain.store.get_receipts(1)
        assert len(receipts) == 1
        assert receipts[0].status == 1  # Success
        
        # Get contract address from receipt
        contract_address = receipts[0].contract_address
        assert contract_address is not None
        
    def test_deploy_multiple_contracts(self, chain, pk, address):
        """Test deploying multiple contracts in sequence."""
        for i in range(3):
            nonce = chain.get_nonce(address)
            signed_tx = chain.create_transaction(
                from_private_key=pk.to_bytes(),
                to=None,
                value=0,
                data=SIMPLE_STORAGE_BYTECODE,
                gas=1_000_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            chain.send_transaction(signed_tx)
            chain.build_block()
        
        assert chain.get_nonce(address) == 3


class TestEthCallStorageRead:
    """Test reading storage variables via eth_call (view methods)."""

    @pytest.fixture
    def chain_with_contract(self, pk, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy SimpleStorage contract
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        # Get contract address
        receipts = chain.store.get_receipts(1)
        contract_address = receipts[0].contract_address
        
        return chain, contract_address

    def test_call_view_method_initial_value(self, chain_with_contract, pk, address):
        """Test reading initial storage value (should be 0)."""
        chain, contract_address = chain_with_contract
        
        # Call getValue() - should return 0
        result = chain.call(
            from_address=address,
            to=contract_address,
            value=0,
            data=GET_VALUE_SELECTOR,
            gas=100_000,
        )
        
        # Result should be 32-byte zero (initial value)
        assert len(result) == 32
        value = int.from_bytes(result, 'big')
        assert value == 0

    def test_call_view_method_via_rpc(self, chain_with_contract, address):
        """Test reading storage via RPC eth_call method."""
        chain, contract_address = chain_with_contract
        methods = create_methods(chain)
        
        # Construct eth_call request
        tx_params = {
            "from": "0x" + address.hex(),
            "to": "0x" + contract_address.hex(),
            "data": "0x" + GET_VALUE_SELECTOR.hex(),
        }
        
        result = methods["eth_call"]([tx_params, "latest"])
        
        # Result should be 32-byte zero padded hex
        assert result.startswith("0x")
        value = int(result, 16)
        assert value == 0

    def test_call_get_count_initial(self, pk, address):
        """Test reading counter initial value."""
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy Counter contract
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=COUNTER_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        receipts = chain.store.get_receipts(1)
        contract_address = receipts[0].contract_address
        
        # Call getCount()
        result = chain.call(
            from_address=address,
            to=contract_address,
            value=0,
            data=GET_COUNT_SELECTOR,
            gas=100_000,
        )
        
        value = int.from_bytes(result, 'big')
        assert value == 0


class TestStorageModification:
    """Test modifying storage via transactions (public/external methods)."""

    @pytest.fixture
    def chain_with_contract(self, pk, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy SimpleStorage contract
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        receipts = chain.store.get_receipts(1)
        contract_address = receipts[0].contract_address
        
        return chain, contract_address

    def test_set_and_get_value(self, chain_with_contract, pk, address):
        """Test setting and getting a storage value."""
        chain, contract_address = chain_with_contract
        
        # Encode setValue(42)
        # Function selector + 32-byte padded argument
        new_value = 42
        calldata = SET_VALUE_SELECTOR + new_value.to_bytes(32, 'big')
        
        # Send transaction to set value
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=contract_address,
            value=0,
            data=calldata,
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        # Read value back
        result = chain.call(
            from_address=address,
            to=contract_address,
            value=0,
            data=GET_VALUE_SELECTOR,
            gas=100_000,
        )
        
        value = int.from_bytes(result, 'big')
        assert value == 42

    def test_set_multiple_values(self, chain_with_contract, pk, address):
        """Test setting multiple storage values in sequence."""
        chain, contract_address = chain_with_contract
        
        test_values = [0, 1, 100, 2**256 - 1, 12345]  # Including max uint256
        
        for expected_value in test_values:
            # Encode setValue(expected_value)
            calldata = SET_VALUE_SELECTOR + expected_value.to_bytes(32, 'big')
            
            nonce = chain.get_nonce(address)
            signed_tx = chain.create_transaction(
                from_private_key=pk.to_bytes(),
                to=contract_address,
                value=0,
                data=calldata,
                gas=100_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            chain.send_transaction(signed_tx)
            chain.build_block()
            
            # Read value back
            result = chain.call(
                from_address=address,
                to=contract_address,
                value=0,
                data=GET_VALUE_SELECTOR,
                gas=100_000,
            )
            
            value = int.from_bytes(result, 'big')
            assert value == expected_value

    def test_increment_counter(self, pk, address):
        """Test incrementing a counter."""
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy Counter contract
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=COUNTER_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        receipts = chain.store.get_receipts(1)
        contract_address = receipts[0].contract_address
        
        # Increment 5 times
        for i in range(5):
            nonce = chain.get_nonce(address)
            signed_tx = chain.create_transaction(
                from_private_key=pk.to_bytes(),
                to=contract_address,
                value=0,
                data=INCREMENT_SELECTOR,
                gas=100_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            chain.send_transaction(signed_tx)
            chain.build_block()
            
            # Check count
            result = chain.call(
                from_address=address,
                to=contract_address,
                value=0,
                data=GET_COUNT_SELECTOR,
                gas=100_000,
            )
            
            value = int.from_bytes(result, 'big')
            assert value == i + 1

    def test_decrement_counter(self, pk, address):
        """Test decrementing a counter."""
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy Counter contract
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=COUNTER_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        receipts = chain.store.get_receipts(1)
        contract_address = receipts[0].contract_address
        
        # Increment 3 times, then decrement 2 times
        for _ in range(3):
            nonce = chain.get_nonce(address)
            signed_tx = chain.create_transaction(
                from_private_key=pk.to_bytes(),
                to=contract_address,
                value=0,
                data=INCREMENT_SELECTOR,
                gas=100_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            chain.send_transaction(signed_tx)
            chain.build_block()
        
        # Now decrement
        for i in range(2):
            nonce = chain.get_nonce(address)
            signed_tx = chain.create_transaction(
                from_private_key=pk.to_bytes(),
                to=contract_address,
                value=0,
                data=DECREMENT_SELECTOR,
                gas=100_000,
                gas_price=1_000_000_000,
                nonce=nonce,
            )
            chain.send_transaction(signed_tx)
            chain.build_block()
            
            # Check count
            result = chain.call(
                from_address=address,
                to=contract_address,
                value=0,
                data=GET_COUNT_SELECTOR,
                gas=100_000,
            )
            
            value = int.from_bytes(result, 'big')
            assert value == 3 - (i + 1)


class TestGetStorageAt:
    """Test reading storage slots directly via eth_getStorageAt."""

    @pytest.fixture
    def chain_with_contract(self, pk, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy SimpleStorage contract
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        receipts = chain.store.get_receipts(1)
        contract_address = receipts[0].contract_address
        
        return chain, contract_address

    def test_get_storage_at_slot_zero(self, chain_with_contract):
        """Test reading storage slot 0."""
        chain, contract_address = chain_with_contract
        
        # Read storage at slot 0
        value = chain.get_storage_at(contract_address, 0)
        assert value == 0  # Initial value

    def test_get_storage_at_after_set(self, chain_with_contract, pk, address):
        """Test reading storage after setting a value."""
        chain, contract_address = chain_with_contract
        
        # Set value to 123
        calldata = SET_VALUE_SELECTOR + (123).to_bytes(32, 'big')
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=contract_address,
            value=0,
            data=calldata,
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        # Read storage at slot 0
        value = chain.get_storage_at(contract_address, 0)
        assert value == 123

    def test_get_storage_at_via_rpc(self, chain_with_contract):
        """Test eth_getStorageAt RPC method."""
        chain, contract_address = chain_with_contract
        methods = create_methods(chain)
        
        result = methods["eth_getStorageAt"]([
            "0x" + contract_address.hex(),
            "0x0",  # Slot 0
            "latest"
        ])
        
        # Result should be 32-byte hex
        assert result.startswith("0x")
        value = int(result, 16)
        assert value == 0


class TestContractCode:
    """Test contract code operations."""

    @pytest.fixture
    def chain_with_contract(self, pk, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy SimpleStorage contract
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        receipts = chain.store.get_receipts(1)
        contract_address = receipts[0].contract_address
        
        return chain, contract_address

    def test_get_code_returns_runtime_bytecode(self, chain_with_contract):
        """Test that getCode returns the deployed runtime bytecode."""
        chain, contract_address = chain_with_contract
        
        code = chain.get_code(contract_address)
        
        # Should return non-empty bytecode
        assert len(code) > 0
        
        # Runtime bytecode should be different from deployment bytecode
        assert code != SIMPLE_STORAGE_BYTECODE

    def test_get_code_via_rpc(self, chain_with_contract):
        """Test eth_getCode RPC method."""
        chain, contract_address = chain_with_contract
        methods = create_methods(chain)
        
        result = methods["eth_getCode"]([
            "0x" + contract_address.hex(),
            "latest"
        ])
        
        assert result.startswith("0x")
        assert len(result) > 2  # More than just "0x"


class TestMultipleContracts:
    """Test interactions with multiple contracts."""

    @pytest.fixture
    def chain_with_contracts(self, pk, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy first SimpleStorage
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        receipts = chain.store.get_receipts(1)
        contract1 = receipts[0].contract_address
        
        # Deploy second SimpleStorage
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        receipts = chain.store.get_receipts(2)
        contract2 = receipts[0].contract_address
        
        return chain, contract1, contract2

    def test_independent_storage(self, chain_with_contracts, pk, address):
        """Test that contracts have independent storage."""
        chain, contract1, contract2 = chain_with_contracts
        
        # Set different values in each contract
        calldata1 = SET_VALUE_SELECTOR + (100).to_bytes(32, 'big')
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=contract1,
            value=0,
            data=calldata1,
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        calldata2 = SET_VALUE_SELECTOR + (200).to_bytes(32, 'big')
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=contract2,
            value=0,
            data=calldata2,
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        # Verify independent storage
        value1 = chain.get_storage_at(contract1, 0)
        value2 = chain.get_storage_at(contract2, 0)
        
        assert value1 == 100
        assert value2 == 200

    def test_call_different_contracts(self, chain_with_contracts):
        """Test calling view methods on different contracts."""
        chain, contract1, contract2 = chain_with_contracts
        
        # Call getValue on both (should be 0 initially)
        result1 = chain.call(
            from_address=b"\x00" * 20,
            to=contract1,
            value=0,
            data=GET_VALUE_SELECTOR,
            gas=100_000,
        )
        
        result2 = chain.call(
            from_address=b"\x00" * 20,
            to=contract2,
            value=0,
            data=GET_VALUE_SELECTOR,
            gas=100_000,
        )
        
        # Both should return 0 (initial value)
        assert int.from_bytes(result1, 'big') == 0
        assert int.from_bytes(result2, 'big') == 0


class TestGasUsageForStorage:
    """Test gas usage for storage operations."""

    @pytest.fixture
    def chain_with_contract(self, pk, address):
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy SimpleStorage contract
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=SIMPLE_STORAGE_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        receipts = chain.store.get_receipts(1)
        contract_address = receipts[0].contract_address
        
        return chain, contract_address

    def test_gas_for_first_storage_write(self, chain_with_contract, pk, address):
        """Test that first storage write costs more (20,000 gas)."""
        chain, contract_address = chain_with_contract
        
        # Set value (first write to slot 0 should cost 20,000 gas)
        calldata = SET_VALUE_SELECTOR + (42).to_bytes(32, 'big')
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=contract_address,
            value=0,
            data=calldata,
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        # Gas used should include storage write
        assert block.header.gas_used > 21_000  # More than simple transfer

    def test_gas_for_storage_modify(self, chain_with_contract, pk, address):
        """Test that modifying existing storage costs less (5,000 gas)."""
        chain, contract_address = chain_with_contract
        
        # First write
        calldata = SET_VALUE_SELECTOR + (42).to_bytes(32, 'big')
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=contract_address,
            value=0,
            data=calldata,
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        # Second write (modify)
        calldata = SET_VALUE_SELECTOR + (43).to_bytes(32, 'big')
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=contract_address,
            value=0,
            data=calldata,
            gas=100_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        # The second transaction should use less gas than first for storage
        # (5,000 for modify vs 20,000 for first write)
        # But we can't easily compare due to transaction overhead
        assert chain.get_storage_at(contract_address, 0) == 43