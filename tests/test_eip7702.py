"""Tests for EIP-7702 SetCode transaction support."""

import pytest
from eth_keys import keys
from eth_utils import to_wei
from eth.vm.forks.prague.transactions import (
    Authorization,
    SetCodeTransaction,
    SET_CODE_TRANSACTION_TYPE,
)

from sequencer.sequencer.chain import Chain
from sequencer.evm.adapter import EVMAdapter, ChainConfig


@pytest.fixture
def simple_contract_bytecode():
    """Simple contract that returns a value."""
    # Contract: store value and return it
    # function setValue(uint256 x) -> stores x, returns x
    # function getValue() -> returns stored value
    return bytes.fromhex(
        "6080604052348015600f57600080fd5b5060043610603c5760003560e01c"
        "8063209652551460415780635524107714605b575b600080fd5b604760c8"
        "565b6040516052919060a1565b60405180910390f35b605f60d4565b6040"
        "51606a919060a1565b60405180910390f35b600080fd5b60008190509190"
        "50565b6085816074565b82525050565b6000819050919050565b609b8160"
        "8c565b82525050565b604051818152602001905060405180910390f35b600"
        "080fd5b600080905090565b60008090509056fea2646970667358221220"
        "000000000000000000000000000000000000000000000000000000000000"
        "0064736f6c63430008070033"
    )


@pytest.fixture
def funded_account():
    """Account with funded balance."""
    pk = keys.PrivateKey(bytes.fromhex("01" * 32))
    return pk, pk.public_key.to_canonical_address()


@pytest.fixture
def second_account():
    """Second account for testing."""
    pk = keys.PrivateKey(bytes.fromhex("02" * 32))
    return pk, pk.public_key.to_canonical_address()


class TestEIP7702Transaction:
    """Tests for EIP-7702 SetCode transaction type 0x04."""

    def test_setcode_transaction_type(self):
        """Verify SetCode transaction type is 0x04."""
        assert SET_CODE_TRANSACTION_TYPE == 4
        assert hex(SET_CODE_TRANSACTION_TYPE) == "0x4"

    def test_create_authorization(self, funded_account, second_account):
        """Test creating an EIP-7702 authorization."""
        pk, eoa_address = funded_account
        pk2, contract_address = second_account
        
        adapter = EVMAdapter(ChainConfig(chain_id=1337))
        
        # Create authorization
        auth = adapter.create_authorization(
            chain_id=1337,
            address=contract_address,
            nonce=0,
            private_key=pk.to_bytes(),
        )
        
        assert isinstance(auth, Authorization)
        assert auth.chain_id == 1337
        assert auth.address == contract_address
        assert auth.nonce == 0
        assert auth.y_parity in (0, 1)
        assert auth.r > 0
        assert auth.s > 0

    def test_create_authorization_for_all_chains(self, funded_account, second_account):
        """Test creating an authorization for all chains (chain_id=0)."""
        pk, eoa_address = funded_account
        pk2, contract_address = second_account
        
        adapter = EVMAdapter(ChainConfig(chain_id=1337))
        
        # Create authorization for all chains
        auth = adapter.create_authorization(
            chain_id=0,  # Valid on all chains
            address=contract_address,
            nonce=0,
            private_key=pk.to_bytes(),
        )
        
        assert auth.chain_id == 0
        assert auth.address == contract_address

    def test_create_unsigned_setcode_transaction(self, funded_account, second_account):
        """Test creating an unsigned SetCode transaction."""
        pk, sender_address = funded_account
        pk2, recipient_address = second_account
        
        adapter = EVMAdapter(ChainConfig(chain_id=1337))
        
        # Create authorization
        auth = adapter.create_authorization(
            chain_id=1337,
            address=recipient_address,
            nonce=0,
            private_key=pk.to_bytes(),
        )
        
        # Create unsigned SetCode transaction
        unsigned_tx = adapter.create_unsigned_setcode_transaction(
            nonce=0,
            max_priority_fee_per_gas=1_000_000_000,
            max_fee_per_gas=2_000_000_000,
            gas=100_000,
            to=recipient_address,
            value=0,
            data=b"",
            authorization_list=[auth],
            chain_id=1337,
        )
        
        assert unsigned_tx.nonce == 0
        assert unsigned_tx.to == recipient_address
        assert unsigned_tx.value == 0
        assert len(unsigned_tx.authorization_list) == 1
        assert unsigned_tx.authorization_list[0].address == recipient_address

    def test_create_setcode_transaction_with_chain(self, funded_account, second_account, simple_contract_bytecode):
        """Test creating and executing a SetCode transaction through the Chain."""
        pk, sender_address = funded_account
        pk2, contract_address = second_account
        
        genesis_state = {
            sender_address: {
                "balance": to_wei(10, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            },
            contract_address: {
                "balance": 0,
                "nonce": 0,
                "code": simple_contract_bytecode,
                "storage": {},
            },
        }
        
        chain = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
        )
        
        # Create authorization for sender to delegate to contract
        auth = chain.create_authorization(
            chain_id=1337,
            address=contract_address,
            nonce=0,
            private_key=pk.to_bytes(),
        )
        
        # Create SetCode transaction
        signed_tx = chain.create_setcode_transaction(
            from_private_key=pk.to_bytes(),
            to=contract_address,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        # Verify transaction was created
        tx_hash = keccak256(signed_tx.encode())
        assert tx_hash is not None
        
        # Send transaction
        chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        assert block is not None
        assert len(block.transactions) == 1

    def test_setcode_transaction_rpc_serialization(self, funded_account, second_account):
        """Test that SetCode transactions are properly serialized in RPC responses."""
        from sequencer.rpc.methods import create_methods, _serialize_tx, _get_tx_type
        from sequencer.core.crypto import keccak256
        
        pk, sender_address = funded_account
        pk2, recipient_address = second_account
        
        genesis_state = {
            sender_address: {
                "balance": to_wei(10, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            },
        }
        
        chain = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
        )
        
        # Create authorization
        auth = chain.create_authorization(
            chain_id=1337,
            address=recipient_address,
            nonce=0,
            private_key=pk.to_bytes(),
        )
        
        # Create SetCode transaction
        signed_tx = chain.create_setcode_transaction(
            from_private_key=pk.to_bytes(),
            to=recipient_address,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        # Send and mine
        chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        # Verify transaction type
        tx = block.transactions[0]
        tx_type = _get_tx_type(tx)
        assert tx_type == 4, f"Expected tx_type 4, got {tx_type}"
        
        # Verify serialization
        serialized = _serialize_tx(tx, block)
        assert serialized["type"] == "0x4"
        assert "authorizationList" in serialized
        assert len(serialized["authorizationList"]) == 1
        # Address is checksum-encoded, so compare case-insensitively
        assert serialized["authorizationList"][0]["address"].lower() == ("0x" + recipient_address.hex()).lower()
        assert "accessList" in serialized
        assert serialized["maxFeePerGas"] is not None
        assert serialized["maxPriorityFeePerGas"] is not None

    def test_eth_sign_authorization_rpc(self, funded_account, second_account):
        """Test eth_signAuthorization RPC method."""
        from sequencer.rpc.methods import create_methods
        
        pk, sender_address = funded_account
        pk2, contract_address = second_account
        
        genesis_state = {
            sender_address: {
                "balance": to_wei(10, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            },
        }
        
        chain = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
        )
        
        methods = create_methods(chain)
        
        # Create authorization via RPC
        result = methods["eth_signAuthorization"]([{
            "chainId": "0x539",  # 1337
            "address": "0x" + contract_address.hex(),
            "nonce": "0x0",
            "_private_key": "0x" + pk.to_bytes().hex(),
        }])
        
        assert "chainId" in result
        assert result["chainId"] == "0x539"
        assert "address" in result
        assert "nonce" in result
        assert result["nonce"] == "0x0"
        assert "yParity" in result
        assert "r" in result
        assert "s" in result

    def test_eth_send_transaction_with_authorization(self, funded_account, second_account):
        """Test eth_sendTransaction with authorizationList."""
        from sequencer.rpc.methods import create_methods
        
        pk, sender_address = funded_account
        pk2, recipient_address = second_account
        
        genesis_state = {
            sender_address: {
                "balance": to_wei(10, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            },
        }
        
        chain = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
        )
        
        methods = create_methods(chain)
        
        # First create authorization
        auth_result = methods["eth_signAuthorization"]([{
            "chainId": "0x539",  # 1337
            "address": "0x" + recipient_address.hex(),
            "nonce": "0x0",
            "_private_key": "0x" + pk.to_bytes().hex(),
        }])
        
        # Send transaction with authorization list
        tx_hash = methods["eth_sendTransaction"]([{
            "from": "0x" + sender_address.hex(),
            "to": "0x" + recipient_address.hex(),
            "value": "0x0",
            "gas": "0x30d40",  # 200,000
            "maxFeePerGas": "0x77359400",  # 2 Gwei
            "maxPriorityFeePerGas": "0x3b9aca00",  # 1 Gwei
            "nonce": "0x0",
            "authorizationList": [auth_result],
            "_private_key": "0x" + pk.to_bytes().hex(),
        }])
        
        assert tx_hash.startswith("0x")
        assert len(tx_hash) == 66  # 0x + 64 hex chars
        
        # Mine block
        block = chain.build_block()
        assert block is not None
        assert len(block.transactions) == 1
        
        # Verify transaction type
        tx = block.transactions[0]
        from sequencer.rpc.methods import _get_tx_type
        assert _get_tx_type(tx) == 4

    def test_decode_raw_setcode_transaction(self, funded_account, second_account):
        """Test decoding a raw SetCode transaction."""
        from sequencer.rpc.methods import create_methods, _decode_raw_transaction, _get_tx_type
        
        pk, sender_address = funded_account
        pk2, recipient_address = second_account
        
        genesis_state = {
            sender_address: {
                "balance": to_wei(10, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            },
        }
        
        chain = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
        )
        
        # Create authorization
        auth = chain.create_authorization(
            chain_id=1337,
            address=recipient_address,
            nonce=0,
            private_key=pk.to_bytes(),
        )
        
        # Create SetCode transaction
        signed_tx = chain.create_setcode_transaction(
            from_private_key=pk.to_bytes(),
            to=recipient_address,
            value=0,
            data=b"",
            gas=200_000,
            authorization_list=[auth],
        )
        
        # Encode and decode
        raw_tx = signed_tx.encode()
        decoded_tx = _decode_raw_transaction(raw_tx)
        
        # Verify decoded transaction
        assert _get_tx_type(decoded_tx) == 4
        assert decoded_tx.nonce == 0
        assert decoded_tx.to == recipient_address
        assert len(decoded_tx.authorization_list) == 1

    def test_setcode_transaction_in_receipt(self, funded_account, second_account):
        """Test that SetCode transactions show correct type in receipt."""
        from sequencer.rpc.methods import create_methods
        
        pk, sender_address = funded_account
        pk2, recipient_address = second_account
        
        genesis_state = {
            sender_address: {
                "balance": to_wei(10, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            },
        }
        
        chain = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
        )
        
        methods = create_methods(chain)
        
        # Create and send SetCode transaction
        auth_result = methods["eth_signAuthorization"]([{
            "chainId": "0x539",
            "address": "0x" + recipient_address.hex(),
            "nonce": "0x0",
            "_private_key": "0x" + pk.to_bytes().hex(),
        }])
        
        tx_hash = methods["eth_sendTransaction"]([{
            "from": "0x" + sender_address.hex(),
            "to": "0x" + recipient_address.hex(),
            "value": "0x0",
            "gas": "0x30d40",
            "maxFeePerGas": "0x77359400",
            "maxPriorityFeePerGas": "0x3b9aca00",
            "nonce": "0x0",
            "authorizationList": [auth_result],
            "_private_key": "0x" + pk.to_bytes().hex(),
        }])
        
        # Mine block
        chain.build_block()
        
        # Get receipt
        receipt = methods["eth_getTransactionReceipt"]([tx_hash])
        assert receipt is not None
        assert receipt["type"] == "0x4"

    def test_access_list_serialization(self, funded_account, second_account):
        """Test that access lists are properly serialized."""
        from sequencer.rpc.methods import create_methods, _serialize_tx, _get_tx_type
        
        pk, sender_address = funded_account
        pk2, recipient_address = second_account
        
        genesis_state = {
            sender_address: {
                "balance": to_wei(10, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            },
        }
        
        chain = Chain.from_genesis(
            genesis_state,
            chain_id=1337,
            block_time=0,
        )
        
        # Create authorization
        auth = chain.create_authorization(
            chain_id=1337,
            address=recipient_address,
            nonce=0,
            private_key=pk.to_bytes(),
        )
        
        # Create SetCode transaction with access list
        unsigned_tx = chain.evm.create_unsigned_setcode_transaction(
            nonce=0,
            max_priority_fee_per_gas=1_000_000_000,
            max_fee_per_gas=2_000_000_000,
            gas=100_000,
            to=recipient_address,
            value=0,
            data=b"",
            authorization_list=[auth],
            chain_id=1337,
            access_list=[(recipient_address, [0, 1])],
        )
        
        # Sign the transaction
        from eth_keys import keys as eth_keys
        pk_obj = eth_keys.PrivateKey(pk.to_bytes())
        signed_tx = unsigned_tx.as_signed_transaction(pk_obj)
        
        # Send and mine
        chain.send_transaction(signed_tx)
        block = chain.build_block()
        
        # Verify serialization
        tx = block.transactions[0]
        serialized = _serialize_tx(tx, block)
        
        assert serialized["type"] == "0x4"
        assert "accessList" in serialized
        # Access list should be present
        assert isinstance(serialized["accessList"], list)


def keccak256(data: bytes) -> bytes:
    """Helper to compute keccak256 hash."""
    from sequencer.core.crypto import keccak256 as _keccak256
    return _keccak256(data)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])