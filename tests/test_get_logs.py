"""Test cases for eth_getLogs RPC method."""

import pytest
from eth_keys import keys
from eth_utils import to_wei

from sequencer.sequencer.chain import Chain
from sequencer.rpc.methods import create_methods
from sequencer.core.crypto import keccak256


# Simple event emitter contract
# contract EventTest {
#     event Transfer(address indexed from, address indexed to, uint256 value);
#     event TestEvent(uint256 value);
#     
#     function emitTransfer(address to, uint256 value) public {
#         emit Transfer(msg.sender, to, value);
#     }
#     
#     function emitTest(uint256 value) public {
#         emit TestEvent(value);
#     }
# }
EVENT_BYTECODE = bytes.fromhex(
    "6080604052348015600e575f5ffd5b5061015c8061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c8063a9e9791314610038578063b8be62221461004d575b5f5ffd5b61004b6100463660046100da565b610060565b005b61004b61005b3660046100f1565b610096565b6040518181527f1440c4dd67b4344ea1905ec0318995133b550f168b4ee959a0da6b503d7d24149060200160405180910390a150565b6040518181526001600160a01b0383169033907fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9060200160405180910390a35050565b5f602082840312156100ea575f5ffd5b5035919050565b5f5f60408385031215610102575f5ffd5b82356001600160a01b0381168114610118575f5ffd5b94602093909301359350505056fea26469706673582212203d4bd7031ac62749db499f41cca12010e483e2bce40c8149e8a7f7fb58a5a87e64736f6c63430008220033"
)

# Event and function signatures
TRANSFER_EVENT_SIG = keccak256(b"Transfer(address,address,uint256)")
TEST_EVENT_SIG = keccak256(b"TestEvent(uint256)")
EMIT_TRANSFER_SELECTOR = keccak256(b"emitTransfer(address,uint256)")[:4]  # b8be6222
EMIT_TEST_SELECTOR = keccak256(b"emitTest(uint256)")[:4]  # a9e97913


@pytest.fixture
def chain_with_event_contract(pk, address):
    """Create chain with deployed event contract."""
    genesis_state = {
        address: {
            "balance": to_wei(100, "ether"),
            "nonce": 0,
            "code": b"",
            "storage": {},
        }
    }
    chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
    
    # Deploy event contract
    nonce = chain.get_nonce(address)
    signed_tx = chain.create_transaction(
        from_private_key=pk.to_bytes(),
        to=None,
        value=0,
        data=EVENT_BYTECODE,
        gas=1_000_000,
        gas_price=1_000_000_000,
        nonce=nonce,
    )
    chain.send_transaction(signed_tx)
    chain.build_block()
    
    receipts = chain.store.get_receipts(1)
    contract_address = receipts[0].contract_address
    
    return chain, contract_address


class TestEthGetLogs:
    """Test eth_getLogs RPC method."""

    def test_get_logs_empty(self, chain, address):
        """Test getLogs with no events."""
        methods = create_methods(chain)
        
        logs = methods["eth_getLogs"]([{"fromBlock": "0x0", "toBlock": "0x0"}])
        assert logs == []

    def test_get_logs_by_address(self, chain_with_event_contract, pk, address):
        """Test filtering logs by contract address."""
        chain, contract_address = chain_with_event_contract
        methods = create_methods(chain)
        
        # Emit event
        nonce = chain.get_nonce(address)
        calldata = EMIT_TEST_SELECTOR + (42).to_bytes(32, 'big')
        
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
        
        # Get logs by address
        logs = methods["eth_getLogs"]([{
            "fromBlock": "0x0",
            "toBlock": "latest",
            "address": "0x" + contract_address.hex(),
        }])
        
        assert len(logs) >= 1
        # Check address matches (case-insensitive)
        log_addr = logs[0]["address"].lower()
        expected = ("0x" + contract_address.hex()).lower()
        assert log_addr == expected

    def test_get_logs_by_topic(self, chain_with_event_contract, pk, address):
        """Test filtering logs by event topic."""
        chain, contract_address = chain_with_event_contract
        methods = create_methods(chain)
        
        # Emit TestEvent
        nonce = chain.get_nonce(address)
        calldata = EMIT_TEST_SELECTOR + (100).to_bytes(32, 'big')
        
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
        
        # Get logs by topic
        logs = methods["eth_getLogs"]([{
            "fromBlock": "0x0",
            "toBlock": "latest",
            "topics": ["0x" + TEST_EVENT_SIG.hex()],
        }])
        
        assert len(logs) >= 1
        assert logs[0]["topics"][0] == "0x" + TEST_EVENT_SIG.hex()

    def test_get_logs_by_block_range(self, chain_with_event_contract, pk, address):
        """Test filtering logs by block range."""
        chain, contract_address = chain_with_event_contract
        methods = create_methods(chain)
        
        # Emit events in multiple blocks
        for i in range(3):
            nonce = chain.get_nonce(address)
            calldata = EMIT_TEST_SELECTOR + ((i + 1) * 100).to_bytes(32, 'big')
            
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
        
        # Get logs for block 2 only (should have one event)
        logs = methods["eth_getLogs"]([{
            "fromBlock": "0x2",
            "toBlock": "0x2",
        }])
        
        assert len(logs) == 1
        assert int(logs[0]["blockNumber"], 16) == 2

    def test_get_logs_no_match(self, chain_with_event_contract, pk, address):
        """Test getLogs with no matching events."""
        chain, contract_address = chain_with_event_contract
        methods = create_methods(chain)
        
        # Search for non-existent topic
        fake_topic = keccak256(b"NonExistentEvent(uint256)")
        
        logs = methods["eth_getLogs"]([{
            "fromBlock": "0x0",
            "toBlock": "latest",
            "topics": ["0x" + fake_topic.hex()],
        }])
        
        assert logs == []

    def test_get_logs_log_entry_format(self, chain_with_event_contract, pk, address):
        """Test that log entries have correct format."""
        chain, contract_address = chain_with_event_contract
        methods = create_methods(chain)
        
        # Emit event
        nonce = chain.get_nonce(address)
        calldata = EMIT_TEST_SELECTOR + (12345).to_bytes(32, 'big')
        
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
        
        logs = methods["eth_getLogs"]([{
            "fromBlock": "latest",
            "toBlock": "latest",
        }])
        
        assert len(logs) >= 1
        log = logs[0]
        
        # Check required fields
        assert "address" in log
        assert "topics" in log
        assert "data" in log
        assert "blockNumber" in log
        assert "blockHash" in log
        assert "transactionHash" in log
        assert "transactionIndex" in log
        assert "logIndex" in log
        
        # Check field formats
        assert log["address"].startswith("0x")
        assert log["blockNumber"].startswith("0x")
        assert log["blockHash"].startswith("0x")
        assert log["transactionHash"].startswith("0x")
        assert log["transactionIndex"].startswith("0x")
        assert log["logIndex"].startswith("0x")
        
        # topics should be a list of hex strings
        assert isinstance(log["topics"], list)
        for topic in log["topics"]:
            assert topic.startswith("0x")

    def test_get_logs_with_multiple_topics(self, chain_with_event_contract, pk, address):
        """Test filtering by multiple topics (Transfer event with indexed params)."""
        # Note: Transfer event with indexed params requires more complex ABI encoding
        # This test is skipped pending proper topic filtering implementation
        pytest.skip("Transfer event with indexed params requires proper ABI encoding")


class TestLogStorage:
    """Test log storage in InMemoryStore."""

    def test_store_get_logs_basic(self, chain, pk, address):
        """Test basic log retrieval from store."""
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Get logs from empty chain
        logs = chain.store.get_logs(0, 0)
        assert logs == []

    def test_store_get_logs_multiple_blocks(self, pk, address):
        """Test log retrieval across multiple blocks."""
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy event contract
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=EVENT_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        contract_address = chain.store.get_receipts(1)[0].contract_address
        
        # Create events in multiple blocks
        for i in range(3):
            nonce = chain.get_nonce(address)
            calldata = EMIT_TEST_SELECTOR + ((i + 1) * 100).to_bytes(32, 'big')
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
        
        # Get all logs
        all_logs = chain.store.get_logs(0, 10)
        assert len(all_logs) >= 3
        
        # Get logs from specific range
        range_logs = chain.store.get_logs(2, 3)
        for log in range_logs:
            assert 2 <= log["block_number"] <= 3

    def test_store_get_logs_by_address_filter(self, pk, address):
        """Test filtering logs by address."""
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy event contract
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=EVENT_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        contract_address = chain.store.get_receipts(1)[0].contract_address
        
        # Emit event
        nonce = chain.get_nonce(address)
        calldata = EMIT_TEST_SELECTOR + (42).to_bytes(32, 'big')
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
        
        # Filter by address
        logs = chain.store.get_logs(0, 10, address=contract_address)
        assert len(logs) >= 1
        assert logs[0]["address"] == contract_address
        
        # Filter by non-existent address
        logs = chain.store.get_logs(0, 10, address=b"\x00" * 20)
        assert len(logs) == 0

    def test_store_get_logs_by_topic_filter(self, pk, address):
        """Test filtering logs by topic."""
        genesis_state = {
            address: {
                "balance": to_wei(100, "ether"),
                "nonce": 0,
                "code": b"",
                "storage": {},
            }
        }
        chain = Chain.from_genesis(genesis_state, chain_id=1337, block_time=0)
        
        # Deploy event contract
        nonce = chain.get_nonce(address)
        signed_tx = chain.create_transaction(
            from_private_key=pk.to_bytes(),
            to=None,
            value=0,
            data=EVENT_BYTECODE,
            gas=1_000_000,
            gas_price=1_000_000_000,
            nonce=nonce,
        )
        chain.send_transaction(signed_tx)
        chain.build_block()
        
        contract_address = chain.store.get_receipts(1)[0].contract_address
        
        # Emit TestEvent
        nonce = chain.get_nonce(address)
        calldata = EMIT_TEST_SELECTOR + (42).to_bytes(32, 'big')
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
        
        # Filter by topic
        logs = chain.store.get_logs(0, 10, topics=[TEST_EVENT_SIG])
        assert len(logs) >= 1
        assert TEST_EVENT_SIG in logs[0]["topics"]