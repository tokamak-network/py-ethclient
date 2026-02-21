# py-ethclient

Ultra-lightweight Ethereum-compatible single sequencer (L1) in Python.

A port from the Rust `ethrex` Ethereum client, simplified for single sequencer environments.

## Design Philosophy

- **Dumb code**: Start small, extend when needed
- **Use libraries directly**: Import py-evm, ethereum-rlp, trie - no unnecessary wrappers
- **Dict first, SQLite later**: In-memory storage, upgrade only if persistence needed
- **Stdlib over deps**: Use `http.server`, `argparse` before external packages

## Single Sequencer Constraints

| Excluded | Reason |
|----------|--------|
| Engine API | No consensus client |
| Fork Choice | No reorgs, linear chain |
| P2P (DiscV4, RLPx, eth/68) | No external peers |
| Block Sync | No external block sources |
| Tx Broadcasting | Only self-generated transactions |

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

### Start RPC Server

```bash
sequencer --port 8545 --chain-id 1337
```

Options:
- `--port`: RPC server port (default: 8545)
- `--host`: RPC server host (default: 127.0.0.1)
- `--chain-id`: Chain ID (default: 1337)
- `--prefunded-account`: Address to prefund (default: derived from private key)
- `--prefunded-private-key`: Private key for prefunded account (default: `01` * 32)

### Programmatic Usage

```python
from eth_keys import keys
from eth_utils import to_wei
from sequencer.sequencer.chain import Chain

# Create chain with prefunded account
pk = keys.PrivateKey(bytes.fromhex("01" * 32))
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

# Create and send transaction
signed_tx = chain.create_transaction(
    from_private_key=pk.to_bytes(),
    to=bytes.fromhex("deadbeef" * 5),  # recipient
    value=to_wei(1, "ether"),
    data=b"",
    gas=21_000,
)

tx_hash = chain.send_transaction(signed_tx)
block = chain.get_latest_block()

# Query state
balance = chain.get_balance(address)
nonce = chain.get_nonce(address)
code = chain.get_code(address)
storage = chain.get_storage_at(address, 0)
```

### Using SQLite Storage

By default, the sequencer uses in-memory storage. For persistent storage across restarts, use SQLite:

```python
from eth_keys import keys
from eth_utils import to_wei
from sequencer.sequencer.chain import Chain

pk = keys.PrivateKey(bytes.fromhex("01" * 32))
address = pk.public_key.to_canonical_address()

genesis_state = {
    address: {
        "balance": to_wei(100, "ether"),
        "nonce": 0,
        "code": b"",
        "storage": {},
    }
}

# Create chain with SQLite storage
chain = Chain.from_genesis(
    genesis_state,
    chain_id=1337,
    store_type="sqlite",
    store_path="my_chain.db",  # SQLite database file
)

# Data persists across restarts
chain.store.get_latest_number()  # Returns latest block number
```

## Implemented Features

### Core Types (~100 LOC)
| Component | Status | Description |
|-----------|--------|-------------|
| `Account` | ✅ | Nonce, balance, storage_root, code_hash |
| `BlockHeader` | ✅ | Full header with Cancun fields |
| `Block` | ✅ | Header + transactions |
| `Receipt` | ✅ | Status, gas_used, logs |

### Crypto (~28 LOC)
| Function | Status | Description |
|----------|--------|-------------|
| `keccak256` | ✅ | Hash function |
| `sign` | ✅ | Sign message hash |
| `recover_address` | ✅ | Recover address from signature |
| `private_key_to_address` | ✅ | Derive address from private key |

### EVM Adapter (~148 LOC)
| Feature | Status | Description |
|---------|--------|-------------|
| py-evm Integration | ✅ | MiningChain with CancunVM |
| NoProofConsensus | ✅ | No consensus validation |
| Transaction Execution | ✅ | Apply and mine transactions |
| State Queries | ✅ | nonce, balance, code, storage |

### Storage (~500 LOC)
| Feature | Status | Description |
|---------|--------|-------------|
| InMemoryStore | ✅ | dict-based block/receipt storage |
| SQLiteStore | ✅ | Persistent SQLite storage backend |
| Block by Number | ✅ | O(1) lookup |
| Block by Hash | ✅ | O(1) lookup |
| Transaction Receipt | ✅ | tx_hash → (block, index, receipt) |
| Log Filtering | ✅ | Filter by block range, address, topics |

### Sequencer Chain (~270 LOC)
| Feature | Status | Description |
|---------|--------|-------------|
| Genesis Block Creation | ✅ | Initialize with custom state |
| Transaction Creation | ✅ | Legacy transactions |
| EIP-1559 Transaction Creation | ✅ | Dynamic fee transactions (Type 0x02) |
| Transaction Signing | ✅ | ECDSA signing with private key |
| Block Building | ✅ | Auto-mine on transaction |
| Dynamic Base Fee | ✅ | EIP-1559 base fee calculation per block |
| State Root Computation | ✅ | Via py-evm |
| Transactions Root | ✅ | Via trie library |
| Receipts Root | ✅ | Via trie library |
| Block Time | ✅ | Timer-based periodic block building |
| Mempool Integration | ✅ | Priority-based tx pool |

### Mempool (~140 LOC)
| Feature | Status | Description |
|---------|--------|-------------|
| Priority Ordering | ✅ | Sort by max_priority_fee_per_gas |
| Nonce Tracking | ✅ | Per-sender nonce management |
| Gap Handling | ✅ | Queue tx with nonce gaps |
| Tx Replacement | ✅ | Replace with 10% higher fee |
| Size Limit | ✅ | Evict lowest fee when full |
| Nonce Validation | ✅ | Reject nonce < current_nonce |

### RPC Server (~450 LOC total)
| Method | Status | Notes |
|--------|--------|-------|
| `eth_chainId` | ✅ | Returns chain ID |
| `eth_blockNumber` | ✅ | Latest block number |
| `eth_getBalance` | ✅ | Account balance |
| `eth_getTransactionCount` | ✅ | Account nonce |
| `eth_getCode` | ✅ | Contract bytecode |
| `eth_getStorageAt` | ✅ | Storage slot value |
| `eth_getBlockByNumber` | ✅ | Block by number |
| `eth_getBlockByHash` | ✅ | Block by hash |
| `eth_sendTransaction` | ✅ | Sign and send (supports Legacy, EIP-1559, EIP-7702) |
| `eth_sendRawTransaction` | ✅ | Send pre-signed transaction (Type 0x0, 0x1, 0x2, 0x4) |
| `eth_getTransactionByHash` | ✅ | Query transaction by hash |
| `eth_getTransactionReceipt` | ✅ | Transaction receipt with effectiveGasPrice |
| `eth_estimateGas` | ✅ | Full binary search estimation |
| `eth_gasPrice` | ✅ | Returns 1 Gwei |
| `eth_feeHistory` | ✅ | Historical gas fee data with base fee |
| `eth_call` | ✅ | Execute call without state change |
| `eth_getLogs` | ✅ | Filter logs by block range, address, topics |
| `eth_signAuthorization` | ✅ | Sign EIP-7702 authorization |
| `net_version` | ✅ | Chain ID as string |
| `eth_accounts` | ✅ | Returns empty list |
| `eth_coinbase` | ✅ | Returns coinbase address |

### CLI (~55 LOC)
| Feature | Status |
|---------|--------|
| Argument parsing | ✅ |
| Prefunded account setup | ✅ |
| RPC server startup | ✅ |

### Tests (~1,200 LOC)
| Test | Status | Description |
|------|--------|-------------|
| `test_get_balance` | ✅ | Balance query |
| `test_chain_id` | ✅ | Chain ID query |
| `test_get_block_by_number` | ✅ | Block query |
| `test_send_transaction_deploy_contract` | ✅ | Contract deployment |
| `test_eth_call_read_storage` | ✅ | eth_call storage read |
| `test_simple_transfer` | ✅ | ETH transfer |
| **EIP-1559 Tests** | | |
| `test_calc_base_fee_same_as_target` | ✅ | Base fee when gas = target |
| `test_calc_base_fee_above_target` | ✅ | Base fee increases when gas > target |
| `test_calc_base_fee_below_target` | ✅ | Base fee decreases when gas < target |
| `test_create_eip1559_transaction` | ✅ | Create EIP-1559 transaction |
| `test_send_eip1559_transaction` | ✅ | Send EIP-1559 transaction |
| `test_base_fee_changes_after_block` | ✅ | Verify base fee updates per block |
| `test_eth_sendTransaction_eip1559_via_rpc` | ✅ | RPC with EIP-1559 params |
| **Fee History Tests** | | |
| `test_fee_history_genesis_only` | ✅ | feeHistory with genesis block |
| `test_fee_history_after_transactions` | ✅ | feeHistory with multiple blocks |
| `test_fee_history_with_reward_percentiles` | ✅ | feeHistory with percentiles |
| `test_fee_history_base_fee_increases_with_high_gas` | ✅ | Verify base fee increase |
| **Mempool Tests** | | |
| `test_mempool_add_and_get_pending` | ✅ | Add tx and get pending |
| `test_mempool_nonce_ordering` | ✅ | Nonce ordering in pending |
| `test_mempool_tx_replacement` | ✅ | Replace tx with higher fee |
| `test_mempool_reject_low_fee_replacement` | ✅ | Reject underpriced replacement |
| `test_mempool_priority_sorting` | ✅ | Priority-based sorting |
| `test_mempool_size_limit_eviction` | ✅ | Evict lowest fee when full |
| `test_mempool_with_chain_integration` | ✅ | Mempool + chain integration |
| `test_mempool_reject_nonce_too_low` | ✅ | Reject nonce < current |
| `test_mempool_pending_high_nonce` | ✅ | High nonce waits for gap |
| `test_mempool_nonce_gap_filled` | ✅ | Gap filled when missing tx arrives |
| `test_mempool_out_of_order_nonce_same_block` | ✅ | Out-of-order nonces in same block |
| **Block Time Tests** | | |
| `test_block_time_prevents_immediate_mining` | ✅ | No mining before elapsed |
| `test_block_time_allows_mining_after_elapsed` | ✅ | Mining after elapsed |
| `test_send_transaction_respects_block_time` | ✅ | sendTransaction respects block_time |
| **Estimate Gas Tests** | | |
| `test_simple_transfer_no_data` | ✅ | Simple transfer returns 21,000 gas |
| `test_transfer_with_zero_value` | ✅ | Zero value transfer |
| `test_transaction_with_data_no_recipient` | ✅ | Contract creation estimation |
| `test_transaction_with_data_and_recipient` | ✅ | Contract call with calldata |
| `test_transaction_with_large_data` | ✅ | Large calldata estimation |
| `test_contract_creation_with_value` | ✅ | Contract creation with ETH |
| `test_contract_creation_bytecode_sizes` | ✅ | Different bytecode sizes |
| `test_estimate_then_execute_simple_transfer` | ✅ | Estimate then use for execution |
| `test_estimate_gas_after_block_production` | ✅ | Estimate after multiple blocks |
| **Get Transaction Tests** | | |
| `test_returns_none_for_unknown_transaction` | ✅ | Unknown hash returns null |
| `test_returns_legacy_transaction_details` | ✅ | Legacy tx all fields |
| `test_legacy_transaction_has_vrs_signature` | ✅ | v, r, s signature fields |
| `test_legacy_transaction_has_gas_price` | ✅ | gasPrice field for legacy |
| `test_returns_eip1559_transaction_details` | ✅ | EIP-1559 tx all fields |
| `test_eip1559_transaction_has_fee_fields` | ✅ | maxFeePerGas, maxPriorityFeePerGas |
| `test_eip1559_transaction_has_chain_id` | ✅ | chainId field for EIP-1559 |
| `test_transaction_includes_block_hash` | ✅ | blockHash in response |
| `test_transaction_includes_correct_block_number` | ✅ | Correct blockNumber |
| `test_contract_creation_transaction` | ✅ | Contract creation (to=null) |
| `test_can_retrieve_multiple_transactions` | ✅ | Multiple txs by hash |
| `test_transactions_in_same_block` | ✅ | Multiple txs same block |
| **Ethereum Compatibility Tests** | | |
| `test_crypto_compatibility` | ✅ | keccak256, ECDSA, address derivation |
| `test_rlp_compatibility` | ✅ | RLP encoding/decoding for Account, Receipt |
| `test_block_compatibility` | ✅ | Block structure, hash calculation |
| `test_rpc_compatibility` | ✅ | RPC response format (eth_* methods) |
| `test_transaction_compatibility` | ✅ | Legacy (0x0) and EIP-1559 (0x2) tx types |
| `test_state_compatibility` | ✅ | State queries, EVM execution |
| **Contract Storage Tests** | | |
| `test_deploy_simple_storage_contract` | ✅ | Contract deployment |
| `test_deploy_multiple_contracts` | ✅ | Sequential contract deployments |
| `test_call_view_method_initial_value` | ✅ | eth_call reads storage |
| `test_call_view_method_via_rpc` | ✅ | eth_call RPC method |
| `test_set_and_get_value` | ✅ | Write and read storage |
| `test_set_multiple_values` | ✅ | Multiple storage updates |
| `test_increment_counter` | ✅ | Counter increment |
| `test_decrement_counter` | ✅ | Counter decrement |
| `test_get_storage_at_slot_zero` | ✅ | eth_getStorageAt |
| `test_get_code_returns_runtime_bytecode` | ✅ | eth_getCode returns runtime code |
| `test_independent_storage` | ✅ | Multiple contracts, independent storage |
| **Get Logs Tests** | | |
| `test_get_logs_empty` | ✅ | getLogs returns empty when no events |
| `test_get_logs_by_address` | ✅ | Filter logs by contract address |
| `test_get_logs_by_topic` | ✅ | Filter logs by event topic |
| `test_get_logs_by_block_range` | ✅ | Filter logs by block range |
| `test_get_logs_no_match` | ✅ | No logs for non-existent topic |
| `test_get_logs_log_entry_format` | ✅ | Log entry has correct fields |
| `test_store_get_logs_basic` | ✅ | Basic log storage retrieval |
| `test_store_get_logs_multiple_blocks` | ✅ | Logs across multiple blocks |
| `test_store_get_logs_by_address_filter` | ✅ | Address filter in store |
| `test_store_get_logs_by_topic_filter` | ✅ | Topic filter in store |
| **SQLite Storage Tests** | | |
| `test_sqlite_store_init` | ✅ | SQLite store initialization |
| `test_save_and_get_block` | ✅ | Save and retrieve blocks |
| `test_get_block_by_hash` | ✅ | Get block by hash |
| `test_save_and_get_receipts` | ✅ | Save and retrieve receipts |
| `test_receipts_with_logs` | ✅ | Receipt storage with event logs |
| `test_get_latest_block` | ✅ | Latest block query |
| `test_get_transaction_receipt` | ✅ | Transaction receipt by hash |
| `test_get_logs` | ✅ | Log retrieval from SQLite |
| `test_get_logs_by_address` | ✅ | Log filter by address |
| `test_get_logs_by_topic` | ✅ | Log filter by topic |
| `test_chain_with_sqlite_backend` | ✅ | Chain with SQLite backend |
| `test_sqlite_persistence_across_restarts` | ✅ | Data persists across restarts |
| **Persistence Integration Tests** | | |
| `test_block_persistence_across_restarts` | ✅ | Blocks persist in SQLite |
| `test_receipt_persistence_across_restarts` | ✅ | Transaction receipts persist |
| `test_contract_deployment_receipt_persistence` | ✅ | Contract address in receipts persist |
| `test_can_continue_adding_blocks_after_restart` | ✅ | New blocks after restart |
| `test_block_chain_continuity_after_restart` | ✅ | Chain continuity verified |
| `test_multiple_deployments_persistence` | ✅ | Multiple contract deployments persist |
| `test_block_hash_consistency_after_restart` | ✅ | Block hashes remain consistent |
| `test_gas_used_persistence` | ✅ | Gas usage persisted in blocks |
| **EVM State Persistence Tests** | | |
| `test_contract_code_persistence` | ✅ | Contract code persists after restart |
| `test_contract_storage_persistence` | ✅ | Contract storage persists after restart |
| `test_account_balance_persistence` | ✅ | Account balances persist after restart |
| `test_account_nonce_persistence` | ✅ | Account nonces persist after restart |
| `test_full_state_recovery` | ✅ | Complete state recovery after restart |
| **EIP-7702 Tests** | | |
| `test_setcode_transaction_type` | ✅ | Type 0x04 constant |
| `test_create_authorization` | ✅ | Create EIP-7702 authorization |
| `test_create_authorization_for_all_chains` | ✅ | Authorization with chain_id=0 |
| `test_create_unsigned_setcode_transaction` | ✅ | Unsigned SetCode transaction |
| `test_create_setcode_transaction_with_chain` | ✅ | Create signed SetCode via Chain |
| `test_setcode_transaction_rpc_serialization` | ✅ | RPC format for Type 0x04 |
| `test_eth_sign_authorization_rpc` | ✅ | eth_signAuthorization RPC |
| `test_eth_send_transaction_with_authorization` | ✅ | Send with authorizationList |
| `test_decode_raw_setcode_transaction` | ✅ | Decode raw Type 0x04 tx |
| `test_setcode_transaction_in_receipt` | ✅ | Receipt type is 0x4 |
| `test_access_list_serialization` | ✅ | Access list in SetCode tx |

## Current Limitations

### ~~EVM State Persistence~~ ✅ RESOLVED

EVM state is now fully persisted in SQLite:

- ✅ Contract code
- ✅ Contract storage
- ✅ Account balances
- ✅ Account nonces
- ✅ Block headers and transactions
- ✅ Transaction receipts
- ✅ Event logs

When restarting a node with SQLite storage, all state is automatically restored from the database.

## Development Roadmap

> **Note**: `py-evm` was archived on September 8, 2025. It supports up to Prague but will not receive Osaka updates.

### ✅ Phase 1: Essential for Public Network (COMPLETED)

Required for operating a public network with standard wallet compatibility (MetaMask, etc.).

| # | Feature | Status | Description |
|---|---------|--------|-------------|
| 1 | EIP-1559 Base Fee | ✅ Done | Dynamic calculation per EIP-1559 formula |
| 2 | EIP-1559 Tx Type 0x02 | ✅ Done | `maxFeePerGas` / `maxPriorityFeePerGas` support |
| 3 | `eth_feeHistory` | ✅ Done | Historical gas fee data endpoint |

**Implemented EIP-1559 Features:**
- `calc_base_fee()` function in `chain.py`
- `create_eip1559_transaction()` method
- Dynamic base fee per block
- `eth_sendTransaction` handles both Legacy and EIP-1559
- Transaction serialization with `type: "0x2"`
- Receipt includes `effectiveGasPrice`

**Periodic Block Building Pattern:**
```python
import asyncio

class Sequencer:
    def __init__(self, block_time=2.0, max_txs=100):
        self.tx_pool = asyncio.Queue()
        self.block_time = block_time
        self.max_txs = max_txs

    async def run(self):
        while True:
            first_tx = await self.tx_pool.get()
            batch = [first_tx]
            start_time = time.monotonic()
            
            while len(batch) < self.max_txs:
                remaining = self.block_time - (time.monotonic() - start_time)
                if remaining <= 0:
                    break
                try:
                    tx = await asyncio.wait_for(self.tx_pool.get(), timeout=remaining)
                    batch.append(tx)
                except asyncio.TimeoutError:
                    break
            
            await self.produce_block(batch)
```

### ✅ Phase 2: Improved Operations (COMPLETED)

| # | Feature | Status | Description |
|---|---------|--------|-------------|
| 1 | Transaction Pool (Mempool) | ✅ Done | Priority-based with nonce tracking, replacement, eviction |
| 2 | Periodic Block Production | ✅ Done | Timer-based block building with `block_time` parameter |
| 3 | `estimateGas` | ✅ Done | Binary search estimation with actual transaction execution |
| 4 | Ethereum Compatibility Tests | ✅ Done | Comprehensive compatibility test suite |

**Implemented Mempool Features:**
- Priority-based transaction ordering (by max_priority_fee_per_gas)
- Nonce tracking per sender with gap handling
- Transaction replacement (requires 10% fee increase)
- Size limit with lowest-fee eviction
- Out-of-order nonce queueing (tx with nonce gap waits until gap filled)

**Block Time Features:**
- `block_time` parameter in `Chain.from_genesis()`
- `should_build_block()` checks if enough time elapsed
- Prevents immediate mining on `send_transaction()`

**Ethereum Compatibility Tests (152 tests):**
- **Crypto**: keccak256 hash verification, ECDSA sign/recover, address derivation
- **RLP**: Account, BlockHeader, Receipt, Transaction encoding/decoding
- **Block**: Structure validation, hash calculation, state root, transactions root
- **RPC**: All eth_* methods response format compliance
- **Transaction**: Legacy (0x0) and EIP-1559 (0x2) type support
- **State**: Balance, nonce, code, storage queries; EVM execution

### Phase 3: Improved Compatibility (~50 LOC)

| # | Feature | Description | Status |
|---|---------|-------------|--------|
| 4 | `eth_call` full implementation | Execute call without state change | ✅ Done |
| 5 | `eth_getTransactionByHash` | Query transaction by hash | ✅ Done |
| 6 | `eth_getLogs` | Event log filtering | ✅ Done |
| 7 | SQLite Persistence | Replace dict storage for data durability | ✅ Done |

### Phase 4: Prague Compatibility (EIP-7702)

| # | Feature | Description | Status |
|---|---------|-------------|--------|
| 8 | Transaction Type 0x04 | EIP-7702 SetCode Transaction | ✅ Done |
| 9 | `eth_signAuthorization` | Sign EIP-7702 authorization | ✅ Done |
| 10 | EOA Code Delegation | Allow EOAs to act as contracts | ✅ Done |

### Phase 5: Future Compatibility

#### Transaction Types (EIP-2718)

| Type | EIP | Name | Current Support | Required |
|------|-----|------|-----------------|----------|
| `0x00` | Legacy | Legacy Transaction | ✅ Yes | - |
| `0x01` | EIP-2930 | Access List | ❌ No | Recommended |
| `0x02` | EIP-1559 | Dynamic Fee | ✅ Yes | - |
| `0x04` | EIP-7702 | Set Code (Prague) | ✅ Yes | - |

> **Note**: Blob transactions (EIP-4844, Type `0x03`) are not required for single sequencer use cases.

#### Prague EIPs (Pectra - May 2025)

| EIP | Description | Status |
|-----|-------------|--------|
| EIP-7702 | EOA Code Delegation (Tx Type 0x04) | ✅ Done |
| EIP-7623 | Increased Calldata Cost | ❌ TODO |
| EIP-2537 | BLS12-381 Precompiles | ❌ TODO |
| EIP-2935 | Block Hash History | ❌ TODO |

#### Osaka EIPs (Fusaka - 2026)

> **Note**: These must be implemented manually since `py-evm` is archived.

| EIP | Description | Status |
|-----|-------------|--------|
| EIP-7951 | secp256r1 Precompile | ❌ TODO |
| EIP-7939 | CLZ Opcode | ❌ TODO |
| EIP-7825 | Transaction Gas Limit Cap | ❌ TODO |
| EIP-7883 | ModExp Gas Cost Increase | ❌ TODO |

### Execution Timeline

```
✅ COMPLETED:
├── [x] EIP-1559 base fee calculation (chain.py)
├── [x] EIP-1559 tx type 0x02 support (methods.py, chain.py, adapter.py)
├── [x] eth_feeHistory RPC endpoint (rpc/methods.py)
├── [x] Mempool with priority queue and nonce tracking (sequencer/mempool.py)
├── [x] Block time support for periodic block building (chain.py)
├── [x] Unit tests for EIP-1559, Mempool, Block Time (tests/test_sequencer.py)
├── [x] Ethereum compatibility test suite (tests/test_*_compatibility.py)
├── [x] gas_used cumulative tracking fix (chain.py)
├── [x] Transaction type detection improvement (methods.py)
├── [x] y_parity support for EIP-1559 transactions (methods.py)
└── [x] eth_estimateGas with binary search (chain.py, methods.py)

Phase 3 - Compatibility:
├── [x] eth_call actual execution
├── [x] eth_getTransactionByHash
├── [x] contract_address in receipt for contract creation
├── [x] eth_getLogs (filtering by block range, address, topics)
└── [x] SQLite persistence (blocks, receipts, EVM state)

Phase 4 - Prague (EIP-7702):
├── [x] Transaction Type 0x04 (SetCodeTransaction)
├── [x] eth_signAuthorization RPC method
├── [x] Authorization creation and signing
├── [x] eth_sendTransaction with authorizationList support
├── [x] Transaction serialization for Type 0x04
└── [x] Receipt serialization for Type 0x04

Phase 5 - Future:
├── [x] CREATE2 Support (EIP-1014) - Address computation, tracking, persistence
├── [x] EIP-2930 (Access List transactions, Type 0x01)
├── [ ] EIP-2537 (BLS12-381 Precompiles)
└── [ ] EIP-2935 (Block Hash History)
```

### Projected LOC

| Phase | Components | LOC |
|-------|------------|-----|
| Current | All (with estimateGas + getTransactionByHash + SQLite + EVM State + EIP-7702 + Tests) | ~6,200 |
| Phase 5 | Future EIPs | +~100 |
| **Total** | | **~6,300** |

## Architecture

```
py-ethclient/
├── src/sequencer/
│   ├── core/                    # Minimal types & crypto
│   │   ├── types.py             # Account, Block, Receipt (~100 LOC)
│   │   ├── crypto.py            # keccak256, sign, recover (~28 LOC)
│   │   ├── constants.py         # Chain constants (~16 LOC)
│   │   └── create2.py           # CREATE2 address computation (~120 LOC)
│   │
│   ├── evm/                     # py-evm bridge
│   │   └── adapter.py           # MiningChain wrapper (~165 LOC)
│   │
│   ├── storage/                 # In-memory storage
│   │   ├── store.py             # dict-based store (~53 LOC)
│   │   └── sqlite_store.py      # SQLite persistence (~700 LOC)
│   │
│   ├── sequencer/               # Sequencer logic
│   │   ├── chain.py             # Block building (~450 LOC)
│   │   └── mempool.py           # Tx pool with priority (~140 LOC)
│   │
│   ├── rpc/                     # JSON-RPC
│   │   ├── server.py            # http.server (~85 LOC)
│   │   └── methods.py           # eth_* methods (~420 LOC)
│   │
│   └── cli.py                   # Entry point (~55 LOC)
│
└── tests/
    ├── conftest.py              # Shared pytest fixtures
    │
    ├── fixtures/                # Test fixtures & utilities
    │   ├── addresses.py         # Named test addresses (Alice, Bob, Charlie)
    │   ├── contracts.py         # Contract bytecodes for testing
    │   └── keys.py              # Private keys and signing utilities
    │
    ├── unit/                    # Unit tests
    │   ├── test_crypto.py       # Crypto operations
    │   ├── test_types.py        # Core type tests
    │   ├── test_builder.py      # Block builder tests
    │   └── test_executor.py     # Execution layer tests
    │
    ├── integration/             # Integration tests
    │   ├── test_transfer_flow.py     # ETH transfer flows
    │   ├── test_contract_flow.py     # Contract deployment & interaction
    │   └── test_eip7702_flow.py      # EIP-7702 end-to-end tests
    │
    ├── spec/                    # Specification tests
    │   ├── test_blockchain.py   # Blockchain spec compliance
    │   ├── test_eips.py         # EIP spec tests
    │   └── test_transactions.py # Transaction spec tests
    │
    ├── test_sequencer.py        # Integration tests (~650 LOC)
    ├── test_eip1559.py          # EIP-1559 tests (~110 LOC)
    ├── test_eip7702.py          # EIP-7702 SetCode tests
    ├── test_create2.py          # CREATE2 (EIP-1014) tests
    ├── test_mempool.py          # Mempool tests (~280 LOC)
    ├── test_block_time.py       # Block time tests (~65 LOC)
    ├── test_fee_history.py      # Fee history tests (~120 LOC)
    ├── test_estimate_gas.py     # Gas estimation tests (~200 LOC)
    ├── test_get_transaction.py  # Transaction lookup tests (~400 LOC)
    ├── test_get_logs.py         # Event log filtering tests
    ├── test_contract_storage.py # Contract storage tests (~750 LOC)
    ├── test_integration.py      # Integration tests (~55 LOC)
    ├── test_rpc.py              # RPC method tests
    ├── test_sqlite_store.py     # SQLite storage tests
    ├── test_persistence_integration.py  # Persistence tests
    ├── test_crypto_compatibility.py    # Crypto compatibility (~75 LOC)
    ├── test_rlp_compatibility.py       # RLP compatibility (~65 LOC)
    ├── test_block_compatibility.py     # Block compatibility (~120 LOC)
    ├── test_rpc_compatibility.py       # RPC compatibility (~200 LOC)
    ├── test_transaction_compatibility.py # Transaction compatibility (~120 LOC)
    └── test_state_compatibility.py     # State compatibility (~200 LOC)

contracts/
├── SimpleStorage.sol           # Simple storage contract example
└── Counter.sol                 # Counter contract example

scripts/
├── deploy_contract.py          # Compile & deploy contracts (~350 LOC)
└── interact_contract.py        # Interact with contracts (~200 LOC)
```

**Total: ~1,800 LOC (src) + ~3,600 LOC (tests) + ~550 LOC (scripts) = ~5,950 LOC**

## Test Structure

The test suite is organized into four categories:

- **`fixtures/`**: Shared test fixtures including:
  - Named test addresses (Alice, Bob, Charlie) with pre-computed keys
  - Standard contract bytecodes for testing
  - Key derivation and signing utilities

- **`unit/`**: Unit tests for individual components:
  - `test_crypto.py` - Core cryptographic operations
  - `test_types.py` - Type encoding/decoding
  - `test_builder.py` - Block builder logic
  - `test_executor.py` - EVM execution

- **`integration/`**: End-to-end integration tests:
  - `test_transfer_flow.py` - ETH transfer scenarios
  - `test_contract_flow.py` - Contract deployment & interaction
  - `test_eip7702_flow.py` - EIP-7702 SetCode transactions

- **`spec/`**: Ethereum specification compliance tests:
  - `test_blockchain.py` - Blockchain spec validation
  - `test_eips.py` - EIP-specific tests
  - `test_transactions.py` - Transaction type tests

## Dependencies

| Package | Purpose | Usage |
|---------|---------|-------|
| `py-evm` | EVM execution | Direct use via MiningChain |
| `rlp` | RLP encoding | Transaction encoding |
| `trie` | Merkle Patricia Trie | Root hash computation |
| `eth-keys` | ECDSA | Signing and recovery |
| `pycryptodome` | Keccak256 | Hash function |
| `eth-utils` | Utilities | Address conversion, wei |

## Development

```bash
# Run tests
pytest tests/ -v

# Type check
mypy src/

# Lint
ruff check src/

# Format
ruff format src/
```

## Contract Deployment

py-ethclient provides scripts for compiling and deploying Solidity contracts.

### Deploy Script

```bash
# Compile and deploy a contract
python scripts/deploy_contract.py contracts/SimpleStorage.sol --name SimpleStorage

# Deploy with constructor arguments
python scripts/deploy_contract.py contracts/MyToken.sol --name MyToken --constructor-args "MyToken,MTK,1000000"

# Deploy and call a view function
python scripts/deploy_contract.py contracts/Counter.sol --name Counter --call getCount

# Deploy and call a write function
python scripts/deploy_contract.py contracts/SimpleStorage.sol --name SimpleStorage --send setValue --send-args 42

# Save deployment info
python scripts/deploy_contract.py contracts/Counter.sol --name Counter --output deployments/counter.json
```

### Interact Script

Interact with an already deployed contract:

```bash
# Call a view function
python scripts/interact_contract.py deployments/counter.json --call getCount

# Call multiple view functions
python scripts/interact_contract.py deployments/counter.json --call getCount --call getOwner

# Call a state-changing function
python scripts/interact_contract.py deployments/counter.json --send increment

# Call with arguments
python scripts/interact_contract.py deployments/counter.json --send setCount --args 100

# Chain multiple calls
python scripts/interact_contract.py deployments/counter.json --send increment --send increment --call getCount
```

### Example Contracts

Sample contracts are provided in `contracts/`:

- **SimpleStorage.sol**: Basic storage with getter/setter
- **Counter.sol**: Simple counter with increment/decrement

## Known Limitations

This is a **beta-quality single sequencer implementation** with the following known limitations:

### Storage Slot Discovery (Heuristic-Based)

The EVM state persistence uses a heuristic to discover storage slots by checking slots 0-99 and any previously stored slots. **Contracts using storage slots >= 100 for the first time may lose state on restart.**

- **Impact**: Contract storage in high slots (>99) not persisted
- **Workaround**: Keep storage slots below 100 (most simple contracts do)
- **Proper Fix**: Hook into EVM's state journal (requires py-evm integration)
- **Tracking**: See GitHub issue #XXX

### py-evm Dependency (Archived)

This project uses `py-evm`, which is no longer actively maintained by the Ethereum Foundation.

- **Impact**: No new EVM features, potential unpatched bugs
- **Monitoring**: We monitor for security issues
- **Migration Plan**: Evaluating `revm` (Rust EVM via pyo3) as alternative

### Block Producer Error Recovery

The block producer thread includes error handling with configurable error threshold (default: 10 consecutive errors). It uses exponential backoff between retry attempts. After max errors, the thread stops gracefully.

- **Impact**: Node may stop producing blocks after persistent errors
- **Workaround**: Restart node manually
- **Configuration**: `max_errors` parameter in `_block_producer(chain, max_errors=10)`
- **Tracking**: See GitHub issue #XXX

## Production Readiness

| Component | Status | Notes |
|-----------|--------|-------|
| Thread Safety | ✅ Production Ready | RLock-protected |
| Transaction Persistence | ✅ Production Ready | Full RLP storage |
| SQL Atomicity | ✅ Production Ready | BEGIN/COMMIT/ROLLBACK |
| State Recovery | ✅ Beta | Storage slot heuristic |
| Gas Limit Enforcement | ✅ Production Ready | Enforced per block |
| Block Producer Recovery | ⚠️ Beta | Manual restart needed |
| CREATE2 Support | ✅ Production Ready | Full EIP-1014 support |

**Recommended Use Cases:**
- ✅ Development and testing environments
- ✅ Private testnets
- ✅ Prototyping and experimentation
- ⚠️ Production (with awareness of limitations)

## License

MIT
