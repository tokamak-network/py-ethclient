# Comparison: py-ethclient vs Ethrex Storage

## Executive Summary

py-ethclient has implemented a complete single-sequencer storage solution with EVM state persistence. Compared to Ethrex, the implementation is simpler but covers all essential functionality for single-sequencer operation.

## Storage Architecture Comparison

### py-ethclient SQLite Tables (6 tables)

| Table | Key | Value | Purpose |
|-------|-----|-------|---------|
| `blocks` | number | header + tx_hashes | Block storage |
| `transactions` | tx_hash | (block_number, tx_index) | Tx → Block mapping |
| `receipts` | (block_number, tx_index) | receipt | Transaction receipts |
| `accounts` | address | (nonce, balance, code_hash, storage_root) | EVM state |
| `contract_code` | code_hash | bytecode | Contract bytecode |
| `contract_storage` | (address, slot) | value | Contract storage |

### Ethrex Storage Tables (18 tables)

| Table | Key | Value | Purpose | Needed? |
|-------|-----|-------|---------|---------|
| `HEADERS` | block_hash | header | Block headers | ✅ Via blocks table |
| `BODIES` | block_hash | body | Block bodies | ✅ Via blocks table |
| `BLOCK_NUMBERS` | block_hash | number | Hash → Number | ✅ Via transactions |
| `CANONICAL_BLOCK_HASHES` | number | hash | Number → Hash | ⚠️ Optimization |
| `TRANSACTION_LOCATIONS` | (tx_hash, block_hash) | location | Tx locations | ✅ Via transactions |
| `RECEIPTS` | (block_hash, index) | receipt | Receipts | ✅ Via receipts |
| `ACCOUNT_CODES` | code_hash | bytecode | Contract code | ✅ contract_code |
| `ACCOUNT_CODE_METADATA` | code_hash | length | Code length | ❌ Optimization |
| `ACCOUNT_TRIE_NODES` | path | node | State trie | ❌ No trie |
| `STORAGE_TRIE_NODES` | (address, path) | node | Storage trie | ❌ No trie |
| `ACCOUNT_FLATKEYVALUE` | hashed_address | account | Flat state | ✅ accounts |
| `STORAGE_FLATKEYVALUE` | (hashed_address, slot) | value | Flat storage | ✅ contract_storage |
| `CHAIN_DATA` | key | value | Chain config | ⚠️ Not persisted |
| `PENDING_BLOCKS` | hash | block | Pending blocks | ❌ Single sequencer |
| `INVALID_CHAINS` | bad_hash | valid_hash | Bad block tracking | ❌ No reorgs |
| `SNAP_STATE` | key | value | Snap sync state | ❌ No snap sync |
| `FULLSYNC_HEADERS` | number | header | Sync headers | ❌ No sync |
| `EXECUTION_WITNESSES` | key | witness | Execution witness | ❌ For L2 |

## Key Design Differences

### 1. State Storage Model

**Ethrex (Ethereum Standard):**
```
State = Merkle Patricia Trie
├── Account Trie (world state)
│   └── hashed_address → AccountState {nonce, balance, storage_root, code_hash}
└── Storage Tries (per account)
    └── slot → value
```

**py-ethclient (Simplified):**
```
State = Flat Key-Value Store
├── accounts table: address → {nonce, balance, code_hash, storage_root}
└── contract_storage table: (address, slot) → value
```

**Implications:**
- ✅ Simpler implementation
- ✅ Faster reads/writes (no trie traversal)
- ❌ No state proofs (can't support `eth_getProof`)
- ❌ No light client support

### 2. State Root Computation

**Both implementations:**
- State root is computed by the EVM (py-evm in our case)
- Stored in block headers
- Consistent across restarts ✅

**Verification:**
```python
# State root consistency test passed
Genesis state root: e0dd54c8... (matches after restart)
Block 1 state root: ff8184c9... (matches after restart)
```

### 3. Block Storage

**Ethrex:**
- Stores headers and bodies in separate tables
- Keyed by block_hash (supports non-canonical blocks)

**py-ethclient:**
- Stores complete blocks in single table
- Keyed by block_number (canonical chain only)
- Suitable for single sequencer

### 4. Transaction Indexing

**Ethrex:**
```sql
-- Supports multiple blocks with same tx (reorgs)
tx_hash + block_hash → (block_number, block_hash, index)
```

**py-ethclient:**
```sql
-- Simpler, assumes canonical chain
tx_hash → (block_number, tx_index)
```

### 5. Receipt Storage

**Ethrex:**
- Keyed by `(block_hash, index)`
- Supports non-canonical blocks

**py-ethclient:**
- Keyed by `(block_number, tx_index)`
- Assumes canonical chain only

## Missing Features Analysis

### Critical for Ethereum Consensus (Not Needed for Single Sequencer)

| Feature | Purpose | Why Not Needed |
|---------|---------|----------------|
| Trie Nodes | State proofs, light clients | No external verification needed |
| CANONICAL_BLOCK_HASHES | Fork choice | No forks in single sequencer |
| PENDING_BLOCKS | Pending state | We execute immediately |
| INVALID_CHAINS | Bad block tracking | No reorgs |
| Snap Sync Tables | Fast sync | No syncing from peers |

### Nice to Have (Could Add Later)

| Feature | Purpose | Priority |
|---------|---------|----------|
| CHAIN_DATA | Persist chain config | Medium |
| Full Tx Data | Faster tx lookup | Low |
| Code Metadata | Faster `eth_getCode` length queries | Low |

## RPC Method Coverage

### Implemented Methods (19)

All essential RPC methods for single-sequencer operation are implemented:

- `eth_chainId`, `eth_blockNumber`, `eth_getBalance`, `eth_getTransactionCount`
- `eth_getCode`, `eth_getStorageAt`, `eth_getBlockByNumber`, `eth_getBlockByHash`
- `eth_sendTransaction`, `eth_sendRawTransaction`, `eth_getTransactionByHash`
- `eth_getTransactionReceipt`, `eth_estimateGas`, `eth_gasPrice`, `eth_feeHistory`
- `eth_call`, `eth_getLogs`, `net_version`, `eth_accounts`, `eth_coinbase`

### Not Implemented

| Method | Data Needed | Priority |
|--------|-------------|----------|
| `eth_getBlockTransactionCountByNumber` | Block tx count | Low |
| `eth_getBlockTransactionCountByHash` | Block tx count | Low |
| `eth_getTransactionByBlockHashAndIndex` | Tx by position | Low |
| `eth_getTransactionByBlockNumberAndIndex` | Tx by position | Low |
| `eth_getProof` | Trie proofs | Not feasible (no trie) |

## Data Integrity Verification

### State Root Consistency ✅
- State root persists correctly across restarts
- Matches before and after restart
- Computed by py-evm internally

### Transactions Root ✅
- Computed per block correctly
- Matches expected format

### Receipts Root ✅
- Computed per block correctly
- Matches expected format

### Logs Bloom ✅
- Stored in block headers
- Computed by py-evm

## Recommendations

### For Single Sequencer (Current Status)
The implementation is **complete and correct** for single-sequencer operation.

### Optional Improvements

1. **Add CHAIN_DATA table** for chain config persistence:
   ```sql
   CREATE TABLE chain_data (
       key TEXT PRIMARY KEY,
       value TEXT NOT NULL
   );
   -- Keys: 'chain_config', 'earliest_block', 'latest_block'
   ```

2. **Optimize transaction storage** if needed:
   ```sql
   CREATE TABLE transaction_data (
       hash BLOB PRIMARY KEY,
       rlp_data BLOB NOT NULL
   );
   ```

3. **Add block hash index** for faster lookups:
   ```sql
   CREATE INDEX idx_blocks_hash ON blocks(hash);
   -- Already exists in current implementation ✅
   ```

## Conclusion

py-ethclient's storage implementation:
- ✅ Covers all essential functionality for single-sequencer operation
- ✅ Correctly persists EVM state (accounts, code, storage)
- ✅ Maintains state root consistency across restarts
- ✅ Supports all commonly-used RPC methods
- ❌ Does not support state proofs (requires trie implementation)
- ❌ Does not support multi-chain/reorg scenarios

The implementation is well-suited for its intended use case as a single sequencer.