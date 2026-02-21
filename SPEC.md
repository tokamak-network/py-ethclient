# py-ethclient Specification

> **Version**: 0.1.0  
> **Ethereum Compatibility**: Cancun (Prague for Type 0x04)  
> **Sequencer Type**: Single Sequencer (No Consensus)

---

## 1. Overview

py-ethclient is an ultra-lightweight Ethereum-compatible single sequencer implementation. It provides JSON-RPC API compatibility for standard Ethereum tooling (MetaMask, ethers.js, web3.py) while operating as a centralized block producer without consensus.

### Key Characteristics

| Aspect | Implementation |
|--------|---------------|
| **Consensus** | None (single sequencer) |
| **P2P** | None (isolated) |
| **Block Production** | Timer-based (default: 1s intervals) |
| **EVM** | py-evm (Cancun) |
| **Storage** | In-Memory or SQLite |
| **Reorgs** | Impossible (linear chain) |

### Excluded Features

Standard Ethereum features that are **not implemented**:

| Feature | Reason | Impact |
|---------|--------|--------|
| Consensus Layer (PoS/PoW) | Single sequencer | `engine_*` methods unsupported |
| P2P Networking | No external peers | Self-contained only |
| Block Sync | No external nodes | Genesis-only chain |
| Transaction Broadcasting | Single origin | No tx gossip |
| Fork Choice | Linear chain | No reorg handling |

---

## 2. Supported RPC Methods

### 2.1 Standard Ethereum Methods

| Method | Status | Notes |
|--------|--------|-------|
| `eth_chainId` | ✅ | Returns configured chain ID |
| `eth_blockNumber` | ✅ | Latest block number |
| `eth_getBalance` | ✅ | Account balance at block |
| `eth_getTransactionCount` | ✅ | Account nonce at block |
| `eth_getCode` | ✅ | Contract bytecode |
| `eth_getStorageAt` | ✅ | Storage slot value |
| `eth_getBlockByNumber` | ✅ | Full or partial block |
| `eth_getBlockByHash` | ✅ | Full or partial block |
| `eth_sendTransaction` | ✅ | Legacy, EIP-1559, EIP-7702 |
| `eth_sendRawTransaction` | ✅ | Pre-signed transactions |
| `eth_getTransactionByHash` | ✅ | Transaction details |
| `eth_getTransactionReceipt` | ✅ | Receipt with logs |
| `eth_estimateGas` | ✅ | Binary search estimation |
| `eth_call` | ✅ | Static execution |
| `eth_gasPrice` | ✅ | Returns 1 Gwei |
| `eth_feeHistory` | ✅ | Historical fee data |
| `eth_getLogs` | ✅ | Log filtering |
| `eth_signAuthorization` | ✅ | EIP-7702 authorization |
| `net_version` | ✅ | Chain ID as string |
| `eth_accounts` | ✅ | Empty list (no key management) |
| `eth_coinbase` | ✅ | Sequencer coinbase address |

### 2.2 Unsupported Methods

| Method | Status | Alternative |
|--------|--------|-------------|
| `eth_syncing` | ❌ | Always return `false` |
| `eth_getUncleByBlockHashAndIndex` | ❌ | No uncles (single sequencer) |
| `eth_getUncleCountByBlockHash` | ❌ | Always return `0` |
| `eth_submitHashrate` | ❌ | No mining |
| `eth_getWork` | ❌ | No mining |
| `eth_submitWork` | ❌ | No mining |
| `engine_forkchoiceUpdated` | ❌ | No consensus |
| `engine_getPayload` | ❌ | No consensus |
| `engine_newPayload` | ❌ | No consensus |
| `engine_exchangeTransitionConfiguration` | ❌ | No consensus |

### 2.3 JSON-RPC Specification

**Transport**: HTTP only (no WebSocket)

**Content-Type**: `application/json`

**Batch Requests**: Supported (array of request objects)

**Notifications**: Supported (requests without `id` field, returns no response)

**Error Codes**:

| Code | Meaning |
|------|---------|
| -32700 | Parse error |
| -32600 | Invalid request |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error |

---

## 3. Transaction Types

### 3.1 Supported Types

| Type | EIP | Status | Notes |
|------|-----|--------|-------|
| `0x00` | Legacy | ✅ | Full support |
| `0x01` | EIP-2930 (Access List) | ❌ | Not implemented |
| `0x02` | EIP-1559 | ✅ | Full support |
| `0x03` | EIP-4844 (Blob) | ❌ | Not needed for single sequencer |
| `0x04` | EIP-7702 (Set Code) | ✅ | Prague support |

### 3.2 Legacy Transaction (Type 0x00)

```json
{
  "type": "0x0",
  "nonce": "0x0",
  "gasPrice": "0x1",
  "gas": "0x5208",
  "to": "0x...",
  "value": "0x0",
  "input": "0x",
  "v": "0x...",
  "r": "0x...",
  "s": "0x...",
  "hash": "0x..."
}
```

### 3.3 EIP-1559 Transaction (Type 0x02)

```json
{
  "type": "0x2",
  "chainId": "0x539",
  "nonce": "0x0",
  "maxPriorityFeePerGas": "0x1",
  "maxFeePerGas": "0x2",
  "gas": "0x5208",
  "to": "0x...",
  "value": "0x0",
  "input": "0x",
  "accessList": [],
  "v": "0x...",
  "r": "0x...",
  "s": "0x...",
  "hash": "0x..."
}
```

### 3.4 EIP-7702 Set Code Transaction (Type 0x04)

```json
{
  "type": "0x4",
  "chainId": "0x539",
  "nonce": "0x0",
  "maxPriorityFeePerGas": "0x1",
  "maxFeePerGas": "0x2",
  "gas": "0x5208",
  "to": "0x...",
  "value": "0x0",
  "input": "0x",
  "accessList": [],
  "authorizationList": [
    {
      "chainId": "0x0",
      "address": "0x...",
      "nonce": "0x0",
      "v": "0x...",
      "r": "0x...",
      "s": "0x..."
    }
  ],
  "v": "0x...",
  "r": "0x...",
  "s": "0x...",
  "hash": "0x..."
}
```

### 3.5 Authorization Signing

For `eth_signAuthorization`:

```python
{
  "from": "0x...",
  "address": "0x...",
  "nonce": "0x0",
  "chainId": "0x0"  # Optional (0 for all chains)
}
```

Returns signed authorization object.

---

## 4. Block Structure

### 4.1 Block Header

| Field | Type | Notes |
|-------|------|-------|
| `parentHash` | Bytes32 | Previous block hash |
| `ommersHash` | Bytes32 | Always `keccak256([])` (empty) |
| `stateRoot` | Bytes32 | py-evm computed state root |
| `transactionsRoot` | Bytes32 | Trie root of transaction RLPs |
| `receiptsRoot` | Bytes32 | Trie root of receipt RLPs |
| `logsBloom` | Bytes256 | Static bloom filter (all zeros) |
| `difficulty` | Uint | Always `0` |
| `number` | Uint | Block height |
| `gasLimit` | Uint | Configured gas limit (default: 30M) |
| `gasUsed` | Uint | Sum of gas used in all tx |
| `timestamp` | Uint | Unix timestamp |
| `extraData` | Bytes | Empty |
| `mixHash` | Bytes32 | Always zeros |
| `nonce` | Bytes8 | Always zeros |
| `baseFeePerGas` | Uint | EIP-1559 base fee |
| `withdrawalsRoot` | Bytes32 | Not implemented |
| `blobGasUsed` | Uint | Not implemented |
| `excessBlobGas` | Uint | Not implemented |
| `parentBeaconBlockRoot` | Bytes32 | Not implemented |

### 4.2 Block Body

```python
{
  "header": {...},
  "transactions": [tx1, tx2, ...],
  "ommers": []  # Always empty
}
```

### 4.3 Receipt Structure

| Field | Type | Notes |
|-------|------|-------|
| `status` | Uint | `1` = success, `0` = failure |
| `cumulativeGasUsed` | Uint | Total gas used in block up to this tx |
| `logs` | Array | Log entries from execution |
| `logsBloom` | Bytes256 | Static (all zeros) |
| `transactionHash` | Bytes32 | Transaction hash |
| `transactionIndex` | Uint | Index in block |
| `blockHash` | Bytes32 | Block hash |
| `blockNumber` | Uint | Block number |
| `from` | Address20 | Sender address |
| `to` | Address20 | Recipient (null for creation) |
| `contractAddress` | Address20 | Created contract address (if any) |
| `effectiveGasPrice` | Uint | Actual gas price paid |
| `gasUsed` | Uint | Gas used by this transaction |

---

## 5. Gas Mechanics

### 5.1 Gas Pricing

| Parameter | Default Value |
|-----------|---------------|
| `initialBaseFee` | 1 Gwei (1,000,000,000 wei) |
| `minBaseFee` | 0 |
| `maxBaseFee` | 2^256-1 |
| `elasticityMultiplier` | 2 |
| `baseFeeMaxChangeDenominator` | 8 |

### 5.2 Base Fee Calculation

Per EIP-1559:

```python
def calc_base_fee(parent_gas_used, parent_gas_limit, parent_base_fee):
    target = parent_gas_limit // 2
    
    if parent_gas_used == target:
        return parent_base_fee
    
    if parent_gas_used > target:
        delta = parent_gas_used - target
        base_fee_delta = max(parent_base_fee * delta // target // 8, 1)
        return parent_base_fee + base_fee_delta
    
    delta = target - parent_gas_used
    base_fee_delta = parent_base_fee * delta // target // 8
    return parent_base_fee - base_fee_delta
```

### 5.3 Gas Limit Enforcement

Block gas limit is enforced **before transaction execution**:

| Check | Behavior |
|-------|----------|
| `tx.gas + cumulative_gas <= block_gas_limit` | Transaction executed |
| `tx.gas + cumulative_gas > block_gas_limit` | Transaction skipped, remains in mempool |

**Transaction Selection Algorithm**:

```python
included_txs = []
cumulative_gas = 0

for tx in pending_txs:
    if cumulative_gas + tx.gas > gas_limit:
        break  # Block full
    execute(tx)
    included_txs.append(tx)
    cumulative_gas += gas_used
```

This ensures:
- Blocks never exceed the configured gas limit
- Skipped transactions remain in mempool for next block
- Gas accounting is accurate (uses cumulative gas from receipt)

---

## 6. State Management

### 6.1 Account Structure

```python
{
  "nonce": Uint,           # Transaction count
  "balance": Uint,         # Wei balance
  "storage": Dict[int, bytes],  # Contract storage
  "code": bytes            # Contract bytecode
}
```

### 6.2 State Persistence

| Storage Type | Persistence | Use Case |
|--------------|-------------|----------|
| `InMemoryStore` | Session only (cleared on restart) | Testing, ephemeral chains |
| `SQLiteStore` | Persistent (survives restart) | Production, state preservation |

**SQLiteStore Features**:
- Thread-safe (RLock-protected)
- Context manager support (`with` statement)
- Automatic optimization on close (`PRAGMA optimize`)
- Atomic transactions (BEGIN/COMMIT/ROLLBACK)

```python
# Using context manager for guaranteed cleanup
with SQLiteStore("chain.db") as store:
    store.save_block(block, receipts, tx_hashes)
# Automatic close() and optimization on exit
```

### 6.3 State Root Calculation

State root is computed by py-evm's `MiningChain.finalize_block()`. The sequencer does not implement its own state trie.

---

## 7. Mempool Specification

### 7.1 Transaction Ordering

Transactions are ordered by:
1. **Priority Fee** (descending): `maxPriorityFeePerGas`
2. **Time**: First-seen (FIFO for same priority)

### 7.2 Nonce Management

| Policy | Behavior |
|--------|----------|
| Valid Range | `nonce >= current_nonce` |
| Exact Nonce | Must be `current_nonce` to execute |
| Gap Handling | Queued (high nonce tx waits for gap) |

### 7.3 Transaction Replacement

- **Requirement**: 10% higher `maxPriorityFeePerGas` or `gasPrice`
- **Same Nonce**: Replaces existing transaction
- **Underpriced**: Rejected

### 7.4 Size Limits

| Parameter | Default |
|-----------|---------|
| Max transactions | 10,000 |
| Per-account limit | 100 |
| Eviction strategy | Lowest priority removed |

---

## 8. Block Production

### 8.1 Trigger Conditions

Blocks are built when:
1. **Time-based**: `block_time` seconds elapsed since last block
2. **Force build**: `should_build_block()` returns `True`

### 8.2 Block Building Process

```
1. Get pending transactions from mempool (up to gas limit)
2. For each transaction:
   - Check gas limit (tx.gas + cumulative <= block_limit)
   - Execute via py-evm
   - Track touched addresses
   - Update cumulative gas
3. Mine block (py-evm.finalize_block())
4. Save block, receipts, and EVM state
5. Update mempool (remove included txs)
```

### 8.3 Error Handling

The block producer includes robust error handling:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_errors` | 10 | Maximum consecutive errors before stopping |
| `backoff_delay` | 5s | Delay after each error before retry |

**Error Recovery Behavior**:
- On error: Log error count, wait `backoff_delay`, retry
- On success: Reset error counter to 0
- After `max_errors`: Thread stops, manual restart required

```python
# Block producer signature
def _block_producer(chain, max_errors: int = 10):
    errors = 0
    while errors < max_errors:
        try:
            # ... block production
            errors = 0  # Reset on success
        except Exception as e:
            errors += 1
            # ... backoff logic
```

### 8.4 Graceful Shutdown

The server supports graceful shutdown via signal handling:

| Signal | Behavior |
|--------|----------|
| `SIGINT` (Ctrl+C) | Graceful shutdown |
| `SIGTERM` | Graceful shutdown |

**Shutdown Process**:
1. Stop accepting new requests
2. Wait for in-flight requests to complete
3. Close database connection (SQLite)
4. Exit cleanly

```python
# SQLiteStore supports context manager for automatic cleanup
with SQLiteStore("chain.db") as store:
    # ... use store
# Automatic close() on exit
```

---

## 9. EVM Execution

### 9.1 VM Configuration

```python
{
  "fork": "Cancun",
  "consensus": "NoProof",  # Sequencer skips validation
  "vm": CancunVM,
  "support_noop_cancun_tweaks": True
}
```

### 9.2 Precompiles

All Cancun precompiles supported:

| Address | Name | Status |
|---------|------|--------|
| `0x01` | ECDSARecover | ✅ |
| `0x02` | SHA256 | ✅ |
| `0x03` | RIPEMD160 | ✅ |
| `0x04` | Identity | ✅ |
| `0x05` | ModExp | ✅ |
| `0x06` | BN256Add | ✅ |
| `0x07` | BN256ScalarMul | ✅ |
| `0x08` | BN256Pairing | ✅ |
| `0x09` | Blake2F | ✅ |
| `0x0a` | KZG | ✅ (Cancun) |

### 9.3 BLS12-381 (EIP-2537)

| Address | Name | Status |
|---------|------|--------|
| `0x0b`-`0x12` | BLS12-381 G1Add, G1Mul, G1MultiExp, G2Add, G2Mul, G2MultiExp, Pairing, MapG1, MapG2 | ❌ Future EIP |

### 9.4 State Access

| Operation | Status |
|-----------|--------|
| `SLOAD` / `SSTORE` | ✅ |
| `BALANCE` | ✅ |
| `EXTCODESIZE` | ✅ |
| `EXTCODECOPY` | ✅ |
| `EXTCODEHASH` | ✅ |
| `BLOCKHASH` | ⚠️ | Limited (no historical blocks) |
| `COINBASE` | ✅ | Returns sequencer address |
| `TIMESTAMP` | ✅ |
| `NUMBER` | ✅ |
| `GASLIMIT` | ✅ | Block gas limit |
| `CHAINID` | ✅ |
| `SELFBALANCE` | ✅ |
| `BASEFEE` | ✅ |

---

## 10. Deviations from Standard Ethereum

### 10.1 Consensus Layer

| Standard | This Implementation |
|----------|---------------------|
| Proof of Work | N/A |
| Proof of Stake | N/A |
| Single Sequencer | Centralized block production |

### 10.2 Networking

| Standard | This Implementation |
|----------|---------------------|
| DevP2P | Not implemented |
| Discovery (v4/v5) | Not implemented |
| Transaction Broadcasting | N/A (single origin) |

### 10.3 Block Time

| Standard | This Implementation |
|----------|---------------------|
| Variable (PoW) | Fixed (PoW) |
| Slot-based (PoS) | Timer-based (configurable) |

### 10.4 State Availability

| Standard | This Implementation |
|----------|---------------------|
| Full state trie | py-evm internal state |
| Archive node | Supported (SQLite) |
| Snap sync | Not needed |

---

## 11. Known Limitations

### 11.1 Storage Slot Discovery

**Issue**: Slots >= 100 may lose state on restart

**Cause**: Heuristic-based discovery (checks slots 0-99 only)

**Current Implementation**:
```python
# Check slots 0-99 plus previously stored slots
slots_to_check = set(range(100)) | set(stored_storage.keys())
```

**Impact**: Contracts using high storage slots (>99) for the first time may lose state on restart

**Workaround**: Keep storage slots below 100 (most simple contracts do)

**Proper Fix**: Hook into EVM state journal to capture all storage writes

**Reference**: [py-evm issue #172](https://github.com/ethereum/py-evm/issues/172)

### 11.2 CREATE2 Contracts (EIP-1014)

**Status**: ✅ Fully Supported

CREATE2 contracts are tracked and persisted alongside CREATE contracts:

| Feature | Implementation |
|---------|---------------|
| **Address Computation** | `compute_create2_address(sender, salt, init_code)` |
| **Contract Tracking** | SQLite table `create2_contracts` |
| **Deployer Lookup** | `get_create2_contracts_by_deployer()` |
| **Reverse Lookup** | `find_create2_contract(deployer, salt, hash)` |
| **Verification** | `is_create2_contract(address)` |

**Address Formula** (EIP-1014):
```
address = keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12:]
```

**Usage**:
```python
# Predict CREATE2 address before deployment
from sequencer.core.create2 import compute_create2_address

sender = bytes.fromhex("deadbeef" * 5)
salt = bytes(32)  # 32-byte salt
init_code = bytes.fromhex("602a600055...")  # Constructor bytecode

predicted_address = compute_create2_address(sender, salt, init_code)

# Or use Chain method
address = chain.compute_create2_address(sender, salt, init_code)

# Check if deployed contract was CREATE2
if chain.is_create2_contract(address):
    info = chain.get_create2_contract_info(address)
    print(f"Deployer: {info['deployer'].hex()}")
    print(f"Salt: {info['salt'].hex()}")
```

### 11.3 Block Sync

**Issue**: Cannot sync from external nodes

**Impact**: Chain must start from genesis

**Workaround**: Export/import SQLite database

---

## 12. Configuration

### 12.1 Chain Parameters

```python
{
  "chain_id": 1337,              # EIP-155 chain ID
  "coinbase": "0x...",           # Block producer address
  "gas_limit": 30000000,         # Block gas limit
  "block_time": 1.0,             # Seconds between blocks
  "genesis_state": {...},        # Initial accounts
  "store_type": "memory",        # or "sqlite"
  "store_path": "chain.db"       # SQLite only
}
```

### 12.2 Environment Variables

| Variable | Purpose |
|----------|---------|
| None | All configuration via Python API or CLI |

---

## 13. Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `py-evm` | >=0.12.0b1 | EVM execution |
| `ethereum-rlp` | >=0.1.4 | RLP encoding |
| `trie` | >=3.1.0 | Merkle Patricia Trie |
| `ethereum-types` | >=0.1.0 | Type definitions |
| `coincurve` | >=21.0.0 | secp256k1 ECDSA |
| `pycryptodome` | >=3.20.0 | Keccak256 |
| `eth-keys` | >=0.5.0 | Key management |
| `eth-utils` | >=5.0.0 | Utilities |
| `rlp` | >=3.0.0 | RLP codec |

---

## 14. Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | Feb 2026 | Initial release with Cancun support, EIP-1559, EIP-7702 |
| 0.1.1 | Feb 2026 | Gas limit enforcement, block producer error handling, graceful shutdown |
| 0.1.2 | Feb 2026 | CREATE2 support (EIP-1014), address computation and persistence |

---

## 15. References

- [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)
- [JSON-RPC Specification](https://eth.wiki/json-rpc/API)
- [EIP-1014](https://eips.ethereum.org/EIPS/eip-1014) - CREATE2 opcode
- [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) - Fee market change
- [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) - Set EOA account code
- [py-evm](https://github.com/ethereum/py-evm) - Python EVM

---

*Last updated: February 2026 (v0.1.2)*
