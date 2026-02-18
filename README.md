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
| Mempool | Only process self-created transactions |

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

### Storage (~53 LOC)
| Feature | Status | Description |
|---------|--------|-------------|
| InMemoryStore | ✅ | dict-based block/receipt storage |
| Block by Number | ✅ | O(1) lookup |
| Block by Hash | ✅ | O(1) lookup |
| Transaction Receipt | ✅ | tx_hash → (block, index, receipt) |

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

### RPC Server (~420 LOC total)
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
| `eth_sendTransaction` | ✅ | Sign and send (supports EIP-1559 and Legacy) |
| `eth_sendRawTransaction` | ✅ | Send pre-signed transaction |
| `eth_getTransactionReceipt` | ✅ | Transaction receipt with effectiveGasPrice |
| `eth_estimateGas` | ⚠️ | Simple estimation (hardcoded) |
| `eth_gasPrice` | ✅ | Returns 1 Gwei |
| `eth_feeHistory` | ✅ | Historical gas fee data with base fee |
| `eth_call` | ⚠️ | **Partial** - returns code only |
| `net_version` | ✅ | Chain ID as string |
| `eth_accounts` | ✅ | Returns empty list |
| `eth_coinbase` | ✅ | Returns coinbase address |

### CLI (~55 LOC)
| Feature | Status |
|---------|--------|
| Argument parsing | ✅ |
| Prefunded account setup | ✅ |
| RPC server startup | ✅ |

### Tests (~320 LOC)
| Test | Status | Description |
|------|--------|-------------|
| `test_get_balance` | ✅ | Balance query |
| `test_chain_id` | ✅ | Chain ID query |
| `test_get_block_by_number` | ✅ | Block query |
| `test_send_transaction_deploy_contract` | ✅ | Contract deployment |
| `test_eth_call_read_storage` | ✅ | eth_call (limited) |
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

### Phase 2: Improved Operations (~230 LOC)

| # | Feature | Current State | Required Work | LOC |
|---|---------|---------------|---------------|-----|
| 1 | `estimateGas` | Hardcoded (21k/100k) | Transaction simulation with actual gas measurement | ~50 |
| 2 | Transaction Pool (Mempool) | Simple list (FIFO) | Priority-based with nonce tracking | ~120 |
| 3 | Periodic Block Production | Mine on every tx | Timer-based block building | ~60 |

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

### Phase 3: Improved Compatibility (~150 LOC)

| # | Feature | Description | LOC |
|---|---------|-------------|-----|
| 4 | `eth_call` full implementation | Execute call without state change | ~30 |
| 5 | `eth_getTransactionByHash` | Query transaction by hash | ~20 |
| 6 | `eth_getLogs` | Event log filtering with bloom filters | ~50 |
| 7 | SQLite Persistence | Replace dict storage for data durability | ~100 |

### Phase 4: Future Compatibility (Prague/Osaka)

#### Transaction Types (EIP-2718)

| Type | EIP | Name | Current Support | Required |
|------|-----|------|-----------------|----------|
| `0x00` | Legacy | Legacy Transaction | ✅ Yes | - |
| `0x01` | EIP-2930 | Access List | ❌ No | Recommended |
| `0x02` | EIP-1559 | Dynamic Fee | ✅ Yes | - |
| `0x04` | EIP-7702 | Set Code (Prague) | ❌ No | **Required** |

> **Note**: Blob transactions (EIP-4844, Type `0x03`) are not required for single sequencer use cases.

#### Prague EIPs (Pectra - May 2025)

| EIP | Description | Impact |
|-----|-------------|--------|
| EIP-7702 | EOA Code Delegation (Tx Type 0x04) | Allow EOAs to temporarily act as smart contracts |
| EIP-7623 | Increased Calldata Cost | Gas calculation update |
| EIP-2537 | BLS12-381 Precompiles | Efficient SNARK verification |
| EIP-2935 | Block Hash History | Store recent block hashes in state |

#### Osaka EIPs (Fusaka - 2026)

> **Note**: These must be implemented manually since `py-evm` is archived.

| EIP | Description | Impact |
|-----|-------------|--------|
| EIP-7951 | secp256r1 Precompile | Hardware wallet/passkey support |
| EIP-7939 | CLZ Opcode | Count Leading Zeros opcode |
| EIP-7825 | Transaction Gas Limit Cap | Gas limit validation |
| EIP-7883 | ModExp Gas Cost Increase | Precompile gas update |

### Execution Timeline

```
✅ COMPLETED:
├── [x] EIP-1559 base fee calculation (chain.py)
├── [x] EIP-1559 tx type 0x02 support (methods.py, chain.py, adapter.py)
├── [x] eth_feeHistory RPC endpoint (rpc/methods.py)
└── [x] Unit tests for EIP-1559 (tests/test_sequencer.py)

Phase 2 - Operations:
├── [ ] Real estimateGas implementation (rpc/methods.py)
├── [ ] Mempool class with priority queue (new: sequencer/mempool.py)
└── [ ] asyncio-based sequencer loop with block_time

Phase 3 - Compatibility:
├── [ ] eth_call actual execution
├── [ ] eth_getTransactionByHash
├── [ ] eth_getLogs (logsBloom)
└── [ ] SQLite store (optional)

Phase 4 - Prague Preparation:
├── [ ] EIP-7702 (Tx Type 0x04) support
└── [ ] Upgrade to PragueVM in py-evm
```

### Projected LOC

| Phase | Components | LOC |
|-------|------------|-----|
| Current | All (with EIP-1559) | ~1,250 |
| Phase 2 | Improved operations | +~230 |
| Phase 3 | Improved compatibility | +~150 |
| **Total** | | **~1,630** |

## Architecture

```
py-ethclient/
├── src/sequencer/
│   ├── core/                    # Minimal types & crypto
│   │   ├── types.py             # Account, Block, Receipt (~100 LOC)
│   │   ├── crypto.py            # keccak256, sign, recover (~28 LOC)
│   │   └── constants.py         # Chain constants (~16 LOC)
│   │
│   ├── evm/                     # py-evm bridge
│   │   └── adapter.py           # MiningChain wrapper (~165 LOC)
│   │
│   ├── storage/                 # In-memory storage
│   │   └── store.py             # dict-based store (~53 LOC)
│   │
│   ├── sequencer/               # Sequencer logic
│   │   └── chain.py             # Block building (~270 LOC)
│   │
│   ├── rpc/                     # JSON-RPC
│   │   ├── server.py            # http.server (~85 LOC)
│   │   └── methods.py           # eth_* methods (~340 LOC)
│   │
│   └── cli.py                   # Entry point (~55 LOC)
│
└── tests/
    └── test_sequencer.py        # Integration tests (~320 LOC)
```

**Total: ~1,250 LOC** (Target: ~1,630 LOC)

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

## License

MIT
