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

### Sequencer Chain (~233 LOC)
| Feature | Status | Description |
|---------|--------|-------------|
| Genesis Block Creation | ✅ | Initialize with custom state |
| Transaction Creation | ✅ | Legacy transactions |
| Transaction Signing | ✅ | ECDSA signing with private key |
| Block Building | ✅ | Auto-mine on transaction |
| State Root Computation | ✅ | Via py-evm |
| Transactions Root | ✅ | Via trie library |
| Receipts Root | ✅ | Via trie library |

### RPC Server (~378 LOC total)
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
| `eth_sendTransaction` | ✅ | Sign and send (requires `_private_key`) |
| `eth_sendRawTransaction` | ✅ | Send pre-signed transaction |
| `eth_getTransactionReceipt` | ✅ | Transaction receipt |
| `eth_estimateGas` | ✅ | Simple estimation |
| `eth_gasPrice` | ✅ | Returns 1 Gwei |
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

### Tests (~146 LOC)
| Test | Status | Description |
|------|--------|-------------|
| `test_get_balance` | ✅ | Balance query |
| `test_chain_id` | ✅ | Chain ID query |
| `test_get_block_by_number` | ✅ | Block query |
| `test_send_transaction_deploy_contract` | ✅ | Contract deployment |
| `test_eth_call_read_storage` | ✅ | eth_call (limited) |
| `test_simple_transfer` | ✅ | ETH transfer |

## Development Roadmap

> **Note**: `py-evm` was archived on September 8, 2025. It supports up to Prague but will not receive Osaka updates.

### Phase 1: Essential for Public Network (~200 LOC)

Required for operating a public network with standard wallet compatibility (MetaMask, etc.).

| # | Feature | Current State | Required Work | LOC |
|---|---------|---------------|---------------|-----|
| 1 | EIP-1559 Base Fee | Fixed at 1 Gwei | Dynamic calculation per EIP-1559 formula | ~30 |
| 2 | EIP-1559 Tx Type 0x02 | Not supported | `maxFeePerGas` / `maxPriorityFeePerGas` support | ~50 |
| 3 | Real `estimateGas` | Hardcoded (21k/100k) | Transaction simulation with actual gas measurement | ~40 |
| 4 | Transaction Pool (Mempool) | Simple list (FIFO) | Priority-based with nonce tracking | ~120 |
| 5 | Periodic Block Production | Mine on every tx | Timer-based block building with batch collection | ~60 |

**EIP-1559 Base Fee Formula:**
```python
def calc_base_fee(parent_gas_used, parent_gas_limit, parent_base_fee):
    gas_target = parent_gas_limit // 2
    if parent_gas_used == gas_target:
        return parent_base_fee
    elif parent_gas_used > gas_target:
        gas_delta = parent_gas_used - gas_target
        fee_delta = max(parent_base_fee * gas_delta // gas_target // 8, 1)
        return parent_base_fee + fee_delta
    else:
        gas_delta = gas_target - parent_gas_used
        fee_delta = parent_base_fee * gas_delta // gas_target // 8
        return max(parent_base_fee - fee_delta, 1)
```

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

### Phase 2: Improved Compatibility (~150 LOC)

| # | Feature | Description | LOC |
|---|---------|-------------|-----|
| 6 | `eth_call` full implementation | Execute call without state change | ~30 |
| 7 | `eth_getTransactionByHash` | Query transaction by hash | ~20 |
| 8 | `eth_getLogs` | Event log filtering with bloom filters | ~50 |
| 9 | SQLite Persistence | Replace dict storage for data durability | ~100 |

### Phase 3: Future Compatibility (Prague/Osaka)

#### Transaction Types (EIP-2718)

| Type | EIP | Name | Current Support | Required |
|------|-----|------|-----------------|----------|
| `0x00` | Legacy | Legacy Transaction | ✅ Yes | - |
| `0x01` | EIP-2930 | Access List | ❌ No | Recommended |
| `0x02` | EIP-1559 | Dynamic Fee | ❌ No | **Required** |
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
Core Infrastructure
├── [ ] EIP-1559 base fee calculation (chain.py)
├── [ ] EIP-1559 tx type 0x02 support (methods.py, chain.py)
├── [ ] Real estimateGas implementation (rpc/methods.py)
└── [ ] Mempool class (new: sequencer/mempool.py)

Block Production
├── [ ] asyncio-based sequencer loop
├── [ ] block_time CLI option
├── [ ] Empty block vs tx-wait policy
└── [ ] Extended unit tests

RPC & Storage
├── [ ] eth_call actual execution
├── [ ] eth_getTransactionByHash
├── [ ] eth_getLogs (logsBloom)
└── [ ] SQLite store (optional)

Prague Preparation
├── [ ] EIP-7702 (Tx Type 0x04) support
└── [ ] Upgrade to PragueVM in py-evm
```

### Projected LOC

| Phase | Components | LOC |
|-------|------------|-----|
| Current | All | ~1,154 |
| Phase 1 | Essential public network | +~200 |
| Phase 2 | Improved compatibility | +~150 |
| **Total** | | **~1,504** |

## Architecture

```
py-ethclient/
├── src/sequencer/
│   ├── core/                    # Minimal types & crypto
│   │   ├── types.py             # Account, Block, Receipt (~100 LOC)
│   │   ├── crypto.py            # keccak256, sign, recover (~28 LOC)
│   │   └── constants.py         # Chain constants (~13 LOC)
│   │
│   ├── evm/                     # py-evm bridge
│   │   └── adapter.py           # MiningChain wrapper (~148 LOC)
│   │
│   ├── storage/                 # In-memory storage
│   │   └── store.py             # dict-based store (~53 LOC)
│   │
│   ├── sequencer/               # Sequencer logic
│   │   └── chain.py             # Block building (~233 LOC)
│   │
│   ├── rpc/                     # JSON-RPC
│   │   ├── server.py            # http.server (~85 LOC)
│   │   └── methods.py           # eth_* methods (~293 LOC)
│   │
│   └── cli.py                   # Entry point (~55 LOC)
│
└── tests/
    └── test_sequencer.py        # Integration tests (~146 LOC)
```

**Total: ~1,154 LOC** (Target: ~1,450 LOC)

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
