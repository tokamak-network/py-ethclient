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

## Not Yet Implemented

### High Priority
| Feature | Description |
|---------|-------------|
| `eth_call` full implementation | Execute call without state change |
| `eth_getTransactionByHash` | Get transaction by hash |
| `eth_getBlockTransactionCountByNumber` | Transaction count in block |
| `eth_getTransactionByBlockHashAndIndex` | Transaction by block + index |
| Contract address calculation | Compute create address for receipts |
| Logs bloom computation | Actual bloom filter for logs |

### Medium Priority
| Feature | Description |
|---------|-------------|
| EIP-1559 transactions | Type 2 transactions with max_fee_per_gas |
| Better error handling | Custom error types, clearer messages |
| Gas estimation improvement | Trace-based gas estimation |
| Block/Transaction range queries | Filter by block range |

### Low Priority (Future)
| Feature | Description |
|---------|-------------|
| Persistent storage (SQLite) | Replace dict with SQLite backend |
| WebSocket support | Real-time event subscriptions |
| eth_subscribe | New block/transaction subscriptions |
| Debug/trace endpoints | For development |

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