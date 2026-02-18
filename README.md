# py-ethclient

A Python Ethereum L1 execution client — a fully independent port of [ethrex](https://github.com/lambdaclass/ethrex) (Rust).

Built to participate directly in the Ethereum network via devp2p. All core logic is implemented from scratch; only cryptographic primitives and the web framework are external dependencies.

> **[한국어 README](./README_ko.md)**

## Requirements

- Python 3.12+
- System dependency: `snappy` library (required to build python-snappy)

### macOS

```bash
brew install snappy
```

### Ubuntu/Debian

```bash
sudo apt install libsnappy-dev
```

## Installation

```bash
# Clone the repository
git clone https://github.com/tokamak-network/py-ethclient.git
cd py-ethclient

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

```bash
# Run with defaults (mainnet, ports 30303/8545)
ethclient

# Connect to Sepolia testnet
ethclient --network sepolia

# Custom configuration
ethclient --network sepolia --port 30304 --rpc-port 8546 --max-peers 10

# Run with a custom genesis file
ethclient --genesis ./genesis.json --port 30303
```

### CLI Options

| Option | Default | Description |
|---|---|---|
| `--network` | `mainnet` | Network to join (`mainnet`, `sepolia`, `holesky`) |
| `--genesis` | — | Path to a custom genesis.json file |
| `--port` | `30303` | P2P TCP/UDP listen port |
| `--rpc-port` | `8545` | JSON-RPC HTTP listen port |
| `--max-peers` | `25` | Maximum number of peer connections |
| `--bootnodes` | per-network defaults | Comma-separated enode URLs for bootstrap |
| `--private-key` | auto-generated | secp256k1 private key for node identity (hex) |
| `--log-level` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

## JSON-RPC API

A JSON-RPC 2.0 endpoint is served at `http://localhost:8545`.

### Supported Methods

**eth_ namespace**

| Method | Description |
|---|---|
| `eth_blockNumber` | Latest block number |
| `eth_getBlockByNumber` | Get block by number |
| `eth_getBlockByHash` | Get block by hash |
| `eth_getBalance` | Account balance |
| `eth_getTransactionCount` | Account nonce |
| `eth_getCode` | Contract bytecode |
| `eth_getStorageAt` | Storage slot value |
| `eth_sendRawTransaction` | Submit a signed transaction |
| `eth_call` | Read-only contract call |
| `eth_estimateGas` | Gas estimation |
| `eth_gasPrice` | Current gas price |
| `eth_maxPriorityFeePerGas` | Priority fee suggestion |
| `eth_feeHistory` | Fee history |
| `eth_chainId` | Chain ID |
| `eth_syncing` | Sync status |
| `eth_getLogs` | Log filter query |
| `eth_getBlockReceipts` | Block receipts |

**net_ namespace**

| Method | Description |
|---|---|
| `net_version` | Network ID |
| `net_peerCount` | Connected peer count |
| `net_listening` | Listening status |

**web3_ namespace**

| Method | Description |
|---|---|
| `web3_clientVersion` | Client version string |
| `web3_sha3` | Keccak-256 hash |

### Usage Examples

```bash
# Get latest block number
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Query account balance
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","latest"],"id":1}'
```

## Testing

```bash
# Run all tests
pytest

# Run tests for a specific module
pytest tests/test_rlp.py         # RLP encoding/decoding
pytest tests/test_trie.py        # Merkle Patricia Trie
pytest tests/test_evm.py         # EVM opcode execution
pytest tests/test_storage.py     # State storage
pytest tests/test_blockchain.py  # Block validation/execution
pytest tests/test_p2p.py         # P2P networking
pytest tests/test_rpc.py         # JSON-RPC server
pytest tests/test_integration.py # End-to-end integration

# Verbose output
pytest -v
```

## Architecture

```
ethclient/
├── main.py                          # CLI entry point, node initialization
├── common/                          # Core foundation modules
│   ├── rlp.py                       # RLP encoding/decoding
│   ├── types.py                     # Block, BlockHeader, Transaction, Account, etc.
│   ├── trie.py                      # Merkle Patricia Trie
│   ├── crypto.py                    # keccak256, secp256k1 ECDSA, address derivation
│   └── config.py                    # Chain config, hardfork params, Genesis
├── vm/                              # EVM (Ethereum Virtual Machine)
│   ├── evm.py                       # Main execution loop, transaction execution
│   ├── opcodes.py                   # All opcode handlers (140+)
│   ├── precompiles.py               # Precompiled contracts (ecrecover, SHA256, etc.)
│   ├── gas.py                       # Gas calculation (EIP-2929, EIP-2200)
│   ├── memory.py                    # 256-bit stack, byte-addressable memory
│   ├── call_frame.py                # Call frames, JUMPDEST validation
│   └── hooks.py                     # Execution hooks (L2 extensibility)
├── storage/                         # State storage
│   ├── store.py                     # Abstract Store interface
│   └── memory_backend.py            # In-memory implementation, state root computation
├── blockchain/                      # Blockchain engine
│   ├── chain.py                     # Block validation, transaction/block execution
│   ├── mempool.py                   # Transaction pool (nonce ordering, replacement)
│   └── fork_choice.py               # Canonical chain management, reorgs
├── networking/                      # P2P networking
│   ├── server.py                    # P2P server main loop
│   ├── rlpx/
│   │   ├── handshake.py             # ECIES handshake (auth/ack)
│   │   ├── framing.py               # RLPx frame encryption/decryption
│   │   └── connection.py            # Encrypted TCP connection management
│   ├── eth/
│   │   ├── protocol.py              # p2p/eth message codes, protocol constants
│   │   └── messages.py              # eth/68 message encoding/decoding
│   ├── discv4/
│   │   ├── discovery.py             # Discovery v4 UDP protocol
│   │   └── routing.py               # Kademlia k-bucket routing table
│   └── sync/
│       └── full_sync.py             # Full sync pipeline
└── rpc/                             # JSON-RPC server
    ├── server.py                    # FastAPI-based JSON-RPC 2.0 dispatcher
    └── eth_api.py                   # eth_/net_/web3_ API handlers
```

## Dependencies

| Package | Purpose |
|---|---|
| [pycryptodome](https://pypi.org/project/pycryptodome/) | AES encryption, SHA-256, RIPEMD-160 |
| [coincurve](https://pypi.org/project/coincurve/) | secp256k1 ECDSA sign/recover, ECDH |
| [eth-hash](https://pypi.org/project/eth-hash/) | Keccak-256 hashing |
| [FastAPI](https://pypi.org/project/fastapi/) | JSON-RPC HTTP server |
| [uvicorn](https://pypi.org/project/uvicorn/) | ASGI server |
| [python-snappy](https://pypi.org/project/python-snappy/) | RLPx message Snappy compression |

**Dev dependencies:**

| Package | Purpose |
|---|---|
| [pytest](https://pypi.org/project/pytest/) | Test framework |
| [pytest-asyncio](https://pypi.org/project/pytest-asyncio/) | Async test support |

## Implementation Details

### Components Built from Scratch

- **RLP (Recursive Length Prefix)** — Ethereum serialization format: encoding/decoding, list/bytes discrimination
- **Merkle Patricia Trie** — Branch/Extension/Leaf nodes, hex-prefix encoding, state root computation
- **EVM** — 140+ opcodes, 256-bit stack, byte-addressable memory, EIP-2929 cold/warm tracking, EIP-1559 base fee
- **Precompiles** — ecrecover, SHA-256, RIPEMD-160, identity, modexp (EIP-2565), BLAKE2f (EIP-152)
- **RLPx Transport** — ECIES encryption, AES-256-CTR frame encryption, SHA3 MAC authentication
- **eth/68 Protocol** — Status, GetBlockHeaders, BlockHeaders, Transactions, and all other message types
- **Discovery v4** — UDP Ping/Pong/FindNeighbours/Neighbours, Kademlia routing table
- **Full Sync** — Header download → body download → block execution pipeline
- **JSON-RPC 2.0** — Request parsing, batch support, error handling, method dispatch

### Supported EIPs

| EIP | Description |
|---|---|
| EIP-155 | Replay protection (chain ID) |
| EIP-1559 | Base fee, dynamic fees |
| EIP-2718 | Typed transaction envelope |
| EIP-2929 | Cold/warm storage access gas |
| EIP-2930 | Access list transactions |
| EIP-2200/3529 | SSTORE gas refund |
| EIP-2565 | ModExp gas cost |
| EIP-152 | BLAKE2f precompile |
| EIP-4844 | Blob transaction type (type definition) |

### Execution Hook System

The EVM includes built-in hook points for L2 extensibility. Extending to L2 requires no changes to the EVM core — just implement `ExecutionHook`:

```python
from ethclient.vm.hooks import ExecutionHook

class L2Hook(ExecutionHook):
    def before_execution(self, tx, env): ...
    def before_call(self, msg, env): ...
    def on_state_change(self, addr, key, value, env): ...
```

## Project Stats

### Source Code

| Module | Files | LOC | Description |
|---|---:|---:|---|
| `common/` | 5 | 1,950 | RLP, types, trie, crypto, config |
| `vm/` | 7 | 2,502 | EVM, opcodes, precompiles, gas |
| `storage/` | 2 | 620 | Store interface, in-memory backend |
| `blockchain/` | 3 | 966 | Block validation, mempool, fork choice |
| `networking/` | 8 | 2,559 | RLPx, discovery, eth/68, sync, server |
| `rpc/` | 2 | 550 | JSON-RPC server, eth API |
| `main.py` | 1 | 333 | CLI entry point |
| **Total** | **28** | **9,480** | |

### Test Code

| Test File | LOC | Tests | Covers |
|---|---:|---:|---|
| `test_rlp.py` | 206 | ~50 | RLP encoding/decoding |
| `test_trie.py` | 213 | ~30 | Merkle Patricia Trie |
| `test_crypto.py` | 113 | ~15 | keccak256, ECDSA, addresses |
| `test_evm.py` | 647 | ~150 | Stack, memory, opcodes, precompiles |
| `test_storage.py` | 407 | ~20 | Store CRUD, state root |
| `test_blockchain.py` | 514 | ~30 | Header validation, block execution, mempool |
| `test_p2p.py` | 769 | ~25 | RLPx, handshake, eth messages |
| `test_rpc.py` | 306 | ~10 | JSON-RPC endpoints |
| `test_integration.py` | 250 | ~10 | Cross-module integration |
| `test_full_sync.py` | 499 | — | Live mainnet verification (standalone) |
| **Total** | **3,924** | **337** | |

## Current Limitations

- **Storage** — In-memory only (no disk backend; state is lost on restart)
- **eth_call / estimateGas** — Stub responses (not yet wired to actual EVM execution)
- **BN128 / KZG** — Precompile stubs (pairing operations not implemented)
- **Engine API** — Not implemented (no PoS consensus layer integration)
- **Snap sync** — Not implemented (full sync only)
- **Transaction indexing** — Hash-based transaction/receipt lookups not implemented

## License

MIT
