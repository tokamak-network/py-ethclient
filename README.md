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

## Docker

```bash
# Build and run (mainnet)
docker compose up -d

# Sepolia testnet
NETWORK=sepolia docker compose up -d

# Debug logging
LOG_LEVEL=DEBUG docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

Or build manually:

```bash
docker build -t py-ethclient .
docker run -p 30303:30303 -p 8545:8545 py-ethclient --network sepolia
```

## Quick Start

```bash
# Run with defaults (mainnet, snap sync, ports 30303/8545)
ethclient

# Connect to Sepolia testnet
ethclient --network sepolia

# Full sync mode (instead of snap sync)
ethclient --network sepolia --sync-mode full

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
| `--sync-mode` | `snap` | Sync mode: `snap` (fast state download) or `full` (sequential block execution) |

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
| `eth_call` | Execute read-only contract call via EVM |
| `eth_estimateGas` | Estimate gas via EVM execution |
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
pytest tests/test_rlp.py              # RLP encoding/decoding
pytest tests/test_trie.py             # Merkle Patricia Trie
pytest tests/test_trie_proofs.py      # Trie Merkle proofs & range verification
pytest tests/test_evm.py              # EVM opcode execution
pytest tests/test_storage.py          # State storage
pytest tests/test_blockchain.py       # Block validation/execution
pytest tests/test_p2p.py              # P2P networking
pytest tests/test_protocol_registry.py # Multi-protocol capability negotiation
pytest tests/test_snap_messages.py    # snap/1 message encoding/decoding
pytest tests/test_snap_sync.py        # Snap sync state machine
pytest tests/test_rpc.py              # JSON-RPC server
pytest tests/test_integration.py      # End-to-end integration

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
│   ├── trie.py                      # Merkle Patricia Trie + proof generation/verification
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
│   ├── store.py                     # Abstract Store interface (+ snap sync methods)
│   └── memory_backend.py            # In-memory implementation, state root computation
├── blockchain/                      # Blockchain engine
│   ├── chain.py                     # Block validation, tx/block execution, simulate_call
│   ├── mempool.py                   # Transaction pool (nonce ordering, replacement)
│   └── fork_choice.py               # Canonical chain management, reorgs
├── networking/                      # P2P networking
│   ├── server.py                    # P2P server — multi-protocol dispatch
│   ├── protocol_registry.py         # Dynamic capability negotiation & offset calculation
│   ├── rlpx/
│   │   ├── handshake.py             # ECIES handshake (auth/ack)
│   │   ├── framing.py               # RLPx frame encryption/decryption
│   │   └── connection.py            # Encrypted TCP connection management
│   ├── eth/
│   │   ├── protocol.py              # p2p/eth message codes, protocol constants
│   │   └── messages.py              # eth/68 message encoding/decoding
│   ├── snap/
│   │   ├── protocol.py              # snap/1 message codes (SnapMsg enum)
│   │   └── messages.py              # snap/1 message encoding/decoding (8 types)
│   ├── discv4/
│   │   ├── discovery.py             # Discovery v4 UDP protocol
│   │   └── routing.py               # Kademlia k-bucket routing table
│   └── sync/
│       ├── full_sync.py             # Full sync pipeline
│       └── snap_sync.py             # Snap sync 4-phase state machine
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
| [py-ecc](https://pypi.org/project/py-ecc/) | BN128 elliptic curve operations (ecAdd, ecMul, ecPairing) |
| [ckzg](https://pypi.org/project/ckzg/) | KZG point evaluation (EIP-4844) |

**Dev dependencies:**

| Package | Purpose |
|---|---|
| [pytest](https://pypi.org/project/pytest/) | Test framework |
| [pytest-asyncio](https://pypi.org/project/pytest-asyncio/) | Async test support |

## Implementation Details

### Components Built from Scratch

- **RLP (Recursive Length Prefix)** — Ethereum serialization format: encoding/decoding, list/bytes discrimination
- **Merkle Patricia Trie** — Branch/Extension/Leaf nodes, hex-prefix encoding, state root computation, Merkle proof generation/verification, range proofs
- **EVM** — 140+ opcodes, 256-bit stack, byte-addressable memory, EIP-2929 cold/warm tracking, EIP-1559 base fee
- **Precompiles** — ecrecover, SHA-256, RIPEMD-160, identity, modexp (EIP-2565), BN128 ecAdd/ecMul/ecPairing (EIP-196/197), BLAKE2f (EIP-152), KZG point evaluation (EIP-4844)
- **RLPx Transport** — ECIES encryption, AES-256-CTR frame encryption, SHA3 MAC authentication
- **Protocol Registry** — Dynamic multi-protocol capability negotiation and message ID offset calculation
- **eth/68 Protocol** — Status, GetBlockHeaders, BlockHeaders, Transactions, and all other message types
- **snap/1 Protocol** — GetAccountRange, AccountRange, GetStorageRanges, StorageRanges, GetByteCodes, ByteCodes, GetTrieNodes, TrieNodes
- **Discovery v4** — UDP Ping/Pong/FindNeighbours/Neighbours, Kademlia routing table
- **Full Sync** — Header download → body download → block execution pipeline
- **Snap Sync** — 4-phase state machine: account download → storage download → bytecode download → trie healing
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
| EIP-196/197 | BN128 elliptic curve add, mul, pairing |
| EIP-4844 | Blob transactions, KZG point evaluation precompile |
| EIP-7702 | Set EOA account code (Prague) |

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
| `common/` | 6 | 2,256 | RLP, types, trie (+ proofs), crypto, config |
| `vm/` | 8 | 2,545 | EVM, opcodes, precompiles, gas |
| `storage/` | 3 | 672 | Store interface (+ snap methods), in-memory backend |
| `blockchain/` | 4 | 1,114 | Block validation, mempool, fork choice, simulate_call |
| `networking/` | 19 | 3,684 | RLPx, discovery, eth/68, snap/1, protocol registry, sync, server |
| `rpc/` | 3 | 590 | JSON-RPC server, eth API |
| `main.py` | 1 | 352 | CLI entry point |
| **Total** | **44** | **11,214** | |

### Test Code

| Test File | LOC | Tests | Covers |
|---|---:|---:|---|
| `test_rlp.py` | 206 | 56 | RLP encoding/decoding |
| `test_trie.py` | 213 | 26 | Merkle Patricia Trie |
| `test_trie_proofs.py` | 254 | 23 | Trie proof generation/verification, range proofs |
| `test_crypto.py` | 113 | 14 | keccak256, ECDSA, addresses |
| `test_evm.py` | 798 | 84 | Stack, memory, opcodes, precompiles |
| `test_storage.py` | 407 | 33 | Store CRUD, state root |
| `test_blockchain.py` | 514 | 31 | Header validation, block execution, mempool |
| `test_p2p.py` | 769 | 51 | RLPx, handshake, eth messages |
| `test_protocol_registry.py` | 168 | 16 | Multi-protocol capability negotiation |
| `test_snap_messages.py` | 267 | 21 | snap/1 message encode/decode roundtrip |
| `test_snap_sync.py` | 303 | 21 | Snap sync state machine, response handlers |
| `test_rpc.py` | 590 | 57 | JSON-RPC endpoints, eth_call/estimateGas EVM execution |
| `test_integration.py` | 250 | 12 | Cross-module integration |
| **Total** | **4,852** | **445** | |

## Current Limitations

- **Storage** — In-memory only (no disk backend; state is lost on restart)
- **Engine API** — Not implemented (no PoS consensus layer integration)
- **Transaction indexing** — Hash-based transaction/receipt lookups not implemented

## License

MIT
