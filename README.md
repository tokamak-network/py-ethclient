# py-ethclient

**A Python Ethereum execution client built from scratch**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-593%20passing-brightgreen)](#testing)
[![LOC](https://img.shields.io/badge/LOC-15%2C271-blue)](#project-stats)

py-ethclient is a fully independent Python implementation of an Ethereum Layer 1 execution client, inspired by [ethrex](https://github.com/lambdaclass/ethrex) (Rust). It connects directly to the Ethereum peer-to-peer network via devp2p/RLPx, implements the Ethereum Virtual Machine (EVM) with 140+ opcodes, and supports both full sync and snap sync for Mainnet and Sepolia.

All core protocol logic — RLP encoding, Merkle Patricia Trie, EVM execution, RLPx transport encryption, eth/68 and snap/1 wire protocols, Discovery v4, and the Engine API — is implemented from scratch in pure Python. Only cryptographic primitives and the web framework are external dependencies.

> **[한국어 README](./README_ko.md)**

## Table of Contents

- [Key Features](#key-features)
- [Why py-ethclient?](#why-py-ethclient)
- [Requirements](#requirements)
- [Installation](#installation)
- [Docker](#docker)
- [Quick Start](#quick-start)
- [JSON-RPC API](#json-rpc-api)
- [Testing](#testing)
- [Architecture](#architecture)
- [Dependencies](#dependencies)
- [Implementation Details](#implementation-details)
- [Project Stats](#project-stats)
- [FAQ](#faq)

## Key Features

- **Full EVM** — 140+ opcodes, precompiles (ecrecover, SHA-256, RIPEMD-160, modexp, BN128, BLAKE2f, KZG), EIP-1559/2929/2930/4844/7702 support
- **Ethereum P2P Networking** — RLPx encrypted transport, eth/68 and snap/1 wire protocols, Discovery v4 with Kademlia routing
- **Sync Modes** — Full sync (sequential block execution) and snap sync (4-phase parallel state download)
- **JSON-RPC 2.0** — 20+ methods including `eth_call`, `eth_estimateGas`, transaction/receipt lookups, log queries
- **Engine API V1/V2/V3** — `forkchoiceUpdated`, `getPayload`, `newPayload` with JWT authentication for consensus layer integration
- **Persistent Storage** — LMDB-backed disk backend with hybrid overlay pattern for atomic state commits
- **Multi-Network** — Mainnet, Sepolia, and Holesky with per-network genesis and fork configurations
- **593 Tests** — Comprehensive test suite covering all protocol layers from RLP to end-to-end integration
- **Docker Support** — Ready-to-use Docker Compose setup for quick deployment
- **L2 Extensibility** — Built-in execution hook system for Layer 2 customization without modifying EVM core

## Why py-ethclient?

Ethereum client diversity is critical for network resilience. py-ethclient is the only Ethereum execution client written in Python, making it uniquely valuable for:

- **Education & Research** — Python's readability makes it the best codebase for understanding how Ethereum actually works at the protocol level. Every component (EVM, RLPx, Merkle tries, sync) is implemented in clear, readable Python
- **Rapid Prototyping** — Test new EIPs, custom opcodes, or consensus changes in hours instead of days. Python's dynamic nature enables fast iteration on protocol experiments
- **L2 Development** — The built-in execution hook system lets you build a Layer 2 execution environment without modifying any core EVM code
- **Client Diversity** — Adding a Python client to the Ethereum ecosystem (alongside Go, Rust, C#, Java) strengthens the network against implementation-specific bugs

### Comparison with Other Execution Clients

| | py-ethclient | [geth](https://github.com/ethereum/go-ethereum) | [reth](https://github.com/paradigmxyz/reth) | [nethermind](https://github.com/NethermindEth/nethermind) |
|---|---|---|---|---|
| **Language** | Python | Go | Rust | C# |
| **Purpose** | Education, Research, L2 | Production | Production | Production |
| **EVM** | 140+ opcodes | Full | Full | Full |
| **Sync modes** | Full + Snap | Full + Snap + Light | Full + Snap | Full + Snap + Fast |
| **Engine API** | V1/V2/V3 | V1/V2/V3 | V1/V2/V3 | V1/V2/V3 |
| **P2P protocols** | eth/68, snap/1 | eth/68, snap/1 | eth/68, snap/1 | eth/68, snap/1 |
| **Code readability** | Very High | High | Medium | Medium |
| **Extensibility** | Hook system | Plugin | Modular | Plugin |

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
| `--data-dir` | — | Data directory for persistent storage (in-memory if not set) |
| `--datadir` | — | Alias for `--data-dir` (geth-compatible) |
| `--engine-port` | `8551` | Engine API JSON-RPC listen port |
| `--metrics-port` | `6060` | Prometheus metrics listen port |
| `--bootnode-only` | off | Only dial configured bootnodes |
| `--archive` | off | Enable archive mode RPC semantics for historical state queries |
| `--jwt-secret` | — | JWT secret or path to jwtsecret file for Engine API auth |

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
| `eth_getTransactionByHash` | Transaction by hash |
| `eth_getTransactionReceipt` | Transaction receipt |
| `eth_getBlockTransactionCountByNumber` | Transaction count in block (by number) |
| `eth_getBlockTransactionCountByHash` | Transaction count in block (by hash) |
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

**engine_ namespace** (served on `--engine-port`, JWT-authenticated)

| Method | Description |
|---|---|
| `engine_exchangeCapabilities` | Capability negotiation |
| `engine_getClientVersionV1` | Client version info |
| `engine_forkchoiceUpdatedV1/V2/V3` | Fork choice state update + payload build trigger |
| `engine_getPayloadV1/V2/V3` | Retrieve built execution payload |
| `engine_newPayloadV1/V2/V3` | Validate and import execution payload |

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
pytest tests/test_rpc.py              # JSON-RPC server + Engine API
pytest tests/test_disk_backend.py     # LMDB persistent storage
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
│   ├── memory_backend.py            # In-memory implementation, state root computation
│   └── disk_backend.py              # LMDB-backed persistent storage with overlay
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
│       ├── full_sync.py             # Full sync pipeline (+ head discovery)
│       └── snap_sync.py             # Snap sync 4-phase state machine
└── rpc/                             # JSON-RPC server
    ├── server.py                    # FastAPI-based JSON-RPC 2.0 dispatcher
    ├── eth_api.py                   # eth_/net_/web3_ API handlers
    ├── engine_api.py                # Engine API V1/V2/V3 handlers
    └── engine_types.py              # Engine API request/response types
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
| [lmdb](https://pypi.org/project/lmdb/) | LMDB key-value store for persistent storage |

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
- **Full Sync** — Peer head discovery via best_hash → header download → body download → block execution pipeline
- **Snap Sync** — 4-phase state machine: account download → storage download → bytecode download → trie healing
- **Engine API** — V1/V2/V3 forkchoiceUpdated, getPayload, newPayload; deterministic payload ID, payload queue, JWT authentication
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
| `common/` | 6 | 2,374 | RLP, types, trie (+ proofs), crypto, config |
| `vm/` | 8 | 2,703 | EVM, opcodes, precompiles, gas |
| `storage/` | 4 | 1,431 | Store interface, in-memory & LMDB backends |
| `blockchain/` | 4 | 1,353 | Block validation, mempool, fork choice, simulate_call |
| `networking/` | 19 | 5,117 | RLPx, discovery, eth/68, snap/1, protocol registry, sync, server |
| `rpc/` | 5 | 1,660 | JSON-RPC server, eth API, Engine API |
| `main.py` | 1 | 633 | CLI entry point |
| **Total** | **47** | **15,271** | |

### Test Code

| Test File | LOC | Tests | Covers |
|---|---:|---:|---|
| `test_rlp.py` | 206 | 56 | RLP encoding/decoding |
| `test_trie.py` | 213 | 26 | Merkle Patricia Trie |
| `test_trie_proofs.py` | 254 | 23 | Trie proof generation/verification, range proofs |
| `test_crypto.py` | 113 | 14 | keccak256, ECDSA, addresses |
| `test_evm.py` | 821 | 88 | Stack, memory, opcodes, precompiles |
| `test_storage.py` | 387 | 65 | Store CRUD, state root (both backends parametrized) |
| `test_blockchain.py` | 617 | 37 | Header validation, block execution, mempool, fork choice |
| `test_p2p.py` | 1,624 | 90 | RLPx, handshake, eth messages, head discovery |
| `test_rpc.py` | 909 | 76 | JSON-RPC endpoints, eth_call/estimateGas, Engine API, tx/receipt lookup |
| `test_protocol_registry.py` | 177 | 17 | Multi-protocol capability negotiation |
| `test_snap_messages.py` | 267 | 21 | snap/1 message encode/decode roundtrip |
| `test_snap_sync.py` | 446 | 29 | Snap sync state machine, response handlers |
| `test_integration.py` | 272 | 14 | Cross-module integration |
| `test_disk_backend.py` | 543 | 31 | LMDB persistence, flush, overlay, state root consistency |
| `integration/` | 68 | 6 | Archive mode, chaindata, Fusaka compliance |
| **Total** | **6,917** | **593** | |

## FAQ

**Is there a Python Ethereum execution client?**
Yes — py-ethclient is a fully functional Ethereum execution client written entirely in Python. It implements the EVM with 140+ opcodes, connects to the Ethereum P2P network via RLPx (eth/68, snap/1), and supports both full sync and snap sync for Mainnet and Sepolia.

**Can py-ethclient sync with Ethereum mainnet?**
Yes. py-ethclient connects to Ethereum mainnet and Sepolia testnet peers, performs peer discovery via Discovery v4, and synchronizes using either full sync (sequential block execution) or snap sync (parallel state download). It has been live-tested against Geth nodes on both networks.

**How does py-ethclient compare to geth?**
geth (Go Ethereum) is the most widely used production execution client. py-ethclient implements the same core protocols (EVM, eth/68, snap/1, Engine API) but is written in Python for readability and research purposes. While geth is optimized for production performance, py-ethclient prioritizes code clarity, making it ideal for learning how Ethereum works at the protocol level.

**Can I use py-ethclient to build an L2?**
Yes. py-ethclient includes a built-in execution hook system (`ExecutionHook`) that lets you customize EVM behavior — including pre/post-execution hooks, call interception, and state change tracking — without modifying any core code. This makes it a practical foundation for L2 execution layer development.

**What EIPs does py-ethclient support?**
py-ethclient supports EIP-155 (replay protection), EIP-1559 (dynamic fees), EIP-2718 (typed transactions), EIP-2929/2930 (access lists), EIP-4844 (blob transactions with KZG), and EIP-7702 (Prague EOA code). See the [Supported EIPs](#supported-eips) section for the full list.

## Current Limitations

- **Engine API** — V1/V2/V3 implemented; block production flow operational but ongoing optimization
- **eth_getLogs** — Stub implementation; log filtering not yet implemented
- **contractAddress** — Transaction receipt does not yet derive the contract address for CREATE transactions

## License

MIT
