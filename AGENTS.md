# AGENTS.md — py-ethclient Guide

Python Ethereum L1 execution client. Fully independent port referencing ethrex (Rust).

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Unit tests (511 tests, ~7s)
pytest

# Test a specific module
pytest tests/test_rlp.py
pytest tests/test_evm.py -v

# Live network verification (connects to mainnet, ~30s)
python3 test_full_sync.py

# Run the node
ethclient --network mainnet --port 30303

# Snap sync (default)
ethclient --network sepolia

# Full sync mode
ethclient --network sepolia --sync-mode full

# Docker
docker compose up -d                        # Mainnet
NETWORK=sepolia docker compose up -d        # Sepolia
docker compose logs -f                      # View logs
docker compose down                         # Stop
```

## Project Structure

```
py-ethclient/                    # ~15,900 LOC (source + tests)
├── ethclient/
│   ├── main.py                  # CLI entry point (argparse, asyncio event loop)
│   ├── common/                  # Foundation modules (no internal dependencies)
│   │   ├── rlp.py               # RLP encoding/decoding
│   │   ├── types.py             # BlockHeader, Transaction, Receipt, Account, TxType
│   │   ├── trie.py              # Merkle Patricia Trie (state root, proofs, range proofs)
│   │   ├── crypto.py            # keccak256, secp256k1, ECDSA, address derivation
│   │   └── config.py            # Chain config, hardfork params, ForkID, genesis
│   ├── vm/                      # EVM implementation
│   │   ├── evm.py               # Fetch-decode-execute main loop
│   │   ├── opcodes.py           # Opcode handlers (full Istanbul support)
│   │   ├── precompiles.py       # Precompiled contracts (ecrecover, modexp, etc.)
│   │   ├── gas.py               # Gas calculation (EIP-2929 cold/warm)
│   │   ├── memory.py            # Byte-addressable memory
│   │   ├── call_frame.py        # 256-bit stack + call frames
│   │   └── hooks.py             # Execution hook interface (L2 extensibility)
│   ├── storage/                 # State storage
│   │   ├── store.py             # Store interface (account/code/storage CRUD + snap sync)
│   │   ├── memory_backend.py    # Dict-based in-memory backend
│   │   └── disk_backend.py     # LMDB-backed persistent storage with overlay
│   ├── blockchain/              # Blockchain engine
│   │   ├── chain.py             # Block validation/execution, PoW rewards, base fee, simulate_call
│   │   ├── mempool.py           # Transaction pool (nonce ordering, replacement)
│   │   └── fork_choice.py       # Canonical chain, reorg handling
│   ├── networking/              # P2P networking
│   │   ├── server.py            # P2P server — multi-protocol dispatch
│   │   ├── protocol_registry.py # Dynamic capability negotiation & offset calculation
│   │   ├── rlpx/                # RLPx encrypted transport layer
│   │   │   ├── handshake.py     # ECIES handshake (EIP-8 support)
│   │   │   ├── framing.py       # Message framing + Snappy compression
│   │   │   └── connection.py    # TCP connection management
│   │   ├── eth/                 # eth/68 sub-protocol
│   │   │   ├── protocol.py      # Message codes, constants
│   │   │   └── messages.py      # Status, GetBlockHeaders, BlockBodies, etc.
│   │   ├── snap/                # snap/1 sub-protocol
│   │   │   ├── protocol.py      # SnapMsg enum (relative codes 0-7)
│   │   │   └── messages.py      # 8 message types (encode/decode)
│   │   ├── discv4/              # Discovery v4 (UDP peer discovery)
│   │   │   ├── discovery.py     # Ping/Pong/FindNeighbours/Neighbours
│   │   │   └── routing.py       # k-bucket routing table
│   │   └── sync/                # Sync engines
│   │       ├── full_sync.py     # Full sync pipeline (+ head discovery)
│   │       └── snap_sync.py     # Snap sync 4-phase state machine
│   └── rpc/                     # JSON-RPC server
│       ├── server.py            # FastAPI-based dispatcher
│       └── eth_api.py           # eth_ namespace handlers
├── tests/                       # pytest unit tests (511 tests)
│   ├── test_rlp.py              # RLP encoding/decoding
│   ├── test_trie.py             # MPT + Ethereum official test vectors
│   ├── test_trie_proofs.py      # Trie Merkle proofs & range verification
│   ├── test_crypto.py           # Cryptography, ECDSA, address derivation
│   ├── test_evm.py              # Stack, memory, gas, opcodes, precompiles
│   ├── test_storage.py          # Store CRUD, state root
│   ├── test_blockchain.py       # Block validation/execution, mempool, fork choice
│   ├── test_p2p.py              # RLPx, handshake, eth messages
│   ├── test_protocol_registry.py # Multi-protocol capability negotiation
│   ├── test_snap_messages.py    # snap/1 message encode/decode roundtrip
│   ├── test_snap_sync.py        # Snap sync state machine, response handlers
│   ├── test_rpc.py              # JSON-RPC endpoints
│   └── test_integration.py      # Cross-module integration tests
├── test_full_sync.py            # Live mainnet verification test (standalone)
├── Dockerfile                   # Ubuntu-based container image
├── docker-compose.yml           # One-command deployment
├── .dockerignore                # Build context exclusions
└── pyproject.toml               # Python 3.12+, dependency definitions
```

## Module Dependency Graph

```
common (rlp, types, trie, crypto, config)
  ↓
vm (evm, opcodes, precompiles, gas)
  ↓
storage (store, memory_backend, disk_backend)
  ↓
blockchain (chain, mempool, fork_choice)
  ↓
networking (rlpx, discv4, eth, snap, sync, server)  +  rpc (server, eth_api)
  ↓
main.py (unified entry point)
```

Lower modules never depend on higher modules. `common` can be safely imported from anywhere.

## Testing

### Unit Tests (offline)

```bash
pytest                           # All tests (511, ~7s)
pytest tests/test_rlp.py         # RLP only
pytest tests/test_evm.py -k "test_add"  # Specific test
pytest -v                        # Verbose output
pytest --tb=short                # Short tracebacks
```

Test coverage by file:

| File | Tests | Covers |
|------|------:|--------|
| test_rlp.py | 56 | RLP encoding/decoding, round-trip |
| test_trie.py | 26 | MPT, Ethereum official vectors |
| test_trie_proofs.py | 23 | Proof generation/verification, range proofs, iterate |
| test_crypto.py | 14 | keccak256, ECDSA, addresses |
| test_evm.py | 84 | Stack, memory, all opcodes, precompiles (BN128, KZG) |
| test_storage.py | 33 | Store CRUD, state root, snap storage |
| test_blockchain.py | 31 | Header validation, base fee, block execution, mempool |
| test_p2p.py | 57 | RLPx, handshake, eth messages, head discovery |
| test_protocol_registry.py | 16 | Capability negotiation, offset calculation |
| test_snap_messages.py | 21 | snap/1 message encode/decode roundtrip |
| test_snap_sync.py | 21 | Snap sync state machine, response handlers |
| test_rpc.py | 57 | JSON-RPC, eth_call/estimateGas EVM execution |
| test_integration.py | 12 | Cross-module integration |

### Live Network Test

```bash
python3 test_full_sync.py        # Mainnet peer connection + block verification
```

Verifies: header chain links, transaction roots (MPT), ECDSA sender recovery, EIP-1559 base fee, all 5 tx types (Legacy/AccessList/FeeMarket/Blob/SetCode).

## Core Types

### BlockHeader (`common/types.py`)

21 RLP fields (post-Prague). `block_hash()` computes `keccak256(rlp(header))`.

Key fields: `parent_hash`, `coinbase`, `state_root`, `transactions_root`, `number`, `gas_limit`, `gas_used`, `base_fee_per_gas`, `withdrawals_root`, `blob_gas_used`, `excess_blob_gas`, `parent_beacon_block_root`, `requests_hash`.

### Transaction (`common/types.py`)

5 transaction types:
- `TxType.LEGACY = 0` — EIP-155
- `TxType.ACCESS_LIST = 1` — EIP-2930
- `TxType.FEE_MARKET = 2` — EIP-1559
- `TxType.BLOB = 3` — EIP-4844
- `TxType.SET_CODE = 4` — EIP-7702 (Prague)

Encoding: Legacy uses raw RLP; all others use `type_byte || rlp(fields)`.

Each type has a different set of fields for `signing_hash()`. Use `recover_sender()` for ECDSA recovery.

## Gotchas and Important Patterns

### EthMsg vs SnapMsg Offset

`EthMsg` enum values already include the `0x10` offset:
```python
class EthMsg(IntEnum):
    STATUS = 0x10
    GET_BLOCK_HEADERS = 0x13
    BLOCK_HEADERS = 0x14
    # ...
```
Never use `0x10 + EthMsg.XXX` — this causes a double-offset bug.

`SnapMsg` enum uses **relative codes** (0-7). Absolute wire codes are computed at runtime by `NegotiatedCapabilities`:
```python
class SnapMsg(IntEnum):
    GET_ACCOUNT_RANGE = 0
    ACCOUNT_RANGE = 1
    # ... (0-7)
```
The protocol registry assigns snap/1 offsets dynamically (typically 0x21-0x28 after eth/68's 0x10-0x20).

### Protocol Registry

Multi-protocol capability negotiation follows the RLPx spec:
1. Sort capabilities alphabetically by name
2. Assign contiguous message ID ranges starting from 0x10
3. `negotiate_capabilities(local, remote)` → `NegotiatedCapabilities`
4. `resolve_msg_code(abs_code)` → `(protocol_name, relative_code)`
5. `absolute_code(protocol_name, relative_code)` → absolute wire code

### Post-Prague Headers

Post-Prague block headers have 21 RLP fields. `requests_hash` (EIP-7685) is appended at index 20. If this field is missing, `block_hash()` returns incorrect values.

### BlockBodies Withdrawals

Post-Shanghai block bodies are 3-element tuples: `[txs, ommers, withdrawals]`. Pre-Shanghai bodies are 2-element: `[txs, ommers]`.

### RLP Decoding

`rlp.decode_list()` decodes the top-level list. Numeric values must be converted via `rlp.decode_uint()`. Empty bytes `b""` are interpreted as 0 (handled by `decode_uint`).

### Snappy Compression

In RLPx, all sub-protocol messages (`msg_code >= 0x10`) use Snappy compression/decompression. This covers both eth (0x10+) and snap (0x21+) messages. p2p messages (Hello=0x00, Disconnect=0x01, etc.) are not compressed.

## Snap Sync Architecture

### 4-Phase State Machine

```
IDLE → ACCOUNT_DOWNLOAD → STORAGE_DOWNLOAD → BYTECODE_DOWNLOAD → TRIE_HEALING → COMPLETE
```

1. **Account Download** — GetAccountRange/AccountRange: iterate entire account trie by range, verify Merkle proofs
2. **Storage Download** — GetStorageRanges/StorageRanges: download slots for accounts with non-empty storage
3. **Bytecode Download** — GetByteCodes/ByteCodes: batch-request contract bytecodes by unique code hash
4. **Trie Healing** — GetTrieNodes/TrieNodes: fill in missing trie nodes caused by chain progression

### Key Classes

- `SnapSyncState` — Progress state (cursors, queues, counters)
- `SnapSync` — Sync engine with `start(peers, target_root, target_block)`
- Response handlers: `handle_account_range`, `handle_storage_ranges`, `handle_byte_codes`, `handle_trie_nodes`

### Peer Selection

```python
snap_peers = [p for p in peers if p.snap_supported]
# Falls back to full sync if no snap-capable peers
```

## Areas for Improvement

1. **Genesis state initialization** — Parse go-ethereum's genesis alloc data to build initial state
2. **Engine API** — `engine_` namespace for Beacon Chain integration
4. **EVM test suite** — Expand EVM correctness verification with ethereum/tests official vectors
5. **Performance** — Trie caching, parallel transaction verification, asyncio optimization

## Dependencies

| Package | Purpose |
|---------|---------|
| pycryptodome | AES, SHA256, RIPEMD160 |
| coincurve | secp256k1 (ECDSA, ECDH) |
| eth-hash[pycryptodome] | keccak256 |
| fastapi + uvicorn | JSON-RPC server |
| python-snappy | RLPx message compression |
| py-ecc | BN128 ecAdd/ecMul/ecPairing |
| ckzg | KZG point evaluation (EIP-4844) |
| pytest + pytest-asyncio | Testing (dev) |

## Network Connection

```python
# Mainnet bootnodes
MAINNET_BOOTNODES = [
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666d@18.138.108.67:30303",
    "enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",
    # ...
]

# Sepolia bootnodes
SEPOLIA_BOOTNODES = [
    "enode://4e5e92199ee224a01932a377160aa432f31d0b351f84ab413a8e0a42f4f36476f8fb1cbe914af0d9aef0d51571571c4f3e910c9719571f16ae5e168d9b09f8258@138.197.51.181:30303",
    # ...
]
```

CLI: `ethclient --network sepolia --bootnodes enode://...`

## Post-Change Checklist

1. `common/types.py` changed → run `test_rlp.py`, `test_blockchain.py`
2. `common/trie.py` changed → run `test_trie.py`, `test_trie_proofs.py`
3. `vm/` changed → run `test_evm.py`
4. `networking/` changed → run `test_p2p.py`, `test_protocol_registry.py`, `test_snap_messages.py`
5. `networking/sync/` changed → run `test_snap_sync.py` + `test_full_sync.py`
6. `blockchain/` changed → run `test_blockchain.py` + `test_integration.py` + `test_rpc.py`
7. New hardfork support → add fork block/timestamp to `config.py`, add new fields to `types.py`
8. Full regression: `pytest && python3 test_full_sync.py`
