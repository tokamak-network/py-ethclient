# AGENTS.md — py-ethclient Guide

A Python L2 development platform for building application-specific ZK rollups. Define your State Transition Function as a plain Python function — the framework handles sequencing, batching, Groth16 proving, and L1 verification. Built on a fully independent Ethereum L1 execution client with EVM, RLPx, eth/68, snap/1, full+snap sync, Engine API, L1↔L2 bridge, and Groth16 ZK toolkit — all in pure Python.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Unit tests (943 tests)
pytest

# Test a specific module
pytest tests/test_rlp.py
pytest tests/test_l2_sequencer.py -v

# Run the L2 rollup
ethclient l2 start --config l2.json

# Run the L1 node
ethclient --network mainnet --port 30303

# Snap sync (default)
ethclient --network sepolia

# Docker
docker compose up -d                        # Mainnet
NETWORK=sepolia docker compose up -d        # Sepolia
```

### L2 Rollup Quick Example

```python
from ethclient.l2.rollup import Rollup

def counter_stf(state, tx):
    count = state.get("count", 0) + 1
    return {"count": count, "result": f"count={count}"}

rollup = Rollup(stf=counter_stf, name="counter")
rollup.submit_tx({"action": "increment"})
rollup.submit_tx({"action": "increment"})
batch = rollup.seal_batch()       # Execute pending txs
receipt = rollup.prove_batch(batch)  # Groth16 proof
result = rollup.submit_batch(receipt)  # L1 verification
assert result["l1_verified"] is True
```

### Sepolia Node Runbook

```bash
# Snap sync (recommended)
ethclient --network sepolia --sync-mode snap --port 30303 --rpc-port 8545 --engine-port 8551 --max-peers 25 --data-dir data/sepolia --log-level INFO

# Full sync mode
ethclient --network sepolia --sync-mode full --port 30303 --rpc-port 8545 --engine-port 8551 --max-peers 25 --data-dir data/sepolia --log-level INFO
```

Monitoring:

```bash
watch -n 5 '
  echo "peerCount:";
  curl -s -H "content-type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"net_peerCount\",\"params\":[],\"id\":1}" \
    http://127.0.0.1:8545;
  echo;
  echo "blockNumber:";
  curl -s -H "content-type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":2}" \
    http://127.0.0.1:8545;
  echo
'
```

## Project Structure

```
py-ethclient/                    # ~33,200 LOC (21,442 source + 11,839 test)
├── ethclient/
│   ├── main.py                  # CLI entry point (argparse, asyncio event loop)
│   ├── l2/                      # L2 Rollup Framework (24 files, 3,024 LOC)
│   │   ├── rollup.py            # Main API — wraps STF, Sequencer, Prover, L1Backend
│   │   ├── types.py             # L2Tx, L2TxType, L2State, STFResult, Batch, BatchReceipt
│   │   ├── interfaces.py        # 4 pluggable ABCs — STF, DAProvider, L1Backend, ProofBackend
│   │   ├── sequencer.py         # Mempool + nonce tracking + STF execution + batch assembly
│   │   ├── prover.py            # Groth16ProofBackend — circuit build, prove, verify
│   │   ├── l1_backend.py        # InMemoryL1Backend — verifier deploy + proof verification
│   │   ├── state.py             # Trie-based Merkle state root for key-value state
│   │   ├── da.py                # LocalDAProvider — in-memory DA with keccak256 commitments
│   │   ├── runtime.py           # PythonRuntime — wraps Python callable as STF
│   │   ├── submitter.py         # BatchSubmitter — prove → submit → verify pipeline
│   │   ├── rpc_api.py           # 7 l2_* JSON-RPC methods
│   │   ├── cli.py               # ethclient l2 {init|start|prove|submit}
│   │   ├── config.py            # L2 chain configuration
│   │   ├── da_s3.py              # S3 DA provider
│   │   ├── da_calldata.py        # Calldata DA provider (EIP-1559)
│   │   ├── da_blob.py            # Blob DA provider (EIP-4844)
│   │   ├── native_prover.py      # NativeProverBackend (rapidsnark/snarkjs)
│   │   ├── eth_l1_backend.py     # Real Ethereum L1 backend (JSON-RPC)
│   │   ├── eth_rpc.py            # Lightweight Ethereum JSON-RPC client
│   │   ├── persistent_state.py   # LMDB-backed L2 state (overlay, WAL)
│   │   ├── health.py             # /health, /ready, /metrics endpoints
│   │   ├── metrics.py            # L2 metrics collector
│   │   └── middleware.py         # API key auth, rate limit, request size
│   ├── zk/                      # ZK Toolkit (7 files)
│   │   ├── circuit.py           # R1CS circuit builder with operator overloading
│   │   ├── groth16.py           # Full Groth16 pipeline — R1CS → QAP → setup → prove → verify
│   │   ├── evm_verifier.py      # Auto-generated EVM bytecode for on-chain verification
│   │   ├── snarkjs_compat.py    # Import/export snarkjs JSON format
│   │   ├── r1cs_export.py       # R1CS export utilities
│   │   └── types.py             # G1Point, G2Point, Proof, VerificationKey
│   ├── bridge/                  # L1↔L2 Bridge (5 files)
│   │   ├── messenger.py         # CrossDomainMessenger with Optimism-style relay
│   │   ├── relay_handlers.py    # EVM, Merkle proof, ZK proof, TinyDB, Direct handlers
│   │   ├── environment.py       # L1+L2+Watcher convenience wrapper
│   │   ├── watcher.py           # Automated outbox drain, relay, force queue
│   │   └── types.py             # CrossDomainMessage, MessageStatus, Domain
│   ├── common/                  # Foundation modules (no internal dependencies)
│   │   ├── rlp.py               # RLP encoding/decoding
│   │   ├── types.py             # BlockHeader, Transaction, Receipt, Account, TxType
│   │   ├── trie.py              # Merkle Patricia Trie (state root, proofs, range proofs)
│   │   ├── crypto.py            # keccak256, secp256k1, ECDSA, address derivation
│   │   └── config.py            # Chain config, hardfork params, ForkID, genesis
│   ├── vm/                      # EVM implementation
│   │   ├── evm.py               # Fetch-decode-execute main loop
│   │   ├── opcodes.py           # 140+ opcode handlers
│   │   ├── precompiles.py       # Precompiled contracts (ecrecover, modexp, BN128, KZG)
│   │   ├── gas.py               # Gas calculation (EIP-2929 cold/warm)
│   │   ├── memory.py            # Byte-addressable memory
│   │   ├── call_frame.py        # 256-bit stack + call frames
│   │   └── hooks.py             # Execution hook interface (L2 extensibility)
│   ├── storage/                 # State storage
│   │   ├── store.py             # Store interface (account/code/storage CRUD + snap sync)
│   │   ├── memory_backend.py    # Dict-based in-memory backend
│   │   └── disk_backend.py      # LMDB-backed persistent storage with overlay
│   ├── blockchain/              # Blockchain engine
│   │   ├── chain.py             # Block validation/execution, base fee, simulate_call
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
│       ├── eth_api.py           # eth_ namespace handlers
│       ├── engine_api.py        # Engine API V1/V2/V3 handlers
│       ├── engine_types.py      # Engine API request/response types
│       └── zk_api.py            # zk_ namespace (verifyGroth16, deployVerifier, verifyOnChain)
├── tests/                       # pytest unit tests (943 tests)
│   ├── test_l2_types.py         # L2 types, state, serialization
│   ├── test_l2_sequencer.py     # Sequencer, mempool, batch assembly
│   ├── test_l2_prover.py        # Groth16 proof backend
│   ├── test_l2_l1.py            # L1 backend, verifier deployment
│   ├── test_l2_da.py            # DA provider, commitments
│   ├── test_l2_runtime.py       # Python runtime, STF wrapping
│   ├── test_l2_integration.py   # End-to-end rollup pipeline
│   ├── test_zk_circuit.py       # R1CS circuit builder
│   ├── test_zk_groth16.py       # Groth16 setup/prove/verify
│   ├── test_zk_evm.py           # EVM on-chain verification
│   ├── test_bridge_messenger.py # CrossDomainMessenger
│   ├── test_bridge_e2e.py       # Bridge end-to-end
│   ├── test_bridge_proof_relay.py # Proof relay handlers
│   ├── test_bridge_censorship.py # Force inclusion, escape hatch
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
│   ├── test_rpc.py              # JSON-RPC endpoints + Engine API
│   ├── test_disk_backend.py     # LMDB persistent storage
│   └── test_integration.py      # Cross-module integration tests
├── tests/integration/           # Integration test suite
│   ├── archive_mode_test.py     # Archive mode RPC semantics
│   ├── chaindata_test.py        # Chaindata persistence
│   └── fusaka_compliance_test.py # Fusaka fork compliance
├── tests/live/                  # Live network tests (require real peers)
│   ├── test_full_sync.py        # Mainnet verification sync
│   ├── test_tx_lookup.py        # Sepolia tx hash lookup
│   └── test_mainnet_discovery.py # Mainnet discv4 discovery
├── Dockerfile                   # Ubuntu-based container image
├── docker-compose.yml           # One-command deployment
└── pyproject.toml               # Python 3.12+, dependency definitions
```

## Module Dependency Graph

```
common (rlp, types, trie, crypto, config)
  ↓
vm (evm, opcodes, precompiles, gas, hooks)
  ↓
storage (store, memory_backend, disk_backend)
  ↓
blockchain (chain, mempool, fork_choice)
  ↓                            ↓
networking (rlpx, discv4,      rpc (server, eth_api, engine_api, zk_api)
  eth, snap, sync, server)       ↓
  ↓                            l2/rpc_api (7 l2_* methods)
main.py                         ↓
                          ┌─── l2 (rollup, sequencer, prover, submitter, ...)
                          │      ↓ uses
                          ├─── zk (circuit, groth16, evm_verifier)
                          │      ↓ used by
                          └─── bridge (messenger, relay_handlers, watcher)
```

Lower modules never depend on higher modules. `common` can be safely imported from anywhere.
`l2` depends on `zk` for Groth16 proving and `common/trie` for Merkle state roots.
`bridge` depends on `vm` for EVM relay execution.

## L2 Rollup Architecture

### How It Works

```
User Python STF → Rollup.submit_tx() → Sequencer (mempool + ordering)
    → seal_batch() → STF execution with snapshot/rollback
    → prove_batch() → Groth16 proof (circuit → setup → prove)
    → submit_batch() → L1 verification (deploy verifier → verify on-chain)
```

### Pluggable Interfaces (`l2/interfaces.py`)

| Interface | Purpose | Default Implementation |
|-----------|---------|----------------------|
| `StateTransitionFunction` | `execute(state, tx) → STFResult` | `PythonRuntime` (any callable) |
| `DAProvider` | `submit(data) → commitment` | `LocalDAProvider` (in-memory) |
| `ProofBackend` | `prove(batch) → proof` | `Groth16ProofBackend` |
| `L1Backend` | `deploy_verifier()`, `verify_proof()` | `InMemoryL1Backend` |

### Key L2 Types (`l2/types.py`)

- `L2Tx` — Transaction with sender, nonce, L2TxType (TRANSFER/CALL/DEPLOY/SYSTEM)
- `L2State` — Trie-backed state with `get(key)`, `set(key, value)`, `root()` (Merkle root)
- `Batch` — Sealed batch: txs + pre_state_root + post_state_root + results
- `BatchReceipt` — Batch + Groth16 proof + DA commitment
- `STFResult` — Single tx result: success, output, state_diff, gas_used

## Testing

### Unit Tests (offline)

```bash
pytest                           # All tests (943)
pytest tests/test_l2_*.py        # L2 rollup tests (230)
pytest tests/test_zk_*.py        # ZK toolkit tests (57)
pytest tests/test_bridge_*.py    # Bridge tests (63)
pytest tests/test_rlp.py         # Specific module
pytest -v                        # Verbose output
pytest --tb=short                # Short tracebacks
```

Test coverage by file:

| File | Tests | Covers |
|------|------:|--------|
| **L2 Rollup** | **230** | |
| test_l2_types.py | 17 | L2 types, state, serialization |
| test_l2_sequencer.py | 10 | Sequencer, mempool, batch assembly |
| test_l2_prover.py | 10 | Groth16 proof backend |
| test_l2_l1.py | 6 | L1 backend, verifier deployment |
| test_l2_da.py | 8 | DA provider, commitments |
| test_l2_runtime.py | 9 | Python runtime, STF wrapping |
| test_l2_integration.py | 12 | End-to-end rollup pipeline |
| test_l2_da_providers.py | 40 | Production DA providers (S3, Calldata, Blob) |
| test_l2_sequencer_hardening.py | 12 | Sequencer input validation, defensive checks |
| test_l2_native_prover.py | 14 | Native prover (rapidsnark/snarkjs) |
| test_l2_eth_l1_backend.py | 12 | Real Ethereum L1 backend |
| test_l2_persistent_state.py | 34 | LMDB persistent state, overlay |
| test_l2_health.py | 3 | Health/ready endpoints |
| test_l2_middleware.py | 13 | RPC middleware |
| **ZK Toolkit** | **57** | |
| test_zk_circuit.py | 26 | R1CS circuit builder |
| test_zk_groth16.py | 18 | Groth16 setup/prove/verify |
| test_zk_evm.py | 13 | EVM on-chain verification |
| **L1↔L2 Bridge** | **63** | |
| test_bridge_messenger.py | 11 | CrossDomainMessenger |
| test_bridge_e2e.py | 10 | Bridge end-to-end |
| test_bridge_proof_relay.py | 28 | Proof relay handlers |
| test_bridge_censorship.py | 14 | Force inclusion, escape hatch |
| **L1 Core** | **593** | |
| test_rlp.py | 56 | RLP encoding/decoding, round-trip |
| test_trie.py | 26 | MPT, Ethereum official vectors |
| test_trie_proofs.py | 23 | Proof generation/verification, range proofs, iterate |
| test_crypto.py | 14 | keccak256, ECDSA, addresses |
| test_evm.py | 88 | Stack, memory, all opcodes, precompiles (BN128, KZG) |
| test_storage.py | 65 | Store CRUD, state root, snap storage (both backends parametrized) |
| test_blockchain.py | 37 | Header validation, base fee, block execution, mempool, fork choice |
| test_p2p.py | 90 | RLPx, handshake, eth messages, head discovery |
| test_protocol_registry.py | 17 | Capability negotiation, offset calculation |
| test_snap_messages.py | 21 | snap/1 message encode/decode roundtrip |
| test_snap_sync.py | 29 | Snap sync state machine, response handlers |
| test_rpc.py | 76 | JSON-RPC, eth_call/estimateGas EVM, Engine API, tx/receipt lookup |
| test_integration.py | 14 | Cross-module integration |
| test_disk_backend.py | 31 | LMDB persistence, flush, overlay, state root |
| integration/ | 6 | Archive mode, chaindata, Fusaka compliance |

### Live Network Test

```bash
python3 tests/live/test_full_sync.py   # Mainnet peer connection + block verification
```

Verifies: header chain links, transaction roots (MPT), ECDSA sender recovery, EIP-1559 base fee, all 5 tx types (Legacy/AccessList/FeeMarket/Blob/SetCode).

## Core Types

### L2 Types (`l2/types.py`)

```python
class L2TxType(IntEnum):
    TRANSFER = 0
    CALL = 1
    DEPLOY = 2
    SYSTEM = 3

@dataclass
class L2Tx:
    sender: str
    nonce: int
    tx_type: L2TxType
    payload: dict
    # ...

@dataclass
class Batch:
    batch_id: int
    txs: list[L2Tx]
    pre_state_root: bytes
    post_state_root: bytes
    results: list[STFResult]
```

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

## Gotchas and Important Patterns

### L2 Rollup Patterns

**STF must be pure**: The State Transition Function should be deterministic — same `(state, tx)` must always produce the same output for valid ZK proofs.

**Sequencer snapshot/rollback**: The sequencer takes a state snapshot before each tx. If the STF fails, it rolls back and marks the tx as failed rather than corrupting state.

**Batch sealing**: `seal_batch()` collects pending txs from the mempool, executes them via STF, and produces a `Batch` with pre/post state roots. The batch is then immutable.

### EthMsg vs SnapMsg Offset

`EthMsg` enum values already include the `0x10` offset:
```python
class EthMsg(IntEnum):
    STATUS = 0x10
    GET_BLOCK_HEADERS = 0x13
    BLOCK_HEADERS = 0x14
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

## CLI Reference

### L2 Commands

```bash
ethclient l2 init --name my-rollup                 # Scaffold L2 project
ethclient l2 start --config l2.json                 # Start sequencer
ethclient l2 prove --config l2.json                 # Generate Groth16 proof
ethclient l2 submit --config l2.json                # Submit to L1
```

### L1 Node Commands

```bash
ethclient --network mainnet --port 30303
ethclient --network sepolia --sync-mode snap
ethclient --network sepolia --sync-mode full
ethclient --network sepolia --data-dir data/sepolia  # Persistent storage
ethclient --network sepolia --engine-port 8551 --jwt-secret jwt.hex  # Engine API
```

## JSON-RPC API

### L2 Namespace

| Method | Description |
|--------|-------------|
| `l2_submitTransaction` | Submit L2 transaction |
| `l2_getState` | Query L2 state by key |
| `l2_getBatch` | Get batch by ID |
| `l2_getBatchReceipt` | Get batch receipt with proof |
| `l2_getTransactionResult` | Get individual tx result |
| `l2_pendingTransactions` | List mempool txs |
| `l2_chainInfo` | Get L2 chain info |

### ZK Namespace

| Method | Description |
|--------|-------------|
| `zk_verifyGroth16` | Off-chain Groth16 verification |
| `zk_deployVerifier` | Deploy EVM verifier contract |
| `zk_verifyOnChain` | On-chain proof verification |

### eth/net/web3 Namespace

20+ standard Ethereum JSON-RPC methods including `eth_call`, `eth_estimateGas`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getBlockByNumber`, `eth_blockNumber`, etc.

### Engine API

`engine_forkchoiceUpdatedV1/V2/V3`, `engine_getPayloadV1/V2/V3`, `engine_newPayloadV1/V2/V3`, `engine_exchangeCapabilities` — JWT-authenticated on separate port (default 8551).

## Dependencies

| Package | Purpose |
|---------|---------|
| pycryptodome | AES, SHA256, RIPEMD160 |
| coincurve | secp256k1 (ECDSA, ECDH) |
| eth-hash[pycryptodome] | keccak256 |
| fastapi + uvicorn | JSON-RPC server |
| python-snappy | RLPx message compression |
| py-ecc | BN128 ecAdd/ecMul/ecPairing (Groth16, precompiles) |
| ckzg | KZG point evaluation (EIP-4844) |
| lmdb | LMDB persistent storage |
| tinydb | TinyDB relay handler (bridge) |
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

1. `l2/` changed → run `test_l2_*.py` (230 tests)
2. `l2/sequencer.py` changed → run `test_l2_sequencer.py`, `test_l2_integration.py`
3. `l2/prover.py` changed → run `test_l2_prover.py`, `test_l2_integration.py`
4. `zk/` changed → run `test_zk_*.py` (57 tests)
5. `zk/groth16.py` changed → run `test_zk_groth16.py`, `test_l2_prover.py`
6. `bridge/` changed → run `test_bridge_*.py` (63 tests)
7. `common/types.py` changed → run `test_rlp.py`, `test_blockchain.py`
8. `common/trie.py` changed → run `test_trie.py`, `test_trie_proofs.py`
9. `vm/` changed → run `test_evm.py`, `test_zk_evm.py`
10. `networking/` changed → run `test_p2p.py`, `test_protocol_registry.py`, `test_snap_messages.py`
11. `networking/sync/` changed → run `test_snap_sync.py` + `tests/live/test_full_sync.py`
12. `blockchain/` changed → run `test_blockchain.py` + `test_integration.py` + `test_rpc.py`
13. `rpc/` changed → run `test_rpc.py`
14. New hardfork support → add fork block/timestamp to `config.py`, add new fields to `types.py`
15. Full regression: `pytest && python3 tests/live/test_full_sync.py`
