# py-ethclient

**The Python L2 development platform — build application-specific ZK rollups in pure Python**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-943%20passing-brightgreen)](#testing)
[![LOC](https://img.shields.io/badge/LOC-21%2C442-blue)](#project-stats)

py-ethclient is a Python L2 development platform for building **application-specific ZK rollups**. Define your state transition function as a plain Python function, and py-ethclient handles the rest — sequencing, batching, Groth16 proving, and L1 verification.

Built on a fully independent Ethereum L1 execution client inspired by [ethrex](https://github.com/lambdaclass/ethrex) (Rust). It connects directly to the Ethereum P2P network via devp2p/RLPx, implements the EVM with 140+ opcodes, and supports full sync and snap sync for Mainnet and Sepolia. The built-in **Groth16 ZK proving**, **L1↔L2 General State Bridge**, and **application-specific rollup framework** make it the fastest way to prototype L2 protocols and ZK circuits.

All core protocol logic — RLP encoding, Merkle Patricia Trie, EVM execution, RLPx transport encryption, eth/68 and snap/1 wire protocols, Discovery v4, Engine API, Groth16 ZK proving, L1↔L2 bridge, and L2 rollup framework — is implemented from scratch in pure Python. Only cryptographic primitives and the web framework are external dependencies.

> **[한국어 README](./README_ko.md)**

## Table of Contents

- [Key Features](#key-features)
- [Why py-ethclient?](#why-py-ethclient)
- [L2 Rollup Framework](#l2-rollup-framework)
  - [Example Apps](#example-apps)
  - [Infrastructure Examples](#infrastructure-examples)
- [L2 Bridge](#l2-bridge)
- [ZK Toolkit](#zk-toolkit)
- [Requirements](#requirements)
- [Installation](#installation)
- [Docker](#docker)
- [Quick Start](#quick-start)
- [JSON-RPC API](#json-rpc-api)
- [Testing](#testing)
- [Claude Code Skills](#claude-code-skills)
- [Architecture](#architecture)
- [Dependencies](#dependencies)
- [Implementation Details](#implementation-details)
- [Project Stats](#project-stats)
- [FAQ](#faq)

## Key Features

- **Application-Specific ZK Rollup** — Define your rollup logic as a Python function (State Transition Function), plug it into the Rollup orchestrator, and get automatic sequencing, Groth16 proving, and L1 verification out of the box
- **4 Pluggable Interfaces** — StateTransitionFunction, DAProvider, L1Backend, ProofBackend — swap any component without touching the rest
- **Full Prove-Verify Pipeline** — Sequencer → Batch → Groth16 Proof → L1 Verification, all in a single Python process
- **L2 RPC API** — 7 `l2_*` JSON-RPC methods for transaction submission, state queries, batch production, and proof submission
- **L1↔L2 General State Bridge** — Optimism-style CrossDomainMessenger with pluggable relay handlers (EVM, Merkle proof, ZK proof, TinyDB, direct state), force inclusion (anti-censorship), and escape hatch (value recovery)
- **Groth16 ZK Toolkit** — Circuit definition, trusted setup, proof generation, native + EVM verification, gas profiling, snarkjs compatibility — all in pure Python
- **Full EVM** — 140+ opcodes, precompiles (ecrecover, SHA-256, RIPEMD-160, modexp, BN128, BLAKE2f, KZG), EIP-1559/2929/2930/4844/7702 support
- **Ethereum P2P Networking** — RLPx encrypted transport, eth/68 and snap/1 wire protocols, Discovery v4 with Kademlia routing
- **Sync Modes** — Full sync (sequential block execution) and snap sync (4-phase parallel state download)
- **JSON-RPC 2.0** — 20+ methods including `eth_call`, `eth_estimateGas`, transaction/receipt lookups, log queries, `zk_` and `l2_` namespaces
- **Engine API V1/V2/V3** — `forkchoiceUpdated`, `getPayload`, `newPayload` with JWT authentication for consensus layer integration
- **Persistent Storage** — LMDB-backed disk backend with hybrid overlay pattern for atomic state commits
- **Multi-Network** — Mainnet, Sepolia, and Holesky with per-network genesis and fork configurations
- **943 Tests** — Comprehensive test suite covering all protocol layers from RLP to ZK proving to L2 rollup to end-to-end integration
- **Docker Support** — Ready-to-use Docker Compose setup for quick deployment

## Why py-ethclient?

Ethereum client diversity is critical for network resilience. py-ethclient is the only Ethereum execution client written in Python, making it uniquely valuable for:

- **Application-Specific L2 Development** — Write your rollup logic as a plain Python function. The framework handles sequencing, batching, Groth16 proving, and L1 verification. No Solidity, no circom, no complex toolchains — just Python
- **ZK Circuit Development** — Define circuits in Python, generate proofs, and test on-chain verification in a single Jupyter notebook. No circom/snarkjs/Solidity toolchain needed — the fastest way to prototype ZK applications, especially with AI coding agents
- **Education & Research** — Python's readability makes it the best codebase for understanding how Ethereum actually works at the protocol level. Every component (EVM, RLPx, Merkle tries, sync) is implemented in clear, readable Python
- **Rapid Prototyping** — Test new EIPs, custom opcodes, or consensus changes in hours instead of days. Python's dynamic nature enables fast iteration on protocol experiments
- **Client Diversity** — Adding a Python client to the Ethereum ecosystem (alongside Go, Rust, C#, Java) strengthens the network against implementation-specific bugs

### Comparison with Other Execution Clients

| | py-ethclient | [geth](https://github.com/ethereum/go-ethereum) | [reth](https://github.com/paradigmxyz/reth) | [nethermind](https://github.com/NethermindEth/nethermind) |
|---|---|---|---|---|
| **Language** | Python | Go | Rust | C# |
| **Purpose** | L2 Development, ZK, Education | Production | Production | Production |
| **App-Specific Rollup** | Built-in framework | N/A | N/A | N/A |
| **ZK Proving** | Built-in Groth16 | N/A | N/A | N/A |
| **L2 Bridge** | Built-in CrossDomainMessenger | N/A | N/A | N/A |
| **EVM** | 140+ opcodes | Full | Full | Full |
| **Sync modes** | Full + Snap | Full + Snap + Light | Full + Snap | Full + Snap + Fast |
| **Engine API** | V1/V2/V3 | V1/V2/V3 | V1/V2/V3 | V1/V2/V3 |
| **P2P protocols** | eth/68, snap/1 | eth/68, snap/1 | eth/68, snap/1 | eth/68, snap/1 |
| **Code readability** | Very High | High | Medium | Medium |

## L2 Rollup Framework

py-ethclient includes a complete **application-specific ZK rollup framework**. Define your state transition logic as a plain Python function, and the framework handles sequencing, batching, Groth16 proving, and L1 verification.

### Quick Example: Counter Rollup

```python
from ethclient.l2 import Rollup, L2Tx, L2TxType

# 1. Define your State Transition Function — just a Python function
def counter_stf(state, tx):
    count = state.get("count", 0)
    if tx.data.get("action") == "increment":
        state["count"] = count + 1
        return {"new_count": count + 1}

# 2. Create a Rollup with your STF
rollup = Rollup(stf=counter_stf)
rollup.setup()  # Groth16 trusted setup + L1 verifier deployment

# 3. Submit transactions
tx = L2Tx(sender=b"\x01"*20, nonce=0, data={"action": "increment"},
          tx_type=L2TxType.CALL)
rollup.submit_tx(tx)

# 4. Produce batch + prove + verify on L1
batch = rollup.produce_batch()
receipt = rollup.prove_and_submit(batch)

assert receipt.verified          # L1 accepted the proof
assert rollup.state["count"] == 1
```

### How It Works

```
User Tx → Sequencer → State Transition Function → Batch Assembly
                                                        ↓
                          L1 Verification ← Groth16 Proof ← DA Storage
```

1. **Sequencer** receives transactions, validates nonces, executes STF with snapshot/rollback
2. **Batch** is sealed when `max_txs_per_batch` is reached or `force_seal()` is called
3. **Groth16 Prover** generates a ZK proof over old_state_root → new_state_root transition
4. **L1 Backend** verifies the proof and records the new state root

### Pluggable Components

The framework uses 4 pluggable interfaces — swap any component without touching the rest:

| Interface | Default | Description |
|---|---|---|
| `StateTransitionFunction` | `PythonRuntime` (wraps any callable) | Your rollup logic |
| `DAProvider` | `LocalDAProvider` (in-memory) | Data availability storage |
| `ProofBackend` | `Groth16ProofBackend` | ZK proof generation and verification |
| `L1Backend` | `InMemoryL1Backend` | L1 contract interaction (verifier) |

```python
from ethclient.l2 import Rollup, L2Config

# Custom configuration
config = L2Config(
    name="my-rollup",
    chain_id=42170,
    max_txs_per_batch=128,
    batch_timeout=30,
    rpc_port=9545,
)

# Plug in custom components
rollup = Rollup(
    stf=my_stf_function,
    da=my_custom_da,        # implement DAProvider
    l1=my_l1_backend,       # implement L1Backend
    prover=my_prover,       # implement ProofBackend
    config=config,
)
```

### Example Apps

9 ready-to-run app examples demonstrate real-world use cases on the rollup framework:

| Example | Description | Run |
|---|---|---|
| **ERC20 Token** | Mint, transfer, burn with admin control | `python examples/apps/l2_token.py` |
| **Name Service** | ENS-style domain register, update, transfer | `python examples/apps/l2_nameservice.py` |
| **Voting** | Proposal creation, weighted voting, quorum-based finalization | `python examples/apps/l2_voting.py` |
| **Rock-Paper-Scissors** | Commit-reveal game with betting and settlement | `python examples/apps/l2_rps_game.py` |
| **DEX (AMM)** | Constant product AMM with LP tokens, 0.3% fee, slippage checks | `python examples/apps/l2_dex.py` |
| **NFT Marketplace** | Mint, list, buy, transfer with 5% creator royalties | `python examples/apps/l2_nft_marketplace.py` |
| **Multisig Wallet** | N-of-M approval, propose/approve/execute workflow | `python examples/apps/l2_multisig.py` |
| **Escrow** | 3-party escrow with state machine (Created→Funded→Released/Refunded) | `python examples/apps/l2_escrow.py` |
| **Prediction Market** | Create markets, bet, oracle resolution, proportional payout | `python examples/apps/l2_prediction_market.py` |

### Infrastructure Examples

10 infrastructure examples demonstrate production features:

| Example | Description | Run |
|---|---|---|
| **RPC Server** | JSON-RPC server with APIKey/RateLimit/RequestSize middleware | `python examples/infra/l2_rpc_server.py` |
| **Persistent State** | LMDB persistence + crash recovery via WAL replay | `python examples/infra/l2_persistent_state.py` |
| **DA Providers** | Local vs Calldata (EIP-1559) vs Blob (EIP-4844) comparison | `python examples/infra/l2_da_providers.py` |
| **Censorship Resistance** | Force inclusion + escape hatch when sequencer censors | `python examples/infra/l2_censorship_resistance.py` |
| **Multi-Batch Ops** | 15-batch loop with prove/submit separation | `python examples/infra/l2_multi_batch_ops.py` |
| **Config Full-Stack** | L2Config-based backend auto-wiring + NativeProver fallback | `python examples/infra/l2_config_fullstack.py` |
| **State Bridge** | L1↔L2 general state bridge end-to-end | `python examples/infra/general_state_bridge.py` |
| **Relay Modes** | EVM, Merkle, ZK proof, TinyDB, Direct relay comparison | `python examples/infra/bridge_relay_modes.py` |
| **ZK Notebook** | Groth16 circuit → setup → prove → verify → EVM demo | `python examples/infra/zk_notebook_demo.py` |
| **ZK Note Settle** | ZK proof-based note settlement | `python examples/infra/zk_note_settle.py` |

Each example follows the same pattern: define an STF → wrap with `PythonRuntime` → create `Rollup` → submit txs → produce batches → prove and verify on L1.

### Balance Transfer Example

```python
def balance_stf(state, tx):
    action = tx.data.get("action")
    if action == "mint":
        addr = tx.data["to"]
        amount = tx.data["amount"]
        state[addr] = state.get(addr, 0) + amount
        return {"minted": amount, "to": addr}
    elif action == "transfer":
        src, dst = tx.data["from"], tx.data["to"]
        amount = tx.data["amount"]
        if state.get(src, 0) < amount:
            raise ValueError("insufficient balance")
        state[src] -= amount
        state[dst] = state.get(dst, 0) + amount
        return {"transferred": amount}

rollup = Rollup(stf=balance_stf)
rollup.setup()
# mint, transfer, produce batch, prove, verify — all works
```

### L2 CLI

```bash
# Scaffold a new rollup project
ethclient l2 init --name my-rollup

# This creates:
#   l2.json      — rollup configuration
#   stf.py       — State Transition Function template

# Start the rollup node (loads stf.py, starts RPC server)
ethclient l2 start --config l2.json --rpc-port 9545

# Generate ZK proofs for all sealed batches
ethclient l2 prove --config l2.json

# Submit proven batches to L1
ethclient l2 submit --config l2.json
```

### L2 RPC API

When running with the L2 module, 7 additional JSON-RPC methods are available:

| Method | Description |
|---|---|
| `l2_sendTransaction` | Submit a transaction to the rollup |
| `l2_getState` | Get current rollup state |
| `l2_getStateRoot` | Get current Merkle state root |
| `l2_getBatch` | Query a sealed batch by number |
| `l2_produceBatch` | Trigger batch production |
| `l2_proveAndSubmit` | Prove a batch and submit to L1 |
| `l2_chainInfo` | Get rollup chain info (name, chain_id, batch count, etc.) |

## L2 Bridge

py-ethclient includes an **L1↔L2 General State Bridge** — an Optimism-style `CrossDomainMessenger` that relays arbitrary messages between L1 and L2 with real EVM execution on the target domain.

```python
from ethclient.bridge import BridgeEnvironment

# Create L1 + L2 environment (two independent EVMs + watcher)
env = BridgeEnvironment()

# Deposit: Alice sends 1 ETH from L1 to Bob on L2
env.send_l1(sender=alice, target=bob, value=1000)
result = env.relay()  # watcher relays L1→L2
assert result.all_success
assert env.l2_balance(bob) == 1000

# State relay: relay arbitrary calldata to L2 contracts
env.send_l1(sender=alice, target=oracle, data=price_calldata)
env.relay()  # executes calldata on L2's EVM
```

### Anti-Censorship

If an L2 operator censors messages, users can bypass them:

| Mechanism | Description |
|---|---|
| **Force Inclusion** | Register censored message on L1 → after 50 blocks, anyone can force-relay to L2 |
| **Escape Hatch** | Last resort: recover deposited value directly on L1 when L2 is unresponsive |

```python
# Operator censors Alice's message
msg = env.send_l1(sender=alice, target=bob, value=1000)
env.l1_messenger.drain_outbox()  # operator takes but doesn't relay

# Force inclusion path
env.force_include(msg)
env.advance_l1_block(50)  # wait for inclusion window
result = env.force_relay(msg)
assert result.success  # bypasses operator

# Or escape hatch (value recovery on L1)
result = env.escape_hatch(msg)
assert env.l1_balance(alice) == 1000  # value returned
```

### Pluggable Relay Handlers

The bridge supports multiple relay modes — L2 doesn't need to run EVM:

| Handler | Trust Model | EVM Required |
|---|---|---|
| `EVMRelayHandler` | On-chain execution (default) | Yes |
| `MerkleProofHandler` | Merkle proof against trusted L1 root | No |
| `ZKProofHandler` | Groth16 zero-knowledge proof | No |
| `TinyDBHandler` | Document DB backend (TinyDB) | No |
| `DirectStateHandler` | Trusted relayer | No |

```python
from ethclient.bridge import BridgeEnvironment, StateUpdate, encode_state_updates

# Direct state relay (no EVM needed)
env = BridgeEnvironment.with_direct_state()
updates = [StateUpdate(address=alice, balance=1000)]
env.send_l1(sender=alice, target=bob, data=encode_state_updates(updates))
env.relay()

# ZK proof relay
env = BridgeEnvironment.with_zk_proof(vk)  # pass Groth16 verification key
```

Run the full demo:

```bash
python examples/infra/general_state_bridge.py
```

## ZK Toolkit

py-ethclient includes a **Groth16 ZK proving toolkit** — the only Python environment where you can define circuits, generate proofs, and test EVM on-chain verification in a single process.

```python
from ethclient.zk import Circuit, groth16
from ethclient.zk.evm_verifier import EVMVerifier

# 1. Define circuit (Python expressions)
c = Circuit()
x, y = c.private("x"), c.private("y")
z = c.public("z")
c.constrain(x * y, z)   # R1CS: x * y = z

# 2. Trusted setup
pk, vk = groth16.setup(c)

# 3. Generate proof
proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)

# 4. Native verification
assert groth16.verify(vk, proof, [15])

# 5. EVM on-chain verification (uses built-in EVM + ecPairing precompile)
result = EVMVerifier(vk).verify_on_evm(proof, [15])
assert result.success  # gas_used ≈ 210,000
```

### What's Included

| Component | Description |
|---|---|
| **Circuit Builder** | Python operator overloading for R1CS constraint definition |
| **Groth16 Prover** | Full proving pipeline: R1CS → QAP → trusted setup → proof generation |
| **Native Verifier** | Pairing-based verification with debug mode (intermediate pairing values) |
| **EVM Verifier** | Auto-generated verifier bytecode using ecAdd/ecMul/ecPairing precompiles |
| **Gas Profiler** | Per-precompile gas breakdown for on-chain cost optimization |
| **snarkjs Compat** | Import/export snarkjs JSON format (vkey, proof, public inputs) |
| **ZK RPC API** | `zk_verifyGroth16`, `zk_deployVerifier`, `zk_verifyOnChain` endpoints |

### Why Not circom + snarkjs?

| | circom + snarkjs + Hardhat | py-ethclient |
|---|---|---|
| **Languages needed** | circom (DSL) + Node.js + Solidity | Python only |
| **Tools to install** | Rust compiler + Node.js + Solidity toolchain | `pip install py-ethclient` |
| **Circuit → Proof → Verify** | 5 CLI commands across 3 tools | 3 Python function calls |
| **EVM testing** | Deploy to testnet | In-memory EVM, instant |
| **Debug failures** | Hex dump analysis | Python traceback + pairing values |
| **AI agent friendly** | Multiple tools, niche DSL | Python (best language for AI agents) |
| **Iteration speed** | Minutes (compile → setup → prove → deploy) | Seconds |

Run the full demo:

```bash
python examples/infra/zk_notebook_demo.py
```

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

### L2 Rollup Mode

```bash
# Scaffold a new rollup project
ethclient l2 init --name my-rollup

# Edit stf.py to define your State Transition Function
# Then start the rollup node
ethclient l2 start --config l2.json
```

### L1 Node Mode

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

**L2 Commands**

| Command | Description |
|---|---|
| `ethclient l2 init --name <name>` | Scaffold a new rollup project (creates l2.json + stf.py) |
| `ethclient l2 start --config <path>` | Start the L2 rollup node (loads STF, starts RPC server) |
| `ethclient l2 prove --config <path>` | Generate ZK proofs for all sealed batches |
| `ethclient l2 submit --config <path>` | Submit proven batches to L1 |

**L1 Node Options**

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

**l2_ namespace** (L2 rollup operations)

| Method | Description |
|---|---|
| `l2_sendTransaction` | Submit a transaction to the rollup |
| `l2_getState` | Get current rollup state dict |
| `l2_getStateRoot` | Get current Merkle state root (hex) |
| `l2_getBatch` | Query a sealed batch by number |
| `l2_produceBatch` | Trigger batch production |
| `l2_proveAndSubmit` | Prove a batch and submit to L1 |
| `l2_chainInfo` | Get rollup chain info |

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

**zk_ namespace**

| Method | Description |
|---|---|
| `zk_verifyGroth16` | Verify a Groth16 proof (accepts snarkjs or native format) |
| `zk_deployVerifier` | Deploy a verifier contract and return bytecode + gas estimate |
| `zk_verifyOnChain` | Verify a proof on-chain via the in-memory EVM |

### Usage Examples

```bash
# Submit L2 transaction
curl -X POST http://localhost:9545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"l2_sendTransaction","params":[{"sender":"0x01","data":{"action":"increment"}}],"id":1}'

# Get L2 state root
curl -X POST http://localhost:9545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"l2_getStateRoot","params":[],"id":1}'

# Get latest block number (L1)
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

## Testing

```bash
# Run all tests (943 tests)
pytest

# Run L2 rollup tests
pytest tests/test_l2_types.py            # L2 types, encoding, state snapshots
pytest tests/test_l2_da.py               # Data availability provider
pytest tests/test_l2_da_providers.py     # Production DA providers (S3, Calldata, Blob)
pytest tests/test_l2_runtime.py          # Python STF runtime wrapper
pytest tests/test_l2_sequencer.py        # Sequencer, mempool, batch assembly
pytest tests/test_l2_sequencer_hardening.py # Sequencer input validation, defensive checks
pytest tests/test_l2_prover.py           # Groth16 proof backend
pytest tests/test_l2_native_prover.py    # Native prover (rapidsnark/snarkjs subprocess)
pytest tests/test_l2_l1.py               # L1 backend, proof verification
pytest tests/test_l2_eth_l1_backend.py   # Real Ethereum L1 backend (JSON-RPC)
pytest tests/test_l2_rpc.py              # L2 RPC API (l2_* methods)
pytest tests/test_l2_state.py            # State store boundary checks, determinism
pytest tests/test_l2_persistent_state.py # LMDB persistent state, overlay, WAL
pytest tests/test_l2_health.py           # Health/ready endpoints
pytest tests/test_l2_middleware.py       # RPC middleware (API key, rate limit, request size)
pytest tests/test_l2_integration.py      # Full cycle: STF → batch → prove → L1 verify

# Run L1 client tests
pytest tests/test_rlp.py                 # RLP encoding/decoding
pytest tests/test_trie.py                # Merkle Patricia Trie
pytest tests/test_trie_proofs.py         # Trie Merkle proofs & range verification
pytest tests/test_evm.py                 # EVM opcode execution
pytest tests/test_storage.py             # State storage
pytest tests/test_blockchain.py          # Block validation/execution
pytest tests/test_p2p.py                 # P2P networking
pytest tests/test_protocol_registry.py   # Multi-protocol capability negotiation
pytest tests/test_snap_messages.py       # snap/1 message encoding/decoding
pytest tests/test_snap_sync.py           # Snap sync state machine
pytest tests/test_rpc.py                 # JSON-RPC server + Engine API
pytest tests/test_disk_backend.py        # LMDB persistent storage

# Run ZK tests
pytest tests/test_zk_circuit.py          # ZK circuit builder (R1CS)
pytest tests/test_zk_groth16.py          # Groth16 prove/verify + snarkjs compat
pytest tests/test_zk_evm.py              # EVM-based ZK verification

# Run bridge tests
pytest tests/test_bridge_messenger.py    # L2 bridge messenger send/relay
pytest tests/test_bridge_e2e.py          # L2 bridge end-to-end scenarios
pytest tests/test_bridge_censorship.py   # Force inclusion + escape hatch
pytest tests/test_bridge_proof_relay.py  # Proof-based relay handlers

# Run integration tests
pytest tests/test_integration.py         # End-to-end integration

# Verbose output
pytest -v
```

## Claude Code Skills

This project includes 7 [Claude Code](https://claude.com/claude-code) skills that provide domain-specific guidance. Invoke them with `/<skill-name>` in Claude Code.

| Skill | Command | Description |
|-------|---------|-------------|
| L2 Rollup | `/l2-rollup <app name or use case>` | Create app-specific ZK rollups — STF definition, PythonRuntime, Rollup lifecycle |
| ZK Circuit | `/zk-circuit <circuit or verification target>` | Build arithmetic circuits & Groth16 proofs — setup, prove, verify, EVM on-chain |
| Bridge | `/bridge <use case or direction>` | L1↔L2 bridge — CrossDomainMessenger, force inclusion, escape hatch |
| Sepolia Deploy | `/sepolia-deploy <app or contract>` | Deploy to Sepolia testnet — EthL1Backend, EIP-1559 tx, on-chain verification |
| Test | `/test <module or feature>` | Run & write tests — pytest commands, patterns, coverage |
| L1 Node | `/l1-node <task or question>` | L1 Ethereum node — EVM, eth/68, snap/1, Engine API, P2P |
| Debug P2P | `/debug-p2p <error message or symptom>` | Debug P2P networking — RLPx, devp2p, sync issues |

### Example Usage

```bash
# In Claude Code, type:
/l2-rollup token transfer app
/zk-circuit merkle proof verification
/bridge L1→L2 deposit
/test l2 sequencer
```

## Architecture

```
ethclient/
├── main.py                          # CLI entry point, node initialization
├── l2/                              # Application-specific ZK rollup framework
│   ├── types.py                     # L2Tx, L2State, Batch, BatchReceipt, STFResult
│   ├── config.py                    # L2Config (chain_id, batch size, timeouts)
│   ├── interfaces.py                # 4 ABCs: STF, DAProvider, L1Backend, ProofBackend
│   ├── state.py                     # L2StateStore (Trie-based Merkle state roots)
│   ├── runtime.py                   # PythonRuntime (wraps callable → STF)
│   ├── da.py                        # LocalDAProvider (in-memory DA)
│   ├── da_s3.py                     # S3DAProvider (AWS S3 DA)
│   ├── da_calldata.py               # CalldataDAProvider (EIP-1559 L1 calldata DA)
│   ├── da_blob.py                   # BlobDAProvider (EIP-4844 blob DA)
│   ├── sequencer.py                 # Sequencer (mempool, nonce tracking, batch assembly)
│   ├── prover.py                    # Groth16ProofBackend (circuit → proof → verify)
│   ├── native_prover.py             # NativeProverBackend (rapidsnark/snarkjs subprocess)
│   ├── l1_backend.py                # InMemoryL1Backend (verifier simulation)
│   ├── eth_l1_backend.py            # EthL1Backend (real Ethereum L1 via JSON-RPC)
│   ├── eth_rpc.py                   # Lightweight Ethereum JSON-RPC client
│   ├── persistent_state.py          # L2PersistentStateStore (LMDB state, overlay, WAL)
│   ├── submitter.py                 # BatchSubmitter (prove → submit → verify pipeline)
│   ├── rollup.py                    # Rollup orchestrator (main user-facing API)
│   ├── rpc_api.py                   # l2_* JSON-RPC method registration
│   ├── health.py                    # /health, /ready, /metrics endpoints
│   ├── metrics.py                   # L2MetricsCollector (operational metrics)
│   ├── middleware.py                # APIKey, RateLimit, RequestSize middleware
│   └── cli.py                       # CLI: ethclient l2 {init|start|prove|submit}
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
├── zk/                              # ZK proving toolkit
│   ├── circuit.py                   # R1CS circuit builder (Signal, Circuit, R1CS)
│   ├── groth16.py                   # Groth16 prover, verifier, debug verifier
│   ├── evm_verifier.py              # EVM verifier bytecode generator + executor
│   ├── snarkjs_compat.py            # snarkjs JSON format import/export
│   ├── r1cs_export.py               # R1CS binary export for snarkjs/circom compat
│   └── types.py                     # G1Point, G2Point, Proof, VerificationKey
├── bridge/                          # L1↔L2 General State Bridge
│   ├── types.py                     # CrossDomainMessage, RelayResult, ForceInclusionEntry
│   ├── relay_handlers.py            # RelayHandler ABC + EVM/Merkle/ZK/TinyDB/Direct handlers
│   ├── messenger.py                 # CrossDomainMessenger (send, relay, pluggable handlers)
│   ├── watcher.py                   # BridgeWatcher (outbox drain + relay + force queue)
│   └── environment.py               # BridgeEnvironment (L1+L2+Watcher + factory methods)
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
├── rpc/                             # JSON-RPC server
│   ├── server.py                    # FastAPI-based JSON-RPC 2.0 dispatcher
│   ├── eth_api.py                   # eth_/net_/web3_ API handlers
│   ├── engine_api.py                # Engine API V1/V2/V3 handlers
│   ├── engine_types.py              # Engine API request/response types
│   └── zk_api.py                    # zk_ namespace RPC handlers
└── examples/
    ├── apps/                            # L2 application STF examples
    │   ├── l2_token.py                  # ERC20 token (mint/transfer/burn)
    │   ├── l2_nameservice.py            # ENS-style name service
    │   ├── l2_voting.py                 # Governance (proposal/vote/finalize)
    │   ├── l2_rps_game.py               # Commit-reveal rock-paper-scissors
    │   ├── l2_dex.py                    # AMM DEX (constant product, LP tokens)
    │   ├── l2_nft_marketplace.py        # NFT marketplace with royalties
    │   ├── l2_multisig.py               # N-of-M multisig wallet
    │   ├── l2_escrow.py                 # 3-party escrow service
    │   └── l2_prediction_market.py      # Prediction market with oracle
    ├── infra/                           # Production infrastructure examples
    │   ├── l2_rpc_server.py             # RPC server + middleware
    │   ├── l2_persistent_state.py       # LMDB persistence + crash recovery
    │   ├── l2_da_providers.py           # DA layer comparison (Local/Calldata/Blob)
    │   ├── l2_censorship_resistance.py  # Force inclusion + escape hatch
    │   ├── l2_multi_batch_ops.py        # Multi-batch operations loop
    │   ├── l2_config_fullstack.py       # L2Config full-stack wiring
    │   ├── general_state_bridge.py      # L1↔L2 bridge end-to-end
    │   ├── bridge_relay_modes.py        # Relay modes comparison
    │   ├── zk_notebook_demo.py          # ZK toolkit end-to-end
    │   └── zk_note_settle.py            # ZK note settlement
    ├── l2_sepolia_hello.py              # Sepolia live deployment
    └── l2_sepolia_all.py                # Sepolia 4-app batch deployment
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

- **Application-Specific ZK Rollup Framework** — Pluggable STF/DA/Prover/L1 interfaces, Sequencer with mempool and nonce tracking, batch assembly with auto-seal, Groth16 proof backend with 128-bit field truncation, BatchSubmitter pipeline, Rollup orchestrator, L2 RPC API, CLI scaffolding
- **L2 State Management** — Trie-based Merkle state root computation for arbitrary key-value state, snapshot/rollback for atomic batch execution, tag-based encoding for mixed-type state values
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
- **Groth16 ZK Proving** — R1CS circuit builder with operator overloading, QAP via Lagrange interpolation, trusted setup with toxic waste, proof generation with randomization, pairing-based verification
- **EVM ZK Verifier** — Auto-generated EVM bytecode for on-chain Groth16 verification using ecAdd/ecMul/ecPairing precompiles, gas profiling, execution tracing
- **snarkjs Compatibility** — Round-trip import/export of snarkjs vkey.json and proof.json formats
- **L1↔L2 General State Bridge** — Optimism-style CrossDomainMessenger with arbitrary message relay, EVM execution on target domain, replay protection, force inclusion (anti-censorship with 50-block window), escape hatch (L1 value recovery)
- **Bridge Watcher** — Automated outbox drain, bidirectional message relay, force queue processing

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
| `l2/` | 24 | 3,024 | App-specific ZK rollup: STF, sequencer, prover, L1 backend, rollup orchestrator, RPC, CLI, production DA (S3/Calldata/Blob), native prover, LMDB state, middleware |
| `common/` | 6 | 2,282 | RLP, types, trie (+ proofs), crypto, config |
| `vm/` | 8 | 2,690 | EVM, opcodes, precompiles, gas |
| `storage/` | 4 | 1,431 | Store interface, in-memory & LMDB backends |
| `blockchain/` | 4 | 1,291 | Block validation, mempool, fork choice, simulate_call |
| `networking/` | 19 | 5,075 | RLPx, discovery, eth/68, snap/1, protocol registry, sync, server |
| `zk/` | 7 | 1,929 | Groth16 circuit builder, prover, verifier, EVM verifier, snarkjs compat, R1CS export |
| `bridge/` | 6 | 1,241 | CrossDomainMessenger, BridgeWatcher, BridgeEnvironment, force inclusion, escape hatch |
| `rpc/` | 6 | 1,832 | JSON-RPC server, eth API, Engine API, ZK API |
| `main.py` | 1 | 647 | CLI entry point |
| **Total** | **86** | **21,442** | |

### Test Code

| Test File | LOC | Tests | Covers |
|---|---:|---:|---|
| `test_l2_types.py` | 153 | 20 | L2 tx types, encoding/decoding, state snapshots, input validation |
| `test_l2_da.py` | 56 | 8 | Data availability provider |
| `test_l2_da_providers.py` | 611 | 40 | Production DA providers (S3, Calldata, Blob) |
| `test_l2_runtime.py` | 99 | 9 | Python STF runtime wrapper |
| `test_l2_sequencer.py` | 198 | 12 | Sequencer, mempool, batch assembly, auto-seal, nonce gap, multi-sender |
| `test_l2_sequencer_hardening.py` | 173 | 12 | Sequencer input validation, defensive checks |
| `test_l2_prover.py` | 193 | 17 | Groth16 proof backend, field truncation, tampering rejection |
| `test_l2_native_prover.py` | 243 | 14 | Native prover backend (rapidsnark/snarkjs subprocess) |
| `test_l2_l1.py` | 86 | 6 | L1 backend, proof verification, batch tracking |
| `test_l2_eth_l1_backend.py` | 229 | 12 | Real Ethereum L1 backend (EIP-1559 tx, EVMVerifier) |
| `test_l2_rpc.py` | 133 | 14 | L2 RPC API (l2_* methods), input validation |
| `test_l2_state.py` | 32 | 3 | State store boundary checks, state root determinism |
| `test_l2_persistent_state.py` | 269 | 34 | LMDB persistent state, overlay, WAL, batch/proof persistence |
| `test_l2_health.py` | 56 | 3 | Health/ready endpoints |
| `test_l2_middleware.py` | 141 | 13 | RPC middleware (API key, rate limit, request size) |
| `test_l2_integration.py` | 274 | 13 | Full cycle: counter STF, balance transfer, multi-batch, state persistence |
| `test_rlp.py` | 207 | 56 | RLP encoding/decoding |
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
| `test_zk_circuit.py` | 292 | 26 | ZK circuit builder, R1CS, field arithmetic |
| `test_zk_groth16.py` | 267 | 18 | Groth16 prove/verify, debug verify, snarkjs compat |
| `test_zk_evm.py` | 162 | 13 | EVM verification, gas profiling, execution trace |
| `test_bridge_messenger.py` | 225 | 11 | Bridge messenger send/relay, replay protection |
| `test_bridge_e2e.py` | 174 | 10 | Bridge E2E: deposit, withdraw, roundtrip, state relay |
| `test_bridge_censorship.py` | 270 | 14 | Force inclusion + escape hatch (anti-censorship) |
| `test_bridge_proof_relay.py` | 585 | 28 | Proof-based relay handlers (EVM, Merkle, ZK, TinyDB, Direct) |
| `test_integration.py` | 272 | 14 | Cross-module integration |
| `test_disk_backend.py` | 543 | 31 | LMDB persistence, flush, overlay, state root consistency |
| `integration/` | 68 | 6 | Archive mode, chaindata, Fusaka compliance |
| **Total** | **11,839** | **943** | |

## FAQ

**Can I build an application-specific rollup with py-ethclient?**
Yes — py-ethclient includes a complete application-specific ZK rollup framework. Define your state transition logic as a plain Python function, and the framework handles sequencing, batching, Groth16 proving, and L1 verification. See the [L2 Rollup Framework](#l2-rollup-framework) section.

**How does the rollup framework work?**
You write a State Transition Function (STF) — a Python function that takes `(state, tx)` and mutates state. The Sequencer collects transactions, executes the STF, and assembles batches. The Groth16 prover generates a ZK proof over the state transition, and the L1 backend verifies it. All 4 components (STF, DA, Prover, L1) are pluggable interfaces.

**Is there a Python Ethereum execution client?**
Yes — py-ethclient is a fully functional Ethereum execution client written entirely in Python. It implements the EVM with 140+ opcodes, connects to the Ethereum P2P network via RLPx (eth/68, snap/1), and supports both full sync and snap sync for Mainnet and Sepolia.

**Can py-ethclient sync with Ethereum mainnet?**
Yes. py-ethclient connects to Ethereum mainnet and Sepolia testnet peers, performs peer discovery via Discovery v4, and synchronizes using either full sync (sequential block execution) or snap sync (parallel state download). It has been live-tested against Geth nodes on both networks.

**How does py-ethclient compare to geth?**
geth (Go Ethereum) is the most widely used production execution client. py-ethclient implements the same core protocols (EVM, eth/68, snap/1, Engine API) but is written in Python for readability and research purposes. While geth is optimized for production performance, py-ethclient prioritizes code clarity, making it ideal for learning how Ethereum works at the protocol level.

**What is the L2 bridge?**
The L2 bridge is an Optimism-style `CrossDomainMessenger` that relays arbitrary messages between L1 and L2. Messages are executed on the target domain's EVM, producing real state changes. It includes force inclusion (bypass censoring operators after a 50-block window) and an escape hatch (recover deposited value on L1 when L2 is unresponsive). See the [L2 Bridge](#l2-bridge) section.

**What relay modes are available?**
The bridge supports 5 relay handlers: EVMRelayHandler (default, full EVM execution), MerkleProofHandler (Merkle proof against trusted L1 state root), ZKProofHandler (Groth16 zero-knowledge proof verification), TinyDBHandler (document DB backend for non-EVM L2), and DirectStateHandler (trusted relayer, direct state application). With proof-based relay, L2 can use any runtime — not just EVM.

**Can I use py-ethclient for ZK development?**
Yes. py-ethclient includes a built-in Groth16 ZK proving toolkit. You can define R1CS circuits using Python expressions, generate proofs, verify them natively or on the in-memory EVM, profile gas costs, and export to snarkjs format — all without installing circom, snarkjs, or Solidity toolchains. See the [ZK Toolkit](#zk-toolkit) section.

**Is the ZK prover production-ready?**
The prover is implemented in pure Python (using py_ecc for BN128 curve operations), so it's best suited for education, prototyping, and small circuits (< 1000 constraints). For production proving, use snarkjs or rapidsnark for proof generation, then verify the proofs with py-ethclient's native or EVM verifier.

**What EIPs does py-ethclient support?**
py-ethclient supports EIP-155 (replay protection), EIP-1559 (dynamic fees), EIP-2718 (typed transactions), EIP-2929/2930 (access lists), EIP-4844 (blob transactions with KZG), and EIP-7702 (Prague EOA code). See the [Supported EIPs](#supported-eips) section for the full list.

## Current Limitations

- **Engine API** — V1/V2/V3 implemented; block production flow operational but ongoing optimization
- **eth_getLogs** — Stub implementation; log filtering not yet implemented
- **contractAddress** — Transaction receipt does not yet derive the contract address for CREATE transactions

## License

MIT
