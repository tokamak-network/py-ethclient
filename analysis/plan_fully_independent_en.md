# Scenario A Implementation Plan: Fully Independent Port (~15,000 LOC)

Implement all components from scratch so the node can independently participate in the Ethereum network via devp2p.

External libraries limited to crypto primitives (pycryptodome, coincurve) and web framework (FastAPI). No py-evm, no py-trie, no pyrlp.

---

## Project Structure

```
py-ethclient/
├── pyproject.toml
├── ethclient/
│   ├── main.py                  # Entry point
│   ├── common/                  # Phase 1
│   │   ├── types.py             # Block, Header, Transaction, Receipt, Account
│   │   ├── rlp.py               # RLP encoding/decoding
│   │   ├── trie.py              # Merkle Patricia Trie
│   │   ├── crypto.py            # Keccak256, BLAKE2f, secp256k1
│   │   └── config.py            # Chain config, hardfork parameters
│   ├── vm/                      # Phase 2
│   │   ├── evm.py               # EVM main loop
│   │   ├── opcodes.py           # Opcode handlers
│   │   ├── precompiles.py       # Precompiled contracts
│   │   ├── gas.py               # Gas calculation
│   │   ├── memory.py            # Stack/memory management
│   │   ├── call_frame.py        # Call frame
│   │   └── hooks.py             # Execution hook interface (L2 extensibility)
│   ├── storage/                 # Phase 3
│   │   ├── store.py             # State store interface
│   │   └── memory_backend.py    # In-memory backend
│   ├── blockchain/              # Phase 4
│   │   ├── chain.py             # Block validation/execution
│   │   ├── mempool.py           # Transaction pool
│   │   └── fork_choice.py       # Fork choice
│   ├── networking/              # Phase 5
│   │   ├── rlpx/
│   │   │   ├── connection.py    # RLPx encrypted transport
│   │   │   ├── handshake.py     # ECIES handshake
│   │   │   └── framing.py       # Message framing
│   │   ├── discv4/
│   │   │   ├── discovery.py     # UDP peer discovery
│   │   │   └── routing.py       # k-bucket routing table
│   │   ├── eth/
│   │   │   ├── protocol.py      # eth/68 subprotocol
│   │   │   └── messages.py      # eth message types
│   │   ├── sync/
│   │   │   └── full_sync.py     # Full sync manager
│   │   └── server.py            # P2P server main loop
│   └── rpc/                     # Phase 6
│       ├── server.py            # JSON-RPC server
│       ├── eth_api.py           # eth_ namespace
│       └── engine_api.py        # Engine API
└── tests/
    ├── test_rlp.py
    ├── test_trie.py
    ├── test_evm.py
    ├── test_blockchain.py
    └── test_p2p.py
```

---

## Implementation Phases & Dependencies

```
Phase 1 (Common) ────────────────────────────┐
    │                                         │
    ├── Phase 2 (EVM)                         │
    │       │                                 │
    │       ├── Phase 3 (Storage)             │
    │       │       │                         │
    │       │       └── Phase 4 (Blockchain) ─┤
    │       │               │                 │
    │       │               ├── Phase 5 (P2P) │
    │       │               │                 │
    │       │               └── Phase 6 (RPC) │
    │       │                       │         │
    │       └───────────────────────┴── Phase 7 (Integration)
```

---

## Phase Details

### Phase 1: Common Foundation (~2,500-3,500 LOC)

No dependencies. Base modules used by all subsequent phases.

| # | Task | LOC | Ref (ethrex) | Description |
|---|---|---:|---|---|
| 1.1 | RLP encoding/decoding | ~400 | `crates/common/rlp/` | encode, decode, list/bytes distinction |
| 1.2 | Core type definitions | ~800 | `crates/common/types/` | Block, BlockHeader, Transaction (EIP-155/1559/2930/4844), Receipt, Account, Genesis |
| 1.3 | Crypto utilities | ~200 | `crates/common/crypto/` | keccak256 wrapper, secp256k1 sign/recover, address derivation |
| 1.4 | Merkle Patricia Trie | ~800 | `crates/common/trie/` | Node (Branch/Extension/Leaf), get/put/delete, state root computation |
| 1.5 | Chain configuration | ~300 | `crates/common/types/genesis.rs` | Hardfork block numbers, chain ID, genesis parsing |

**Verification**: RLP round-trip tests, Ethereum official trie test vectors

---

### Phase 2: EVM (~3,500-4,500 LOC)

Depends on Phase 1. Most logic-dense module.

| # | Task | LOC | Ref (ethrex) | Description |
|---|---|---:|---|---|
| 2.1 | Stack/memory/call frame | ~300 | `crates/vm/levm/call_frame.rs` | 256-bit stack, byte memory, call depth management |
| 2.2 | Gas calculation | ~400 | `crates/vm/levm/gas_cost.rs` | Per-opcode gas, memory expansion cost, EIP-2929 cold/warm |
| 2.3 | Arithmetic/bitwise/comparison opcodes | ~400 | `crates/vm/levm/opcode_handlers/arithmetic.rs`, `bitwise_comparison.rs` | ADD, MUL, SUB, DIV, MOD, EXP, LT, GT, EQ, AND, OR, XOR, etc. |
| 2.4 | Environment/block opcodes | ~300 | `crates/vm/levm/opcode_handlers/environment.rs`, `block.rs` | ADDRESS, BALANCE, CALLER, CALLVALUE, GASPRICE, BLOCKHASH, COINBASE, TIMESTAMP, etc. |
| 2.5 | Stack/memory/storage/flow opcodes | ~400 | `crates/vm/levm/opcode_handlers/stack_memory_storage_flow.rs` | POP, MLOAD, MSTORE, SLOAD, SSTORE, JUMP, JUMPI, PC, MSIZE, etc. |
| 2.6 | System opcodes | ~500 | `crates/vm/levm/opcode_handlers/system.rs` | CALL, CALLCODE, DELEGATECALL, STATICCALL, CREATE, CREATE2, SELFDESTRUCT, RETURN, REVERT |
| 2.7 | Logging/PUSH/DUP/SWAP | ~200 | `crates/vm/levm/opcode_handlers/logging.rs`, `push.rs`, `dup.rs`, `exchange.rs` | LOG0-4, PUSH1-32, DUP1-16, SWAP1-16 |
| 2.8 | Precompiles | ~600 | `crates/vm/levm/precompiles.rs` | ecrecover, SHA256, RIPEMD160, identity, modexp, ecadd, ecmul, ecpairing, BLAKE2f, KZG point eval |
| 2.9 | EVM main loop | ~400 | `crates/vm/levm/vm.rs` | fetch-decode-execute, substate (access lists, transient storage), checkpoint/rollback |
| 2.10 | Execution hook system | ~50 | `crates/vm/levm/hooks/` | ExecutionHook interface + DefaultHook (L1 no-op). Hook points: before_tx, before_call, on_state_change. Future L2 extensibility |

**Verification**: Ethereum Foundation EVM test suite (ethereum/tests)

**Design note — Hook system:**
The EVM main loop includes hook points at key execution moments (before tx execution, before CALL/CREATE, on state change). For L1-only, DefaultHook is a no-op. This adds ~50 LOC but enables future L2 extension without restructuring.

```python
# hooks.py (~50 LOC)
class ExecutionHook:
    def before_execution(self, tx): pass
    def before_call(self, msg): pass
    def on_state_change(self, addr, key, value): pass

class DefaultHook(ExecutionHook):
    pass  # L1: all hooks are no-op
```

---

### Phase 3: Storage (~500-800 LOC)

Depends on Phase 1. In-memory first.

| # | Task | LOC | Ref (ethrex) | Description |
|---|---|---:|---|---|
| 3.1 | Store interface | ~200 | `crates/storage/store.rs` | Account/code/storage CRUD, block header/body/receipt storage/retrieval |
| 3.2 | In-memory backend | ~300 | `crates/storage/backend/in_memory.rs` | dict-based implementation |
| 3.3 | State management | ~200 | `crates/storage/layering.rs` | Per-block state commit/rollback |

**Verification**: State root computation correctness tests

---

### Phase 4: Blockchain Engine (~1,500-2,000 LOC)

Depends on Phase 1, 2, 3.

| # | Task | LOC | Ref (ethrex) | Description |
|---|---|---:|---|---|
| 4.1 | Block header validation | ~300 | `crates/blockchain/blockchain.rs` | Timestamp, gas limit, difficulty/base fee validation |
| 4.2 | Transaction execution | ~400 | `crates/blockchain/vm.rs` | tx → EVM call, gas deduction, state changes, receipt generation |
| 4.3 | Block execution | ~300 | `crates/blockchain/blockchain.rs` | Header validation → sequential tx execution → state root check → commit |
| 4.4 | Mempool | ~300 | `crates/blockchain/mempool.rs` | Per-sender nonce-ordered queues, pending/queued management |
| 4.5 | Fork choice | ~200 | `crates/blockchain/fork_choice.rs` | Canonical chain management, reorg handling |

**Verification**: Compare execution results against known mainnet blocks

---

### Phase 5: P2P Networking (~4,000-5,500 LOC)

Depends on Phase 1, 4. Largest module.

| # | Task | LOC | Ref (ethrex) | Description |
|---|---|---:|---|---|
| 5.1 | ECIES encryption | ~300 | `crates/networking/p2p/rlpx/connection/` | secp256k1 ECDH + AES-256-CTR + HMAC-SHA256 |
| 5.2 | RLPx handshake | ~400 | `crates/networking/p2p/rlpx/connection/handshake.rs` | auth/ack messages, session key derivation |
| 5.3 | RLPx framing | ~300 | `crates/networking/p2p/rlpx/connection/codec.rs` | Message framing, encrypt/decrypt, snappy compression |
| 5.4 | p2p subprotocol | ~200 | `crates/networking/p2p/rlpx/p2p.rs` | Hello, Disconnect, Ping/Pong |
| 5.5 | eth subprotocol messages | ~400 | `crates/networking/p2p/rlpx/eth/` | Status, GetBlockHeaders, BlockHeaders, GetBlockBodies, BlockBodies, Transactions, NewPooledTransactionHashes |
| 5.6 | Discovery v4 | ~800 | `crates/networking/p2p/discv4/` | Ping/Pong/FindNeighbours/Neighbours UDP messages, k-bucket table |
| 5.7 | Peer management | ~400 | `crates/networking/p2p/network.rs`, `peer_handler.rs` | Peer connection pool, event loop, connect/disconnect management |
| 5.8 | Full Sync | ~500 | `crates/networking/p2p/sync/full.rs` | Header download → body download → block execution pipeline |
| 5.9 | TX broadcast | ~200 | `crates/networking/p2p/tx_broadcaster.rs` | Transaction propagation to connected peers |
| 5.10 | P2P server | ~500 | `crates/networking/p2p/` | asyncio-based TCP/UDP server, overall coordination |

**Verification**: devp2p test tools (hive) for handshake/message exchange, testnet peer connection

---

### Phase 6: JSON-RPC Server (~1,500-2,000 LOC)

Depends on Phase 1, 3, 4.

| # | Task | LOC | Ref (ethrex) | Description |
|---|---|---:|---|---|
| 6.1 | RPC server framework | ~200 | `crates/networking/rpc/rpc.rs` | FastAPI-based JSON-RPC dispatcher |
| 6.2 | eth_ account API | ~200 | `crates/networking/rpc/eth/account.rs` | getBalance, getCode, getStorageAt, getTransactionCount |
| 6.3 | eth_ block API | ~300 | `crates/networking/rpc/eth/block.rs` | getBlockByHash, getBlockByNumber, getBlockReceipts, blockNumber |
| 6.4 | eth_ transaction API | ~300 | `crates/networking/rpc/eth/transaction.rs` | sendRawTransaction, call, estimateGas, getTransactionByHash, getTransactionReceipt |
| 6.5 | eth_ filter/log API | ~200 | `crates/networking/rpc/eth/filter.rs` | getLogs, newFilter, getFilterChanges |
| 6.6 | eth_ misc API | ~150 | `crates/networking/rpc/eth/` | gasPrice, feeHistory, chainId, syncing |
| 6.7 | net_/web3_ API | ~50 | `crates/networking/rpc/` | net_version, net_peerCount, web3_clientVersion |
| 6.8 | Engine API (optional) | ~500 | `crates/networking/rpc/engine/` | newPayload, forkchoiceUpdated, getPayload |

**Verification**: curl/httpie RPC call tests, web3.py connection verification

---

### Phase 7: Integration & Entry Point (~300-500 LOC)

Depends on all phases.

| # | Task | LOC | Description |
|---|---|---:|---|
| 7.1 | CLI entry point | ~100 | argparse-based configuration (port, bootnodes, datadir, etc.) |
| 7.2 | Node initialization | ~200 | genesis load → storage init → P2P start → RPC start → sync start |
| 7.3 | Signal handling | ~50 | Graceful shutdown |

**Verification**: Testnet bootnode connection → block sync → RPC response confirmation

---

## LOC Summary by Phase

| Phase | LOC |
|---|---:|
| 1. Common foundation | 2,500-3,500 |
| 2. EVM | 3,500-4,500 |
| 3. Storage | 500-800 |
| 4. Blockchain | 1,500-2,000 |
| 5. P2P | 4,000-5,500 |
| 6. RPC | 1,500-2,000 |
| 7. Integration | 300-500 |
| **Total** | **13,800-18,800** |

---

## Tech Stack

- Python 3.12+
- `pycryptodome` — AES, SHA256, RIPEMD160
- `coincurve` — secp256k1 (ECDSA, ECDH)
- `eth-hash[pycryptodome]` — keccak256
- `fastapi` + `uvicorn` — JSON-RPC server
- `python-snappy` — RLPx message compression
- `asyncio` — Async networking

---

## Verification Strategy

1. **Unit tests**: pytest-based tests per Phase
2. **Ethereum official tests**: RLP, Trie, EVM test vectors from ethereum/tests repo
3. **Testnet connection**: Connect to Sepolia/Holesky bootnodes for real sync
4. **RPC compatibility**: Connect via web3.py to verify standard API behavior
