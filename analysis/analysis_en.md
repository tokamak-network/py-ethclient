# ethrex L1 Client → Python Porting Analysis

## Overview

Source repository: https://github.com/lambdaclass/ethrex

ethrex is a Rust implementation of the Ethereum protocol by LambdaClass, described as "minimalist, stable, modular, fast, and ZK-native." It operates in two modes: a standard L1 execution client and a ZK-rollup L2 stack.

---

## Repository Structure

```
ethrex/
├── cmd/ethrex/              # Main binary entry point
├── crates/
│   ├── blockchain/          # L1: Block validation, execution, mempool
│   ├── common/              # SHARED: Types, RLP, trie, crypto, serde utilities
│   ├── networking/
│   │   ├── p2p/             # L1: devp2p (RLPx, discv4/5, snap sync)
│   │   └── rpc/             # L1: JSON-RPC + Engine API
│   ├── storage/             # L1: State/block storage (RocksDB + in-memory)
│   ├── vm/
│   │   ├── levm/            # L1/L2 SHARED: Custom EVM ("Lambda EVM")
│   │   └── backends/        # L1: VM backend wiring
│   ├── l2/                  # L2 ONLY (excluded from analysis)
│   └── guest-program/       # ZK guest programs (excluded from analysis)
```

---

## L1 Client Rust LOC Breakdown

| Component | Crate Path | Est. Rust LOC |
|---|---|---:|
| EVM (LEVM) — opcodes, precompiles, gas | `crates/vm/levm/` | ~18,400 |
| P2P Networking — RLPx, discv4/5, snap sync | `crates/networking/p2p/` | ~30,500 |
| JSON-RPC + Engine API | `crates/networking/rpc/` | ~14,900 |
| Blockchain engine — validation, execution, mempool | `crates/blockchain/` | ~8,500 |
| Storage — RocksDB / in-memory state DB | `crates/storage/` | ~6,300 |
| Common — types, trie, RLP, crypto | `crates/common/` | ~26,800 |
| VM backends + binary entry point | `crates/vm/backends/` + `cmd/` | ~7,200 |
| **Total** | | **~112,600** |

### Subsystem Details

#### EVM (LEVM) ~18,400 LOC
- Custom EVM implementation (not a fork of revm)
- Opcode handlers: arithmetic, bitwise, environment, stack/memory/storage, system (CALL, CREATE), logging
- All precompiles: ecrecover, SHA256, RIPEMD160, modexp, ecadd/ecmul/ecpairing, BLAKE2f, KZG (EIP-4844), BLS12-381 (EIP-2537)
- Gas accounting for all opcodes
- Pluggable hooks (L1 default, L2, backup)

#### P2P Networking ~30,500 LOC
- **RLPx** (~8,200): ECIES handshake, framing codec, tokio-based connection loop
- **Discovery v4 + v5** (~10,100): UDP peer discovery, k-bucket routing, ENR records
- **Snap protocol** (~2,700): State download protocol
- **Sync orchestration** (~4,500): Full sync + snap sync + trie healing
- **eth/68-69 subprotocol**: Status, GetBlockHeaders, GetBlockBodies, Transactions, NewPooledTransactionHashes

#### JSON-RPC + Engine API ~14,900 LOC
- Built on axum HTTP server
- `eth_` namespace: getBalance, getCode, getBlockByHash, sendRawTransaction, call, estimateGas, getLogs, feeHistory, etc.
- Engine API (CL-EL interface): newPayload, getPayload, forkchoiceUpdated (V1-V5)
- `debug_`, `admin_`, `net_`, `trace_` namespaces
- WebSocket subscriptions, JWT authentication

#### Blockchain Engine ~8,500 LOC
- Block validation & execution pipeline
- Transaction mempool with nonce-ordered queues
- Fork choice (post-Merge, follows Engine API directives)
- Payload builder for consensus client
- Prometheus metrics

#### Storage ~6,300 LOC
- `Store` struct: account state, code, storage trie, block headers/bodies/receipts
- `TrieLayerCache`: write-ahead in-memory trie cache
- RocksDB + in-memory backends
- LRU code cache (64 MB), flat key-value index

#### Common / Shared ~26,800 LOC
- Core types: Block, BlockHeader, Transaction (all types: EIP-155/1559/2930/4844/7702), Receipt, Account, Genesis, ForkId
- Merkle Patricia Trie: node encoding, parallel trie generation, range verification
- RLP encode/decode with derive macros
- Crypto: BLAKE2f (with assembly), Keccak256, KZG commitments

---

## Python Porting Estimate

### Compression Factors

Rust to Python compression ratio is approximately **3~4:1** due to:

- No type declarations, lifetime annotations, or borrow checker
- No `Result<T, E>` / `match` error handling boilerplate
- Dynamic typing eliminates struct definitions and derive macros
- Rich library ecosystem (pyrlp, pycryptodome, py_ecc, asyncio, FastAPI)

### Reusable Python Libraries

| Library | Replaces |
|---|---|
| `pyrlp` | RLP encode/decode (~1,600 LOC) |
| `pycryptodome` | SHA256, RIPEMD160, AES (ECIES) |
| `py_ecc` | ecrecover, BN128, BLS12-381 precompiles |
| `coincurve` / `eth_keys` | secp256k1 signing, ECIES handshake |
| `pyethash` / `eth_hash` | Keccak256 |
| `ckzg` | KZG commitments (EIP-4844) |
| `FastAPI` / `aiohttp` | JSON-RPC HTTP/WS server |
| `asyncio` | Async networking (replaces tokio) |
| `plyvel` / `rocksdb` | RocksDB storage backend |
| `trie` (from ethereum/py-trie) | Merkle Patricia Trie |

### Estimated Python LOC

| Component | Full Port | Minimal Port | Notes |
|---|---:|---:|---|
| EVM | 4,000-6,000 | 3,000-4,000 | Same opcode count, simpler syntax |
| P2P Networking | 8,000-12,000 | 4,000-5,000 | Minimal: no snap sync, basic discovery |
| JSON-RPC + Engine API | 2,000-3,000 | 1,000-1,500 | FastAPI drastically reduces boilerplate |
| Blockchain engine | 1,500-2,500 | 1,000-1,500 | Core validation/execution logic |
| Storage | 1,000-2,000 | 500-1,000 | Minimal: in-memory only |
| Common (types, trie, RLP) | 3,000-5,000 | 2,000-3,000 | pyrlp + py-trie reduce significantly |
| **Total** | **20,000-30,000** | **12,000-16,000** | |

### Summary (Self-Implemented)

| Scenario | Estimated LOC | Description |
|---|---:|---|
| **Ultra-minimal** | ~15,000 | In-memory storage, full sync only, minimal RPC, no snap sync |
| **Practical complete** | ~25,000 | All essential features, library-heavy |
| **Full-featured** | ~30,000 | Snap sync, all RPC endpoints, RocksDB, metrics |

---

## Further Reduction Strategies

The estimates above assume implementing most components from scratch. By leveraging existing Python Ethereum libraries more aggressively, or by removing entire subsystems, the codebase can be reduced dramatically.

### Strategy 1: Aggressive Library Reuse

| Library | Eliminates | LOC Saved |
|---|---|---:|
| `py-evm` (Ethereum Foundation) | Entire EVM (opcodes, precompiles, gas) | -3,000~5,000 |
| `py-trie` + `eth-hash` | Trie + hash implementation | -1,000~2,000 |
| `devp2p` / Trinity networking | RLPx, discovery (partial) | -2,000~3,000 |
| `eth-rlp` + `eth-typing` | Type definitions + RLP encoding | -500~1,000 |

### Strategy 2: Remove P2P Entirely (Proxy Mode)

P2P networking accounts for **40%** of the total codebase. It can be eliminated entirely by connecting to an existing Geth/Reth node via JSON-RPC to fetch block data.

- P2P 30,500 LOC (Rust) / 8,000-12,000 LOC (Python) → **0 LOC**
- Only ~500 LOC of RPC client code needed as replacement

### Strategy 3: Remove Engine API

If there is no need to connect to a consensus client (e.g., Lighthouse), the Engine API can be removed entirely → **-1,000~1,500 LOC**

### All Scenarios Compared

| Scenario                 |     Est. LOC | P2P                           | EVM              | Independence                                                     |
| ------------------------ | -----------: | ----------------------------- | ---------------- | ---------------------------------------------------------------- |
| **A. Fully Independent** |      ~15,000 | Self-implemented              | Self-implemented | Standalone node, participates in Ethereum network via devp2p     |
| **B. Library-Heavy**     | ~5,000-8,000 | Self-implemented              | py-evm           | Network participation possible, EVM delegated to py-evm          |
| **C. Proxy Mode**        | ~3,000-5,000 | None (proxy to existing node) | py-evm           | Depends on external node for block data, self-validates/executes |
| **D. Pure EVM Executor** | ~1,500-2,500 | None                          | py-evm (wrapper) | Local-only dev/test node, no network participation               |

### Scenario Details

#### A. Fully Independent (~15,000 LOC)
- All components implemented from scratch in Python
- Full sync via devp2p (no snap sync)
- Minimal JSON-RPC, in-memory storage
- Can join the Ethereum network as a standalone execution client
- **Trade-off**: Maximum independence, maximum code

#### B. Library-Heavy (~5,000-8,000 LOC)
- EVM execution delegated to `py-evm`
- Trie operations via `py-trie`
- P2P networking still self-implemented (RLPx, discv4)
- **Trade-off**: Reduced code while retaining network participation

#### C. Proxy Mode (~3,000-5,000 LOC)
- Connects to an existing Geth/Reth node via JSON-RPC to receive blocks
- Independently executes and validates blocks using `py-evm`
- No P2P stack, no Engine API
- Useful as an independent block verifier or shadow node
- **Trade-off**: Depends on external node, but self-verifies everything

#### D. Pure EVM Executor (~1,500-2,500 LOC)
- Thin wrapper around `py-evm`
- In-memory state only
- Minimal JSON-RPC (eth_call, eth_sendTransaction, eth_getBalance)
- No sync, no P2P, no Engine API
- Equivalent to a local development node (like Ganache/Hardhat node)
- **Trade-off**: Minimal code, but local-only

### Core Trade-off Spectrum

```
Code size ↓↓↓  ←→  Independence ↓↓↓

  A. ~15,000 LOC  │  Fully independent node (P2P, own EVM)
  B.  ~5,000 LOC  │  Network-capable, borrows EVM from py-evm
  C.  ~3,000 LOC  │  Parasitic on existing node, self-validates only
  D.  ~1,500 LOC  │  Essentially a py-evm wrapper (local-only)
```

The two biggest cost drivers are **P2P networking** (40% of codebase) and **EVM implementation** (20%). Delegating both to existing libraries reduces the total to ~3,000 LOC.

---

## Appendix: Sync Modes Explained

### Full Sync
- Downloads and **re-executes every block** from genesis
- Reconstructs the entire state by replaying all transactions
- Most secure, but **extremely slow** (days to weeks)

### Snap Sync
Introduced in Geth v1.10 as the successor to fast sync. Instead of replaying history, it **downloads the latest state trie snapshot directly from peers**.

**Process:**
1. Request account and storage data from peers in range-based batches
2. Reconstruct the state trie from the downloaded data
3. **Trie healing** — patch any parts that changed during the download window
4. From that point on, follow new blocks normally

**Comparison:**

| | Full Sync | Snap Sync |
|---|---|---|
| Analogy | Recalculating every ledger entry since company founding | Copying today's balance sheet wholesale |
| Speed | Slow (days/weeks) | Fast (hours) |
| Verification | Every transaction verified | Integrity verified via state root hash |

**Impact on codebase:**
- Snap sync protocol messages: ~2,700 LOC
- Related sync orchestration + trie healing: ~4,500 LOC
- Total snap sync-related code: ~7,200 LOC (24% of total P2P networking)
- Excluding snap sync reduces P2P from ~30,500 to ~23,300 LOC in Rust, and from ~8,000-12,000 to ~4,000-5,000 LOC in the Python minimal port

---

## Scenario A Implementation Plan

See [plan_fully_independent_en.md](plan_fully_independent_en.md) for the full implementation plan (7 phases, 35 tasks, ~13,800-18,800 LOC).

---

## Key Architectural Decisions

1. **No revm** — ethrex uses its own EVM (LEVM) with pluggable hooks
2. **Pure execution client** — Communicates with consensus client via Engine API (post-Merge)
3. **Storage layering** — Write-ahead TrieLayerCache above RocksDB
4. **Dual sync** — Full sync + snap sync with post-sync trie healing
5. **discv4 + discv5** — Both discovery protocols implemented
6. **L2 is additive** — L2 code is entirely separate, no L1 dependency on L2

---

## Appendix: revm vs LEVM — EVM Implementation Choices

### What is revm?

**revm** stands for **Rust EVM**. It is a standalone, general-purpose EVM implementation written in Rust by Dragan Rakita. It is designed as a reusable library that any project can import and use.

### What is LEVM?

**LEVM** stands for **Lambda EVM**. It is ethrex's own EVM implementation, built from scratch inside the ethrex repository (`crates/vm/levm/`). It is not a fork of revm.

### Comparison

| | revm | LEVM (ethrex) |
|---|---|---|
| Developer | Dragan Rakita (individual) | LambdaClass |
| Nature | General-purpose library (anyone can use) | ethrex-specific implementation |
| Used by | **Reth**, Foundry, Hardhat, Helios, etc. | ethrex only |
| Location | Separate repo (`bluealloy/revm`) | Inside ethrex (`crates/vm/levm/`) |
| Focus | Performance optimization, battle-tested | ZK-proving optimized hook system |

### Why did ethrex build its own EVM?

ethrex needs to support both L1 execution and L2 ZK-rollup proving. This requires injecting different behaviors during EVM execution via a **hook system**:

- **L1 hook (default)**: Standard Ethereum execution rules
- **L2 hook**: Additional fee deduction logic for rollup operation
- **Backup hook**: Checkpoint mechanism for ZK proving

Rather than forking revm and heavily modifying it, LambdaClass chose to build LEVM from scratch with hooks as a first-class concept.

### Analogy

- **revm** = Toyota engine (general-purpose, used across many vehicles)
- **LEVM** = Custom-built engine designed specifically for one vehicle's unique requirements

### How the Hook System Works

During EVM execution of a transaction, the hook system allows **injecting custom logic at specific points** without modifying the core EVM code. It is essentially a callback mechanism.

**Simplified transaction execution flow:**

```
1. Deduct gas fee from sender
2. [HOOK: before_execution]    ← hook point
3. Execute EVM bytecode
4. [HOOK: after_execution]     ← hook point
5. Refund remaining gas
6. Transfer ETH to recipient
```

**Without hooks** — L1/L2 branching is hardcoded inside the EVM (bad design):

```python
def execute_tx(tx):
    deduct_gas(tx)
    if is_l2_mode:           # EVM must know about L2
        deduct_l2_fee(tx)
    run_bytecode(tx)
    refund_gas(tx)
```

**With hooks** — EVM knows nothing about L2. Hooks handle it:

```python
class DefaultHook:    # For L1
    def before_execution(self, tx):
        pass           # No-op

class L2Hook:         # For L2
    def before_execution(self, tx):
        deduct_l2_fee(tx)  # Deduct L2 fee

def execute_tx(tx, hook):
    deduct_gas(tx)
    hook.before_execution(tx)   # L1: no-op, L2: fee deduction
    run_bytecode(tx)
    refund_gas(tx)
```

**Hook points in ethrex LEVM:**

| Hook Point | L1 Default Behavior | L2 Behavior |
|---|---|---|
| Before tx execution | No-op | Deduct L2 fee |
| Before CALL/CREATE | No-op | Additional validation |
| On state change | Apply directly | Record checkpoint (for ZK proving) |

The benefit: **one EVM codebase** supports both L1 and L2 cleanly, without code duplication or if/else branches.

### Hooks and ZK Proving: Clarification

Important: **ZKP itself is not a hook.** Hooks are used to **collect data needed to generate ZK proofs**.

ethrex's L2 is a ZK-rollup. How a ZK-rollup works:

```
1. Execute transactions on L2 (using EVM)
2. Generate a ZK proof that "this execution was performed correctly"
3. Submit that proof to L1 → L1 only verifies the proof (no re-execution needed)
```

For step 2, the ZK prover needs a complete record of **all state changes during EVM execution** (called an "execution trace" or "witness"). Collecting this trace is exactly what the hook does.

```python
class BackupHook(ExecutionHook):    # Hook for ZK proving
    def __init__(self):
        self.trace = []             # Execution trace record

    def on_state_change(self, addr, key, old_val, new_val):
        # Record every state change
        self.trace.append({
            "address": addr,
            "key": key,
            "before": old_val,
            "after": new_val
        })

    # Later, self.trace is passed to the ZK prover to generate the proof
```

**End-to-end flow:**

```
During EVM execution                After EVM execution
┌─────────────┐                    ┌─────────────┐
│ Execute      │                    │             │
│ opcode       │                    │  ZK Prover  │
│  [hook call] │ ──→ trace data ──→ │  (SP1 etc.) │ ──→ ZK Proof
│      │       │                    │             │
│ Next opcode  │                    └─────────────┘
└─────────────┘
```

| Component | Role |
|---|---|
| **Hook** | Callback during EVM execution. Records state changes |
| **ZK prover** | Separate program that generates proofs from recorded data (trace) after execution completes (SP1, RISC Zero, etc.) |
| **ZK proof** | Mathematical evidence that "this execution was valid". Submitted to L1 |

In short: hooks do **not execute** ZK proofs. They **collect input data** for ZK proof generation.

### Relevance to this Python port

In our fully independent port (Scenario A), we implement our own EVM from scratch — similar to how ethrex chose LEVM over revm. The Python ecosystem has `py-evm` (Ethereum Foundation's Python EVM, analogous to revm), but Scenario A deliberately avoids it for maximum independence. Scenarios B-D use `py-evm` to reduce code size.

For the L1-only port, the hook system is not strictly required. However, the EVM main loop (Phase 2.9) will be designed with hook points in mind (~50 LOC overhead) so that L2 extensions can be added later without restructuring the EVM.

---

## Appendix: SP1 and zkVMs

### What is SP1?

**SP1** is a **zkVM (Zero-Knowledge Virtual Machine)** built by Succinct Labs. It is a virtual machine that "executes a normal program and automatically generates a ZK proof that the execution was correct."

### How it works

```
┌──────────────┐         ┌─────────┐         ┌──────────┐
│ Write normal  │         │         │         │          │
│ Rust program  │ ──────→ │   SP1   │ ──────→ │ ZK Proof │
│ (RISC-V target)│        │  zkVM   │         │(small,fast)│
└──────────────┘         └─────────┘         └──────────┘
```

1. Developer writes **normal Rust code** (no ZK circuit knowledge required)
2. Code is compiled to **RISC-V instructions**
3. SP1 executes the RISC-V instructions and **automatically generates a ZK proof**

### Why it matters

Previously, generating ZK proofs required manually designing "ZK circuits" — an extremely difficult and specialized task.

| Approach | Difficulty | Analogy |
|---|---|---|
| **Manual circuit design** | Extremely hard | Programming in assembly |
| **Using SP1** | Accessible to general developers | Programming in Python |

SP1 enables developers without ZK expertise to build systems that leverage ZK proofs.

### Role in ethrex

In ethrex's L2 ZK-rollup:

```
1. EVM executes transactions (hooks collect trace)
2. Trace is fed into SP1 guest program
3. SP1 generates ZK proof that "this EVM execution was correct"
4. Proof is submitted to L1
```

The ethrex repo contains SP1 guest programs in `crates/guest-program/`. It also supports multiple zkVM backends beyond SP1.

### zkVM Comparison

| zkVM | Developer | Base ISA | Notes |
|---|---|---|---|
| **SP1** | Succinct Labs | RISC-V | ethrex default backend |
| **RISC Zero** | RISC Zero Inc. | RISC-V | Oldest general-purpose zkVM |
| **ZisK** | Polygon | RISC-V | Polygon ecosystem |
| **OpenVM** | OpenVM | RISC-V | Open source |

All are RISC-V based, meaning normal Rust code can be proven without modification.

### Relevance to this Python port

Scenario A (fully independent port) is L1-only, so SP1/ZK provers are not directly relevant. However, by designing the hook system upfront, the codebase is ready for future L2 extension with SP1 guest program integration.

---

## Appendix: zkVM vs Direct Circuit Design — Are zkVMs Still Needed in the Age of Agentic Coding?

### The Question

With agentic coding (AI agents that autonomously write, test, and iterate on software), can developers design ZK circuits directly? If so, is an abstraction layer like SP1 still necessary?

### What Agentic Coding Can Do

An AI coding agent could:

```
1. Read EVM opcode specs
2. Generate circom/halo2 circuits for each opcode
3. Validate against Ethereum official test vectors
4. Fix failures and iterate
```

This is actually feasible at the individual opcode level. Some projects already design circuits directly:

| Project | Approach | Result |
|---|---|---|
| **Polygon zkEVM** | Direct circuit design | Fast proving, years of development |
| **Scroll** | Direct circuit design (halo2) | Efficient proofs, 50+ person team |
| **ethrex (SP1)** | zkVM | Fast development, slower proving |

### Core Trade-off

```
             Dev speed ←────────────────→ Proving speed
                │                            │
   SP1/zkVM    ███████████░░░░░░░░░░░        Fast dev, slow proving (10-100x overhead)
   Direct      ░░░░░░░░░░░███████████        Slow dev (years), fast proving
```

### The Remaining Problem: Formal Verification

The real bottleneck for agentic coding is **formal verification**.

#### What is Formal Verification?

"Guaranteeing program correctness through **mathematical proof, not testing**."

```
Testing:              Try 10 inputs → all pass → "probably correct"
Formal verification:  Prove for ALL possible inputs → "definitely correct"
```

| | Testing | Formal Verification |
|---|---|---|
| Method | Check specific inputs | Prove for all possible inputs |
| Confidence | "Works for these cases" | "Works for every case" |
| Analogy | Drive 10 trucks onto a bridge | Calculate load limits with structural engineering |

#### Why Formal Verification is Critical for ZK Circuits

Normal code bugs cause crashes — easy to discover. ZK circuit bugs **silently allow fake proofs**:

```
Normal:  "A sends 100 ETH to B" → valid proof → L1 approves
Bug:     "A creates 1M ETH from nothing" → fake proof passes → L1 approves → funds stolen
```

Tests can miss this — the circuit works for normal inputs but breaks only for specially crafted attacker inputs.

| | Normal code | ZK circuits |
|---|---|---|
| When bugged | Test fails / crash | **Tests may still pass** |
| Consequence | Service outage | **Billions of dollars stolen** |
| Detection | Logs, debugger | Formal verification needed |

Agentic coding excels at writing "code that passes tests." But producing "circuits where soundness is mathematically guaranteed for all inputs" is a different problem.

#### Practical Limits of Formal Verification

| Strengths | Limitations |
|---|---|
| Mathematical certainty | Verification itself is very slow and difficult |
| Covers all inputs | Meaningless if the property to verify is mis-specified |
| Permanent once done | Must redo when code changes |

Current formal verification tools: Coq, Isabelle, Lean, Z3, Dafny

### Conclusion

Why zkVMs like SP1 are chosen today:

1. **Safety**: Normal Rust code is easy to audit; circuit bugs are catastrophic
2. **Maintenance**: When Ethereum hard forks, just update Rust code (no circuit redesign)
3. **Dev speed**: Small teams can build ZK-rollups
4. **Proving gap is closing**: SP1 v2/v3 reducing overhead over time

However, as agentic coding + formal verification tools mature, the barrier to direct circuit design will lower, potentially reducing the need for zkVMs. **Both sides are converging.**

---

## Appendix F: zkVM Base ISA — RISC-V and Alternatives

### What is an ISA (Instruction Set Architecture)?

An ISA is the specification of the instruction set a CPU understands. High-level code (Rust, C, etc.) is compiled by a compiler into machine code for a specific ISA.

### What it Means for a zkVM to Use RISC-V

A zkVM is "a virtual machine that executes a program while simultaneously generating a ZK proof that the execution was correct."

```
Normal execution: Rust code → RISC-V machine code → runs on real CPU
zkVM execution:   Rust code → RISC-V machine code → zkVM "simulates" execution → generates ZK proof
```

Why RISC-V was chosen as the base ISA:

1. **Simplicity**: RISC-V has only ~47 base instructions (x86 has ~1,500+). Fewer instructions = easier to convert to ZK circuits
2. **Regularity**: All instructions are fixed-length (32-bit), making decoding straightforward
3. **Openness**: Open ISA with no licensing fees
4. **Ecosystem**: Mature compilers (GCC, LLVM) already support RISC-V → Rust, C, C++ compile directly
5. **Generality**: Unlike Ethereum's EVM, can execute general-purpose programs

### Alternative ISA Comparison

| ISA | Examples | Characteristics |
|---|---|---|
| **RISC-V** | SP1, RISC Zero, ZisK, OpenVM | Most popular. Simple and general-purpose |
| **MIPS** | zkMIPS (ZKM) | Also a RISC family, simple. Good for verifying existing MIPS binaries |
| **WASM** | zkWasm, Delphinus | Compatible with web ecosystem. Suited for verifying browser-executed programs |
| **EVM** | zkEVM (Polygon, Scroll, Taiko) | Proves Ethereum bytecode directly. Ethereum-specific, not general-purpose |
| **Cairo VM** | StarkNet (StarkWare) | Custom ISA optimized for ZK proving. Best proving efficiency but requires a dedicated language (Cairo) |
| **Custom VM** | Valida (Lita Foundation) | Entirely new ISA designed for ZK proving optimization |

### Core Trade-off

```
Generality (existing language support)     ←→     Proving Efficiency
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RISC-V / MIPS / WASM                        Cairo VM / Custom VM
"Prove existing Rust code as-is"            "Must use dedicated lang, but proving 10-100x faster"
```

- **RISC-V family**: Developer experience first. Can prove existing Rust/C code without modification. But general-purpose ISA means complex ZK circuits and slower proving
- **Cairo/Custom**: Proving efficiency first. Instructions designed for field arithmetic optimization. But requires learning a dedicated language

### Recent Trends

RISC-V is converging as the de facto standard:
- Major projects (SP1, RISC Zero, ZisK, OpenVM) all adopted RISC-V
- The value proposition "write in any programming language, get a proof" is decisive for developer adoption
- Even StarkWare is gradually expanding general-purpose support beyond Cairo
