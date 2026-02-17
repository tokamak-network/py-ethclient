# AGENTS.md - Coding Agent Guide

> **Project**: Python Single Sequencer L1  
> **Philosophy**: Dumb code. Start small. Extend when needed.  

---

## Project Overview

This project implements an ultra-lightweight Ethereum-compatible single sequencer (L1) in Python. It's a port from the Rust `ethrex` Ethereum client, simplified for single sequencer environments.

### Single Sequencer Constraints

- **No Consensus**: No consensus client needed
- **No P2P**: No communication with external peers
- **No Reorgs**: Linear chain, no reorganizations
- **Centralized Block Production**: Designated sequencer produces all blocks

### Excluded Components

| Component | Reason |
|-----------|--------|
| Engine API | No consensus client |
| Fork Choice | No reorgs, linear chain |
| P2P (DiscV4, RLPx, eth/68) | No external peers |
| Block Sync | No external block sources |
| Tx Broadcasting | Only self-generated transactions |
| Mempool (optional) | Only process self-created transactions |

---

## Core Principles

### 1. Use Libraries Directly

**DON'T** reimplement what's already available:

| Component | Library | Approach |
|-----------|---------|----------|
| **EVM** | py-evm | **Direct import and use** - no wrappers unless necessary |
| **RLP** | ethereum-rlp | Direct use - 0 LOC from us |
| **Crypto** | coincurve + pycryptodome | Direct use - minimal wrappers (~50 LOC) |
| **Trie** | trie (py-trie) | Direct use - 0 LOC from us |
| **Types** | ethereum-types | Direct use - minimal wrappers only |
| **State** | py-evm.State | Use py-evm's state management |

**Rule**: "Direct use" means import and use immediately. Only write adapter code when there's a type mismatch between py-evm and our code.

### 2. Don't Extend Libraries

> "Extend when needed" means **actually needed**, not "might be nice to have".

**Anti-patterns to avoid**:
- Creating wrapper classes around library types "just in case"
- Adding methods "for future use"
- Abstracting layers that don't need abstraction
- Building "frameworks" instead of "scripts"

**Patterns to follow**:
```python
# GOOD: Direct usage
from eth.vm.forks.cancun import CancunVM
from trie import HexaryTrie

# GOOD: Simple function wrapper (not class wrapper)
def keccak256(data: bytes) -> bytes:
    """Just a function - no class needed"""
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

# BAD: Unnecessary class hierarchy
class CustomEVM(BaseEVMWrapper):
    def __init__(self):
        self.vm = CancunVM  # Just use CancunVM directly!
```

### 3. Start with dict(), Upgrade to SQLite Later

**Phase 1**: Use `dict` for storage
**Phase 2**: Replace with SQLite only when needed

```python
# Phase 1 - In-memory only
class Store:
    def __init__(self):
        self._blocks: dict[int, Block] = {}
        self._trie_nodes: dict[bytes, bytes] = {}

# Phase 2 - Only if we need persistence (don't implement until asked)
```

### 4. Prefer stdlib Over External Dependencies

| Use Case | Preferred | Upgrade Path |
|----------|-----------|--------------|
| HTTP Server | `http.server` | aiohttp (if needed) |
| Async | `asyncio` | - |
| JSON | `json` | - |
| CLI | `argparse` | click (if needed) |

---

## Project Structure

```
py-ethclient/
├── pyproject.toml
├── src/
│   └── sequencer/
│       ├── __init__.py
│       │
│       ├── core/                    # Minimal wrappers only
│       │   ├── __init__.py
│       │   ├── types.py             # Account, Receipt wrappers (~150 LOC)
│       │   ├── crypto.py            # keccak256, sign, recover (~50 LOC)
│       │   ├── constants.py         # Chain constants (~20 LOC)
│       │   └── chainspec.py         # Fork schedule (~30 LOC)
│       │
│       ├── evm/                     # py-evm adapters (not wrappers!)
│       │   ├── __init__.py
│       │   ├── adapter.py           # py-evm bridge (~200 LOC)
│       │   └── state.py             # StateDB adapter (~100 LOC)
│       │
│       ├── storage/                 # dict-based storage
│       │   ├── __init__.py
│       │   └── store.py             # In-memory store (~100 LOC)
│       │
│       ├── sequencer/               # Sequencer logic
│       │   ├── __init__.py
│       │   ├── executor.py          # Block execution (~200 LOC)
│       │   ├── builder.py           # Block building (~300 LOC)
│       │   └── chain.py             # Chain management (~100 LOC)
│       │
│       ├── rpc/                     # RPC (Phase 2)
│       │   ├── __init__.py
│       │   ├── server.py            # http.server (~100 LOC)
│       │   └── methods.py           # eth_* methods (~150 LOC)
│       │
│       └── cli.py                   # CLI entry point (~50 LOC)
│
├── tests/
│   ├── test_executor.py
│   ├── test_builder.py
│   └── test_chain.py
│
└── README.md
```

### Directory Rules

1. **`core/`**: Only types we MUST define ourselves. Prefer ethereum-types.
2. **No `rlp/`**: Use ethereum-rlp directly.
3. **No `trie/`**: Use trie library directly.
4. **No `crypto/`**: Single file `crypto.py`, not a package.
5. **No `opcodes/`, `precompiles/`**: Use py-evm directly.

---

## Dependencies

### Core Dependencies (Always Use)

```toml
[project]
dependencies = [
    "py-evm>=0.12.0b1",              # EVM execution engine - DIRECT USE
    "ethereum-rlp>=0.1.4",           # RLP encoding - DIRECT USE
    "trie>=3.1.0",                   # Merkle Patricia Trie - DIRECT USE
    "ethereum-types>=0.1.0",         # Type definitions - DIRECT USE
    "coincurve>=21.0.0",             # secp256k1 (fast ECDSA)
    "pycryptodome>=3.20.0",          # Keccak256
    "eth-utils>=5.0.0",              # Utilities
]
```

### When to Add New Dependencies

1. Check if stdlib has it first
2. Check if existing deps provide it
3. Only add if it saves >100 LOC or is critical
4. Get approval before adding

---

## Code Style

### Function Over Classes

```python
# GOOD: Functions
from trie import HexaryTrie
from ethereum_rlp import encode

def compute_tx_root(transactions: list) -> bytes:
    trie = HexaryTrie({})
    for i, tx in enumerate(transactions):
        trie[encode(i)] = encode(tx)
    return trie.root_hash

# BAD: Class with single method
class TransactionRootComputer:
    def __init__(self):
        self.trie = HexaryTrie({})
    
    def compute(self, transactions: list) -> bytes:
        ...
```

### Type Hints

```python
# Always use types - but prefer ethereum-types
from ethereum_types.numeric import U256, Uint
from ethereum_types.bytes import Bytes20, Bytes32

# Good
def transfer(from_addr: Bytes20, to_addr: Bytes20, amount: U256) -> bool:
    ...

# Avoid (unless necessary)
def transfer(from_addr: bytes, to_addr: bytes, amount: int) -> bool:
    ...
```

### Error Handling

```python
# Simple exceptions - no custom error hierarchies
raise ValueError(f"Parent not found: {parent_number}")

# Not:
raise ParentNotFoundException(parent_number)  # Too much
```

---

## Implementation Phases

### Phase 1: Core Foundation (Target: ~600 LOC)

**Goal**: Execute blocks using py-evm

| Component | LOC | Deliverable |
|-----------|-----|-------------|
| Types wrapper | ~150 | Account, BlockHeader, Block |
| Crypto wrapper | ~50 | keccak256, sign, recover |
| EVM adapter | ~200 | py-evm bridge |
| State adapter | ~100 | trie bridge |
| Storage | ~100 | dict-based |

**Validation**:
- Single transaction execution works
- State root calculation works

### Phase 2: Sequencer (Target: ~600 LOC)

**Goal**: Build blocks

| Component | LOC | Deliverable |
|-----------|-----|-------------|
| Block Executor | ~200 | Execute + minimal validation |
| Block Builder | ~300 | Create new blocks |
| Chain | ~100 | Append-only management |

**Validation**:
- Sequential block production from genesis
- State consistency maintained

### Phase 3: RPC (Target: ~250 LOC)

**Goal**: Basic queries

| Component | LOC | Deliverable |
|-----------|-----|-------------|
| HTTP Server | ~100 | stdlib http.server |
| eth_* methods | ~150 | Read-only queries |

---

## Testing

### Unit Tests

```python
# tests/test_evm.py
def test_evm_adapter():
    adapter = EVMAdapter(test_config)
    result = adapter.execute_transaction(test_tx)
    assert result.success
    assert result.gas_used > 0
```

### Integration Tests

```python
# tests/test_chain.py
def test_sequential_blocks():
    chain = Chain.from_genesis(test_genesis)
    for i in range(10):
        tx = create_test_tx(nonce=i)
        block = chain.produce_block([tx])
        assert block.header.number == i + 1
```

### Don't Test Library Code

- py-evm is already tested (EF Tests)
- trie is already tested
- ethereum-rlp is already tested

**Only test our adapter code.**

---

## Agent Working Rules

### Before Writing Code

1. **Check if library has it**: Search py-evm, ethereum-rlp, trie docs
2. **Check ethereum-types first**: Use existing types
3. **Check stdlib first**: No unnecessary deps

### While Writing Code

1. **Start dumb**: Working code > perfect abstraction
2. **No premature optimization**: Profile first, optimize later
3. **No premature generalization**: Hardcode if it's only used once
4. **Keep functions small**: <50 lines, <3 indent levels

### After Writing Code

1. **Run tests**: `pytest tests/`
2. **Check types**: `mypy src/`
3. **Check style**: `ruff check src/`

### When in Doubt

```
Simpler is better. 
Working code today > perfect code tomorrow.
Libraries exist for a reason - use them.
```

---

## Reference: ethrex Structure

When porting from Rust `ethrex`, map components as follows:

| Rust Crate | Python Approach |
|------------|-----------------|
| `common/types` | Use ethereum-types + minimal wrappers |
| `common/rlp` | Use ethereum-rlp directly |
| `common/crypto` | Use coincurve/pycryptodome directly |
| `common/trie` | Use trie library directly |
| `vm/levm` | **Use py-evm directly** - no port |
| `storage` | dict-based, upgrade to SQLite later |
| `blockchain/execution` | Use py-evm + minimal logic |
| `blockchain/validation` | Minimal validation only |
| `blockchain/payload` | Implement (~300 LOC) |
| `blockchain/mempool` | **Exclude** - single sequencer |
| `blockchain/fork_choice` | **Exclude** - no reorgs |
| `networking/p2p` | **Exclude** - no P2P |
| `networking/rpc` | stdlib http.server (~150 LOC) |
| `networking/rpc/engine` | **Exclude** - no consensus |

---

## Summary

| Principle | Rule |
|-----------|------|
| **Use Libraries** | Import py-evm, ethereum-rlp, trie directly |
| **Don't Extend** | "Later" means "when actually needed" |
| **Dict First** | SQLite only if persistence required |
| **Stdlib First** | External deps need approval |
| **Functions > Classes** | No unnecessary OOP |
| **Test Our Code** | Don't test libraries |
| **Dumb > Smart** | Easier to fix, easier to replace |

**Target**: ~1,450 LOC total (76% reduction from ~6,150 LOC)

---

## Quick Reference

### Essential Imports

```python
# EVM
from eth.vm.forks.cancun import CancunVM
from eth.vm.message import Message
from eth.vm.computation import BaseComputation

# RLP
from ethereum_rlp import encode, decode, decode_to

# Trie
from trie import HexaryTrie

# Crypto
from coincurve import PrivateKey, PublicKey
from Crypto.Hash import keccak

# Types
from ethereum_types.numeric import U256, Uint
from ethereum_types.bytes import Bytes20, Bytes32
```

### Essential Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Type check
mypy src/

# Lint
ruff check src/

# Format
ruff format src/
```

---

*Keep it simple. Keep it dumb. Keep it working.*
