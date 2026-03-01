---
description: "App-Specific ZK Rollup — from STF definition to L1 verification"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "app name or use case description"
user-invocable: true
---

# L2 ZK Rollup Creation Skill

Specialized skill for creating and operating App-Specific ZK Rollups. Guides the entire pipeline: STF (State Transition Function) definition → PythonRuntime wrapping → Rollup lifecycle (setup → submit → batch → prove → L1 verify).

## Key File References

| File | Role |
|------|------|
| `ethclient/l2/rollup.py` | Rollup orchestrator |
| `ethclient/l2/runtime.py` | PythonRuntime — wraps callable as STF |
| `ethclient/l2/types.py` | L2Tx, STFResult, Batch, BatchReceipt, L2State |
| `ethclient/l2/sequencer.py` | Sequencer — mempool, nonce tracking, batch assembly |
| `ethclient/l2/prover.py` | Groth16ProofBackend (pure Python) |
| `ethclient/l2/native_prover.py` | NativeProverBackend (rapidsnark/snarkjs) |
| `ethclient/l2/interfaces.py` | 4 pluggable interface definitions |
| `ethclient/l2/config.py` | L2Config settings |

## Quick Start Template

```python
from ethclient.l2.types import L2Tx, STFResult
from ethclient.l2.rollup import Rollup

# 1. Define STF — write app logic as a pure Python function
def my_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    if op == "increment":
        state["counter"] = state.get("counter", 0) + 1
        return STFResult(success=True, output={"counter": state["counter"]})
    return STFResult(success=False, error=f"unknown op: {op}")

# 2. Create Rollup (callable STF is auto-wrapped with PythonRuntime)
rollup = Rollup(stf=my_stf)

# 3. Trusted Setup (ZK circuit + verifier deployment)
rollup.setup()

# 4. Submit transaction
USER = b"\x01" * 20
error = rollup.submit_tx(L2Tx(sender=USER, nonce=0, data={"op": "increment"}))
assert error is None

# 5. Produce batch + prove + submit to L1
batch = rollup.produce_batch()
receipt = rollup.prove_and_submit(batch)
assert receipt.verified

# 6. Check state
print(rollup.state.get("counter"))  # 1
```

## L2Tx Constraints

```python
@dataclass
class L2Tx:
    sender: bytes        # Must be 20 bytes (ValueError if != 20)
    nonce: int = 0       # >= 0 (ValueError if < 0)
    data: dict = {}      # Values must be str, int, bytes, or dict only
    value: int = 0       # >= 0
    tx_type: L2TxType = L2TxType.CALL  # CALL=0, DEPOSIT=1, WITHDRAWAL=2
    signature: bytes = b""
    timestamp: int = 0   # 0 means auto-set to time.time()
```

**Data serialization rules**: Dict values use tag-based RLP encoding. `\x01`=int, `\x02`=bytes, `\x03`=str, `\x04`=nested dict. Keys are sorted alphabetically.

## STF Writing Patterns

### Basic STF (function only)
```python
def counter_stf(state: dict, tx: L2Tx) -> STFResult:
    state["counter"] = state.get("counter", 0) + 1
    return STFResult(success=True)
```

### STF with Validator
```python
from ethclient.l2.runtime import PythonRuntime

def my_validator(state: dict, tx: L2Tx) -> str | None:
    if "op" not in tx.data:
        return "missing 'op' field"
    return None  # pass

runtime = PythonRuntime(
    func=my_stf,
    validator=my_validator,
    genesis={"counter": 0, "admin": b"\x01" * 20},
)
rollup = Rollup(stf=runtime)
```

### STFResult Structure
```python
@dataclass
class STFResult:
    success: bool
    output: dict = {}    # App-specific return value on success
    error: str | None = None  # Error message on failure
```

- Function returns `None` → `STFResult(success=True)`
- Function returns `dict` → `STFResult(success=True, output=dict)`
- Function raises exception → `STFResult(success=False, error=str(e))`

## Nonce Management

The Sequencer enforces strict nonce ordering:
- Expected nonce per sender = previous successful nonce + 1 (genesis = 0)
- **No gaps**: Must submit nonce 0 → 1 → 2 in order. Sending nonce 2 first is rejected
- **No duplicates**: Resubmitting an already-used nonce returns "nonce too low"

```python
# Correct pattern
rollup.submit_tx(L2Tx(sender=ALICE, nonce=0, data=...))  # OK
rollup.submit_tx(L2Tx(sender=ALICE, nonce=1, data=...))  # OK
rollup.submit_tx(L2Tx(sender=BOB, nonce=0, data=...))    # OK (different sender)

# Incorrect pattern
rollup.submit_tx(L2Tx(sender=ALICE, nonce=2, data=...))  # Error: nonce too high
rollup.submit_tx(L2Tx(sender=ALICE, nonce=0, data=...))  # Error: nonce too low
```

## 2-Batch Chaining Example

```python
rollup = Rollup(stf=counter_stf)
rollup.setup()

ALICE = b"\x01" * 20

# Batch 0
rollup.submit_tx(L2Tx(sender=ALICE, nonce=0, data={"op": "inc"}))
rollup.submit_tx(L2Tx(sender=ALICE, nonce=1, data={"op": "inc"}))
batch0 = rollup.produce_batch()
receipt0 = rollup.prove_and_submit(batch0)
assert receipt0.verified

# Batch 1 — old_state_root == batch0.new_state_root (auto-chaining)
rollup.submit_tx(L2Tx(sender=ALICE, nonce=2, data={"op": "inc"}))
batch1 = rollup.produce_batch()
receipt1 = rollup.prove_and_submit(batch1)
assert receipt1.verified
assert batch1.old_state_root == batch0.new_state_root
```

## L2Config Key Settings

```python
from ethclient.l2.config import L2Config

config = L2Config(
    name="my-rollup",
    chain_id=42170,
    max_txs_per_batch=32,        # Circuit capacity (default 32)
    batch_timeout=5,              # Auto-seal interval in seconds (default 5)
    mempool_max_size=10000,       # Mempool size limit
    state_backend="memory",       # "memory" or "lmdb"
    l1_backend="memory",          # "memory" or "eth_rpc"
    prover_backend="python",      # "python" or "native"
    hash_function="keccak256",    # "keccak256" or "poseidon" (ZK-friendly)
    l1_confirmations=2,           # L1 block confirmations before finality (default 2)
    rate_limit_rps=100,           # RPC rate limit per IP (requests/sec)
    max_request_size=1_048_576,   # Max RPC request body size in bytes (1MB)
    cors_origins=["*"],           # CORS allowed origins
    enable_metrics=True,          # Enable /metrics endpoint
    # LMDB settings
    data_dir="./data/my-rollup",
    # EthL1Backend settings
    l1_rpc_url="https://...",
    l1_private_key="hex...",
    l1_chain_id=11155111,
    # NativeProverBackend settings
    prover_binary="rapidsnark",
    prover_working_dir="./prover",
)
rollup = Rollup(stf=my_stf, config=config)
```

## Rollup Lifecycle Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `setup()` | None | ZK circuit setup + verifier deployment. Must be called before prove |
| `submit_tx(tx)` | `str\|None` | Error string on failure, None on success |
| `produce_batch()` | `Batch` | Process mempool + seal. RuntimeError if no txs |
| `prove_and_submit(batch)` | `BatchReceipt` | Generate proof + submit to L1 (one step) |
| `prove_batch(batch)` | `Batch` | Generate proof only (no L1 submission) |
| `submit_batch(batch)` | `BatchReceipt` | Submit already-proven batch to L1 |
| `chain_info()` | `dict` | name, chain_id, state_root, is_setup, pending_txs, etc. |
| `recover()` | None | Crash recovery from LMDB WAL |

## Security Considerations

### STF Integrity Gap (WHITEPAPER 7.3.1)

Groth16 proves **execution-trace binding** only — it guarantees that the claimed state transition matches the computation, but does **not** verify the correctness or safety of the STF logic itself.

The circuit enforces:

```
old_root × ∏ᵢ private_i ≡ new_root × tx_commitment  (mod p)
```

This proves: *"The prover knows private values that algebraically connect these three public inputs."*

**What the circuit does NOT enforce:**

- Whether `apply_tx(state, tx)` was executed correctly
- Whether failed transactions were excluded from the batch
- Whether balance checks, access control, or any STF logic was honored
- Whether `new_state_root` is the honest result of applying the STF to `old_state_root`

**Attack scenarios:**

1. **Including failed transactions** — A malicious sequencer skips rollback for failed txs, including them in the batch with incorrect state effects. The proof remains valid because the circuit only checks the algebraic relationship.
2. **Manipulating the STF** — A malicious sequencer replaces the STF (e.g., skips balance checks, mints tokens), computes a new `new_state_root`, and generates a valid proof for `(old_root, evil_new_root, tx_commitment)`. The L1 verifier accepts it.

**Defense layers:**

| Layer | Mechanism | Trust Model |
|-------|-----------|-------------|
| Groth16 proof | Prevents proof forgery for fixed public inputs | Trustless (mathematical) |
| Data availability | Tx data on L1 (calldata/blob) allows re-execution | DA assumption |
| Off-chain re-execution | Verifiers re-run STF on DA data, compare `new_root` | 1-of-N honest verifier |
| Social consensus | Community detects mismatch, responds | Governance |

This is effectively an **optimistic verification model**: the ZK proof guarantees execution-trace binding, but STF correctness relies on off-chain re-execution and data availability.

### STF Security Checklist (WHITEPAPER 10.1.8)

Every production STF should implement these safeguards:

```python
def secure_stf(state: dict, tx: L2Tx) -> STFResult:
    # 1. Transaction authentication — verify sender signature
    if not verify_signature(tx):
        return STFResult(success=False, error="invalid signature")

    # 2. Replay protection — enforce strict nonce ordering
    expected = state.get(f"nonce:{tx.sender.hex()}", 0)
    if tx.nonce != expected:
        return STFResult(success=False, error="invalid nonce")

    # 3. Input validation — sanitize all data fields
    if not validate_data(tx.data):
        return STFResult(success=False, error="invalid data")

    # 4. Access control — check permissions
    if tx.data.get("op") == "admin_action":
        if tx.sender != state.get("admin"):
            return STFResult(success=False, error="unauthorized")

    # 5. MEV prevention — use commit-reveal or ordering rules
    # 6. Transaction expiry — reject stale transactions
    if tx.timestamp > 0 and time.time() - tx.timestamp > 3600:
        return STFResult(success=False, error="tx expired")

    # ... actual app logic ...
    state[f"nonce:{tx.sender.hex()}"] = tx.nonce + 1
    return STFResult(success=True)
```

### Four Security Properties (WHITEPAPER 3.5)

| Property | Guarantee | Limitation |
|----------|-----------|------------|
| **Validity** | Groth16 proof ensures state transition matches execution trace | Does not verify STF logic correctness |
| **Data Availability** | Batch data posted to L1 calldata/blobs | Blob data expires after ~18 days |
| **Censorship Resistance** | Force inclusion mechanism on L1 (50-block window) | Relies on L1 liveness; no forced execution |
| **Value Safety** | Escape hatch allows L1 fund recovery if L2 halts | Only recovers ETH deposits with value > 0 |

## Caveats

1. **`setup()` required**: Must be called before `prove_and_submit()`. Otherwise RuntimeError
2. **Max tx count**: Up to `max_txs_per_batch - 1` txs. The last slot is reserved for balance factor
3. **State snapshot/rollback**: Failed txs do not affect state (automatic rollback)
4. **Field modulus truncation**: 32-byte hashes are reduced modulo BN128 field modulus. Deterministic but non-intuitive
5. **Zero product impossible**: Proof fails if state_root is a multiple of the field modulus (probability < 1/2^252)
6. **STF integrity gap**: Groth16 proves execution binding only, not STF correctness — secure your STF logic independently
7. **Poseidon hash**: When using `hash_function="poseidon"`, state roots use Poseidon (~240 R1CS constraints) instead of keccak256 (~150,000). More ZK-friendly but less battle-tested
8. **L1 finality**: Set `l1_confirmations >= 2` for production. PoS Ethereum requires 2 epoch finality (~13 min); without sufficient confirmations, L1 reorgs may invalidate submitted batches
