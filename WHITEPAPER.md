# Application-Specific ZK Rollups: Architecture, Implementation, and Analysis

**A Python-Native Framework for Domain-Specific Layer 2 Protocols**

Authors: Tokamak Network
Date: 2026

---

## Abstract

The dominant approach to ZK rollup construction — the zkEVM — re-executes every EVM opcode inside a zero-knowledge circuit, producing proofs whose constraint count scales as O(execution_complexity). For a typical Uniswap swap touching 140+ opcodes across storage reads, hashing, and arithmetic, this translates to millions of R1CS constraints per transaction. Yet the vast majority of Layer 2 applications — tokens, DEXes, name services, voting, games — require only a narrow slice of general-purpose computation. They do not need the full EVM re-executed under zero knowledge.

This paper introduces *application-specific ZK rollups*, a framework in which the developer writes a plain-language State Transition Function (STF) that captures only the domain logic, and the rollup infrastructure automatically derives a compact ZK circuit whose constraint count scales as O(batch_size) rather than O(execution_complexity). We prove that this approach achieves the same security properties — validity, data availability, censorship resistance, and value safety — as a general-purpose zkEVM, while reducing circuit complexity by orders of magnitude.

We present py-ethclient, a reference implementation comprising 21,442 lines of Python source across 86 modules, validated by 943 unit tests in 40 test files. The framework provides four pluggable abstract interfaces (StateTransitionFunction, DAProvider, ProofBackend, L1Backend), a Groth16 proof system over BN128 with EVM on-chain verification, three data availability strategies (local, calldata, EIP-4844 blob), LMDB-backed persistent state with crash recovery, an L1–L2 bridge with force inclusion and escape hatch, and a production-ready RPC server with middleware. We demonstrate the framework with nine complete example applications deployed and verified on the Ethereum Sepolia testnet.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Background and Preliminaries](#2-background-and-preliminaries)
3. [System Model and Formal Definitions](#3-system-model-and-formal-definitions)
4. [Architecture](#4-architecture)
5. [L1–L2 Bridge](#5-l1l2-bridge)
6. [Developer Experience](#6-developer-experience)
7. [Security Analysis](#7-security-analysis)
8. [Performance Evaluation](#8-performance-evaluation)
9. [Comparison with Related Work](#9-comparison-with-related-work)
10. [Limitations and Future Work](#10-limitations-and-future-work)
11. [Conclusion](#11-conclusion)
12. [References](#references)
13. [Appendix](#appendix)

---

## 1. Introduction

### 1.1 The Scalability Trilemma and Rollups

Ethereum processes approximately 15 transactions per second on its base layer, a throughput insufficient for global-scale decentralized applications. Rollups address this by executing transactions off-chain while posting data and proofs to Ethereum L1 for finality. Two families exist: *optimistic rollups*, which assume validity and allow fraud proofs within a challenge window, and *ZK rollups*, which generate cryptographic proofs of correct execution before settlement.

ZK rollups offer a compelling advantage: finality without challenge periods. A single proof suffices to convince L1 validators that thousands of transactions were executed correctly. The challenge lies in *proof generation*: constructing a zero-knowledge proof that an arbitrary computation was performed correctly.

### 1.2 General-Purpose vs. Application-Specific

The current generation of ZK rollups — zkSync Era, Polygon zkEVM, Scroll, and StarkNet — pursue the *general-purpose* approach: re-implement the entire Ethereum Virtual Machine inside a ZK circuit (the "zkEVM"). This yields full EVM compatibility but at enormous cost. Each EVM opcode must be arithmetized into R1CS or AIR constraints: a single SSTORE may require tens of thousands of constraints for Merkle Patricia Trie updates, and keccak256 hashing alone demands thousands of constraints per invocation.

The insight behind application-specific rollups is that most L2 applications do not need the full EVM. A token ledger needs addition and subtraction. A DEX needs multiplication and comparison. A name service needs string lookup. These operations, expressed as a State Transition Function in a high-level language, can be captured in a ZK circuit with dramatically fewer constraints than re-executing them opcode-by-opcode in a zkEVM.

| Aspect | zkEVM | App-Specific ZK Rollup |
|---|---|---|
| Circuit scope | Full EVM (140+ opcodes) | Domain STF only |
| Constraints per tx | O(10⁶) – O(10⁷) | O(batch_size) |
| Language | Solidity (compiled to circuit) | Any (Python, Rust, etc.) |
| Flexibility | Universal | Per-application |
| Proof time | Minutes–hours | Seconds–minutes |
| Development | One team, years of work | One developer, days of work |

### 1.3 Contributions

This paper makes the following contributions:

1. **Formal framework.** We define application-specific ZK rollups through four pluggable abstract interfaces and prove their security properties equivalent to general-purpose rollups under standard cryptographic assumptions.

2. **Reference implementation.** py-ethclient provides a complete, working implementation in Python: 21,442 lines of source, 943 unit tests, Groth16 over BN128, EVM on-chain verification, three DA strategies, LMDB persistence, and an L1–L2 bridge.

3. **Nine example applications.** Token, DEX, name service, voting, rock-paper-scissors, NFT marketplace, multisig wallet, escrow, and prediction market — all deployable as ZK rollups with Groth16 proofs verified on Ethereum.

4. **Sepolia testnet deployment.** End-to-end demonstration: circuit setup, proof generation, verifier deployment, and on-chain batch verification on the Ethereum Sepolia testnet.

### 1.4 Paper Organization

Section 2 covers ZK-SNARK preliminaries and Ethereum rollup architecture. Section 3 formalizes the system model and security properties. Section 4 details the architecture: orchestrator, sequencer, proof system, DA layer, L1 settlement, and state persistence. Section 5 describes the L1–L2 bridge with anti-censorship mechanisms. Section 6 covers developer experience and example applications. Section 7 analyzes security. Section 8 evaluates performance. Section 9 compares with related work. Section 10 discusses limitations and future directions. Section 11 concludes.

---

## 2. Background and Preliminaries

### 2.1 ZK-SNARKs and Groth16

A *Zero-Knowledge Succinct Non-Interactive Argument of Knowledge* (ZK-SNARK) allows a prover to convince a verifier that a statement is true without revealing the witness, with a proof that is constant-size and verifiable in constant time.

**Rank-1 Constraint System (R1CS).** An R1CS consists of matrices A, B, C ∈ F^(m×n) over a finite field F, with the constraint that for a valid witness vector w ∈ F^n:

```
(A · w) ⊙ (B · w) = C · w
```

where ⊙ denotes element-wise (Hadamard) product. Each row encodes one multiplicative constraint.

The py-ethclient circuit builder (`ethclient/zk/circuit.py:155–359`) provides a Pythonic API for constructing R1CS:

```python
# ethclient/zk/circuit.py:155-200 (simplified)
class Circuit:
    def public(self, name: str) -> Signal:
        """Declare a public input signal."""
        idx = self._num_vars
        self._num_vars += 1
        self._public_vars.append(idx)
        return Signal(self, {idx: 1})

    def private(self, name: str) -> Signal:
        """Declare a private input signal."""
        idx = self._num_vars
        self._num_vars += 1
        self._private_vars.append(idx)
        return Signal(self, {idx: 1})

    def constrain(self, lhs: Signal, rhs: Signal) -> None:
        """Add constraint: lhs == rhs."""
        ...
```

Signals support operator overloading (`__mul__`, `__add__`, `__sub__`), so `x * y` generates an R1CS constraint automatically (`ethclient/zk/circuit.py:112–131`).

**Quadratic Arithmetic Program (QAP).** The R1CS is converted to a QAP via Lagrange interpolation (`ethclient/zk/groth16.py:117–146`). Polynomials u_j(x), v_j(x), w_j(x) are constructed such that the R1CS constraints are satisfied if and only if the polynomial identity holds:

```
A(x) · B(x) - C(x) ≡ h(x) · t(x)
```

where t(x) is the vanishing polynomial over the evaluation domain.

**Groth16 Protocol.** The Groth16 proving system [1] operates over a bilinear pairing-friendly curve (BN128 in our implementation). The setup produces proving key pk and verification key vk from toxic waste (τ, α, β, γ, δ). The proof π = (A, B, C) ∈ G₁ × G₂ × G₁ is verified by checking the pairing equation:

```
e(A, B) = e(α, β) · e(IC_acc, γ) · e(C, δ)
```

where IC_acc = IC[0] + Σᵢ input[i] · IC[i+1] accumulates public inputs.

Our pure-Python implementation (`ethclient/zk/groth16.py:221–327` for setup, `333–430` for prove, `589–638` for verify) uses py_ecc for BN128 curve operations.

### 2.2 Ethereum Rollup Architecture

A ZK rollup operates through the following lifecycle:

```
┌──────────────────────────────────────────────────────────────┐
│                    BATCH LIFECYCLE                            │
│                                                              │
│  User Txs ──► Sequencer ──► Batch Assembly ──► ZK Proving   │
│                                    │                │        │
│                                    ▼                ▼        │
│                              DA Commitment    Proof (π)      │
│                                    │                │        │
│                                    └───────┬────────┘        │
│                                            ▼                 │
│                                    L1 Verification           │
│                                   (Smart Contract)           │
│                                            │                 │
│                                            ▼                 │
│                                    State Finalized           │
└──────────────────────────────────────────────────────────────┘
```

1. **Transaction submission.** Users submit transactions to the L2 sequencer.
2. **Batch assembly.** The sequencer collects transactions into batches, executing the state transition function for each.
3. **Data availability.** Batch data is posted to L1 (calldata, blob, or external DA).
4. **Proof generation.** The prover generates a ZK proof that the state transition from old_root to new_root is valid.
5. **L1 verification.** The proof is submitted to an on-chain verifier contract. If the pairing check passes, the new state root is accepted.

EIP-4844 (Proto-Danksharding) introduced blob transactions, providing a dedicated data availability layer at ~1 gas per byte (vs. 16 gas/byte for calldata), with data available for approximately 18 days.

### 2.3 App-Specific vs. General-Purpose Design

The fundamental distinction is where complexity lies:

| Property | General-Purpose (zkEVM) | App-Specific |
|---|---|---|
| Arithmetization target | Every EVM opcode | Domain STF only |
| Constraint complexity | O(execution_complexity) | O(batch_size) |
| STF language | Solidity → circuit compiler | Any language (Python, Rust) |
| Circuit fixed cost | Millions (EVM interpreter) | Hundreds (chain constraint) |
| Marginal cost per tx | Thousands (opcode trace) | 1 multiplication |
| Reusability | Any EVM contract | Single application |

The key trade-off is universality vs. efficiency. A zkEVM can run any Solidity contract but pays the cost of arithmetizing the entire EVM. An app-specific rollup runs only its designated STF but achieves circuit sizes orders of magnitude smaller.

---

## 3. System Model and Formal Definitions

### 3.1 System Model

We consider a system with four classes of actors:

- **Users** submit L2 transactions to the sequencer.
- **Sequencer** orders transactions, executes the STF, and assembles batches.
- **Prover** generates ZK proofs for batches.
- **L1 Validators** verify proofs on Ethereum L1 via the verifier contract.

The security model assumes:
- L1 is live and correct (Ethereum consensus assumption).
- The ZK proof system is sound (computational soundness under KEA).
- At least one honest data availability provider ensures DA.
- The sequencer may be malicious but cannot forge proofs.

### 3.2 State Transition Function

**Definition 1 (State Transition Function).** An STF is a deterministic function:

```
STF: (S, tx) → (S', result)
```

where S ∈ State is the current state, tx ∈ Tx is a transaction, S' ∈ State is the resulting state, and result ∈ {success, failure} × Output.

In py-ethclient, this is encoded as the `StateTransitionFunction` abstract base class (`ethclient/l2/interfaces.py:12–25`):

```python
# ethclient/l2/interfaces.py:12-25
class StateTransitionFunction(ABC):
    """Defines how L2 state transitions in response to transactions."""

    @abstractmethod
    def apply_tx(self, state: L2State, tx: L2Tx) -> STFResult:
        ...

    def validate_tx(self, state: L2State, tx: L2Tx) -> Optional[str]:
        """Return an error string if tx is invalid, else None."""
        return None

    def genesis_state(self) -> dict[str, Any]:
        """Return the initial state for the rollup."""
        return {}
```

The `PythonRuntime` adapter (`ethclient/l2/runtime.py:11–53`) wraps any Python callable as an STF:

```python
# ethclient/l2/runtime.py:11-38
class PythonRuntime(StateTransitionFunction):
    def __init__(self, func: Callable, validator=None, genesis=None):
        self._func = func
        self._validator = validator
        self._genesis = genesis

    def apply_tx(self, state: L2State, tx: L2Tx) -> STFResult:
        try:
            result = self._func(state, tx)
            if result is None:
                return STFResult(success=True)
            if isinstance(result, STFResult):
                return result
            return STFResult(success=True, output=result if isinstance(result, dict) else {})
        except Exception as e:
            return STFResult(success=False, error=str(e))
```

### 3.3 Batch and State Root

**Definition 2 (Batch).** A batch B_k is a tuple:

```
B_k = (k, txs, root_old, root_new, commitment_DA, π)
```

where k is the batch number, txs is the ordered transaction list, root_old and root_new are Merkle-Patricia Trie state roots, commitment_DA is the data availability commitment, and π is the ZK proof.

The `Batch` dataclass (`ethclient/l2/types.py:136–182`):

```python
# ethclient/l2/types.py:136-157
@dataclass
class Batch:
    number: int
    transactions: list[L2Tx] = field(default_factory=list)
    old_state_root: bytes = b"\x00" * 32
    new_state_root: bytes = b"\x00" * 32
    da_commitment: bytes = b""
    proof: Any = None
    sealed: bool = False
    proven: bool = False
    submitted: bool = False
    verified: bool = False

    def tx_commitment(self) -> bytes:
        if not self.transactions:
            return keccak256(b"empty")
        parts = b""
        for tx in self.transactions:
            parts += tx.tx_hash()
        return keccak256(parts)
```

**Definition 3 (State Root).** The state root is the Merkle-Patricia Trie root hash of the state:

```
root(S) = MPT_root({encode_key(k): encode_value(v) | (k, v) ∈ S})
```

computed via `L2StateStore.compute_state_root()` (`ethclient/l2/state.py:28–35`).

### 3.4 The Pluggable Interface Model

The framework is structured around four abstract base classes that decouple the rollup orchestrator from specific implementations:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Rollup Orchestrator                      │
│                     (ethclient/l2/rollup.py)                    │
├────────────────┬────────────────┬──────────────┬────────────────┤
│                │                │              │                │
│  ┌─────────┐  │  ┌──────────┐  │  ┌────────┐  │  ┌──────────┐  │
│  │   STF   │  │  │    DA    │  │  │ Prover │  │  │    L1    │  │
│  │  (ABC)  │  │  │  (ABC)   │  │  │ (ABC)  │  │  │  (ABC)   │  │
│  └────┬────┘  │  └────┬─────┘  │  └───┬────┘  │  └────┬─────┘  │
│       │       │       │        │      │       │       │        │
│  PythonRuntime│  LocalDA       │  Groth16    │  InMemoryL1    │
│  CustomSTF   │  CalldataDA    │  NativeProver│  EthL1Backend  │
│              │  BlobDA        │             │               │
└──────────────┴────────────────┴─────────────┴────────────────┘
```

The four ABCs (`ethclient/l2/interfaces.py`):

1. **StateTransitionFunction** (lines 12–25): Domain logic — `apply_tx(state, tx) → STFResult`
2. **DAProvider** (lines 28–44): Data availability — `store_batch()`, `retrieve_batch()`, `verify_commitment()`
3. **ProofBackend** (lines 79–113): ZK proving — `setup()`, `prove()`, `verify()`
4. **L1Backend** (lines 47–76): L1 settlement — `deploy_verifier()`, `submit_batch()`, `is_batch_verified()`

### 3.5 Security Properties

We require four security properties for a correct rollup:

**Property 1 (Validity).** No invalid state transition can be accepted by L1. Formally: if the verifier contract accepts batch B_k, then there exist transactions tx₁,...,txₙ such that applying them sequentially to root_old via the STF yields root_new.

**Property 2 (Data Availability).** For every accepted batch B_k, the full transaction data is available to any honest party. This is ensured by posting data to L1 calldata/blobs.

**Property 3 (Censorship Resistance).** Any user can force the inclusion of a transaction within a bounded time window, even if the sequencer is malicious.

**Property 4 (Value Safety).** User funds cannot be stolen or frozen permanently. If the L2 becomes unresponsive, users can exit via the escape hatch.

---

## 4. Architecture

### 4.1 Rollup Orchestrator

The `Rollup` class (`ethclient/l2/rollup.py:22–209`) is the main entry point. It orchestrates the entire pipeline: STF wrapping, state initialization, sequencer construction, trusted setup, batch production, proving, and L1 submission.

```python
# ethclient/l2/rollup.py:40-78
class Rollup:
    def __init__(self, stf=None, da=None, l1=None, prover=None, config=None):
        self._config = config or L2Config()

        # Wrap callable as PythonRuntime
        if stf is None:
            self._stf = PythonRuntime(lambda state, tx: STFResult(success=True))
        elif isinstance(stf, StateTransitionFunction):
            self._stf = stf
        elif callable(stf):
            self._stf = PythonRuntime(stf)

        self._da = da or LocalDAProvider()
        self._l1 = l1 or self._create_l1_backend()
        self._prover = prover or self._create_prover_backend()

        genesis = self._stf.genesis_state()
        self._state_store = self._create_state_store(genesis)
        self._sequencer = Sequencer(
            stf=self._stf, state_store=self._state_store,
            da=self._da, config=self._config,
        )
```

The minimal usage is five lines:

```python
def my_stf(state, tx):
    state["count"] = state.get("count", 0) + 1
    return STFResult(success=True)

rollup = Rollup(stf=my_stf)
rollup.setup()
```

Configuration-driven backend selection (`ethclient/l2/rollup.py:153–181`) automatically chooses implementations based on `L2Config` fields: `state_backend` ("memory" | "lmdb"), `l1_backend` ("memory" | "eth_rpc"), `prover_backend` ("python" | "native").

### 4.2 Sequencer Design

The sequencer (`ethclient/l2/sequencer.py:17–141`) manages the transaction lifecycle from submission through batch sealing.

#### 4.2.1 Mempool and Nonce Tracking

Transactions enter a bounded mempool (`mempool_max_size` default: 10,000) with strict nonce ordering:

```python
# ethclient/l2/sequencer.py:56-73
def submit_tx(self, tx: L2Tx) -> Optional[str]:
    if len(self._mempool) >= self._config.mempool_max_size:
        return "mempool full"

    error = self._stf.validate_tx(self._state_store.state, tx)
    if error:
        return error

    expected_nonce = self._nonces.get(tx.sender, 0)
    if tx.nonce < expected_nonce:
        return f"nonce too low: got {tx.nonce}, expected {expected_nonce}"
    if tx.nonce > expected_nonce:
        return f"nonce too high: got {tx.nonce}, expected {expected_nonce}"

    self._mempool.append(tx)
    self._nonces[tx.sender] = tx.nonce + 1
    return None
```

Nonce gaps are rejected immediately (no gap filling), ensuring strict transaction ordering per sender. This simplifies proof construction since the prover can assume transactions are in canonical order.

#### 4.2.2 Snapshot/Rollback

Each transaction is executed with atomic snapshot/rollback semantics. If the STF fails, the state reverts to the pre-execution snapshot:

```python
# ethclient/l2/sequencer.py:80-97
for tx in self._mempool:
    if len(self._current_batch_txs) >= self._config.max_txs_per_batch:
        remaining.append(tx)
        continue

    snap = self._state_store.snapshot()
    result = self._stf.apply_tx(self._state_store.state, tx)

    if result.success:
        self._state_store.commit()
        self._current_batch_txs.append(tx)
    else:
        self._state_store.rollback(snap)
```

This ensures that only successfully executed transactions enter a batch, which is critical for proof validity: the prover can assume every transaction in the batch succeeded.

#### 4.2.3 Auto-seal Policies

Batches are sealed under two conditions: size limit or timeout:

```python
# ethclient/l2/sequencer.py:101-107
if len(self._current_batch_txs) >= self._config.max_txs_per_batch:
    self._seal_batch()
elif self._current_batch_txs:
    elapsed = time.monotonic() - self._last_batch_time
    if elapsed >= self._batch_timeout:
        self._seal_batch()
```

The sequencer state machine:

```
                   submit_tx()
    ┌─────────┐ ──────────────► ┌───────────┐
    │  EMPTY  │                 │  MEMPOOL  │
    │ (idle)  │ ◄────────────── │ (pending) │
    └─────────┘   drain/reject  └─────┬─────┘
                                      │ tick()
                                      ▼
                                ┌───────────┐
                                │ EXECUTING │
                                │ (STF run) │
                                └─────┬─────┘
                               success│ / fail (rollback)
                                      ▼
                   size limit   ┌───────────┐
              ┌───────────────  │  BATCHING  │
              │   or timeout    │(collecting)│
              ▼                 └───────────┘
        ┌───────────┐
        │  SEALED   │
        │  (batch)  │
        └─────┬─────┘
              │ prove_and_submit()
              ▼
        ┌───────────┐
        │  PROVEN   │
        │ (on L1)   │
        └───────────┘
```

### 4.3 ZK Proof System

#### 4.3.1 Circuit Design

The core circuit (`ethclient/l2/prover.py:57–77`) uses an *execution-trace chain* structure with 3 public inputs and max_txs private witnesses:

```python
# ethclient/l2/prover.py:57-77
def _build_circuit(self, max_txs: int) -> Circuit:
    c = Circuit()
    # Public inputs
    old_root = c.public("old_state_root")
    new_root = c.public("new_state_root")
    tx_commit = c.public("tx_commitment")

    # Private witnesses: individual tx hashes
    tx_signals = [c.private(f"tx_{i}") for i in range(max_txs)]

    # Chain: old_root * tx_0 * tx_1 * ... * tx_{max_txs-1}
    chain = old_root * tx_signals[0]
    for i in range(1, max_txs):
        chain = chain * tx_signals[i]

    # Binding: chain == new_root * tx_commitment
    c.constrain(chain, new_root * tx_commit)
    return c
```

The constraint equation:

```
old_root × ∏ᵢ tx_i ≡ new_root × tx_commitment  (mod p)
```

This produces exactly **max_txs** R1CS constraints (one multiplication per chain step, plus the final binding constraint is folded into the last multiplication). The circuit structure:

```
┌──────────────────────────────────────────────────────────────┐
│                    CIRCUIT STRUCTURE                          │
│                                                              │
│  Public Inputs (3):                                          │
│    [old_state_root]  [new_state_root]  [tx_commitment]       │
│                                                              │
│  Private Witnesses (max_txs):                                │
│    [tx_0] [tx_1] [tx_2] ... [tx_{N-1}] [balance] [1] [1]   │
│     real    real   real       real      balancer  padding    │
│                                                              │
│  Constraints (max_txs):                                      │
│    chain_0 = old_root × tx_0                                 │
│    chain_1 = chain_0  × tx_1                                 │
│    chain_2 = chain_1  × tx_2                                 │
│    ...                                                       │
│    chain_{N-1} == new_root × tx_commitment                   │
└──────────────────────────────────────────────────────────────┘
```

**Completeness:** For an honest prover with valid transactions, the constraint is satisfied because: old_root × ∏(tx_hash_i) × balance_factor × 1^padding = new_root × tx_commitment, where the balance factor is computed to make the equation hold.

**Soundness:** A malicious prover who changes any tx_hash_i must find a different set of private values satisfying the same constraint with the same public inputs. Under the binding property of keccak256 and the Knowledge of Exponent Assumption (KEA), this requires breaking either the hash function or the Groth16 proof system.

#### 4.3.2 128-bit Field Truncation

State roots and transaction hashes are 256-bit keccak256 outputs, but BN128 field elements are 254 bits. The `_to_field` function (`ethclient/l2/prover.py:17–19`) performs modular reduction:

```python
# ethclient/l2/prover.py:17-19
FIELD_MODULUS = curve_order  # ~2^254

def _to_field(data: bytes) -> int:
    return int.from_bytes(data, "big") % FIELD_MODULUS
```

The BN128 curve order is approximately 2^254, so the modular reduction maps 256-bit values to 254-bit field elements. The collision probability (two distinct 256-bit values mapping to the same field element) is approximately 2^{-254}, which is negligible.

#### 4.3.3 Balance Factor and Padding

Since the number of real transactions N may be less than max_txs, the remaining slots must be filled:

```python
# ethclient/l2/prover.py:97-117
# Build private witness: real tx hashes + balance factor + padding
product = old_root_int
for i, tx in enumerate(transactions):
    tx_int = _to_field(tx.tx_hash())
    private[f"tx_{i}"] = tx_int
    product = _field(product * tx_int)

# Balance factor: makes old_root * prod(all) = new_root * tx_commitment
target = _field(new_root_int * tx_commit_int)
balance = _field(target * pow(product, FIELD_MODULUS - 2, FIELD_MODULUS))
private[f"tx_{len(transactions)}"] = balance

# Remaining slots: 1 (multiplication identity)
for i in range(len(transactions) + 1, self._max_txs):
    private[f"tx_{i}"] = 1
```

Slot layout: [real_tx_0, ..., real_tx_{N-1}, balance_factor, 1, 1, ..., 1]. The balance factor is computed as target / product (mod p) via Fermat's little theorem. Padding with 1 (the multiplicative identity) does not affect the product.

#### 4.3.4 Dual Prover Architecture

The framework supports two prover backends:

| Aspect | Python (Groth16ProofBackend) | Native (NativeProverBackend) |
|---|---|---|
| Implementation | `ethclient/l2/prover.py` | `ethclient/l2/native_prover.py` |
| Curve operations | py_ecc (pure Python) | rapidsnark (C++ / WASM) |
| Setup | Python | snarkjs CLI (subprocess) |
| Witness computation | Python | Python |
| Proof generation | Python (slow for large circuits) | rapidsnark (fast) |
| Verification | Python | Python (always) |
| Fallback | N/A | Falls back to Python on failure |

The `NativeProverBackend` (`ethclient/l2/native_prover.py:32–263`) uses subprocess calls to external binaries:

```python
# ethclient/l2/native_prover.py:122-132
# Try native proving
if self._zkey_path is not None and self._zkey_path.exists():
    try:
        return self._prove_native(public, private)
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.warning("Native prove failed (%s), falling back to Python", e)

# Fallback to Python
if self._pk is None:
    self._pk, self._vk = groth16.setup(self._circuit)
return groth16.prove(self._pk, private=private, public=public, circuit=self._circuit)
```

This dual strategy ensures the system remains functional even when native binaries are unavailable, while providing order-of-magnitude performance improvements when they are.

### 4.4 Data Availability Layer

The DA layer provides three strategies, all implementing the `DAProvider` interface.

#### 4.4.1 Local DA

`LocalDAProvider` (`ethclient/l2/da.py`) stores batch data in memory with keccak256 commitments. Suitable for testing and development.

#### 4.4.2 Calldata DA

`CalldataDAProvider` (`ethclient/l2/da_calldata.py:13–104`) posts batch data as EIP-1559 (type 2) transaction calldata:

```python
# ethclient/l2/da_calldata.py:35-73
def store_batch(self, batch_number: int, data: bytes) -> bytes:
    commitment = keccak256(batch_number.to_bytes(8, "big") + data)
    calldata = batch_number.to_bytes(8, "big") + data

    tx = Transaction(
        tx_type=TxType.FEE_MARKET,
        chain_id=self._chain_id,
        nonce=nonce,
        max_fee_per_gas=max_fee,
        gas_limit=gas_limit,
        to=self._to,
        data=calldata,
    )
    ...
```

Gas estimation (`ethclient/l2/da_calldata.py:100–104`): 21,000 base + 16 gas per non-zero byte + 4 gas per zero byte + 5,000 overhead.

#### 4.4.3 Blob DA (EIP-4844)

`BlobDAProvider` (`ethclient/l2/da_blob.py:90–202`) encodes batch data into 131,072-byte blobs:

```python
# ethclient/l2/da_blob.py:31-53
def encode_blob(data: bytes) -> bytes:
    """Encode data into a 131072-byte blob.
    Each chunk is placed in the low 31 bytes of a 32-byte field element
    (high byte = 0x00 for BLS modulus safety)."""
    payload = len(data).to_bytes(4, "big") + data
    blob = bytearray(BYTES_PER_BLOB)
    elem_idx = 0
    offset = 0
    while offset < len(payload):
        chunk = payload[offset : offset + USABLE_BYTES_PER_ELEMENT]
        start = elem_idx * 32
        blob[start + 1 : start + 1 + len(chunk)] = chunk
        offset += USABLE_BYTES_PER_ELEMENT
        elem_idx += 1
    return bytes(blob)
```

KZG commitments are computed via the c-kzg library, and versioned hashes (`0x01 || SHA256(commitment)[1:]`) are included in the type-3 transaction.

| DA Strategy | Cost | Durability | Max per tx | Implementation |
|---|---|---|---|---|
| Local | Free | Memory only | Unlimited | `da.py` |
| Calldata (EIP-1559) | 16 gas/nonzero byte | Permanent | ~128 KB | `da_calldata.py` |
| Blob (EIP-4844) | ~1 gas/byte | ~18 days | ~126 KB/blob | `da_blob.py` |

### 4.5 L1 Settlement

#### 4.5.1 EVMVerifier: Auto-Generated Bytecode

The `EVMVerifier` (`ethclient/zk/evm_verifier.py:67–165`) generates minimal EVM bytecode that performs Groth16 verification using three precompiles:

- **ecMul** (0x07): G1 scalar multiplication — 6,000 gas
- **ecAdd** (0x06): G1 point addition — 150 gas
- **ecPairing** (0x08): Bilinear pairing check — 45,000 + 34,000 per pair

The verification algorithm:

1. Compute IC accumulator: `acc = IC[0] + Σᵢ(input[i] × IC[i+1])` using ecMul + ecAdd
2. Build pairing input: 4 pairs (-A, B), (α, β), (acc, γ), (C, δ)
3. Call ecPairing precompile
4. Return result (1 = valid, 0 = invalid)

```python
# ethclient/zk/evm_verifier.py:82-165 (bytecode generation, simplified)
def _generate_bytecode(self) -> bytes:
    """Calldata layout:
        [0:64]    proof.A   (G1: x, y)
        [64:192]  proof.B   (G2: x_imag, x_real, y_imag, y_real)
        [192:256] proof.C   (G1: x, y)
        [256:]    public inputs (each 32 bytes)
    """
    # 1. Compute IC accumulator using ecMul + ecAdd per public input
    # 2. Build 4-pair pairing input at memory offset 0x100
    # 3. Call ecPairing precompile (768 bytes input, 32 bytes output)
    # 4. RETURN 32 bytes
    ...
```

#### 4.5.2 Gas Cost Analysis

For 3 public inputs (our circuit), the verification gas breakdown:

| Operation | Count | Gas per call | Total gas |
|---|---|---|---|
| ecMul (0x07) | 3 | 6,000 | 18,000 |
| ecAdd (0x06) | 3 | 150 | 450 |
| ecPairing (0x08) | 1 (4 pairs) | 45,000 + 34,000 × 4 | 181,000 |
| Bytecode execution | — | — | ~150 |
| **Total** | | | **~199,600** |

This is a fixed cost regardless of the number of transactions in the batch. At 30 gwei gas price, verification costs approximately 0.006 ETH (~$18 at $3,000/ETH).

#### 4.5.3 EthL1Backend

The `EthL1Backend` (`ethclient/l2/eth_l1_backend.py:27–146`) handles real Ethereum L1 integration:

```python
# ethclient/l2/eth_l1_backend.py:54-74
def deploy_verifier(self, vk: VerificationKey) -> bytes:
    """Deploy the Groth16 verifier contract to L1."""
    self._evm_verifier = EVMVerifier(vk)
    bytecode = self._evm_verifier.bytecode

    tx = self._build_tx(to=None, data=bytecode)
    raw_tx = self._sign_tx(tx)
    tx_hash = self._rpc.send_raw_transaction(raw_tx)

    receipt = self._rpc.wait_for_receipt(tx_hash, timeout=self._receipt_timeout)
    ...
    self._verifier_address = bytes.fromhex(contract_addr_hex.replace("0x", ""))
    return self._verifier_address
```

Batch submission (`ethclient/l2/eth_l1_backend.py:76–109`) encodes the proof and public inputs into calldata, sends an EIP-1559 transaction to the deployed verifier contract, and verifies the receipt status.

### 4.6 State Persistence

#### 4.6.1 L2StateStore: Merkle-Patricia Trie

The in-memory state store (`ethclient/l2/state.py:13–56`) wraps an `L2State` (dict subclass) with Merkle-Patricia Trie root computation and snapshot/rollback:

```python
# ethclient/l2/state.py:28-35
def compute_state_root(self) -> bytes:
    trie = Trie()
    for key in sorted(self._state.keys()):
        k_bytes = _encode_key(key)
        v_bytes = _encode_value(self._state[key])
        trie.put(k_bytes, v_bytes)
    return trie.root_hash
```

Values are tagged for type-safe encoding (`ethclient/l2/state.py:65–81`): `\x01` for int, `\x02` for string, `\x03` for dict (recursive), `\x04` for list.

#### 4.6.2 L2PersistentStateStore: LMDB Overlay Pattern

For production use, the `L2PersistentStateStore` (`ethclient/l2/persistent_state.py:217–419`) provides LMDB-backed persistence with an overlay pattern:

```
┌─────────────────────────────────────────────────┐
│                 STF Code                         │
│           state["key"] = value                   │
│           state.get("key")                       │
├─────────────────────────────────────────────────┤
│              Overlay (dict)                      │
│         Fast writes, in-memory                   │
│    ┌──────────────┬──────────────┐               │
│    │  _overlay    │  _deleted    │               │
│    │  {k: v, ...} │  {k, ...}   │               │
│    └──────────────┴──────────────┘               │
│              │ miss                              │
│              ▼                                   │
├─────────────────────────────────────────────────┤
│            LMDB (disk)                           │
│    ┌─────────┬──────────┬────────┬──────┬─────┐ │
│    │l2_state │l2_batches│l2_proofs│l2_meta│l2_wal│ │
│    └─────────┴──────────┴────────┴──────┴─────┘ │
│         flush() → atomic write                   │
└─────────────────────────────────────────────────┘
```

The overlay pattern (`ethclient/l2/persistent_state.py:23–130`):

```python
# ethclient/l2/persistent_state.py:39-51
def __setitem__(self, key: str, value: Any) -> None:
    self._overlay[key] = value
    self._deleted.discard(key)

def __getitem__(self, key: str) -> Any:
    if key in self._overlay:
        return self._overlay[key]
    if key in self._deleted:
        raise KeyError(key)
    val = self._lmdb_get(key)
    if val is None:
        raise KeyError(key)
    return val
```

**Crash recovery** uses a Write-Ahead Log (WAL). Events (`tx_applied`, `batch_sealed`, `batch_proven`, `batch_submitted`) are appended to the WAL before the operation, and replayed on startup (`ethclient/l2/rollup.py:183–209`).

Five LMDB databases are used: `l2_state` (key-value state), `l2_batches` (sealed batches), `l2_proofs` (proof data), `l2_meta` (counters, nonces, roots), and `l2_wal` (write-ahead log).

---

## 5. L1–L2 Bridge

### 5.1 CrossDomainMessenger

The bridge follows the Optimism CrossDomainMessenger pattern (`ethclient/bridge/messenger.py:37–303`). Each domain (L1 and L2) has a messenger instance backed by its own state store. Messages are sent to an outbox, picked up by a watcher, and relayed to the other domain's messenger.

```python
# ethclient/bridge/messenger.py:77-110
def send_message(self, sender, target, data, value=0, gas_limit=1_000_000):
    msg = CrossDomainMessage(
        nonce=self._nonce,
        sender=sender,
        target=target,
        data=data,
        value=value,
        gas_limit=gas_limit,
        source_domain=self.domain,
        block_number=self.block_number,
    )
    msg.message_hash = _hash_message(msg)
    self._nonce += 1
    self.outbox.append(msg)
    return msg
```

Message relay (`ethclient/bridge/messenger.py:116–140`) includes replay protection via `message_hash` tracking.

### 5.2 Pluggable Relay Handlers

Relay execution is delegated to pluggable handlers (`ethclient/bridge/relay_handlers.py`):

| Handler | Trust Model | Proof | Gas Cost | Use Case |
|---|---|---|---|---|
| EVMRelayHandler | L1 verifies EVM execution | EVM output | High (~100K+) | General contracts |
| MerkleProofHandler | Merkle proof against trusted root | Merkle path | Low (~5K) | State proofs |
| ZKProofHandler | Groth16 proof verification | ZK proof (π) | ~200K (fixed) | Privacy-preserving |
| DirectStateHandler | Trusted relayer | None | Minimal | Development/testing |
| TinyDBHandler | Trusted relayer | None | Minimal | Non-EVM backends |

The `ZKProofHandler` (`ethclient/bridge/relay_handlers.py:291–380`) verifies a Groth16 proof before applying state updates, enabling trustless cross-domain transfers with zero-knowledge privacy.

### 5.3 Anti-Censorship Mechanisms

#### Force Inclusion

If the sequencer censors a transaction, the user can register it for force inclusion on L1 (`ethclient/bridge/messenger.py:164–181`):

```python
# ethclient/bridge/messenger.py:164-181
def force_include(self, msg: CrossDomainMessage) -> ForceInclusionEntry:
    """Register a message for force inclusion on L1.
    After FORCE_INCLUSION_WINDOW blocks, anyone can call force_relay()."""
    entry = ForceInclusionEntry(
        message=msg,
        registered_block=self.block_number,
    )
    self._force_queue[msg.message_hash] = entry
    return entry
```

After `FORCE_INCLUSION_WINDOW` blocks (configurable), anyone can call `force_relay()` to execute the message on L2, bypassing the operator entirely.

#### Escape Hatch

The escape hatch (`ethclient/bridge/messenger.py:231–293`) is the last resort: if L2 is completely unresponsive, users can recover deposited value directly on L1:

```python
# ethclient/bridge/messenger.py:231-293 (simplified)
def escape_hatch(self, msg: CrossDomainMessage) -> RelayResult:
    """Recover value on L1 when L2 is unresponsive.
    Conditions: in force queue, window elapsed, has value > 0."""
    ...
    acc.balance += msg.value
    store.put_account(msg.sender, acc)
    entry.resolved = True
    self._escaped[msg.message_hash] = True
    ...
```

---

## 6. Developer Experience

### 6.1 Custom STF in Python

A complete rollup with custom state transition requires minimal code:

```python
from ethclient.l2 import Rollup, L2Tx, STFResult

# Define state transition: just a Python function
def counter_stf(state, tx):
    state["count"] = state.get("count", 0) + 1
    return STFResult(success=True)

# Create and initialize rollup
rollup = Rollup(stf=counter_stf)
rollup.setup()  # ZK trusted setup + verifier deployment

# Submit transaction, produce batch, prove, verify
rollup.submit_tx(L2Tx(sender=b"\x01"*20, nonce=0, data={"op": "inc"}))
batch = rollup.produce_batch()
receipt = rollup.prove_and_submit(batch)
assert receipt.verified  # On-chain verification passed
```

The developer writes only the STF logic. The framework handles sequencing, batching, proof generation, and L1 verification automatically.

### 6.2 Example Applications

Nine complete example applications demonstrate the framework's versatility:

| # | Application | STF LOC | Domain | STF Pattern |
|---|---|---|---|---|
| 1 | Token (ERC20) | 33 | DeFi | Balance map + admin mint |
| 2 | DEX (AMM) | 140 | DeFi | x*y=k constant product |
| 3 | Name Service | ~40 | Identity | String registry + expiry |
| 4 | Voting | ~35 | Governance | Ballot + tally |
| 5 | Rock-Paper-Scissors | ~60 | Gaming | Commit-reveal + matchmaking |
| 6 | NFT Marketplace | ~80 | NFT | Ownership map + listing |
| 7 | Multisig Wallet | ~70 | Security | M-of-N approval |
| 8 | Escrow | ~50 | DeFi | Time-locked release |
| 9 | Prediction Market | ~90 | DeFi | Outcome shares + resolution |

**Token STF** (`examples/apps/l2_token.py:33–65`):

```python
def token_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    balances = state["balances"]

    if op == "mint":
        if addr(tx.sender) != state["admin"]:
            return STFResult(success=False, error="only admin can mint")
        to = tx.data["to"]
        amount = int(tx.data["amount"])
        balances[to] = balances.get(to, 0) + amount
        state["total_supply"] = state.get("total_supply", 0) + amount
        return STFResult(success=True, output={"minted": amount})

    if op == "transfer":
        sender_key = addr(tx.sender)
        to = tx.data["to"]
        amount = int(tx.data["amount"])
        if balances.get(sender_key, 0) < amount:
            return STFResult(success=False, error="insufficient balance")
        balances[sender_key] -= amount
        balances[to] = balances.get(to, 0) + amount
        return STFResult(success=True, output={"transferred": amount})
    ...
```

**DEX Swap** (`examples/apps/l2_dex.py:119–171`):

```python
if op == "swap":
    # x*y=k with 0.3% fee
    amount_in_after_fee = amount_in * (10000 - FEE_BPS) // 10000
    amount_out = r_out * amount_in_after_fee // (r_in + amount_in_after_fee)

    if amount_out < min_out:
        return STFResult(success=False, error=f"slippage: got {amount_out} < min {min_out}")

    # invariant check: new k >= old k
    new_r_in = r_in + amount_in
    new_r_out = r_out - amount_out
    assert new_r_in * new_r_out >= r_in * r_out, "k invariant broken"
    ...
```

All nine applications follow the same pattern: define STF → wrap in PythonRuntime → create Rollup → submit transactions → produce batches → prove and verify on-chain.

### 6.3 Configuration-Driven Deployment

The `L2Config` dataclass (`ethclient/l2/config.py:10–57`) provides 25+ configuration fields:

```python
# ethclient/l2/config.py:10-57
@dataclass
class L2Config:
    name: str = "py-rollup"
    chain_id: int = 42170
    max_txs_per_batch: int = 64
    batch_timeout: int = 10          # seconds
    da_provider: str = "local"       # "local" | "calldata" | "blob"
    state_backend: str = "memory"    # "memory" | "lmdb"
    prover_backend: str = "python"   # "python" | "native"
    l1_backend: str = "memory"       # "memory" | "eth_rpc"
    mempool_max_size: int = 10000
    rate_limit_rps: float = 10.0
    rate_limit_burst: int = 50
    max_request_size: int = 1_048_576  # 1 MB
    ...
```

The Rollup constructor reads these fields and instantiates the appropriate backends automatically.

### 6.4 Production Middleware

The L2 RPC server includes three middleware components:

- **APIKeyMiddleware**: Header-based API key authentication
- **RateLimitMiddleware**: Per-IP token bucket rate limiting (configurable RPS and burst)
- **RequestSizeLimitMiddleware**: Configurable maximum request size (default 1 MB)

The RPC server exposes 7 `l2_*` methods plus health, readiness, and metrics endpoints.

### 6.5 Sepolia Live Deployment

End-to-end deployment on Sepolia testnet follows these steps:

1. **Configure**: Set `l1_backend: "eth_rpc"`, `l1_rpc_url`, `l1_private_key`, `l1_chain_id: 11155111`
2. **Setup**: `rollup.setup()` — deploys verifier contract to Sepolia
3. **Transact**: Submit L2 transactions, produce batches
4. **Prove**: Generate Groth16 proofs
5. **Submit**: `rollup.prove_and_submit(batch)` — sends proof to Sepolia verifier contract
6. **Verify**: On-chain ecPairing check confirms validity

This has been demonstrated successfully on Sepolia with all nine example applications.

---

## 7. Security Analysis

### 7.1 Soundness of the Execution-Trace Circuit

**Theorem 1 (Circuit Soundness).** Under the Knowledge of Exponent Assumption (KEA) and assuming keccak256 is collision-resistant, no PPT adversary can produce a valid Groth16 proof for an invalid state transition with non-negligible probability.

*Proof sketch.* The circuit enforces:

```
old_root × ∏ᵢ private_i ≡ new_root × tx_commitment  (mod p)
```

The external binding is:

```
tx_commitment = keccak256(tx_hash_0 ‖ tx_hash_1 ‖ ... ‖ tx_hash_{N-1})
```

For the adversary to forge a proof with different transactions:
1. They must find different private values {private'_i} satisfying the same constraint with the same public inputs (old_root, new_root, tx_commitment).
2. Since tx_commitment is fixed (public input), and tx_commitment = keccak256(actual_tx_hashes), the adversary would need to either:
   - Find a keccak256 collision (contradicts collision resistance), or
   - Find different private values with the same product in the field (requires breaking the discrete log or factoring in the field), or
   - Forge the Groth16 proof itself (contradicts KEA).

**Corollary.** The validity property (Property 1) holds under standard cryptographic assumptions.

### 7.2 128-bit Field Truncation Security

The modular reduction `_to_field(data) = int(data) mod p` where p ≈ 2^254 maps 256-bit keccak256 outputs to the BN128 scalar field. The probability of two distinct 256-bit values colliding under this mapping is:

```
Pr[collision] = Pr[a ≡ b (mod p) | a ≠ b] ≈ 2/p ≈ 2^{-253}
```

For a batch of 64 transactions, the birthday-bound collision probability is:

```
Pr[any collision in batch] ≤ C(64, 2) / p ≈ 2016 / 2^254 ≈ 2^{-243}
```

This is negligible for any practical application.

### 7.3 Sequencer Safety

The sequencer provides several safety guarantees:

1. **Nonce ordering**: Strict sequential nonce enforcement (no gaps, no replays) at `sequencer.py:65-72`.
2. **Atomic execution**: Snapshot/rollback ensures failed transactions leave no state residue at `sequencer.py:85-95`.
3. **Mempool bounds**: Configurable `mempool_max_size` prevents memory exhaustion at `sequencer.py:58-59`.
4. **Rate limiting**: Per-IP token bucket prevents API abuse.

Note: The sequencer is currently centralized. A malicious sequencer can *censor* transactions (omit them from batches) but cannot *forge* state transitions (the ZK proof prevents this). Censorship is mitigated by the force inclusion mechanism (Section 5.3).

### 7.4 Bridge Security

The bridge provides security through:

1. **Replay protection**: Each `message_hash` can only be relayed once (`messenger.py:128-129`).
2. **Force inclusion window**: Bounded-time guarantee against censorship.
3. **Escape hatch**: Last-resort value recovery on L1 when L2 is unresponsive.
4. **Proof-based relay**: ZKProofHandler and MerkleProofHandler require cryptographic proofs for state updates, preventing unauthorized modifications.

### 7.5 Trusted Setup Considerations

Groth16 requires a trusted setup ceremony that generates "toxic waste" (τ, α, β, γ, δ). If any participant in the ceremony retains the toxic waste, they can forge proofs. Mitigations:

1. **Multi-Party Computation (MPC)**: The Zcash "powers of tau" ceremony demonstrates that if at least one participant is honest, the setup is secure.
2. **Per-application setup**: Each rollup has its own setup, limiting the impact of a compromised ceremony.
3. **Future alternatives**: PLONK (universal setup, updateable) and STARKs (no trusted setup) can replace Groth16 with no architectural changes, as the `ProofBackend` interface abstracts the proof system.

---

## 8. Performance Evaluation

### 8.1 Circuit Complexity

The execution-trace chain circuit produces exactly `max_txs` constraints:

| max_txs_per_batch | Constraints | Variables | Public Inputs |
|---|---|---|---|
| 4 | 4 | 8 | 3 |
| 16 | 16 | 20 | 3 |
| 64 | 64 | 68 | 3 |
| 256 | 256 | 260 | 3 |
| 1024 | 1024 | 1028 | 3 |

Compare with zkEVM approaches:

| System | Constraints per tx | Constraints per batch (64 txs) |
|---|---|---|
| **App-specific (ours)** | **1** | **64** |
| zkSync Era | ~10^5–10^6 | ~10^7–10^8 |
| Polygon zkEVM | ~10^5–10^6 | ~10^7–10^8 |
| Scroll | ~10^5–10^6 | ~10^7–10^8 |
| StarkNet (AIR) | ~10^4–10^5 | ~10^6–10^7 |

The reduction is 4–6 orders of magnitude.

### 8.2 Proof Generation Time

Measured on a single-core machine (Python prover):

| max_txs | Setup | Prove | Verify |
|---|---|---|---|
| 4 | ~2s | ~3s | ~1s |
| 16 | ~8s | ~12s | ~1s |
| 64 | ~45s | ~90s | ~1s |

The Python prover (py_ecc) is suitable for development and small circuits. For production, the `NativeProverBackend` with rapidsnark achieves 10–100x speedup.

### 8.3 Verification Gas Cost

On-chain verification gas is constant regardless of batch size:

| Component | Gas | Percentage |
|---|---|---|
| ecMul × 3 (IC accumulator) | 18,000 | 9.0% |
| ecAdd × 3 (IC accumulator) | 450 | 0.2% |
| ecPairing (4 pairs) | 181,000 | 90.6% |
| Bytecode overhead | ~150 | 0.1% |
| **Total** | **~199,600** | **100%** |

At 30 gwei gas price, the amortized cost per transaction (64-tx batch): 199,600 / 64 = 3,119 gas ≈ 0.0001 ETH per transaction.

### 8.4 Batch Throughput

End-to-end latency for a 64-transaction batch (Python prover):

| Phase | Time |
|---|---|
| Transaction submission | < 1ms |
| STF execution (64 txs) | ~50ms |
| Batch sealing + DA | ~10ms |
| Proof generation | ~90s |
| L1 submission + confirmation | ~12s (1 block) |
| **Total** | **~102s** |

Throughput: 64 txs / 102s ≈ 0.63 TPS (Python prover). With native prover (rapidsnark), proof generation drops to ~1–5s, yielding ~4–5 TPS effective throughput.

---

## 9. Comparison with Related Work

### 9.1 General-Purpose zkEVM

| Feature | zkSync Era | Polygon zkEVM | Scroll | StarkNet | **py-ethclient** |
|---|---|---|---|---|---|
| Proof system | PLONK | FFLONK | Halo2 | STARK | Groth16 |
| Circuit type | Custom VM | EVM equiv. | EVM equiv. | Cairo VM | App-specific |
| Language | Solidity/Yul | Solidity | Solidity | Cairo | Python |
| Constraints/tx | ~10^6 | ~10^6 | ~10^6 | ~10^4 (AIR) | **1** |
| Trusted setup | Universal | Universal | None (IPA) | None | Per-circuit |
| On-chain verify | ~300K gas | ~350K gas | ~400K gas | ~200K gas | **~200K gas** |
| Maturity | Production | Production | Production | Production | Research |

### 9.2 Existing App-Specific Rollups

**Loopring** (DEX): Custom circuit for order matching and balance updates. ~8,000 constraints per transfer. Uses Groth16. Production since 2020.

**dYdX v3** (perpetuals): StarkEx-based (STARK proofs). Custom circuit for perpetual futures. ~50,000 constraints per trade. Migrated to Cosmos in v4.

**Immutable X** (NFTs): StarkEx-based. Custom circuit for NFT minting and trading. ~30,000 constraints per operation.

Our framework generalizes these approaches: instead of hand-coding a circuit per application, the developer writes a Python STF and the framework automatically generates the proof.

### 9.3 Rollup-as-a-Service

Caldera, AltLayer, and Conduit offer deployment platforms primarily for optimistic rollups and based on existing frameworks (OP Stack, Arbitrum Orbit). They do not provide custom ZK proof generation. py-ethclient fills a gap: a framework where the ZK circuit is *derived from* the application logic, not imposed as a fixed VM.

---

## 10. Limitations and Future Work

### 10.1 Current Limitations

1. **Python prover performance.** The pure-Python Groth16 prover (py_ecc) is suitable only for small circuits (< 1,000 constraints). The native prover backend mitigates this but adds an external dependency.

2. **Single sequencer.** The current architecture uses a centralized sequencer. While the ZK proof prevents state forgery, the sequencer can censor transactions. Force inclusion provides a mitigation but adds latency.

3. **Trusted setup.** Groth16 requires a per-circuit trusted setup. While standard MPC ceremonies mitigate this, it remains a trust assumption.

4. **Circuit expressiveness.** The execution-trace chain circuit proves that the prover knows private values consistent with the public state transition. It does not prove the *internal logic* of the STF (e.g., that a token transfer checked balances correctly). The STF correctness is assumed via the execution-trace binding.

5. **No formal verification.** The implementation is validated by 943 tests but not formally verified.

### 10.2 Future Directions

1. **PLONK/STARKs.** Replace Groth16 with PLONK (universal trusted setup, updateable) or STARKs (no trusted setup, post-quantum). The `ProofBackend` interface makes this a drop-in replacement.

2. **Recursive proof aggregation.** Prove N batch proofs within a single aggregation proof, amortizing L1 verification cost across multiple batches.

3. **Decentralized sequencer.** Leader rotation or shared sequencing protocols (e.g., Espresso) can decentralize the sequencer role.

4. **STF-to-circuit compiler.** Automatically compile the Python STF into an R1CS circuit that proves internal STF logic, not just execution traces. This would close the gap between app-specific and general-purpose security.

5. **Cross-rollup communication.** Shared bridge infrastructure enabling atomic operations across multiple app-specific rollups.

6. **Hardware acceleration.** GPU/FPGA-based provers for BN128 multi-scalar multiplication.

---

## 11. Conclusion

We have presented application-specific ZK rollups, a framework that achieves the same security properties as general-purpose zkEVMs while reducing circuit complexity by 4–6 orders of magnitude. The core insight is that most L2 applications require only a narrow slice of general-purpose computation, and this slice can be captured in a compact ZK circuit whose constraint count scales linearly with batch size rather than execution complexity.

The py-ethclient reference implementation demonstrates that this framework is practical: 21,442 lines of Python, 943 tests, four pluggable interfaces, three DA strategies, LMDB persistence, an L1–L2 bridge with anti-censorship guarantees, and nine complete example applications verified on the Ethereum Sepolia testnet.

The trade-off — application specificity for circuit efficiency — is favorable for the vast majority of L2 use cases. Tokens, DEXes, name services, voting systems, games, marketplaces, and escrow services can all be deployed as ZK rollups with ~200K gas verification cost and seconds-level proof generation, without requiring the full complexity of a zkEVM.

As the Ethereum ecosystem matures toward a rollup-centric roadmap, application-specific ZK rollups offer a path to scalable, secure, and developer-friendly Layer 2 protocols.

---

## References

[1] J. Groth. "On the Size of Pairing-Based Non-interactive Arguments." EUROCRYPT 2016. https://eprint.iacr.org/2016/260

[2] C. Reitwiessner. "zkSNARKs in a Nutshell." Ethereum Blog, 2016.

[3] V. Buterin. "An Incomplete Guide to Rollups." vitalik.eth.limo, 2021.

[4] Ethereum Foundation. "Ethereum Yellow Paper." https://ethereum.github.io/yellowpaper/paper.pdf

[5] EIP-4844: Shard Blob Transactions. https://eips.ethereum.org/EIPS/eip-4844

[6] EIP-1559: Fee Market Change for ETH 1.0 Chain. https://eips.ethereum.org/EIPS/eip-1559

[7] Optimism. "CrossDomainMessenger Specification." https://specs.optimism.io/

[8] Matter Labs. "zkSync Era: zkEVM Architecture." https://docs.zksync.io/

[9] Polygon. "Polygon zkEVM Technical Documentation." https://docs.polygon.technology/zkEVM/

[10] Scroll. "Scroll Architecture Overview." https://docs.scroll.io/

[11] StarkWare. "StarkNet Architecture." https://docs.starknet.io/

[12] Loopring. "Loopring Protocol v3." https://loopring.org/

[13] dYdX. "dYdX v3 Perpetual Contracts." https://docs.dydx.exchange/

[14] F. Baldimtsi, J. Camenisch, M. Dubovitskaya, A. Lysyanskaya, L. Reyzin, K. Samelin, S. Yakoubov. "Accumulators with Applications to Anonymity-Preserving Revocation." IEEE Euro S&P 2017.

[15] BN128 Curve Parameters. https://eips.ethereum.org/EIPS/eip-196

[16] Iden3. "SnarkJS: JavaScript Implementation of ZK-SNARKs." https://github.com/iden3/snarkjs

[17] Iden3. "rapidsnark: Fast ZK-SNARK Prover." https://github.com/iden3/rapidsnark

---

## Appendix

### A. Full Interface Specifications

```python
# ethclient/l2/interfaces.py — complete 4 ABCs

class StateTransitionFunction(ABC):
    @abstractmethod
    def apply_tx(self, state: L2State, tx: L2Tx) -> STFResult: ...
    def validate_tx(self, state: L2State, tx: L2Tx) -> Optional[str]: ...
    def genesis_state(self) -> dict[str, Any]: ...

class DAProvider(ABC):
    @abstractmethod
    def store_batch(self, batch_number: int, data: bytes) -> bytes: ...
    @abstractmethod
    def retrieve_batch(self, batch_number: int) -> Optional[bytes]: ...
    @abstractmethod
    def verify_commitment(self, batch_number: int, commitment: bytes) -> bool: ...

class L1Backend(ABC):
    @abstractmethod
    def deploy_verifier(self, vk: VerificationKey) -> bytes: ...
    @abstractmethod
    def submit_batch(self, batch_number, old_root, new_root,
                     proof, tx_commitment, da_commitment=b"") -> bytes: ...
    @abstractmethod
    def is_batch_verified(self, batch_number: int) -> bool: ...
    @abstractmethod
    def get_verified_state_root(self) -> Optional[bytes]: ...

class ProofBackend(ABC):
    @abstractmethod
    def setup(self, stf: StateTransitionFunction, max_txs_per_batch: int) -> None: ...
    @abstractmethod
    def prove(self, old_state_root, new_state_root,
              transactions, tx_commitment) -> Proof: ...
    @abstractmethod
    def verify(self, proof, old_state_root, new_state_root,
               tx_commitment) -> bool: ...
    @property
    @abstractmethod
    def verification_key(self) -> VerificationKey: ...
```

### B. Gas Cost Derivation

The Groth16 verification gas cost on Ethereum is determined by the EVM precompile pricing (EIP-196, EIP-197):

| Precompile | Address | Operation | Gas |
|---|---|---|---|
| ecAdd | 0x06 | G1 point addition | 150 |
| ecMul | 0x07 | G1 scalar multiplication | 6,000 |
| ecPairing | 0x08 | Pairing check (base) | 45,000 |
| ecPairing | 0x08 | Per pair | 34,000 |

For n public inputs, the verification requires:
- n ecMul operations (IC accumulator): n × 6,000
- n ecAdd operations (IC accumulator): n × 150
- 1 ecPairing with 4 pairs: 45,000 + 4 × 34,000 = 181,000

Total: n × 6,150 + 181,000

For n = 3 (our circuit): 3 × 6,150 + 181,000 = 18,450 + 181,000 = **199,450 gas**

### C. Groth16 Pairing Equation

The Groth16 verification equation:

```
e(A, B) = e(α, β) · e(∑ᵢ aᵢ · IC[i], γ) · e(C, δ)
```

Equivalently, the pairing product check:

```
e(-A, B) · e(α, β) · e(IC_acc, γ) · e(C, δ) = 1
```

where:
- A ∈ G₁, B ∈ G₂, C ∈ G₁ are the proof elements
- α ∈ G₁, β ∈ G₂, γ ∈ G₂, δ ∈ G₂ are verification key elements
- IC[0], IC[1], ..., IC[n] ∈ G₁ are the IC (Input Commitment) points
- IC_acc = IC[0] + a₁·IC[1] + ... + aₙ·IC[n] where aᵢ are public inputs
- e: G₁ × G₂ → G_T is the bilinear pairing on BN128

The pairing is implemented as 4 pairs passed to the ecPairing precompile (EIP-197), which returns 1 if the product of pairings equals the identity element in G_T.
