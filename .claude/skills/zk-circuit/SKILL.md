---
description: "ZK Circuit Build & Groth16 Proofs — from circuit design to EVM verification"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "circuit description or verification target"
user-invocable: true
---

# ZK Circuit & Groth16 Proof Skill

Guides the full pipeline: arithmetic circuit definition → R1CS → Groth16 Trusted Setup → Prove → Verify → EVM on-chain verification.

## Key File References

| File | Role |
|------|------|
| `ethclient/zk/circuit.py` | Circuit builder, Signal operations, R1CS conversion |
| `ethclient/zk/groth16.py` | Setup, Prove, Verify (pure Python) |
| `ethclient/zk/types.py` | G1Point, G2Point, Proof, VerificationKey, ProvingKey |
| `ethclient/zk/evm_verifier.py` | EVMVerifier — on-chain verification bytecode generation |
| `ethclient/zk/r1cs_export.py` | snarkjs .r1cs binary format export |
| `ethclient/zk/snarkjs_compat.py` | snarkjs JSON parsing/export |
| `ethclient/l2/prover.py` | Groth16ProofBackend (for L2 rollup) |
| `ethclient/l2/native_prover.py` | NativeProverBackend (rapidsnark integration) |

## Quick Start: Multiplication Circuit

```python
from ethclient.zk import Circuit, groth16

# 1. Define circuit: x * y == z (x, y are private, z is public)
c = Circuit()
x = c.private("x")
y = c.private("y")
z = c.public("z")
c.constrain(x * y, z)

# 2. Trusted Setup
pk, vk = groth16.setup(c)

# 3. Generate proof
proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)

# 4. Verify (Python)
assert groth16.verify(vk, proof, [15])

# 5. EVM verification
from ethclient.zk.evm_verifier import EVMVerifier
verifier = EVMVerifier(vk)
result = verifier.verify_on_evm(proof, [15])
assert result.success
print(f"Gas used: {result.gas_used}")
```

## Field Arithmetic (BN128)

```python
FIELD_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583
# ~254 bits, BN128 curve order

# Basic operations
def _field(x): return x % FIELD_MODULUS
def _field_inv(x): return pow(x, FIELD_MODULUS - 2, FIELD_MODULUS)  # Fermat's little theorem
```

All circuit operations are performed over this finite field. 32-byte hash values are converted via `int.from_bytes(data, "big") % FIELD_MODULUS`.

## Circuit API

### Signal Declaration
```python
c = Circuit()
x = c.public("x")     # Public input (known to verifier)
y = c.private("y")     # Private input (known only to prover)
tmp = c.intermediate("tmp")  # Intermediate variable
```

### Signal Operations
```python
# Addition/subtraction: linear combination without constraints
a + b       # Signal + Signal
a + 5       # Signal + constant
a - b

# Multiplication: auto-generates R1CS constraint
a * b       # → intermediate variable + constraint: a * b = _tmp
a * 3       # Constant multiplication: no constraint (scalar mult)

# Negation
-a          # Negate all coefficients
```

### Adding Constraints
```python
c.constrain(x * y, z)       # x * y == z (replace C in multiplication result)
c.constrain(a + b, c_var)   # a + b == c (linear equality: (a+b-c)*1 = 0)
```

### R1CS Conversion & Validation
```python
r1cs = c.to_r1cs()
# R1CS { A, B, C: sparse matrix, num_variables, num_public, num_constraints }

witness = c.compute_witness(private={"x": 3, "y": 5}, public={"z": 15})
assert r1cs.check_witness(witness)  # A[i]·w * B[i]·w == C[i]·w for all i
```

### Witness Variable Ordering
1. Index 0: constant `1`
2. Index 1..num_public-1: public inputs (declaration order)
3. Index num_public..: private inputs, intermediate variables

## Groth16 Pipeline

### Setup (Trusted Setup)
```python
pk, vk = groth16.setup(circuit)
# pk: ProvingKey — kept by prover (secret)
# vk: VerificationKey — published to verifier
```
- Toxic waste (tau, alpha, beta, gamma, delta) generated then discarded
- Performed once per circuit

### Prove
```python
proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)
# proof: Proof(a: G1Point, b: G2Point, c: G1Point)
```
- Witness computation → R1CS validation → QAP conversion → proof generation
- Random blinding factors (r, s) used

### Verify
```python
valid = groth16.verify(vk, proof, [15])  # public_inputs as list[int]
# or
valid = groth16.verify(vk, proof, {"z": 15})  # dict form also supported
```
- Pairing check: `e(A,B) == e(alpha,beta) * e(IC_acc,gamma) * e(C,delta)`

### Debug Verify
```python
result = groth16.debug_verify(vk, proof, [15])
# result.valid, result.e_ab, result.e_alpha_beta, result.e_ic_gamma, result.e_c_delta
```

## EVM On-Chain Verification

### Bytecode Generation & Execution
```python
from ethclient.zk.evm_verifier import EVMVerifier

verifier = EVMVerifier(vk)
bytecode = verifier.bytecode  # Deployment bytecode

# Local EVM execution
result = verifier.verify_on_evm(proof, [15])
# EVMResult(success=True, gas_used=..., return_data=...)
```

### Gas Profiling
```python
profile = verifier.gas_profile(proof, [15])
# GasProfile(total_gas, ecadd_gas, ecadd_calls, ecmul_gas, ecmul_calls, ecpairing_gas, ecpairing_calls)
```

### Precompile Costs
| Precompile | Address | Gas |
|------------|---------|-----|
| ECADD | 0x06 | 150 |
| ECMUL | 0x07 | 6,000 |
| ECPAIRING | 0x08 | 45,000 + 34,000 * num_pairs |

Total gas: ~181,000 base + 6,150 per public input

### Calldata Layout
```
[0:64]    proof.A   (x, y)
[64:192]  proof.B   (x_imag, x_real, y_imag, y_real)  ← note G2 EVM encoding order
[192:256] proof.C   (x, y)
[256:]    public_inputs (32 bytes each)
```

## snarkjs Compatibility

### R1CS Export
```python
from ethclient.zk.r1cs_export import export_r1cs_binary, export_witness_json

r1cs_bytes = export_r1cs_binary(circuit)
with open("circuit.r1cs", "wb") as f:
    f.write(r1cs_bytes)

witness_json = export_witness_json(public={"z": 15}, private={"x": 3, "y": 5}, circuit=c)
```

### snarkjs JSON Parsing
```python
from ethclient.zk.snarkjs_compat import verify_snarkjs, parse_snarkjs_proof

# Verify snarkjs artifacts directly
valid = verify_snarkjs(vkey_json, proof_json, public_json)
```

### FQ2 Encoding Note
- snarkjs: `[c1, c0]` = `[imag, real]`
- EVM: `x_imag || x_real || y_imag || y_real` (imaginary first)

## L2 Rollup Circuit Structure

Circuit used by `Groth16ProofBackend`:

```
Public (3): old_state_root, new_state_root, tx_commitment
Private (max_txs): tx_0, tx_1, ..., tx_{max_txs-1}

Constraints:
  chain_0 = old_state_root * tx_0
  chain_i = chain_{i-1} * tx_i
  chain_{last} == new_state_root * tx_commitment
```

- 128-bit field truncation: `int.from_bytes(hash, "big") % FIELD_MODULUS`
- Balance factor: inserts `(new_root * tx_commit) / product` in last slot
- Actual max tx count = `max_txs_per_batch - 1`

## Poseidon Circuit

ZK-friendly hash function available as a circuit primitive:

```python
from ethclient.zk.poseidon import poseidon_circuit

c = Circuit()
x = c.private("x")
y = c.private("y")
out = c.public("out")

# Build Poseidon hash circuit for 2 inputs
poseidon_circuit(c, inputs=[x, y], output=out)
# Generates ~240 R1CS constraints
```

### Poseidon vs keccak256

| Property | Poseidon | keccak256 |
|----------|----------|-----------|
| R1CS constraints | ~240 | ~150,000 |
| ZK-friendliness | Native field operations | Bitwise ops (expensive in R1CS) |
| Security | 128-bit (conjectured) | 256-bit (standard) |
| Use case | In-circuit hashing | Out-of-circuit, general purpose |

### Poseidon Parameters
- **t** = 3 (state width: 2 inputs + 1 capacity)
- **RF** = 8 (full rounds)
- **RP** = 57 (partial rounds)
- **S-box**: x^5 (field-native exponentiation)
- **Field**: BN128 scalar field

## Complex Circuit Example: Range Proof

```python
c = Circuit()
x = c.private("x")
bound = c.public("bound")

# Prove that x is in range [0, bound)
# (x) * (bound - x - 1) = result, guaranteeing result >= 0
diff = bound + (-x) + (-Signal.one(c))  # bound - x - 1
result = c.intermediate("result")
c.constrain(x * diff, result)
```

## Security Considerations

### Field Truncation Security (WHITEPAPER 7.2)

When 32-byte hash values are reduced modulo the BN128 scalar field (`int.from_bytes(hash, "big") % FIELD_MODULUS`), a **field aliasing** risk exists: different hash values could map to the same field element. The collision probability is approximately **2^{-243}**, which is negligible for practical purposes but must be understood.

### Trusted Setup Risk (WHITEPAPER 7.5)

The Groth16 trusted setup generates **toxic waste** (tau, alpha, beta, gamma, delta). If this material is not properly discarded, a party in possession of it can forge arbitrary proofs.

**Mitigations:**
- Current implementation generates toxic waste in-memory and discards on process exit
- For production: use an **MPC ceremony** (e.g., Hermez-style) with multiple participants
- Future alternatives: **PLONK** (universal trusted setup) or **STARKs** (no trusted setup)

### Circuit Expressiveness Limitation (WHITEPAPER 10.1.2 #2)

The L2 rollup circuit proves an **execution-trace chain** only — it verifies that the product of private tx values matches the public state transition commitment. It does **not** verify:
- Individual transaction validity
- STF logic correctness
- Data availability of intermediate states

## Caveats

1. **Pure Python performance**: Suitable for <1000 constraints. Use NativeProverBackend for large circuits
2. **Toxic waste**: Generated randomly during setup(), exists in memory only. Destroyed on process exit
3. **Automatic witness solving**: `compute_witness()` iteratively solves intermediate variables (fixed-point iteration)
4. **G2 byte order**: EVM uses imaginary first. snarkjs also uses imaginary first. Consistent
5. **Polynomial division**: O(n^2) naive implementation. Bottleneck for large circuits
6. **Circuit expressiveness**: The rollup circuit proves execution-trace binding only, not individual transaction validity
7. **No recursive proofs**: The current implementation does not support proof composition or recursive SNARKs
