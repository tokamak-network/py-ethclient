#!/usr/bin/env python3
"""ZK Groth16 Toolkit Demo — py-ethclient

This script demonstrates the full ZK workflow:
  Circuit definition → Trusted Setup → Proof generation → Native verification
  → EVM on-chain verification → Gas profiling → snarkjs compatibility

Run:
    python examples/zk_notebook_demo.py
"""

import time

# ── 1. Circuit Definition ───────────────────────────────────────────

from ethclient.zk import Circuit, groth16

print("=" * 60)
print("  py-ethclient Groth16 ZK Toolkit Demo")
print("=" * 60)

c = Circuit()
x, y = c.private("x"), c.private("y")
z = c.public("z")
c.constrain(x * y, z)  # R1CS: x * y = z

print(f"\n[1] Circuit defined:")
print(f"    Constraints: {c.num_constraints}")
print(f"    Public inputs: {c.num_public}")
print(f"    Private inputs: {c.num_private}")

# ── 2. Trusted Setup ────────────────────────────────────────────────

print(f"\n[2] Running trusted setup...")
t0 = time.time()
pk, vk = groth16.setup(c)
t_setup = time.time() - t0

print(f"    Setup time: {t_setup:.2f}s")
print(f"    Verification key: {vk.num_public_inputs} public input(s)")
print(f"    IC points: {len(vk.ic)}")

# ── 3. Proof Generation ─────────────────────────────────────────────

print(f"\n[3] Generating proof for x=3, y=5, z=15...")
t0 = time.time()
proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)
t_prove = time.time() - t0

print(f"    Proof time: {t_prove:.2f}s")
print(f"    A = ({proof.a.x % (10**8)}..., {proof.a.y % (10**8)}...)")
print(f"    B = ({proof.b.x_real % (10**8)}..., ...)")
print(f"    C = ({proof.c.x % (10**8)}..., {proof.c.y % (10**8)}...)")

# ── 4. Native Python Verification ───────────────────────────────────

print(f"\n[4] Native verification...")
t0 = time.time()
valid = groth16.verify(vk, proof, [15])
t_verify = time.time() - t0

print(f"    Valid: {valid}")
print(f"    Verify time: {t_verify:.2f}s")
assert valid, "Verification failed!"

# ── 5. EVM On-Chain Verification ────────────────────────────────────

print(f"\n[5] EVM on-chain verification...")
from ethclient.zk.evm_verifier import EVMVerifier

verifier = EVMVerifier(vk)
print(f"    Verifier bytecode: {len(verifier.bytecode)} bytes")

t0 = time.time()
result = verifier.verify_on_evm(proof, [15])
t_evm = time.time() - t0

print(f"    EVM result: success={result.success}, gas_used={result.gas_used}")
print(f"    EVM verify time: {t_evm:.2f}s")
assert result.success, "EVM verification failed!"

# ── 6. Wrong Proof Detection ────────────────────────────────────────

print(f"\n[6] Wrong input detection...")
wrong_result = verifier.verify_on_evm(proof, [16])
print(f"    z=16 (wrong): success={wrong_result.success}")
assert not wrong_result.success, "Should have failed!"

# ── 7. Gas Profiling ────────────────────────────────────────────────

print(f"\n[7] Gas profiling...")
profile = verifier.gas_profile(proof, [15])
print(f"    ecAdd:     {profile.ecadd_calls} calls, {profile.ecadd_gas} gas")
print(f"    ecMul:     {profile.ecmul_calls} calls, {profile.ecmul_gas} gas")
print(f"    ecPairing: {profile.ecpairing_calls} calls, {profile.ecpairing_gas} gas")
print(f"    Total precompile gas: {profile.ecadd_gas + profile.ecmul_gas + profile.ecpairing_gas}")

# ── 8. Debug Verification ───────────────────────────────────────────

print(f"\n[8] Debug verification (valid proof)...")
debug = groth16.debug_verify(vk, proof, [15])
print(f"    Valid: {debug.valid}")
print(f"    e(A,B) == e(alpha,beta) * e(IC,gamma) * e(C,delta): {debug.valid}")

# ── 9. snarkjs Compatibility ────────────────────────────────────────

print(f"\n[9] snarkjs format round-trip...")
from ethclient.zk.snarkjs_compat import (
    export_snarkjs_vkey,
    export_snarkjs_proof,
    verify_snarkjs,
)

vk_json = export_snarkjs_vkey(vk)
proof_json = export_snarkjs_proof(proof)
public_json = ["15"]

valid_snarkjs = verify_snarkjs(vk_json, proof_json, public_json)
print(f"    snarkjs format verification: {valid_snarkjs}")
assert valid_snarkjs, "snarkjs format verification failed!"

# ── Summary ──────────────────────────────────────────────────────────

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  Setup: {t_setup:.2f}s | Prove: {t_prove:.2f}s | Verify: {t_verify:.2f}s | EVM: {t_evm:.2f}s")
print(f"  EVM gas: {result.gas_used} (pairing: {profile.ecpairing_gas})")
print(f"{'=' * 60}")
