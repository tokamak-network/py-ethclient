#!/usr/bin/env python3
"""ZK Note Settlement — ERC20 토큰 비공개 정산 데모

Deposit: secret과 amount로 커밋먼트를 만들고, ERC20을 vault에 예치
Settle:  ZK proof로 소유권 증명 + nullifier로 이중 사용 방지

증명하는 것:
  1. secret × amount == commitment (소유권)
  2. secret × secret == nullifier (이중 사용 방지)

비밀로 유지하는 것:
  - secret (소유자 비밀키)
  - amount (토큰 양)

Run:
    python examples/zk_note_settle.py
"""

import time

from ethclient.zk import Circuit, groth16
from ethclient.zk.evm_verifier import EVMVerifier
from ethclient.zk.snarkjs_compat import (
    export_snarkjs_proof,
    export_snarkjs_vkey,
    verify_snarkjs,
)

print("=" * 60)
print("  ZK Note Settlement — Private ERC20 Settle")
print("=" * 60)

# ━━━ 1. Circuit 정의 ━━━
c = Circuit()
secret = c.private("secret")
amount = c.private("amount")
commitment = c.public("commitment")
nullifier = c.public("nullifier")

c.constrain(secret * amount, commitment)  # 소유권 증명
c.constrain(secret * secret, nullifier)  # Nullifier 생성

print(f"\n[1] Circuit")
print(f"    {c.num_constraints} constraints, {c.num_public} public, {c.num_private} private")

# ━━━ 2. Trusted Setup ━━━
print(f"\n[2] Trusted setup...")
t0 = time.time()
pk, vk = groth16.setup(c)
print(f"    {time.time() - t0:.1f}s")

# ━━━ 3. Deposit (off-chain 계산) ━━━
alice_secret, alice_amount = 42, 100
alice_commitment = alice_secret * alice_amount  # 4200
alice_nullifier = alice_secret * alice_secret  # 1764

print(f"\n[3] Alice deposits 100 USDC")
print(f"    commitment: {alice_commitment}")
print(f"    (secret={alice_secret}, amount={alice_amount} — kept private)")

# ━━━ 4. Settle (ZK proof 생성) ━━━
print(f"\n[4] Alice settles with ZK proof")
t0 = time.time()
proof = groth16.prove(
    pk,
    private={"secret": alice_secret, "amount": alice_amount},
    public={"commitment": alice_commitment, "nullifier": alice_nullifier},
    circuit=c,
)
print(f"    Proof generated: {time.time() - t0:.1f}s")

# ━━━ 5. Verify ━━━
print(f"\n[5] DEX contract verifies proof")
t0 = time.time()
valid = groth16.verify(vk, proof, [alice_commitment, alice_nullifier])
t_verify = time.time() - t0
print(f"    Native verify: {'PASS' if valid else 'FAIL'} ({t_verify:.2f}s)")
assert valid

# ━━━ 6. EVM on-chain 검증 ━━━
verifier = EVMVerifier(vk)
print(f"\n[6] EVM on-chain verification")
print(f"    Bytecode: {len(verifier.bytecode)} bytes")

t0 = time.time()
result = verifier.verify_on_evm(proof, [alice_commitment, alice_nullifier])
t_evm = time.time() - t0
print(f"    EVM result: {'PASS' if result.success else 'FAIL'} ({t_evm:.2f}s)")
print(f"    Gas used: {result.gas_used:,}")
assert result.success

# ━━━ 7. 보안 테스트 ━━━
print(f"\n[7] Security tests")

# 7a. 이중 사용 방지
spent_nullifiers = {alice_nullifier}
print(f"    Double-spend: nullifier {alice_nullifier} already in spent set")

# 7b. 틀린 nullifier
assert not verifier.verify_on_evm(proof, [alice_commitment, 9999]).success
print(f"    Wrong nullifier(9999): EVM rejected")

# 7c. 틀린 commitment
assert not verifier.verify_on_evm(proof, [9999, alice_nullifier]).success
print(f"    Wrong commitment(9999): EVM rejected")

# 7d. Bob의 위조 시도
try:
    # Bob은 secret=42를 모르므로 다른 조합을 시도
    # secret=10, amount=420 → commitment 4200 OK, 하지만 nullifier=100≠1764
    groth16.prove(
        pk,
        private={"secret": 10, "amount": 420},
        public={"commitment": 4200, "nullifier": 1764},
        circuit=c,
    )
    print("    Bob forgery: unexpectedly succeeded")
except ValueError:
    print(f"    Bob forgery (secret=10): rejected — R1CS unsatisfied")

# ━━━ 8. Bob의 노트 ━━━
print(f"\n[8] Bob deposits 200 USDC (secret=77)")
bob_secret, bob_amount = 77, 200
bob_commitment = bob_secret * bob_amount  # 15400
bob_nullifier = bob_secret * bob_secret  # 5929

proof_bob = groth16.prove(
    pk,
    private={"secret": bob_secret, "amount": bob_amount},
    public={"commitment": bob_commitment, "nullifier": bob_nullifier},
    circuit=c,
)
assert groth16.verify(vk, proof_bob, [bob_commitment, bob_nullifier])
assert verifier.verify_on_evm(proof_bob, [bob_commitment, bob_nullifier]).success
print(f"    Bob settle: PASS (commitment={bob_commitment}, nullifier={bob_nullifier})")

# ━━━ 9. snarkjs 호환 ━━━
print(f"\n[9] snarkjs compatibility")
vk_json = export_snarkjs_vkey(vk)
proof_json = export_snarkjs_proof(proof)
assert verify_snarkjs(
    vk_json, proof_json, [str(alice_commitment), str(alice_nullifier)]
)
print(f"    snarkjs format verify: PASS")
print(f"    protocol={vk_json['protocol']}, curve={vk_json['curve']}")

# ━━━ Gas 프로파일 ━━━
profile = verifier.gas_profile(proof, [alice_commitment, alice_nullifier])

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  Notes settled: Alice(100 USDC), Bob(200 USDC)")
print(f"  Verify: native={t_verify:.2f}s | EVM={t_evm:.2f}s")
print(f"  EVM gas: {result.gas_used:,}")
print(
    f"  Breakdown: ecMul={profile.ecmul_gas:,}"
    f" + ecAdd={profile.ecadd_gas:,}"
    f" + ecPairing={profile.ecpairing_gas:,}"
)
print(f"{'=' * 60}")
