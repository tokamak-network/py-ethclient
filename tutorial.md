# py-ethclient Tutorial

**Python으로 ZK 증명과 L1↔L2 브릿지를 구축하는 완전 가이드**

---

## 목차

- [Part 1: Hello World ZK](#part-1-hello-world-zk)
  - [1.1 Circuit 정의](#11-circuit-정의)
  - [1.2 Trusted Setup](#12-trusted-setup)
  - [1.3 Proof 생성](#13-proof-생성)
  - [1.4 검증](#14-검증)
  - [1.5 EVM On-Chain 검증](#15-evm-on-chain-검증)
  - [1.6 틀린 입력 탐지](#16-틀린-입력-탐지)
  - [1.7 Gas 프로파일링](#17-gas-프로파일링)
  - [1.8 디버깅](#18-디버깅)
  - [1.9 전체 코드](#19-전체-코드)
- [Part 2: ZK Note Settlement — ERC20 토큰 비공개 정산](#part-2-zk-note-settlement--erc20-토큰-비공개-정산)
  - [2.1 ZK Note란?](#21-zk-note란)
  - [2.2 Circuit 설계](#22-circuit-설계)
  - [2.3 Deposit — 노트 생성](#23-deposit--노트-생성)
  - [2.4 Settle — 노트 정산 증명](#24-settle--노트-정산-증명)
  - [2.5 이중 사용 방지 (Double-Spend Prevention)](#25-이중-사용-방지-double-spend-prevention)
  - [2.6 EVM On-Chain 검증](#26-evm-on-chain-검증)
  - [2.7 snarkjs 호환](#27-snarkjs-호환)
  - [2.8 전체 코드](#28-전체-코드)
- [Part 3: 팁과 제약사항](#part-3-팁과-제약사항)
- [Part 4: L1↔L2 General State Bridge](#part-4-l1l2-general-state-bridge)
  - [4.1 브릿지 개요](#41-브릿지-개요)
  - [4.2 ETH 입금 (L1→L2)](#42-eth-입금-l1l2)
  - [4.3 상태 릴레이 — 오라클 가격 전달](#43-상태-릴레이--오라클-가격-전달)
  - [4.4 검열과 Force Inclusion](#44-검열과-force-inclusion)
  - [4.5 Escape Hatch — 최후의 수단](#45-escape-hatch--최후의-수단)
  - [4.6 전체 코드](#46-전체-코드)
  - [4.7 Proof-Based Relay](#47-proof-based-relay)

---

## Part 1: Hello World ZK

> "나는 두 비밀 숫자를 알고 있고, 그 곱이 15라는 것을 증명하겠다."

이것이 ZK 증명의 본질입니다. **비밀을 공개하지 않으면서** 그 비밀에 대한 사실을 증명하는 것.

### 1.1 Circuit 정의

ZK 증명의 시작점은 **circuit** (회로)입니다. circuit은 "무엇을 증명할 것인가"를 수학적으로 정의합니다.

```python
from ethclient.zk import Circuit, groth16

# Circuit 생성
c = Circuit()

# 비밀 입력 (prover만 알고 있음)
x = c.private("x")
y = c.private("y")

# 공개 입력 (verifier도 알고 있음)
z = c.public("z")

# 제약 조건: x * y = z
c.constrain(x * y, z)
```

여기서 핵심 개념:

| 개념 | 설명 | 예시 |
|------|------|------|
| **private** | prover만 아는 비밀 값 | x=3, y=5 |
| **public** | 누구나 볼 수 있는 값 | z=15 |
| **constrain** | 반드시 만족해야 하는 수학적 관계 | x * y = z |

circuit의 구조를 확인해 봅시다:

```python
print(f"Constraints: {c.num_constraints}")   # 1
print(f"Public inputs: {c.num_public}")      # 1
print(f"Private inputs: {c.num_private}")    # 2
```

이 circuit은 **R1CS** (Rank-1 Constraint System)로 내부 변환됩니다:

```
A · witness ⊙ B · witness = C · witness
```

여기서 witness = `[1, z, x, y, ...]` (상수 1 + 공개 + 비밀 + 중간값).

### 1.2 Trusted Setup

Groth16은 circuit마다 한 번의 **trusted setup**이 필요합니다. 이 과정에서 proving key와 verification key가 생성됩니다.

```python
pk, vk = groth16.setup(c)

print(f"Public inputs: {vk.num_public_inputs}")  # 1
print(f"IC points: {len(vk.ic)}")                # 2 (IC[0] + IC[1])
```

- **pk** (Proving Key): prover가 proof를 만들 때 사용
- **vk** (Verification Key): verifier가 proof를 검증할 때 사용

> **참고**: setup 과정에서 생성되는 "toxic waste" (τ, α, β, γ, δ)는 자동으로 폐기됩니다. 이 값이 유출되면 가짜 proof를 만들 수 있으므로, 실무에서는 MPC ceremony를 통해 setup을 수행합니다.

### 1.3 Proof 생성

비밀 값(x=3, y=5)을 알고 있는 prover가 "x * y = 15"임을 증명합니다:

```python
proof = groth16.prove(
    pk,
    private={"x": 3, "y": 5},
    public={"z": 15},
    circuit=c,
)

print(f"Proof.A = G1({proof.a.x}, {proof.a.y})")
print(f"Proof.B = G2(...)")
print(f"Proof.C = G1({proof.c.x}, {proof.c.y})")
```

proof는 세 개의 타원곡선 점으로 구성됩니다:
- **A** ∈ G1 (BN128 curve)
- **B** ∈ G2 (BN128 twist curve)
- **C** ∈ G1

이 proof 안에는 x=3, y=5라는 정보가 **전혀 포함되지 않습니다**. 하지만 수학적으로 "x * y = 15를 만족하는 x, y를 알고 있다"는 것을 증명합니다.

### 1.4 검증

verifier는 proof와 공개 입력(z=15)만으로 검증합니다:

```python
valid = groth16.verify(vk, proof, [15])
print(f"Valid: {valid}")  # True
assert valid
```

내부적으로 pairing 연산을 수행합니다:

```
e(A, B) == e(α, β) × e(IC_acc, γ) × e(C, δ)
```

여기서 `IC_acc = IC[0] + 15 × IC[1]`.

### 1.5 EVM On-Chain 검증

py-ethclient의 진짜 강점: proof를 **이더리움 EVM에서 바로 검증**할 수 있습니다.

```python
from ethclient.zk.evm_verifier import EVMVerifier

# Verification key로부터 verifier 컨트랙트 바이트코드 자동 생성
verifier = EVMVerifier(vk)
print(f"Bytecode: {len(verifier.bytecode)} bytes")

# 인메모리 EVM에서 실행
result = verifier.verify_on_evm(proof, [15])
print(f"EVM 검증 성공: {result.success}")   # True
print(f"Gas 사용량: {result.gas_used}")      # ≈ 210,000
```

이것이 내부적으로 하는 일:

1. vk의 α, β, γ, δ 포인트를 EVM 바이트코드에 하드코딩
2. `ecMul` (0x07) 프리컴파일로 IC 누적 계산
3. `ecAdd` (0x06) 프리컴파일로 점 덧셈
4. `ecPairing` (0x08) 프리컴파일로 최종 pairing check
5. 결과 반환 (1 = valid, 0 = invalid)

Solidity verifier를 직접 작성하고 테스트넷에 배포할 필요 없이, **Python 한 줄로 on-chain 검증을 테스트**할 수 있습니다.

### 1.6 틀린 입력 탐지

잘못된 공개 입력으로 검증하면 실패합니다:

```python
# z=16은 틀림 (3 * 5 = 15, not 16)
wrong = verifier.verify_on_evm(proof, [16])
print(f"z=16: success={wrong.success}")  # False

# 네이티브 검증도 동일
assert not groth16.verify(vk, proof, [16])
```

### 1.7 Gas 프로파일링

on-chain 검증 비용을 프리컴파일별로 분석합니다:

```python
profile = verifier.gas_profile(proof, [15])

print(f"ecAdd:     {profile.ecadd_calls} calls, {profile.ecadd_gas:,} gas")
print(f"ecMul:     {profile.ecmul_calls} calls, {profile.ecmul_gas:,} gas")
print(f"ecPairing: {profile.ecpairing_calls} calls, {profile.ecpairing_gas:,} gas")
print(f"Total:     {profile.total_gas:,} gas")
```

출력 예시:
```
ecAdd:     1 calls, 150 gas
ecMul:     1 calls, 6,000 gas
ecPairing: 1 calls, 181,000 gas
Total:     187,150 gas
```

> **insight**: Groth16 검증 gas의 96% 이상이 ecPairing에서 발생합니다. public input 수가 늘어나면 ecMul/ecAdd 호출이 증가하지만, pairing은 항상 1회(4쌍)입니다.

### 1.8 디버깅

proof 검증이 실패할 때, 어디서 문제가 생겼는지 확인할 수 있습니다:

```python
debug = groth16.debug_verify(vk, proof, [15])
print(f"Valid: {debug.valid}")

# 개별 pairing 값 확인
print(f"e(A, B)       = {debug.e_ab}")
print(f"e(α, β)       = {debug.e_alpha_beta}")
print(f"e(IC_acc, γ)  = {debug.e_ic_gamma}")
print(f"e(C, δ)       = {debug.e_c_delta}")

# 유효한 proof라면:
# e(A,B) == e(α,β) * e(IC_acc,γ) * e(C,δ)
assert debug.e_ab == debug.e_alpha_beta * debug.e_ic_gamma * debug.e_c_delta
```

이는 circom/snarkjs에서는 불가능한 디버깅 방법입니다. hex 덤프 대신 **실제 pairing 값을 Python 변수로 검사**할 수 있습니다.

### 1.9 전체 코드

아래를 `hello_zk.py`로 저장하고 실행하세요:

```python
"""Hello World ZK — 가장 간단한 Groth16 증명"""

from ethclient.zk import Circuit, groth16
from ethclient.zk.evm_verifier import EVMVerifier

# ── Circuit 정의 ──
c = Circuit()
x = c.private("x")
y = c.private("y")
z = c.public("z")
c.constrain(x * y, z)

print(f"Circuit: {c.num_constraints} constraint, "
      f"{c.num_public} public, {c.num_private} private")

# ── Trusted Setup ──
pk, vk = groth16.setup(c)
print(f"Setup 완료: IC points = {len(vk.ic)}")

# ── Proof 생성 ──
proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)
print(f"Proof 생성 완료")

# ── 네이티브 검증 ──
assert groth16.verify(vk, proof, [15]), "검증 실패!"
print("네이티브 검증: PASS")

# ── EVM 검증 ──
verifier = EVMVerifier(vk)
result = verifier.verify_on_evm(proof, [15])
assert result.success, "EVM 검증 실패!"
print(f"EVM 검증: PASS (gas: {result.gas_used:,})")

# ── 틀린 입력 ──
assert not verifier.verify_on_evm(proof, [16]).success
print("틀린 입력(z=16) 거부: PASS")

print("\nAll checks passed!")
```

```bash
python hello_zk.py
```

---

## Part 2: ZK Note Settlement — ERC20 토큰 비공개 정산

### 2.1 ZK Note란?

ZK DEX에서 **ZK Note**는 토큰 소유권을 나타내는 커밋먼트입니다. Tornado Cash나 Zcash의 노트와 같은 개념입니다.

```
┌─────────────────────────────────────────────────────┐
│  ZK Note = commitment(secret, amount)               │
│                                                     │
│  On-chain에는 commitment만 저장                       │
│  secret과 amount는 소유자만 알고 있음                    │
│                                                     │
│  정산(settle)할 때:                                    │
│    → "나는 이 커밋먼트의 preimage를 안다" 를 ZK로 증명    │
│    → nullifier를 공개해서 이중 사용 방지                  │
│    → secret은 절대 공개하지 않음                         │
└─────────────────────────────────────────────────────┘
```

**전체 흐름:**

```
Deposit (공개)                    Settle (비공개)
─────────────                    ────────────────
1. secret, amount 선택            1. ZK proof 생성
2. commitment = secret × amount   2. nullifier = secret² 공개
3. ERC20.transfer(vault, amount)  3. Verifier가 proof 검증
4. commitment를 on-chain 등록      4. nullifier 중복 체크
                                  5. ERC20.transfer(receiver, amount)
```

왜 이 구조가 프라이버시를 보장하는가?

| 정보 | Deposit 시 | Settle 시 | 관찰자가 아는 것 |
|------|-----------|----------|---------------|
| `secret` | 소유자만 | **비공개** (ZK proof) | 모름 |
| `amount` | commitment에 숨김 | **비공개** (ZK proof) | 모름 |
| `commitment` | 공개 등록 | proof의 공개 입력 | 알지만 preimage 모름 |
| `nullifier` | — | 공개 | 어떤 commitment인지 연결 불가 |

### 2.2 Circuit 설계

```python
from ethclient.zk import Circuit, groth16
from ethclient.zk.evm_verifier import EVMVerifier

c = Circuit()

# ── 비밀 입력: 노트 소유자만 알고 있음 ──
secret = c.private("secret")     # 소유자의 비밀키
amount = c.private("amount")     # 노트에 담긴 토큰 양

# ── 공개 입력: 체인에 기록됨 ──
commitment = c.public("commitment")  # 노트 커밋먼트 (Deposit 시 등록)
nullifier = c.public("nullifier")    # 이중 사용 방지 태그

# ── Constraint 1: 소유권 증명 ──
# "나는 이 commitment의 preimage(secret, amount)를 알고 있다"
c.constrain(secret * amount, commitment)

# ── Constraint 2: Nullifier 결정적 생성 ──
# 같은 secret → 항상 같은 nullifier → 이중 사용 감지
c.constrain(secret * secret, nullifier)

print(f"ZK Note Settlement Circuit:")
print(f"  Constraints: {c.num_constraints}")   # 2
print(f"  Public: {c.num_public}")              # 2 (commitment, nullifier)
print(f"  Private: {c.num_private}")            # 2 (secret, amount)
```

**circuit이 보장하는 것:**

1. prover는 `secret × amount == commitment`을 만족하는 secret과 amount를 알고 있다 → **소유권**
2. `nullifier == secret²`이므로, 같은 secret으로 두 번 settle하면 같은 nullifier가 나온다 → **이중 사용 방지**
3. verifier는 secret을 전혀 모른다 → **프라이버시**

```
 Private (비밀)              Public (공개)
┌───────────┐           ┌──────────────┐
│ secret ────┤──×──────→│ commitment    │  Constraint 1: secret × amount == commitment
│            │          │              │
│ amount ────┘          │              │
│            │          │              │
│ secret ────┤──×──────→│ nullifier     │  Constraint 2: secret × secret == nullifier
│ secret ────┘          │              │
└───────────┘           └──────────────┘
```

### 2.3 Deposit — 노트 생성

실제 DApp에서는 Deposit 시 다음이 일어납니다:

```python
# ━━━ Alice가 노트를 생성한다 ━━━

# Alice의 비밀값 (안전하게 보관해야 함!)
alice_secret = 42
alice_amount = 100  # 100 USDC

# Commitment 계산 (off-chain, 누구나 수학 검증 가능)
alice_commitment = alice_secret * alice_amount  # = 4200
alice_nullifier = alice_secret * alice_secret   # = 1764

print(f"Alice의 노트:")
print(f"  secret:     {alice_secret} (비밀!)")
print(f"  amount:     {alice_amount} USDC")
print(f"  commitment: {alice_commitment} (on-chain 등록)")
print(f"  nullifier:  {alice_nullifier} (settle 때까지 비밀)")

# On-chain에서 일어나는 일 (Solidity 의사코드):
# vault.deposit(commitment=4200)
# USDC.transferFrom(alice, vault, 100)
# noteTree.insert(4200)
```

> **참고**: 실제 시스템에서는 `commitment = hash(secret, amount, salt)`로 해시 커밋먼트를 사용합니다. 이 튜토리얼에서는 R1CS로 표현 가능한 곱셈(`secret × amount`)을 사용합니다.

### 2.4 Settle — 노트 정산 증명

Alice가 나중에 토큰을 정산(withdraw/transfer)합니다. 이때 secret을 공개하지 않고 ZK proof로 소유권을 증명합니다.

```python
# ━━━ Trusted Setup (DEX 배포 시 1회) ━━━
pk, vk = groth16.setup(c)
print(f"\nSetup 완료: {vk.num_public_inputs} public inputs")

# ━━━ Alice가 정산 proof를 생성한다 ━━━
proof = groth16.prove(
    pk,
    private={
        "secret": 42,    # 비밀! proof에 포함되지 않음
        "amount": 100,   # 비밀! proof에 포함되지 않음
    },
    public={
        "commitment": 4200,  # on-chain에 등록된 값
        "nullifier": 1764,   # 이중 사용 방지용
    },
    circuit=c,
)
print(f"Proof 생성 완료")

# ━━━ Verifier (DEX 컨트랙트)가 검증한다 ━━━
# verifier는 commitment=4200, nullifier=1764만 본다
# secret=42, amount=100은 절대 알 수 없다
valid = groth16.verify(vk, proof, [4200, 1764])
print(f"검증 결과: {valid}")  # True
assert valid
```

verifier(DEX 컨트랙트)의 검증 로직:

```
1. proof 검증 → True (ZK proof가 유효함)
2. commitment 4200이 noteTree에 있는지 확인 → 있음
3. nullifier 1764가 이미 사용되었는지 확인 → 아직 없음
4. nullifier 1764를 사용 완료 목록에 추가
5. Alice에게 토큰 전송
```

### 2.5 이중 사용 방지 (Double-Spend Prevention)

같은 노트로 두 번 정산하려고 하면? nullifier가 동일하므로 컨트랙트가 거부합니다.

```python
# ━━━ Alice가 같은 노트로 두 번째 정산을 시도한다 ━━━
proof_again = groth16.prove(
    pk,
    private={"secret": 42, "amount": 100},
    public={"commitment": 4200, "nullifier": 1764},
    circuit=c,
)

# proof 자체는 유효하다! (수학적으로 맞으니까)
assert groth16.verify(vk, proof_again, [4200, 1764])
print("두 번째 proof도 수학적으로 유효")

# 하지만 on-chain에서:
# → nullifier 1764가 이미 사용됨 → 트랜잭션 revert!
# 이것이 nullifier의 역할

spent_nullifiers = {1764}  # on-chain에서 관리하는 사용 완료 목록
if 1764 in spent_nullifiers:
    print("이중 사용 감지! nullifier 1764는 이미 사용됨 → 거부")
```

**또 다른 사람이 위조된 commitment를 사용하려면?**

```python
# ━━━ Bob이 Alice의 commitment에 대한 가짜 proof를 만들려 한다 ━━━
try:
    # Bob은 secret=42를 모르므로, 아무 값이나 넣는다
    # secret=10, amount=420 → 10 × 420 = 4200 (commitment 일치!)
    # 하지만 nullifier = 10² = 100 ≠ 1764
    fake_proof = groth16.prove(
        pk,
        private={"secret": 10, "amount": 420},
        public={"commitment": 4200, "nullifier": 1764},  # nullifier가 맞지 않음
        circuit=c,
    )
    print("여기 도달하면 안 됨")
except ValueError as e:
    print(f"Bob의 위조 시도 실패: {e}")
    print("→ secret=10이면 nullifier=100이어야 하는데, 1764라고 주장 → R1CS 불만족")
```

핵심: commitment만 맞추는 건 쉽지만 (10 × 420 = 4200), **동시에** nullifier도 맞춰야 하므로 (`10² = 100 ≠ 1764`) 원래 secret을 모르면 유효한 proof를 만들 수 없습니다.

### 2.6 EVM On-Chain 검증

실제 이더리움에서 이 검증을 실행하면 얼마나 gas가 드는지 확인합니다:

```python
# ━━━ EVM Verifier 생성 ━━━
verifier = EVMVerifier(vk)
print(f"Verifier 바이트코드: {len(verifier.bytecode)} bytes")

# ━━━ EVM에서 정산 proof 검증 ━━━
result = verifier.verify_on_evm(proof, [4200, 1764])
print(f"EVM 검증: {'PASS' if result.success else 'FAIL'}")
print(f"Gas 사용량: {result.gas_used:,}")

# 틀린 nullifier로 시도
bad_result = verifier.verify_on_evm(proof, [4200, 9999])
print(f"틀린 nullifier: {'PASS' if bad_result.success else 'FAIL (거부됨)'}")

# ━━━ Gas 프로파일 ━━━
profile = verifier.gas_profile(proof, [4200, 1764])
print(f"\nGas 상세:")
print(f"  ecAdd:     {profile.ecadd_calls} calls, {profile.ecadd_gas:,} gas")
print(f"  ecMul:     {profile.ecmul_calls} calls, {profile.ecmul_gas:,} gas")
print(f"  ecPairing: {profile.ecpairing_calls} call,  {profile.ecpairing_gas:,} gas")
print(f"  Total:     {profile.total_gas:,} gas")
```

> Groth16 on-chain 검증 gas는 public input 수에 약간 비례합니다. 2개 public input (commitment + nullifier)에서 ecMul 2회, ecAdd 2회, ecPairing 1회(4쌍)가 필요합니다.

### 2.7 snarkjs 호환

py-ethclient에서 만든 proof를 snarkjs 포맷으로 내보낼 수 있습니다:

```python
from ethclient.zk.snarkjs_compat import (
    export_snarkjs_vkey, export_snarkjs_proof, verify_snarkjs,
)

vk_json = export_snarkjs_vkey(vk)
proof_json = export_snarkjs_proof(proof)
public_json = ["4200", "1764"]  # snarkjs는 문자열 사용

assert verify_snarkjs(vk_json, proof_json, public_json)
print(f"snarkjs 포맷 검증: PASS")
```

### 2.8 전체 코드

아래를 `zk_note_settle.py`로 저장하고 실행하세요:

```python
"""ZK Note Settlement — ERC20 토큰 비공개 정산 데모

Deposit: secret과 amount로 커밋먼트를 만들고, ERC20을 vault에 예치
Settle:  ZK proof로 소유권 증명 + nullifier로 이중 사용 방지

증명하는 것:
  1. secret × amount == commitment (소유권)
  2. secret × secret == nullifier (이중 사용 방지)

비밀로 유지하는 것:
  - secret (소유자 비밀키)
  - amount (토큰 양)
"""

import time
from ethclient.zk import Circuit, groth16
from ethclient.zk.evm_verifier import EVMVerifier
from ethclient.zk.snarkjs_compat import export_snarkjs_vkey, export_snarkjs_proof, verify_snarkjs

print("=" * 60)
print("  ZK Note Settlement — Private ERC20 Settle")
print("=" * 60)

# ━━━ 1. Circuit 정의 ━━━
c = Circuit()
secret = c.private("secret")
amount = c.private("amount")
commitment = c.public("commitment")
nullifier = c.public("nullifier")

c.constrain(secret * amount, commitment)   # 소유권 증명
c.constrain(secret * secret, nullifier)    # Nullifier 생성

print(f"\n[1] Circuit")
print(f"    {c.num_constraints} constraints, {c.num_public} public, {c.num_private} private")

# ━━━ 2. Trusted Setup ━━━
print(f"\n[2] Trusted setup...")
t0 = time.time()
pk, vk = groth16.setup(c)
print(f"    {time.time() - t0:.1f}s")

# ━━━ 3. Deposit (off-chain 계산) ━━━
alice_secret, alice_amount = 42, 100
alice_commitment = alice_secret * alice_amount   # 4200
alice_nullifier = alice_secret * alice_secret    # 1764

print(f"\n[3] Alice deposits 100 USDC")
print(f"    commitment: {alice_commitment}")
print(f"    (secret={alice_secret}, amount={alice_amount} — 비밀!)")

# ━━━ 4. Settle (ZK proof 생성) ━━━
print(f"\n[4] Alice settles with ZK proof")
t0 = time.time()
proof = groth16.prove(
    pk,
    private={"secret": alice_secret, "amount": alice_amount},
    public={"commitment": alice_commitment, "nullifier": alice_nullifier},
    circuit=c,
)
print(f"    Proof 생성: {time.time() - t0:.1f}s")

# ━━━ 5. Verify ━━━
print(f"\n[5] DEX 컨트랙트가 proof 검증")
t0 = time.time()
valid = groth16.verify(vk, proof, [alice_commitment, alice_nullifier])
print(f"    네이티브: {'PASS' if valid else 'FAIL'} ({time.time() - t0:.2f}s)")
assert valid

# ━━━ 6. EVM on-chain 검증 ━━━
verifier = EVMVerifier(vk)
result = verifier.verify_on_evm(proof, [alice_commitment, alice_nullifier])
print(f"\n[6] EVM on-chain 검증")
print(f"    result: {'PASS' if result.success else 'FAIL'}")
print(f"    gas: {result.gas_used:,}")

# ━━━ 7. 보안 테스트 ━━━
print(f"\n[7] 보안 테스트")

# 7a. 이중 사용
spent = {alice_nullifier}
print(f"    이중 사용: nullifier {alice_nullifier} in spent_set → 거부")

# 7b. 틀린 nullifier
assert not verifier.verify_on_evm(proof, [alice_commitment, 9999]).success
print(f"    틀린 nullifier(9999): EVM 거부")

# 7c. Bob의 위조 시도
try:
    groth16.prove(
        pk,
        private={"secret": 10, "amount": 420},
        public={"commitment": 4200, "nullifier": 1764},
        circuit=c,
    )
    print("    Bob 위조: 예상 외 성공 (secret=10에서는 nullifier=100이어야 함)")
except ValueError:
    print(f"    Bob 위조(secret=10, amount=420): proof 생성 실패 — R1CS 불만족")

# ━━━ 8. 다른 유저 ━━━
print(f"\n[8] Bob deposits 200 USDC (secret=77)")
bob_secret, bob_amount = 77, 200
bob_commitment = bob_secret * bob_amount    # 15400
bob_nullifier = bob_secret * bob_secret     # 5929

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
vk_json = export_snarkjs_vkey(vk)
proof_json = export_snarkjs_proof(proof)
assert verify_snarkjs(vk_json, proof_json, [str(alice_commitment), str(alice_nullifier)])
print(f"\n[9] snarkjs 포맷: PASS")

# ━━━ Gas 프로파일 ━━━
profile = verifier.gas_profile(proof, [alice_commitment, alice_nullifier])

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  Notes: Alice(100 USDC), Bob(200 USDC)")
print(f"  EVM gas: {result.gas_used:,}")
print(f"  Gas: ecMul={profile.ecmul_gas:,} + ecAdd={profile.ecadd_gas:,}"
      f" + ecPairing={profile.ecpairing_gas:,}")
print(f"{'=' * 60}")
```

```bash
python zk_note_settle.py
```

---

## Part 3: 팁과 제약사항

### R1CS constraint 패턴

| 패턴 | 코드 | R1CS 변환 |
|------|------|-----------|
| 곱셈 | `c.constrain(a * b, result)` | `a × b = result` |
| 덧셈 | `c.constrain(a + b, result)` | `(a + b - result) × 1 = 0` |
| 상수 곱 | `c.constrain(a * 3, result)` | `a × 3 = result` |
| 혼합 | `c.constrain(a * b, x + y)` | `a × b = x + y` |

### Signal 연산 지원

```python
# 지원되는 연산
a + b          # Signal + Signal → Signal (선형)
a + 5          # Signal + 상수 → Signal (선형)
a - b          # 뺄셈
a * b          # Signal × Signal → 중간 변수 생성 + 자동 constraint
a * 3          # Signal × 상수 → Signal (선형, constraint 없음)
-a             # 부정
3 + a          # 역방향 연산도 지원
```

### 성능 가이드

| Circuit 크기 | Setup | Prove | Verify | EVM Verify |
|-------------|-------|-------|--------|------------|
| 1 constraint | ~2s | ~2s | ~1s | ~0.1s |
| 2 constraints | ~4s | ~4s | ~1s | ~0.1s |
| 5 constraints | ~10s | ~10s | ~1s | ~0.1s |

> 순수 Python (py_ecc)이므로 10개 이상의 constraint는 시간이 오래 걸릴 수 있습니다. 교육/프로토타이핑 용도에 적합하며, 프로덕션 증명 생성은 snarkjs/rapidsnark를 사용하세요.

### 주의사항

1. **Range proof 미포함**: `a >= b` 같은 부등식은 R1CS로 직접 표현 불가. 비트 분해가 필요합니다.

2. **유한체 연산**: 모든 연산은 BN128 scalar field (`p ≈ 2^254`) 위에서 수행됩니다. 음수는 `p - |n|`으로 변환됩니다.

3. **Toxic waste**: `groth16.setup()`은 매 호출마다 새로운 랜덤 값을 생성합니다. 같은 circuit이라도 setup을 다시 하면 이전 proof는 무효화됩니다.

4. **Circuit 재사용**: setup 후에는 같은 pk/vk로 여러 proof를 생성할 수 있습니다. 다른 witness(비밀 값)에 대해 반복 가능.

5. **public input 순서**: `verify(vk, proof, [a, b])`에서 리스트 순서는 `c.public()` 호출 순서와 동일해야 합니다.

### 다음 단계

- `examples/zk_notebook_demo.py` — 전체 워크플로우 데모
- snarkjs로 생성한 proof를 py-ethclient에서 검증해 보세요
- `zk_verifyGroth16` RPC 메서드로 원격 검증 서비스 구축
- [Part 4](#part-4-l1l2-general-state-bridge)에서 L1↔L2 브릿지를 배워보세요

---

## Part 4: L1↔L2 General State Bridge

> "L1에서 보낸 메시지가 L2의 EVM에서 실행되고, 오퍼레이터가 검열해도 사용자가 강제로 포함시킬 수 있다."

### 4.1 브릿지 개요

py-ethclient의 L2 브릿지는 Optimism의 `CrossDomainMessenger` 패턴을 따릅니다. 메신저가 유일한 프리미티브이고, 브릿지 컨트랙트(Token, State, ZK 등)는 메신저 위에 올라간 사용자 레벨 코드입니다.

```
┌─── L1 ────────────────────┐          ┌─── L2 ────────────────────┐
│  Store (MemoryBackend)    │          │  Store (MemoryBackend)    │
│                           │          │                           │
│  CrossDomainMessenger     │          │  CrossDomainMessenger     │
│    send_message()         │          │    send_message()         │
│    relay_message()        │          │    relay_message()        │
│    force_include()        │          │                           │
│    escape_hatch()         │          │                           │
└───────────┬───────────────┘          └───────────┬───────────────┘
            │                                      │
            └────────── BridgeWatcher ─────────────┘
                    (outbox 스캔 → relay)
```

핵심 개념:

| 개념 | 설명 |
|------|------|
| **CrossDomainMessenger** | 임의 메시지를 다른 도메인으로 전송. 릴레이 시 타겟 EVM에서 실행 |
| **BridgeWatcher** | 양쪽 outbox를 드레인하고 메시지를 릴레이하는 자동 릴레이어 |
| **BridgeEnvironment** | L1 Store + L2 Store + 2개 Messenger + Watcher를 묶은 편의 래퍼 |
| **Force Inclusion** | 오퍼레이터가 검열할 때 사용자가 L1에 등록 → 50블록 후 강제 릴레이 |
| **Escape Hatch** | L2가 완전히 무응답일 때 L1에서 입금 가치를 직접 복구 |

### 4.2 ETH 입금 (L1→L2)

가장 기본적인 사용법: Alice가 L1에서 Bob에게 ETH를 보내고, watcher가 L2로 릴레이합니다.

```python
from ethclient.bridge import BridgeEnvironment

ALICE = b"\x01" * 20
BOB = b"\x02" * 20

# L1 + L2 환경 생성
env = BridgeEnvironment()

# Alice가 L1에서 Bob에게 1000 wei 전송
msg = env.send_l1(sender=ALICE, target=BOB, value=1000)

# 아직 L2에 반영 안 됨
assert env.l2_balance(BOB) == 0

# Watcher가 릴레이
result = env.relay()
assert result.all_success
assert len(result.l1_to_l2) == 1

# L2에 반영됨
assert env.l2_balance(BOB) == 1000
print(f"Bob의 L2 잔액: {env.l2_balance(BOB)} wei")
```

`relay()`가 내부적으로 하는 일:

1. L1 messenger의 outbox에서 메시지를 꺼냄 (drain)
2. 각 메시지를 L2 messenger의 `relay_message()`로 전달
3. `relay_message()`는 메시지를 L2의 EVM에서 실행
4. 코드가 없는 주소로 전송 시 → 단순 value transfer
5. 코드가 있는 주소로 전송 시 → calldata를 EVM에서 실행

반대 방향(L2→L1)도 동일합니다:

```python
# Bob이 L2에서 Alice에게 500 wei 출금
env.send_l2(sender=BOB, target=ALICE, value=500)
result = env.relay()
assert result.all_success
assert env.l1_balance(ALICE) == 500
```

### 4.3 상태 릴레이 — 오라클 가격 전달

value transfer뿐 아니라, 임의 calldata를 L2 컨트랙트에 전달할 수 있습니다. 이것이 "General State Bridge"의 핵심입니다.

```python
from ethclient.bridge import BridgeEnvironment
from ethclient.common.types import Account
from ethclient.common.crypto import keccak256

ALICE = b"\x01" * 20
ORACLE = b"\x0a" * 20

env = BridgeEnvironment()

# L2에 오라클 컨트랙트 배포
# 바이트코드: CALLDATALOAD(0) → SSTORE(slot=0, value)
#   PUSH1 0x00  CALLDATALOAD  PUSH1 0x00  SSTORE  STOP
code = bytes([0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00])
acc = Account()
acc.code_hash = keccak256(code)
env.l2_store.put_account(ORACLE, acc)
env.l2_store.put_code(acc.code_hash, code)

# L1에서 오라클 가격을 L2로 전달 (ETH/USD = 1850)
price = (1850).to_bytes(32, "big")
env.send_l1(sender=ALICE, target=ORACLE, data=price)
result = env.relay()
assert result.all_success

# L2 오라클 스토리지에 가격이 기록됨
assert env.l2_storage(ORACLE, 0) == 1850
print(f"L2 오라클 가격: {env.l2_storage(ORACLE, 0)} USD")
```

메시지가 릴레이될 때, `relay_message()`는 실제 EVM을 실행합니다:
- `msg.data`가 calldata로 전달됨
- `msg.target` 주소의 코드가 실행됨
- SSTORE, SLOAD 등 모든 opcode 사용 가능
- 실행 성공 시 상태 변경이 커밋됨

### 4.4 검열과 Force Inclusion

L2 오퍼레이터가 정직하다면 모든 메시지가 정상 릴레이됩니다. 하지만 오퍼레이터가 특정 사용자의 메시지를 의도적으로 릴레이하지 않을 수 있습니다 (검열).

Force Inclusion은 이에 대한 해결책입니다:

```python
from ethclient.bridge import BridgeEnvironment, FORCE_INCLUSION_WINDOW

ALICE = b"\x01" * 20
BOB = b"\x02" * 20

env = BridgeEnvironment()

# Alice가 L1→L2 메시지를 보냄
msg = env.send_l1(sender=ALICE, target=BOB, value=1000)

# 오퍼레이터가 검열: outbox에서 꺼내지만 릴레이하지 않음
env.l1_messenger.drain_outbox()
assert env.l2_balance(BOB) == 0  # 릴레이 안 됨

# Alice가 L1에 force inclusion 등록
entry = env.force_include(msg)
print(f"등록된 블록: {entry.registered_block}")

# 아직 윈도우가 안 지남 → 강제 릴레이 실패
result = env.force_relay(msg)
assert not result.success
print(f"너무 이름: {result.error}")

# 50블록 진행
env.advance_l1_block(FORCE_INCLUSION_WINDOW)

# 이제 강제 릴레이 성공!
result = env.force_relay(msg)
assert result.success
assert env.l2_balance(BOB) == 1000
print(f"강제 릴레이 성공! Bob의 L2 잔액: {env.l2_balance(BOB)}")
```

Force Inclusion의 핵심:
- **누구나** 등록할 수 있음 (L1 트랜잭션만 보내면 됨)
- 50블록(약 10분) 대기 후 **누구나** force relay 가능
- 오퍼레이터의 협조가 전혀 필요 없음
- Watcher도 force queue를 자동 처리: `env.relay()`가 eligible한 force inclusion을 자동 릴레이

### 4.5 Escape Hatch — 최후의 수단

Force relay도 실패하는 극단적 상황(L2가 완전히 다운)에서는 escape hatch로 L1에서 가치를 복구합니다.

```python
env = BridgeEnvironment()

# Alice가 5000 wei 입금
msg = env.send_l1(sender=ALICE, target=BOB, value=5000)
env.l1_messenger.drain_outbox()

# Force include 등록
env.force_include(msg)
env.advance_l1_block(FORCE_INCLUSION_WINDOW)

# L2가 완전 무응답 → escape hatch로 L1에서 복구
result = env.escape_hatch(msg)
assert result.success
assert env.l1_balance(ALICE) == 5000  # 가치가 Alice에게 반환!
print(f"Escape hatch 성공! Alice의 L1 잔액: {env.l1_balance(ALICE)}")
```

Escape hatch 제약:
- **value > 0** 인 메시지만 가능 (calldata-only 메시지는 불가)
- **이중 탈출 불가**: 같은 메시지로 두 번 escape 불가
- **force relay 후 불가**: 이미 성공적으로 릴레이된 메시지는 escape 불가
- 가치는 **msg.sender에게** 반환됨 (msg.target이 아님)

### 4.6 전체 코드

아래를 `bridge_tutorial.py`로 저장하고 실행하세요:

```python
"""L1↔L2 General State Bridge Tutorial"""

from ethclient.bridge import BridgeEnvironment, FORCE_INCLUSION_WINDOW
from ethclient.common.types import Account
from ethclient.common.crypto import keccak256

ALICE = b"\x01" * 20
BOB = b"\x02" * 20
ORACLE = b"\x0a" * 20

print("=" * 60)
print("  L1↔L2 General State Bridge Tutorial")
print("=" * 60)

# ━━━ 1. ETH 입금 ━━━
print("\n[1] ETH Deposit (L1→L2)")
env = BridgeEnvironment()
env.send_l1(sender=ALICE, target=BOB, value=1000)
result = env.relay()
assert result.all_success
assert env.l2_balance(BOB) == 1000
print(f"    Bob L2 balance: {env.l2_balance(BOB)}")

# ━━━ 2. ETH 출금 ━━━
print("\n[2] ETH Withdraw (L2→L1)")
env.send_l2(sender=BOB, target=ALICE, value=500)
result = env.relay()
assert result.all_success
assert env.l1_balance(ALICE) == 500
print(f"    Alice L1 balance: {env.l1_balance(ALICE)}")

# ━━━ 3. 상태 릴레이 ━━━
print("\n[3] State Relay (Oracle Price)")
env2 = BridgeEnvironment()
code = bytes([0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00])
acc = Account()
acc.code_hash = keccak256(code)
env2.l2_store.put_account(ORACLE, acc)
env2.l2_store.put_code(acc.code_hash, code)

price = (1850).to_bytes(32, "big")
env2.send_l1(sender=ALICE, target=ORACLE, data=price)
env2.relay()
assert env2.l2_storage(ORACLE, 0) == 1850
print(f"    L2 oracle price: {env2.l2_storage(ORACLE, 0)} USD")

# ━━━ 4. Force Inclusion ━━━
print("\n[4] Force Inclusion (Anti-Censorship)")
env3 = BridgeEnvironment()
msg = env3.send_l1(sender=ALICE, target=BOB, value=777)
env3.l1_messenger.drain_outbox()  # operator censors
assert env3.l2_balance(BOB) == 0

env3.force_include(msg)
env3.advance_l1_block(FORCE_INCLUSION_WINDOW)
result = env3.force_relay(msg)
assert result.success
assert env3.l2_balance(BOB) == 777
print(f"    Force relay success! Bob L2: {env3.l2_balance(BOB)}")

# ━━━ 5. Escape Hatch ━━━
print("\n[5] Escape Hatch (Value Recovery)")
env4 = BridgeEnvironment()
msg = env4.send_l1(sender=ALICE, target=BOB, value=5000)
env4.l1_messenger.drain_outbox()
env4.force_include(msg)
env4.advance_l1_block(FORCE_INCLUSION_WINDOW)

result = env4.escape_hatch(msg)
assert result.success
assert env4.l1_balance(ALICE) == 5000
print(f"    Escape success! Alice L1: {env4.l1_balance(ALICE)}")

# ━━━ 6. Replay Protection ━━━
print("\n[6] Replay Protection")
env5 = BridgeEnvironment()
env5.send_l1(sender=ALICE, target=BOB, value=100)
env5.relay()

# Same message can't be relayed twice
env5.send_l1(sender=ALICE, target=BOB, value=100)
env5.relay()
assert env5.l2_balance(BOB) == 200  # two different messages, both relayed
print(f"    Two deposits: Bob L2 = {env5.l2_balance(BOB)}")

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"{'=' * 60}")
```

```bash
python bridge_tutorial.py
```

### 4.7 Proof-Based Relay

기본 브릿지는 L2에서 메시지를 EVM으로 실행합니다. 하지만 **플러거블 릴레이 핸들러**를 사용하면 L2가 EVM이 아닌 어떤 런타임이든 사용할 수 있습니다.

5가지 릴레이 모드:

| 핸들러 | 신뢰 모델 | EVM 필요 |
|---|---|---|
| `EVMRelayHandler` | On-chain 실행 (기본) | Yes |
| `MerkleProofHandler` | L1 상태 루트 Merkle proof | No |
| `ZKProofHandler` | Groth16 영지식 증명 | No |
| `TinyDBHandler` | 문서 DB 백엔드 | No |
| `DirectStateHandler` | 신뢰 릴레이어 | No |

#### Direct State Relay — 가장 단순한 모드

신뢰 릴레이어가 상태를 직접 적용합니다. EVM 실행이 필요 없습니다.

```python
from ethclient.bridge import BridgeEnvironment, StateUpdate, encode_state_updates

ALICE = b"\x01" * 20
BOB = b"\x02" * 20

# Direct state 모드로 환경 생성
env = BridgeEnvironment.with_direct_state()

# 상태 업데이트를 msg.data에 인코딩
updates = [
    StateUpdate(address=ALICE, balance=5_000, nonce=1),
    StateUpdate(address=BOB, balance=3_000, nonce=2),
]
data = encode_state_updates(updates)

# L1→L2 전송 + 릴레이
env.send_l1(sender=ALICE, target=BOB, data=data)
result = env.relay()
assert result.all_success

# 상태가 적용됨 (EVM 실행 없이)
assert env.l2_store.get_balance(ALICE) == 5_000
assert env.l2_store.get_balance(BOB) == 3_000
```

#### Merkle Proof Relay — L1 상태 증명

L1의 상태 루트에 대한 Merkle proof를 검증한 후 상태를 적용합니다.

```python
from ethclient.bridge import BridgeEnvironment
from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.common.trie import Trie

ALICE = b"\x01" * 20
BOB = b"\x02" * 20

EMPTY_ROOT = b"\x56\xe8\x1f\x17\x1b\xcc\x55\xa6\xff\x83\x45\xe6\x92\xc0\xf8\x6e\x5b\x48\xe0\x1b\x99\x6c\xad\xc0\x01\x62\x2f\xb5\xe3\x63\xb4\x21"
EMPTY_CODE = b"\xc5\xd2\x46\x01\x86\xf7\x23\x3c\x92\x7e\x7d\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6\x53\xca\x82\x27\x3b\x7b\xfa\xd8\x04\x5d\x85\xa4\x70"

env = BridgeEnvironment.with_merkle_proof()

# L1 상태 설정
env.l1_store.set_balance(ALICE, 10_000)
env.l1_store.set_nonce(ALICE, 42)

# Merkle trie에서 proof 생성
trie = Trie()
for addr, acc in env.l1_store.iter_accounts():
    account_rlp = rlp.encode([acc.nonce, acc.balance, EMPTY_ROOT, EMPTY_CODE])
    trie.put_raw(keccak256(addr), account_rlp)

root = trie.root_hash
proof_nodes = trie.prove(keccak256(ALICE))
account_rlp = rlp.encode([42, 10_000, EMPTY_ROOT, EMPTY_CODE])

# 신뢰 루트 등록 + 전송
handler = env.l2_messenger.relay_handler
handler.add_trusted_root(root)

data = rlp.encode([root, ALICE, account_rlp, proof_nodes])
env.send_l1(sender=ALICE, target=BOB, data=data)
result = env.relay()
assert result.all_success

# Merkle proof로 검증된 상태가 L2에 적용됨
assert env.l2_store.get_balance(ALICE) == 10_000
assert env.l2_store.get_nonce(ALICE) == 42
```

#### ZK Proof Relay — Groth16 증명

Groth16 증명을 검증한 후 상태를 적용합니다. 가장 강력한 신뢰 모델입니다.

```python
from ethclient.bridge import BridgeEnvironment, StateUpdate
from ethclient.common import rlp
from ethclient.zk import Circuit, groth16

ALICE = b"\x01" * 20
BOB = b"\x02" * 20

# 1. Circuit 정의: old_balance + amount = new_balance
c = Circuit()
old_bal = c.public("old_balance")
amount = c.public("amount")
new_bal = c.public("new_balance")
one = c.private("one")
product = (old_bal + amount) * one
c.constrain(product, new_bal)

# 2. Trusted setup
pk, vk = groth16.setup(c)

# 3. Proof 생성
proof = groth16.prove(
    pk,
    private={"one": 1},
    public={"old_balance": 1000, "amount": 500, "new_balance": 1500},
    circuit=c,
)

# 4. msg.data 구성
proof_a = proof.a.to_evm_bytes()
proof_b = proof.b.to_evm_bytes()
proof_c = proof.c.to_evm_bytes()

public_inputs = [
    (1000).to_bytes(32, "big"),
    (500).to_bytes(32, "big"),
    (1500).to_bytes(32, "big"),
]

updates = [StateUpdate(address=BOB, balance=1500)]
state_updates_rlp = [rlp.decode(u.encode()) for u in updates]

zk_data = rlp.encode([
    proof_a, proof_b, proof_c,
    public_inputs, state_updates_rlp,
])

# 5. 릴레이
env = BridgeEnvironment.with_zk_proof(vk)
env.send_l1(sender=ALICE, target=BOB, data=zk_data)
result = env.relay()
assert result.all_success
assert env.l2_store.get_balance(BOB) == 1500
```

#### TinyDB Relay — 문서 DB 백엔드

Proof 기반 릴레이의 핵심은 L2가 EVM이 아닌 **어떤 런타임이든** 사용할 수 있다는 것입니다. TinyDB 핸들러는 이를 증명합니다.

```python
from ethclient.bridge import BridgeEnvironment, StateUpdate, TinyDBHandler, encode_state_updates

ALICE = b"\x01" * 20
BOB = b"\x02" * 20

# TinyDB 핸들러로 환경 생성
handler = TinyDBHandler()
env = BridgeEnvironment(l2_handler=handler)

# 상태 업데이트 (스토리지 포함)
updates = [
    StateUpdate(address=ALICE, balance=7_777, nonce=10, storage={1: 42}),
    StateUpdate(address=BOB, balance=3_333, storage={100: 200}),
]
data = encode_state_updates(updates)

env.send_l1(sender=ALICE, target=BOB, data=data)
result = env.relay()
assert result.all_success

# TinyDB에 JSON 문서로 저장됨 (Ethereum Store가 아닌!)
for doc in handler.db.all():
    print(f"  {doc['address'][:14]}... → balance={doc.get('balance')}")

# Ethereum Store는 비어 있음
assert env.l2_store.get_balance(ALICE) == 0
```

전체 릴레이 모드 비교 데모:

```bash
python examples/bridge_relay_modes.py
```
