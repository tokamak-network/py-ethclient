---
description: "ZK Circuit 빌드 & Groth16 증명 — 회로 설계부터 EVM 검증까지"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "회로 설명이나 검증 대상"
user-invocable: true
---

# ZK Circuit & Groth16 증명 스킬

산술 회로 정의 → R1CS → Groth16 Trusted Setup → Prove → Verify → EVM on-chain 검증까지 전체 파이프라인을 안내한다.

## 핵심 파일 참조

| 파일 | 역할 |
|------|------|
| `ethclient/zk/circuit.py` | Circuit 빌더, Signal 연산, R1CS 변환 |
| `ethclient/zk/groth16.py` | Setup, Prove, Verify (pure Python) |
| `ethclient/zk/types.py` | G1Point, G2Point, Proof, VerificationKey, ProvingKey |
| `ethclient/zk/evm_verifier.py` | EVMVerifier — on-chain 검증 바이트코드 생성 |
| `ethclient/zk/r1cs_export.py` | snarkjs .r1cs 바이너리 포맷 내보내기 |
| `ethclient/zk/snarkjs_compat.py` | snarkjs JSON 파싱/내보내기 |
| `ethclient/l2/prover.py` | Groth16ProofBackend (L2 rollup용) |
| `ethclient/l2/native_prover.py` | NativeProverBackend (rapidsnark 연동) |

## 빠른 시작: 곱셈 회로

```python
from ethclient.zk import Circuit, groth16

# 1. 회로 정의: x * y == z (x, y는 비밀, z는 공개)
c = Circuit()
x = c.private("x")
y = c.private("y")
z = c.public("z")
c.constrain(x * y, z)

# 2. Trusted Setup
pk, vk = groth16.setup(c)

# 3. 증명 생성
proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)

# 4. 검증 (Python)
assert groth16.verify(vk, proof, [15])

# 5. EVM 검증
from ethclient.zk.evm_verifier import EVMVerifier
verifier = EVMVerifier(vk)
result = verifier.verify_on_evm(proof, [15])
assert result.success
print(f"Gas used: {result.gas_used}")
```

## Field 산술 (BN128)

```python
FIELD_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583
# ~254 bits, BN128 curve order

# 기본 연산
def _field(x): return x % FIELD_MODULUS
def _field_inv(x): return pow(x, FIELD_MODULUS - 2, FIELD_MODULUS)  # Fermat's little theorem
```

모든 회로 연산은 이 유한체 위에서 수행된다. 32바이트 해시값은 `int.from_bytes(data, "big") % FIELD_MODULUS`로 변환.

## Circuit API

### Signal 선언
```python
c = Circuit()
x = c.public("x")     # 공개 입력 (검증자가 알고 있음)
y = c.private("y")     # 비밀 입력 (증명자만 알고 있음)
tmp = c.intermediate("tmp")  # 중간 변수
```

### Signal 연산
```python
# 덧셈/뺄셈: 제약 없이 선형 결합
a + b       # Signal + Signal
a + 5       # Signal + 상수
a - b

# 곱셈: R1CS 제약 자동 생성
a * b       # → 중간 변수 + 제약: a * b = _tmp
a * 3       # 상수 곱: 제약 없음 (스칼라 곱)

# 부정
-a          # 모든 계수 부정
```

### 제약 추가
```python
c.constrain(x * y, z)       # x * y == z (곱셈 결과에서 C 교체)
c.constrain(a + b, c_var)   # a + b == c (선형 등식: (a+b-c)*1 = 0)
```

### R1CS 변환 & 검증
```python
r1cs = c.to_r1cs()
# R1CS { A, B, C: sparse matrix, num_variables, num_public, num_constraints }

witness = c.compute_witness(private={"x": 3, "y": 5}, public={"z": 15})
assert r1cs.check_witness(witness)  # A[i]·w * B[i]·w == C[i]·w for all i
```

### Witness 변수 순서
1. Index 0: 상수 `1`
2. Index 1..num_public-1: 공개 입력 (선언 순서)
3. Index num_public..: 비밀 입력, 중간 변수

## Groth16 파이프라인

### Setup (Trusted Setup)
```python
pk, vk = groth16.setup(circuit)
# pk: ProvingKey — 증명자 보관 (비밀)
# vk: VerificationKey — 검증자 공개
```
- Toxic waste (tau, alpha, beta, gamma, delta) 생성 후 폐기
- 회로별 1회 수행

### Prove
```python
proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)
# proof: Proof(a: G1Point, b: G2Point, c: G1Point)
```
- Witness 계산 → R1CS 검증 → QAP 변환 → 증명 생성
- 랜덤 blinding factors (r, s) 사용

### Verify
```python
valid = groth16.verify(vk, proof, [15])  # public_inputs as list[int]
# 또는
valid = groth16.verify(vk, proof, {"z": 15})  # dict 형태도 가능
```
- 페어링 검사: `e(A,B) == e(alpha,beta) * e(IC_acc,gamma) * e(C,delta)`

### Debug Verify
```python
result = groth16.debug_verify(vk, proof, [15])
# result.valid, result.e_ab, result.e_alpha_beta, result.e_ic_gamma, result.e_c_delta
```

## EVM on-chain 검증

### 바이트코드 생성 & 실행
```python
from ethclient.zk.evm_verifier import EVMVerifier

verifier = EVMVerifier(vk)
bytecode = verifier.bytecode  # 배포용 바이트코드

# 로컬 EVM 실행
result = verifier.verify_on_evm(proof, [15])
# EVMResult(success=True, gas_used=..., return_data=...)
```

### Gas 프로파일링
```python
profile = verifier.gas_profile(proof, [15])
# GasProfile(total_gas, ecadd_gas, ecadd_calls, ecmul_gas, ecmul_calls, ecpairing_gas, ecpairing_calls)
```

### Precompile 비용
| Precompile | 주소 | Gas |
|------------|------|-----|
| ECADD | 0x06 | 150 |
| ECMUL | 0x07 | 6,000 |
| ECPAIRING | 0x08 | 45,000 + 34,000 * num_pairs |

총 가스: ~181,000 base + 6,150 per public input

### Calldata 레이아웃
```
[0:64]    proof.A   (x, y)
[64:192]  proof.B   (x_imag, x_real, y_imag, y_real)  ← G2 EVM 인코딩 주의
[192:256] proof.C   (x, y)
[256:]    public_inputs (각 32바이트)
```

## snarkjs 호환

### R1CS 내보내기
```python
from ethclient.zk.r1cs_export import export_r1cs_binary, export_witness_json

r1cs_bytes = export_r1cs_binary(circuit)
with open("circuit.r1cs", "wb") as f:
    f.write(r1cs_bytes)

witness_json = export_witness_json(public={"z": 15}, private={"x": 3, "y": 5}, circuit=c)
```

### snarkjs JSON 파싱
```python
from ethclient.zk.snarkjs_compat import verify_snarkjs, parse_snarkjs_proof

# snarkjs 아티팩트 직접 검증
valid = verify_snarkjs(vkey_json, proof_json, public_json)
```

### FQ2 인코딩 주의
- snarkjs: `[c1, c0]` = `[imag, real]`
- EVM: `x_imag || x_real || y_imag || y_real` (imaginary first)

## L2 Rollup용 회로 구조

`Groth16ProofBackend`가 사용하는 회로:

```
Public (3): old_state_root, new_state_root, tx_commitment
Private (max_txs): tx_0, tx_1, ..., tx_{max_txs-1}

Constraints:
  chain_0 = old_state_root * tx_0
  chain_i = chain_{i-1} * tx_i
  chain_{last} == new_state_root * tx_commitment
```

- 128-bit field 절삭: `int.from_bytes(hash, "big") % FIELD_MODULUS`
- Balance factor: 마지막 슬롯에 `(new_root * tx_commit) / product` 삽입
- 실제 tx 최대 수 = `max_txs_per_batch - 1`

## 복잡한 회로 예제: 범위 증명

```python
c = Circuit()
x = c.private("x")
bound = c.public("bound")

# x가 0 이상 bound 미만임을 증명
# (x) * (bound - x - 1) = result, result가 0 이상임을 보장
diff = bound + (-x) + (-Signal.one(c))  # bound - x - 1
result = c.intermediate("result")
c.constrain(x * diff, result)
```

## 주의사항

1. **Pure Python 성능**: <1000 제약에 적합. 대규모 회로는 NativeProverBackend 사용
2. **Toxic waste**: setup() 시 랜덤 생성 후 메모리에서만 존재. 프로세스 종료 시 소멸
3. **Witness 자동 풀이**: `compute_witness()`가 중간 변수를 반복적으로 풀어냄 (고정점 반복)
4. **G2 바이트 순서**: EVM은 imaginary first. snarkjs도 imaginary first. 일관됨
5. **다항식 나눗셈**: O(n^2) naive. 대규모 회로에서 병목
