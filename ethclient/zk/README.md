# py-ethclient ZK Toolkit

**Python Groth16 ZK 증명 — Circuit 정의부터 EVM on-chain 검증까지**

## 개요

py-ethclient ZK Toolkit은 Groth16 영지식 증명의 전체 워크플로우를 Python 한 프로세스에서 실행합니다.

```
Circuit 정의 → Trusted Setup → Proof 생성 → 네이티브 검증 → EVM 검증 → Gas 분석
```

이더리움 실행 클라이언트(py-ethclient)에 내장된 EVM과 BN128 precompile을 그대로 활용하므로, 외부 도구 없이 on-chain 검증까지 테스트할 수 있는 유일한 Python 환경입니다.

---

## 특징

### Circuit Builder — Python 표현식으로 R1CS 정의

연산자 오버로딩(`*`, `+`, `-`)으로 제약 조건을 자연스러운 Python 문법으로 작성합니다.

```python
from ethclient.zk import Circuit

c = Circuit()
x, y = c.private("x"), c.private("y")
z = c.public("z")
c.constrain(x * y, z)   # R1CS: x × y = z
```

- `private()` / `public()` / `intermediate()` signal 선언
- 곱셈 (`a * b`), 덧셈 (`a + b`), 뺄셈 (`a - b`), 상수 곱 (`a * 3`), 부정 (`-a`)
- 자동 R1CS 변환: sparse matrix (A, B, C) 표현
- witness 자동 계산: 중간 변수를 constraint propagation으로 해결

### Groth16 Prover/Verifier — 순수 Python 구현

BN128 curve 위의 Groth16 증명 시스템을 py_ecc 라이브러리로 구현했습니다.

```python
from ethclient.zk import groth16

pk, vk = groth16.setup(c)
proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)
assert groth16.verify(vk, proof, [15])
```

- **setup()**: R1CS → QAP (Lagrange 보간법) → toxic waste 샘플링 → pk/vk 생성
- **prove()**: witness 계산 → h(x) 다항식 → A/B/C 커밋먼트 → 랜덤화 (r, s)
- **verify()**: pairing 검증 `e(A,B) == e(α,β) · e(IC_acc,γ) · e(C,δ)`
- **debug_verify()**: 개별 pairing 값(e_ab, e_alpha_beta, e_ic_gamma, e_c_delta) 반환

### EVM Verifier — 자동 바이트코드 생성 + on-chain 테스트

Verification key로부터 EVM 바이트코드를 자동 생성하고, 인메모리 EVM에서 실행합니다.

```python
from ethclient.zk.evm_verifier import EVMVerifier

verifier = EVMVerifier(vk)
result = verifier.verify_on_evm(proof, [15])
# result.success=True, result.gas_used=210,000
```

- ecAdd (0x06), ecMul (0x07), ecPairing (0x08) precompile 호출
- 실제 이더리움과 동일한 gas 계산
- `gas_profile()`: precompile별 gas 분석
- `trace_on_evm()`: 실행 트레이스

### snarkjs 호환 — 기존 생태계 연동

snarkjs JSON 포맷(verification_key.json, proof.json)의 import/export를 지원합니다.

```python
from ethclient.zk.snarkjs_compat import export_snarkjs_vkey, verify_snarkjs

vk_json = export_snarkjs_vkey(vk)           # snarkjs 포맷으로 내보내기
valid = verify_snarkjs(vk_json, proof_json, ["15"])  # snarkjs proof 검증
```

- circom으로 만든 proof를 py-ethclient에서 검증 가능
- py-ethclient proof를 Solidity verifier에서 검증 가능

### ZK RPC API — JSON-RPC 엔드포인트

```bash
curl -X POST http://localhost:8545 \
  -d '{"jsonrpc":"2.0","method":"zk_verifyGroth16","params":[...] ,"id":1}'
```

| 메서드 | 설명 |
|---|---|
| `zk_verifyGroth16` | Groth16 proof 검증 (snarkjs/native 포맷) |
| `zk_deployVerifier` | verifier 바이트코드 생성 + gas 추정 |
| `zk_verifyOnChain` | 인메모리 EVM에서 on-chain 검증 |

---

## 사용법

### 설치

```bash
pip install -e ".[dev]"  # py-ecc가 의존성에 포함
```

### Hello World — 최소 예제

```python
from ethclient.zk import Circuit, groth16
from ethclient.zk.evm_verifier import EVMVerifier

# Circuit: x * y = z
c = Circuit()
x, y = c.private("x"), c.private("y")
z = c.public("z")
c.constrain(x * y, z)

# Setup → Prove → Verify
pk, vk = groth16.setup(c)
proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)

assert groth16.verify(vk, proof, [15])                         # 네이티브 검증
assert EVMVerifier(vk).verify_on_evm(proof, [15]).success      # EVM 검증
```

### ZK Note Settlement — 실전 예제

```python
from ethclient.zk import Circuit, groth16
from ethclient.zk.evm_verifier import EVMVerifier

# Circuit: ZK note 소유권 + 이중 사용 방지
c = Circuit()
secret = c.private("secret")
amount = c.private("amount")
commitment = c.public("commitment")   # secret × amount
nullifier = c.public("nullifier")     # secret²

c.constrain(secret * amount, commitment)
c.constrain(secret * secret, nullifier)

pk, vk = groth16.setup(c)

# Alice: 100 USDC deposit → settle
proof = groth16.prove(
    pk,
    private={"secret": 42, "amount": 100},
    public={"commitment": 4200, "nullifier": 1764},
    circuit=c,
)

assert groth16.verify(vk, proof, [4200, 1764])

verifier = EVMVerifier(vk)
result = verifier.verify_on_evm(proof, [4200, 1764])
print(f"EVM gas: {result.gas_used:,}")  # ≈ 414,000
```

### 디버깅

```python
debug = groth16.debug_verify(vk, proof, [15])
print(debug.valid)          # True/False
print(debug.e_ab)           # e(A, B) pairing 값
print(debug.e_alpha_beta)   # e(α, β)
print(debug.e_ic_gamma)     # e(IC_acc, γ)
print(debug.e_c_delta)      # e(C, δ)
# 유효한 proof: e_ab == e_alpha_beta * e_ic_gamma * e_c_delta
```

### Gas 프로파일링

```python
profile = verifier.gas_profile(proof, [15])
print(f"ecAdd:     {profile.ecadd_calls} calls, {profile.ecadd_gas:,} gas")
print(f"ecMul:     {profile.ecmul_calls} calls, {profile.ecmul_gas:,} gas")
print(f"ecPairing: {profile.ecpairing_calls} call,  {profile.ecpairing_gas:,} gas")
```

### snarkjs 포맷 연동

```python
from ethclient.zk.snarkjs_compat import (
    export_snarkjs_vkey, export_snarkjs_proof,  # py-ethclient → snarkjs
    parse_snarkjs_vkey, parse_snarkjs_proof,    # snarkjs → py-ethclient
    verify_snarkjs,                              # snarkjs 포맷 직접 검증
)
```

### 데모 실행

```bash
python examples/zk_notebook_demo.py    # 전체 워크플로우 (Hello World)
python examples/zk_note_settle.py      # ZK Note Settlement (DEX)
```

---

## API 레퍼런스

### Circuit (`ethclient.zk.circuit`)

| 메서드 | 설명 |
|---|---|
| `Circuit()` | 빈 circuit 생성 |
| `c.private(name)` → `Signal` | 비밀 입력 선언 |
| `c.public(name)` → `Signal` | 공개 입력 선언 |
| `c.intermediate(name)` → `Signal` | 중간 변수 선언 |
| `c.constrain(lhs, rhs)` | 제약 조건 추가 (lhs == rhs) |
| `c.num_constraints` | 제약 조건 수 |
| `c.num_public` / `c.num_private` | 공개/비밀 입력 수 |
| `c.to_r1cs()` → `R1CS` | R1CS 행렬 추출 |
| `c.compute_witness(private, public)` → `list[int]` | witness 벡터 계산 |

### Signal 연산

| 연산 | 예시 | R1CS 영향 |
|---|---|---|
| Signal × Signal | `a * b` | 중간 변수 + constraint 자동 생성 |
| Signal × 상수 | `a * 3` | 선형 (constraint 없음) |
| Signal + Signal | `a + b` | 선형 (constraint 없음) |
| Signal - Signal | `a - b` | 선형 (constraint 없음) |
| constrain(곱, 결과) | `c.constrain(a * b, z)` | 곱셈 constraint |
| constrain(합, 결과) | `c.constrain(a + b, z)` | 선형 constraint |

### Groth16 (`ethclient.zk.groth16`)

| 함수 | 시그니처 | 설명 |
|---|---|---|
| `setup` | `(circuit: Circuit)` → `(ProvingKey, VerificationKey)` | trusted setup |
| `prove` | `(pk, private, public, circuit)` → `Proof` | proof 생성 |
| `verify` | `(vk, proof, public_inputs)` → `bool` | 검증 |
| `debug_verify` | `(vk, proof, public_inputs)` → `DebugResult` | 디버그 검증 |

### EVM Verifier (`ethclient.zk.evm_verifier`)

| 메서드 | 설명 |
|---|---|
| `EVMVerifier(vk)` | verification key로 verifier 생성 |
| `.bytecode` → `bytes` | 생성된 EVM 바이트코드 |
| `.verify_on_evm(proof, inputs)` → `EVMResult` | EVM 검증 실행 |
| `.gas_profile(proof, inputs)` → `GasProfile` | gas 상세 분석 |
| `.trace_on_evm(proof, inputs)` → `list[TraceStep]` | 실행 트레이스 |
| `.encode_calldata(proof, inputs)` → `bytes` | calldata 인코딩 |

### 타입

| 타입 | 주요 필드 |
|---|---|
| `G1Point` | `x: int`, `y: int` |
| `G2Point` | `x_real: int`, `x_imag: int`, `y_real: int`, `y_imag: int` |
| `Proof` | `a: G1Point`, `b: G2Point`, `c: G1Point` |
| `VerificationKey` | `alpha: G1`, `beta: G2`, `gamma: G2`, `delta: G2`, `ic: list[G1]` |
| `EVMResult` | `success: bool`, `gas_used: int`, `return_data: bytes` |
| `GasProfile` | `ecadd_gas`, `ecmul_gas`, `ecpairing_gas`, `*_calls`, `total_gas` |
| `DebugResult` | `valid`, `e_ab`, `e_alpha_beta`, `e_ic_gamma`, `e_c_delta` |

---

## 한계점

### 성능

| 항목 | 현재 | 비고 |
|---|---|---|
| Prover | 순수 Python (py_ecc) | **느림** — constraint당 ~2초 |
| 적정 규모 | < 10 constraints | 그 이상은 수분~수십 분 |
| Verifier | 네이티브 ~1초, EVM ~10초 | BN128 pairing이 순수 Python |

> **교육/프로토타이핑 전용**. 프로덕션 proving은 snarkjs(WASM) 또는 rapidsnark(C++)를 사용하세요. py-ethclient는 검증과 EVM 테스트에 적합합니다.

### 수학적 제약

| 한계 | 설명 | 해결 방법 |
|---|---|---|
| **부등식 불가** | `a >= b`를 R1CS로 직접 표현 불가 | 비트 분해(bit decomposition)로 range proof 구성 |
| **해시 미지원** | SHA-256, Poseidon 등의 hash circuit 없음 | 곱셈 기반 커밋먼트로 대체 (tutorial 참조) |
| **유한체 연산** | 모든 값은 BN128 scalar field (≈2^254) 위에서 동작 | 음수는 `p - |n|`으로 자동 변환됨 |
| **단일 곱셈** | 하나의 `constrain()`에 곱셈은 1개만 | `a*b*c`는 중간 변수로 분해: `t = a*b`, `c.constrain(t*c, result)` |

### 보안

| 항목 | 상태 | 비고 |
|---|---|---|
| Trusted setup | 로컬 랜덤 생성 | MPC ceremony 미지원 — toxic waste가 프로세스 메모리에 존재 |
| Randomness | Python `secrets` 모듈 | CSPRNG이지만 전용 HSM 수준은 아님 |
| Side-channel | 미방어 | 타이밍 공격, 캐시 공격 등에 대한 방어 없음 |
| 감사 | 미감사 | 프로덕션 사용 전 보안 감사 필요 |

### 기능

| 미구현 | 설명 |
|---|---|
| 실제 체인 배포 | 인메모리 EVM만 지원 (실제 이더리움 배포 불가) |
| PLONK / Halo2 | Groth16만 지원 |
| Recursive proof | proof-of-proofs 미지원 |
| Proof aggregation | 여러 proof를 하나로 집계하는 기능 없음 |
| Poseidon hash | ZK-friendly 해시 함수 circuit 미구현 |

### 프로덕션 경로

py-ethclient에서 프로토타이핑한 후 프로덕션으로 가려면:

```
py-ethclient (프로토타이핑)         프로덕션
──────────────────────────        ─────────────
Circuit() API로 로직 설계     →    circom DSL로 변환
groth16.prove()로 테스트      →    snarkjs/rapidsnark로 proving
EVM gas 프로파일링            →    Solidity verifier 배포
snarkjs 포맷 내보내기         →    기존 toolchain에 통합
```

또는 snarkjs export를 활용한 하이브리드:

```python
# py-ethclient에서 proof 생성
proof_json = export_snarkjs_proof(proof)
vk_json = export_snarkjs_vkey(vk)
# → 이 JSON을 실제 Solidity Verifier.verifyProof()에 전달
```

---

## L2 Bridge와의 연동

ZK Toolkit은 L1↔L2 브릿지의 **ZKProofHandler**와 직접 연동됩니다. Groth16 증명을 생성하고, 이를 브릿지 릴레이에서 검증하여 L2 상태를 적용할 수 있습니다.

### ZKProofHandler로 ZK proof 릴레이

```python
from ethclient.zk import Circuit, groth16
from ethclient.bridge import BridgeEnvironment, StateUpdate
from ethclient.common import rlp

# 1. Circuit: old_balance + amount = new_balance
c = Circuit()
old_bal = c.public("old_balance")
amount = c.public("amount")
new_bal = c.public("new_balance")
one = c.private("one")
product = (old_bal + amount) * one
c.constrain(product, new_bal)

# 2. Setup + Prove
pk, vk = groth16.setup(c)
proof = groth16.prove(
    pk,
    private={"one": 1},
    public={"old_balance": 1000, "amount": 500, "new_balance": 1500},
    circuit=c,
)

# 3. msg.data 구성 (RLP: [proof_a, proof_b, proof_c, public_inputs, state_updates])
proof_a = proof.a.to_evm_bytes()
proof_b = proof.b.to_evm_bytes()
proof_c = proof.c.to_evm_bytes()

public_inputs = [(1000).to_bytes(32, "big"), (500).to_bytes(32, "big"), (1500).to_bytes(32, "big")]
updates = [StateUpdate(address=b"\x02" * 20, balance=1500)]
state_updates_rlp = [rlp.decode(u.encode()) for u in updates]

zk_data = rlp.encode([proof_a, proof_b, proof_c, public_inputs, state_updates_rlp])

# 4. 브릿지 릴레이 — ZK proof 검증 후 상태 적용
env = BridgeEnvironment.with_zk_proof(vk)
env.send_l1(sender=b"\x01" * 20, target=b"\x02" * 20, data=zk_data)
result = env.relay()
assert result.all_success
assert env.l2_store.get_balance(b"\x02" * 20) == 1500
```

### 핵심 포인트

- `BridgeEnvironment.with_zk_proof(vk)` — VerificationKey를 전달하여 ZK 릴레이 모드 활성화
- `ZKProofHandler`는 `groth16.verify()`를 내부적으로 호출하여 proof를 검증
- 검증 성공 시에만 `StateUpdate`가 L2 Store에 적용됨
- 잘못된 proof는 `RelayResult(success=False, error="ZK proof verification failed")` 반환
- L2가 EVM을 실행하지 않아도 됨 — proof 검증만으로 상태 전이 가능

---

## 파일 구조

```
ethclient/zk/
├── __init__.py           31 LOC    public API re-export
├── circuit.py           480 LOC    R1CS circuit builder (Signal, Circuit, R1CS)
├── groth16.py           690 LOC    prover, verifier, debug verifier
├── evm_verifier.py      328 LOC    EVM verifier bytecode 생성 + 실행
├── snarkjs_compat.py    129 LOC    snarkjs JSON import/export
├── types.py             186 LOC    G1Point, G2Point, Proof, VerificationKey 등
└── README.md                       ← 이 파일

ethclient/rpc/
└── zk_api.py            178 LOC    zk_ JSON-RPC 핸들러

tests/
├── test_zk_circuit.py   292 LOC    26 tests — circuit builder, R1CS, 필드 연산
├── test_zk_groth16.py   267 LOC    18 tests — prove/verify, debug, snarkjs 호환
└── test_zk_evm.py       162 LOC    13 tests — EVM 검증, gas, trace

examples/
├── zk_notebook_demo.py  128 LOC    전체 워크플로우 데모
└── zk_note_settle.py    160 LOC    ZK Note Settlement 데모
```

| 카테고리 | 파일 | LOC | 테스트 |
|---|---:|---:|---:|
| 소스 (zk/) | 6 | 1,844 | — |
| 소스 (rpc/) | 1 | 178 | — |
| 테스트 | 3 | 721 | 57 |
| 예제 | 2 | 288 | — |
| **합계** | **12** | **3,031** | **57** |

---

## 의존성

| 패키지 | 용도 |
|---|---|
| [py-ecc](https://pypi.org/project/py-ecc/) | BN128 G1/G2/FQ12 연산, pairing (Groth16의 모든 수학) |

py-ethclient의 기존 EVM 모듈을 활용:

| 모듈 | 사용하는 기능 |
|---|---|
| `vm/evm.py` | `ExecutionEnvironment`, `run_bytecode()` |
| `vm/precompiles.py` | `precompile_ecadd` (0x06), `precompile_ecmul` (0x07), `precompile_ecpairing` (0x08) |
| `vm/call_frame.py` | `CallFrame` |
| `rpc/server.py` | `RPCServer.method()` 데코레이터 |
