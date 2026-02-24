---
description: "App-Specific ZK Rollup 생성 — STF 정의부터 L1 검증까지"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "앱 이름이나 유스케이스 설명"
user-invocable: true
---

# L2 ZK Rollup 생성 스킬

App-Specific ZK Rollup을 생성하고 운영하는 전문 스킬. STF(State Transition Function) 정의 → PythonRuntime 래핑 → Rollup 라이프사이클(setup → submit → batch → prove → L1 verify) 전체를 안내한다.

## 핵심 파일 참조

| 파일 | 역할 |
|------|------|
| `ethclient/l2/rollup.py` | Rollup 오케스트레이터 |
| `ethclient/l2/runtime.py` | PythonRuntime — callable을 STF로 래핑 |
| `ethclient/l2/types.py` | L2Tx, STFResult, Batch, BatchReceipt, L2State |
| `ethclient/l2/sequencer.py` | Sequencer — mempool, nonce 추적, batch 조립 |
| `ethclient/l2/prover.py` | Groth16ProofBackend (pure Python) |
| `ethclient/l2/native_prover.py` | NativeProverBackend (rapidsnark/snarkjs) |
| `ethclient/l2/interfaces.py` | 4 플러거블 인터페이스 정의 |
| `ethclient/l2/config.py` | L2Config 설정 |

## 빠른 시작 템플릿

```python
from ethclient.l2.types import L2Tx, STFResult
from ethclient.l2.rollup import Rollup

# 1. STF 정의 — 앱 로직을 순수 Python 함수로 작성
def my_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    if op == "increment":
        state["counter"] = state.get("counter", 0) + 1
        return STFResult(success=True, output={"counter": state["counter"]})
    return STFResult(success=False, error=f"unknown op: {op}")

# 2. Rollup 생성 (STF가 callable이면 자동으로 PythonRuntime 래핑)
rollup = Rollup(stf=my_stf)

# 3. Trusted Setup (ZK circuit + verifier 배포)
rollup.setup()

# 4. 트랜잭션 제출
USER = b"\x01" * 20
error = rollup.submit_tx(L2Tx(sender=USER, nonce=0, data={"op": "increment"}))
assert error is None

# 5. Batch 생산 + 증명 + L1 제출
batch = rollup.produce_batch()
receipt = rollup.prove_and_submit(batch)
assert receipt.verified

# 6. 상태 확인
print(rollup.state.get("counter"))  # 1
```

## L2Tx 제약사항

```python
@dataclass
class L2Tx:
    sender: bytes        # 반드시 20바이트 (ValueError if != 20)
    nonce: int = 0       # >= 0 (ValueError if < 0)
    data: dict = {}      # 값은 str, int, bytes, dict만 허용
    value: int = 0       # >= 0
    tx_type: L2TxType = L2TxType.CALL  # CALL=0, DEPOSIT=1, WITHDRAWAL=2
    signature: bytes = b""
    timestamp: int = 0   # 0이면 자동으로 time.time() 설정
```

**data 직렬화 규칙**: dict 값은 태그 기반 RLP 인코딩. `\x01`=int, `\x02`=bytes, `\x03`=str, `\x04`=nested dict. 키는 알파벳순 정렬.

## STF 작성 패턴

### 기본 STF (함수만)
```python
def counter_stf(state: dict, tx: L2Tx) -> STFResult:
    state["counter"] = state.get("counter", 0) + 1
    return STFResult(success=True)
```

### Validator 포함 STF
```python
from ethclient.l2.runtime import PythonRuntime

def my_validator(state: dict, tx: L2Tx) -> str | None:
    if "op" not in tx.data:
        return "missing 'op' field"
    return None  # 통과

runtime = PythonRuntime(
    func=my_stf,
    validator=my_validator,
    genesis={"counter": 0, "admin": b"\x01" * 20},
)
rollup = Rollup(stf=runtime)
```

### STFResult 구조
```python
@dataclass
class STFResult:
    success: bool
    output: dict = {}    # 성공 시 앱별 반환값
    error: str | None = None  # 실패 시 에러 메시지
```

- 함수가 `None` 반환 → `STFResult(success=True)`
- 함수가 `dict` 반환 → `STFResult(success=True, output=dict)`
- 함수가 예외 발생 → `STFResult(success=False, error=str(e))`

## Nonce 관리

Sequencer는 strict nonce 순서를 강제한다:
- 각 sender별 예상 nonce = 이전 성공 nonce + 1 (genesis = 0)
- **갭 불허**: nonce 0 → 1 → 2 순서대로만. nonce 2를 먼저 보내면 거부
- **중복 불허**: 이미 사용된 nonce 재전송 시 "nonce too low" 에러

```python
# 올바른 패턴
rollup.submit_tx(L2Tx(sender=ALICE, nonce=0, data=...))  # OK
rollup.submit_tx(L2Tx(sender=ALICE, nonce=1, data=...))  # OK
rollup.submit_tx(L2Tx(sender=BOB, nonce=0, data=...))    # OK (다른 sender)

# 잘못된 패턴
rollup.submit_tx(L2Tx(sender=ALICE, nonce=2, data=...))  # Error: nonce too high
rollup.submit_tx(L2Tx(sender=ALICE, nonce=0, data=...))  # Error: nonce too low
```

## 2-Batch 체이닝 예제

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

# Batch 1 — old_state_root == batch0.new_state_root (자동 체이닝)
rollup.submit_tx(L2Tx(sender=ALICE, nonce=2, data={"op": "inc"}))
batch1 = rollup.produce_batch()
receipt1 = rollup.prove_and_submit(batch1)
assert receipt1.verified
assert batch1.old_state_root == batch0.new_state_root
```

## L2Config 주요 설정

```python
from ethclient.l2.config import L2Config

config = L2Config(
    name="my-rollup",
    chain_id=42170,
    max_txs_per_batch=32,       # 회로 용량 (기본 32)
    batch_timeout=5,             # 초 단위 자동 seal (기본 5)
    mempool_max_size=10000,      # mempool 크기 제한
    state_backend="memory",      # "memory" 또는 "lmdb"
    l1_backend="memory",         # "memory" 또는 "eth_rpc"
    prover_backend="python",     # "python" 또는 "native"
    # LMDB용
    data_dir="./data/my-rollup",
    # EthL1Backend용
    l1_rpc_url="https://...",
    l1_private_key="hex...",
    l1_chain_id=11155111,
    # NativeProverBackend용
    prover_binary="rapidsnark",
    prover_working_dir="./prover",
)
rollup = Rollup(stf=my_stf, config=config)
```

## Rollup 라이프사이클 메서드

| 메서드 | 반환 | 설명 |
|--------|------|------|
| `setup()` | None | ZK circuit setup + verifier 배포. 반드시 prove 전에 호출 |
| `submit_tx(tx)` | `str\|None` | 에러 시 문자열, 성공 시 None |
| `produce_batch()` | `Batch` | mempool 처리 + seal. tx 없으면 RuntimeError |
| `prove_and_submit(batch)` | `BatchReceipt` | 증명 생성 + L1 제출 (원스텝) |
| `prove_batch(batch)` | `Batch` | 증명만 생성 (L1 미제출) |
| `submit_batch(batch)` | `BatchReceipt` | 이미 증명된 batch를 L1 제출 |
| `chain_info()` | `dict` | name, chain_id, state_root, is_setup, pending_txs 등 |
| `recover()` | None | LMDB WAL에서 crash recovery |

## 주의사항

1. **`setup()` 필수**: `prove_and_submit()` 전에 반드시 호출. 안 하면 RuntimeError
2. **tx 최대 개수**: `max_txs_per_batch - 1`개까지. 마지막 슬롯은 balance factor용
3. **상태 snapshot/rollback**: 실패한 tx는 상태에 영향 없음 (자동 rollback)
4. **Field modulus 절삭**: 32바이트 해시는 BN128 field modulus로 나머지 연산. 결정적이지만 비직관적
5. **Zero product 불가**: state_root가 field modulus의 배수이면 증명 실패 (확률 < 1/2^252)
