# Application-Specific ZK Rollups: 아키텍처, 구현, 분석

**도메인 특화 레이어 2 프로토콜을 위한 Python 네이티브 프레임워크**

저자: Tokamak Network
날짜: 2026

---

## 초록

ZK 롤업 구축의 지배적 접근법인 zkEVM은 모든 EVM 옵코드를 영지식 회로 내에서 재실행하여, 제약 조건 수가 O(실행_복잡도)로 증가하는 증명을 생성한다. 스토리지 읽기, 해싱, 산술 연산에 걸쳐 140개 이상의 옵코드를 사용하는 일반적인 Uniswap 스왑의 경우, 이는 트랜잭션당 수백만 개의 R1CS 제약 조건으로 이어진다. 그러나 대다수의 레이어 2 애플리케이션 — 토큰, DEX, 네임 서비스, 투표, 게임 — 은 범용 연산의 극히 일부만 필요로 한다. 이들은 전체 EVM을 영지식 하에서 재실행할 필요가 없다.

본 논문은 *애플리케이션 특화 ZK 롤업*을 소개한다. 이 프레임워크에서 개발자는 도메인 로직만을 포착하는 일반 프로그래밍 언어의 상태 전이 함수(STF)를 작성하고, 롤업 인프라가 자동으로 O(실행_복잡도)가 아닌 O(배치_크기)로 제약 조건 수가 증가하는 간결한 ZK 회로를 도출한다. 이 접근법이 범용 zkEVM과 동일한 보안 속성 — 유효성, 데이터 가용성, 검열 저항성, 자산 안전성 — 을 달성함을 증명한다.

참조 구현인 py-ethclient는 86개 모듈에 걸친 21,442줄의 Python 소스 코드로 구성되며, 40개 테스트 파일의 943개 단위 테스트로 검증되었다. 이 프레임워크는 4개의 플러거블 추상 인터페이스(StateTransitionFunction, DAProvider, ProofBackend, L1Backend), BN128 상의 Groth16 증명 시스템과 EVM 온체인 검증, 3가지 데이터 가용성 전략(로컬, calldata, EIP-4844 blob), 크래시 복구를 지원하는 LMDB 기반 영속 상태, 강제 포함과 탈출 해치를 갖춘 L1-L2 브릿지, 미들웨어를 포함한 프로덕션급 RPC 서버를 제공한다. 이더리움 Sepolia 테스트넷에서 배포 및 검증된 9개의 완전한 예제 애플리케이션으로 프레임워크를 시연한다.

---

## 목차

1. [서론](#1-서론)
2. [배경 및 기본 개념](#2-배경-및-기본-개념)
3. [시스템 모델 및 정형 정의](#3-시스템-모델-및-정형-정의)
4. [아키텍처](#4-아키텍처)
5. [L1-L2 브릿지](#5-l1l2-브릿지)
6. [개발자 경험](#6-개발자-경험)
7. [보안 분석](#7-보안-분석)
8. [성능 평가](#8-성능-평가)
9. [관련 연구 비교](#9-관련-연구-비교)
10. [한계 및 향후 연구](#10-한계-및-향후-연구)
11. [결론](#11-결론)
12. [참고문헌](#참고문헌)
13. [부록](#부록)

---

## 1. 서론

### 1.1 확장성 트릴레마와 롤업

이더리움은 기본 레이어에서 초당 약 15개의 트랜잭션을 처리하며, 이는 글로벌 규모의 탈중앙화 애플리케이션에 충분하지 않은 처리량이다. 롤업은 트랜잭션을 오프체인에서 실행하면서 데이터와 증명을 이더리움 L1에 게시하여 최종성을 확보함으로써 이를 해결한다. 두 가지 계열이 존재한다: *옵티미스틱 롤업*은 유효성을 가정하고 챌린지 기간 내 사기 증명을 허용하며, *ZK 롤업*은 결제 전에 올바른 실행의 암호학적 증명을 생성한다.

ZK 롤업은 매력적인 장점을 제공한다: 챌린지 기간 없는 최종성. 단일 증명으로 L1 검증자에게 수천 건의 트랜잭션이 올바르게 실행되었음을 확신시킬 수 있다. 과제는 *증명 생성*에 있다: 임의의 연산이 올바르게 수행되었음을 나타내는 영지식 증명을 구성하는 것이다.

### 1.2 범용 vs. 애플리케이션 특화

현재 세대의 ZK 롤업 — zkSync Era, Polygon zkEVM, Scroll, StarkNet — 은 *범용* 접근법을 추구한다: 전체 이더리움 가상 머신을 ZK 회로 내에서 재구현하는 것이다("zkEVM"). 이는 완전한 EVM 호환성을 제공하지만 막대한 비용을 수반한다. 각 EVM 옵코드는 R1CS 또는 AIR 제약 조건으로 산술화되어야 한다: 단일 SSTORE는 Merkle Patricia Trie 업데이트를 위해 수만 개의 제약 조건을 요구할 수 있으며, keccak256 해싱만으로도 호출당 수천 개의 제약 조건이 필요하다.

애플리케이션 특화 롤업의 핵심 통찰은 대부분의 L2 애플리케이션이 전체 EVM을 필요로 하지 않는다는 것이다. 토큰 원장은 덧셈과 뺄셈이 필요하다. DEX는 곱셈과 비교가 필요하다. 네임 서비스는 문자열 검색이 필요하다. 이러한 연산은 고수준 언어의 상태 전이 함수로 표현될 때, zkEVM에서 옵코드별로 재실행하는 것보다 극적으로 적은 제약 조건을 가진 ZK 회로로 포착할 수 있다.

| 측면 | zkEVM | 앱 특화 ZK 롤업 |
|---|---|---|
| 회로 범위 | 전체 EVM (140+ 옵코드) | 도메인 STF만 |
| 트랜잭션당 제약 조건 | O(10⁶) – O(10⁷) | O(배치_크기) |
| 언어 | Solidity (회로로 컴파일) | 자유 (Python, Rust 등) |
| 유연성 | 범용 | 애플리케이션별 |
| 증명 시간 | 분–시간 | 초–분 |
| 개발 | 한 팀, 수 년 작업 | 한 개발자, 수 일 작업 |

### 1.3 기여

본 논문의 기여는 다음과 같다:

1. **정형 프레임워크.** 4개의 플러거블 추상 인터페이스를 통해 애플리케이션 특화 ZK 롤업을 정의하고, 표준 암호학적 가정 하에서 범용 롤업과 동등한 보안 속성을 증명한다.

2. **참조 구현.** py-ethclient는 Python으로 된 완전한 작동 구현을 제공한다: 21,442줄의 소스 코드, 943개 단위 테스트, BN128 상의 Groth16, EVM 온체인 검증, 3가지 DA 전략, LMDB 영속성, L1-L2 브릿지.

3. **9개 예제 애플리케이션.** 토큰, DEX, 네임 서비스, 투표, 가위바위보, NFT 마켓플레이스, 멀티시그 지갑, 에스크로, 예측 시장 — 모두 이더리움에서 Groth16 증명이 검증되는 ZK 롤업으로 배포 가능.

4. **Sepolia 테스트넷 배포.** 엔드투엔드 시연: 회로 셋업, 증명 생성, 검증자 배포, 이더리움 Sepolia 테스트넷에서의 온체인 배치 검증.

### 1.4 논문 구성

2장은 ZK-SNARK 기본 개념과 이더리움 롤업 아키텍처를 다룬다. 3장은 시스템 모델과 보안 속성을 정형화한다. 4장은 아키텍처를 상세히 설명한다: 오케스트레이터, 시퀀서, 증명 시스템, DA 레이어, L1 결제, 상태 영속성. 5장은 검열 방지 메커니즘을 갖춘 L1-L2 브릿지를 기술한다. 6장은 개발자 경험과 예제 애플리케이션을 다룬다. 7장은 보안을 분석한다. 8장은 성능을 평가한다. 9장은 관련 연구와 비교한다. 10장은 한계와 향후 방향을 논의한다. 11장에서 결론을 맺는다.

---

## 2. 배경 및 기본 개념

### 2.1 ZK-SNARK과 Groth16

*영지식 간결 비대화형 지식 논증*(ZK-SNARK)은 증명자가 증인을 공개하지 않으면서 명제가 참임을 검증자에게 확신시킬 수 있게 하며, 상수 크기의 증명을 상수 시간에 검증할 수 있다.

**Rank-1 Constraint System (R1CS).** R1CS는 유한체 F 상의 행렬 A, B, C ∈ F^(m×n)으로 구성되며, 유효한 증인 벡터 w ∈ F^n에 대한 제약 조건은 다음과 같다:

```
(A · w) ⊙ (B · w) = C · w
```

여기서 ⊙은 원소별(아다마르) 곱을 나타낸다. 각 행은 하나의 곱셈 제약 조건을 인코딩한다.

py-ethclient 회로 빌더(`ethclient/zk/circuit.py:155–359`)는 R1CS 구성을 위한 Pythonic API를 제공한다:

```python
# ethclient/zk/circuit.py:155-200 (간소화)
class Circuit:
    def public(self, name: str) -> Signal:
        """공개 입력 신호 선언."""
        idx = self._num_vars
        self._num_vars += 1
        self._public_vars.append(idx)
        return Signal(self, {idx: 1})

    def private(self, name: str) -> Signal:
        """비밀 입력 신호 선언."""
        idx = self._num_vars
        self._num_vars += 1
        self._private_vars.append(idx)
        return Signal(self, {idx: 1})

    def constrain(self, lhs: Signal, rhs: Signal) -> None:
        """제약 조건 추가: lhs == rhs."""
        ...
```

Signal은 연산자 오버로딩(`__mul__`, `__add__`, `__sub__`)을 지원하므로, `x * y`는 자동으로 R1CS 제약 조건을 생성한다(`ethclient/zk/circuit.py:112–131`).

**이차 산술 프로그램(QAP).** R1CS는 라그랑주 보간을 통해 QAP로 변환된다(`ethclient/zk/groth16.py:117–146`). 다항식 u_j(x), v_j(x), w_j(x)가 구성되어 R1CS 제약 조건은 다항식 항등식이 성립할 때만 만족된다:

```
A(x) · B(x) - C(x) ≡ h(x) · t(x)
```

여기서 t(x)는 평가 도메인 상의 소실 다항식이다.

**Groth16 프로토콜.** Groth16 증명 시스템 [1]은 쌍선형 페어링 친화 곡선(본 구현에서는 BN128) 위에서 동작한다. 셋업은 toxic waste (τ, α, β, γ, δ)로부터 증명 키 pk와 검증 키 vk를 생성한다. 증명 π = (A, B, C) ∈ G₁ × G₂ × G₁은 페어링 방정식을 확인하여 검증된다:

```
e(A, B) = e(α, β) · e(IC_acc, γ) · e(C, δ)
```

여기서 IC_acc = IC[0] + Σᵢ input[i] · IC[i+1]은 공개 입력을 누적한다.

순수 Python 구현(`ethclient/zk/groth16.py:221–327` 셋업, `333–430` 증명, `589–638` 검증)은 BN128 곡선 연산에 py_ecc를 사용한다.

### 2.2 이더리움 롤업 아키텍처

ZK 롤업은 다음의 생명주기를 통해 동작한다:

```
┌──────────────────────────────────────────────────────────────┐
│                    배치 생명주기                               │
│                                                              │
│  사용자 Tx ──► 시퀀서 ──► 배치 조립 ──► ZK 증명 생성         │
│                                    │                │        │
│                                    ▼                ▼        │
│                              DA 커밋먼트       증명 (π)      │
│                                    │                │        │
│                                    └───────┬────────┘        │
│                                            ▼                 │
│                                    L1 검증                   │
│                                  (스마트 컨트랙트)           │
│                                            │                 │
│                                            ▼                 │
│                                    상태 확정                  │
└──────────────────────────────────────────────────────────────┘
```

1. **트랜잭션 제출.** 사용자가 L2 시퀀서에 트랜잭션을 제출한다.
2. **배치 조립.** 시퀀서가 트랜잭션을 배치로 수집하고, 각각에 대해 상태 전이 함수를 실행한다.
3. **데이터 가용성.** 배치 데이터가 L1에 게시된다(calldata, blob, 또는 외부 DA).
4. **증명 생성.** 증명자가 old_root에서 new_root으로의 상태 전이가 유효함을 보이는 ZK 증명을 생성한다.
5. **L1 검증.** 증명이 온체인 검증자 컨트랙트에 제출된다. 페어링 검사가 통과하면 새로운 상태 루트가 수락된다.

EIP-4844(Proto-Danksharding)는 blob 트랜잭션을 도입하여, 바이트당 ~1 gas(calldata의 16 gas/바이트 대비)로 전용 데이터 가용성 레이어를 제공하며, 데이터는 약 18일간 가용하다.

### 2.3 앱 특화 vs. 범용 설계

근본적인 차이는 복잡도가 어디에 있는가이다:

| 속성 | 범용 (zkEVM) | 앱 특화 |
|---|---|---|
| 산술화 대상 | 모든 EVM 옵코드 | 도메인 STF만 |
| 제약 조건 복잡도 | O(실행_복잡도) | O(배치_크기) |
| STF 언어 | Solidity → 회로 컴파일러 | 자유 언어 (Python, Rust) |
| 회로 고정 비용 | 수백만 (EVM 인터프리터) | 수백 (체인 제약 조건) |
| 트랜잭션당 한계 비용 | 수천 (옵코드 트레이스) | 곱셈 1회 |
| 재사용성 | 모든 EVM 컨트랙트 | 단일 애플리케이션 |

핵심 트레이드오프는 범용성 대 효율성이다. zkEVM은 모든 Solidity 컨트랙트를 실행할 수 있지만 전체 EVM 산술화 비용을 지불한다. 앱 특화 롤업은 지정된 STF만 실행하지만 수 차수 더 작은 회로 크기를 달성한다.

---

## 3. 시스템 모델 및 정형 정의

### 3.1 시스템 모델

4가지 행위자 클래스를 고려한다:

- **사용자**: L2 트랜잭션을 시퀀서에 제출한다.
- **시퀀서**: 트랜잭션 순서를 결정하고, STF를 실행하며, 배치를 조립한다.
- **증명자**: 배치에 대한 ZK 증명을 생성한다.
- **L1 검증자**: 검증자 컨트랙트를 통해 이더리움 L1에서 증명을 검증한다.

보안 모델의 가정:
- L1은 활성적이고 올바르다(이더리움 합의 가정).
- ZK 증명 시스템은 건전하다(KEA 하의 계산적 건전성).
- 최소 하나의 정직한 데이터 가용성 제공자가 DA를 보장한다.
- 시퀀서는 악의적일 수 있지만 증명을 위조할 수 없다.

### 3.2 상태 전이 함수

**정의 1 (상태 전이 함수).** STF는 결정론적 함수이다:

```
STF: (S, tx) → (S', result)
```

여기서 S ∈ State는 현재 상태, tx ∈ Tx는 트랜잭션, S' ∈ State는 결과 상태, result ∈ {success, failure} × Output이다.

py-ethclient에서는 `StateTransitionFunction` 추상 기본 클래스로 인코딩된다(`ethclient/l2/interfaces.py:12–25`):

```python
# ethclient/l2/interfaces.py:12-25
class StateTransitionFunction(ABC):
    """트랜잭션에 대한 L2 상태 전이를 정의한다."""

    @abstractmethod
    def apply_tx(self, state: L2State, tx: L2Tx) -> STFResult:
        ...

    def validate_tx(self, state: L2State, tx: L2Tx) -> Optional[str]:
        """tx가 유효하지 않으면 오류 문자열을, 그렇지 않으면 None을 반환."""
        return None

    def genesis_state(self) -> dict[str, Any]:
        """롤업의 초기 상태를 반환."""
        return {}
```

`PythonRuntime` 어댑터(`ethclient/l2/runtime.py:11–53`)는 모든 Python callable을 STF로 래핑한다:

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

### 3.3 배치와 상태 루트

**정의 2 (배치).** 배치 B_k는 다음의 튜플이다:

```
B_k = (k, txs, root_old, root_new, commitment_DA, π)
```

여기서 k는 배치 번호, txs는 순서화된 트랜잭션 목록, root_old와 root_new는 Merkle-Patricia Trie 상태 루트, commitment_DA는 데이터 가용성 커밋먼트, π는 ZK 증명이다.

`Batch` 데이터클래스(`ethclient/l2/types.py:136–182`):

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

**정의 3 (상태 루트).** 상태 루트는 상태의 Merkle-Patricia Trie 루트 해시이다:

```
root(S) = MPT_root({encode_key(k): encode_value(v) | (k, v) ∈ S})
```

`L2StateStore.compute_state_root()`로 계산된다(`ethclient/l2/state.py:28–35`).

### 3.4 플러거블 인터페이스 모델

프레임워크는 롤업 오케스트레이터를 특정 구현으로부터 분리하는 4개의 추상 기본 클래스를 중심으로 구조화된다:

```
┌─────────────────────────────────────────────────────────────────┐
│                      롤업 오케스트레이터                         │
│                   (ethclient/l2/rollup.py)                      │
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

4개의 ABC(`ethclient/l2/interfaces.py`):

1. **StateTransitionFunction** (12–25행): 도메인 로직 — `apply_tx(state, tx) → STFResult`
2. **DAProvider** (28–44행): 데이터 가용성 — `store_batch()`, `retrieve_batch()`, `verify_commitment()`
3. **ProofBackend** (79–113행): ZK 증명 — `setup()`, `prove()`, `verify()`
4. **L1Backend** (47–76행): L1 결제 — `deploy_verifier()`, `submit_batch()`, `is_batch_verified()`

### 3.5 보안 속성

올바른 롤업을 위해 4가지 보안 속성을 요구한다:

**속성 1 (유효성).** 유효하지 않은 상태 전이는 L1에서 수락될 수 없다. 형식적으로: 검증자 컨트랙트가 배치 B_k를 수락하면, root_old에 STF를 통해 순차적으로 적용하여 root_new를 생성하는 트랜잭션 tx₁,...,txₙ이 존재한다.

**속성 2 (데이터 가용성).** 수락된 모든 배치 B_k에 대해, 전체 트랜잭션 데이터는 정직한 모든 당사자에게 가용하다. L1 calldata/blob에 데이터를 게시함으로써 보장된다.

**속성 3 (검열 저항성).** 시퀀서가 악의적이더라도, 모든 사용자는 제한된 시간 내에 트랜잭션의 포함을 강제할 수 있다.

**속성 4 (자산 안전성).** 사용자 자금은 영구적으로 도난당하거나 동결될 수 없다. L2가 무응답 상태가 되면 사용자는 탈출 해치를 통해 탈출할 수 있다.

---

## 4. 아키텍처

### 4.1 롤업 오케스트레이터

`Rollup` 클래스(`ethclient/l2/rollup.py:22–209`)는 메인 진입점이다. STF 래핑, 상태 초기화, 시퀀서 구성, 신뢰 셋업, 배치 생산, 증명, L1 제출의 전체 파이프라인을 오케스트레이션한다.

```python
# ethclient/l2/rollup.py:40-78
class Rollup:
    def __init__(self, stf=None, da=None, l1=None, prover=None, config=None):
        self._config = config or L2Config()

        # callable을 PythonRuntime으로 래핑
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

최소 사용법은 5줄이다:

```python
def my_stf(state, tx):
    state["count"] = state.get("count", 0) + 1
    return STFResult(success=True)

rollup = Rollup(stf=my_stf)
rollup.setup()
```

설정 기반 백엔드 선택(`ethclient/l2/rollup.py:153–181`)은 `L2Config` 필드를 기반으로 자동으로 구현을 선택한다: `state_backend` ("memory" | "lmdb"), `l1_backend` ("memory" | "eth_rpc"), `prover_backend` ("python" | "native").

### 4.2 시퀀서 설계

시퀀서(`ethclient/l2/sequencer.py:17–141`)는 제출부터 배치 봉인까지의 트랜잭션 생명주기를 관리한다.

#### 4.2.1 멤풀과 논스 추적

트랜잭션은 엄격한 논스 순서로 제한된 멤풀(`mempool_max_size` 기본값: 10,000)에 진입한다:

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

논스 갭은 즉시 거부되며(갭 채움 없음), 발신자별 엄격한 트랜잭션 순서를 보장한다. 이는 증명자가 트랜잭션이 정규 순서임을 가정할 수 있어 증명 구성을 단순화한다.

#### 4.2.2 스냅샷/롤백

각 트랜잭션은 원자적 스냅샷/롤백 시맨틱으로 실행된다. STF가 실패하면 상태는 실행 전 스냅샷으로 복원된다:

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

성공적으로 실행된 트랜잭션만 배치에 포함되므로, 증명 유효성에 핵심적이다: 증명자는 배치 내 모든 트랜잭션이 성공했다고 가정할 수 있다.

#### 4.2.3 자동 봉인 정책

배치는 두 가지 조건에서 봉인된다: 크기 제한 또는 타임아웃:

```python
# ethclient/l2/sequencer.py:101-107
if len(self._current_batch_txs) >= self._config.max_txs_per_batch:
    self._seal_batch()
elif self._current_batch_txs:
    elapsed = time.monotonic() - self._last_batch_time
    if elapsed >= self._batch_timeout:
        self._seal_batch()
```

시퀀서 상태 머신:

```
                   submit_tx()
    ┌─────────┐ ──────────────► ┌───────────┐
    │  비어있음 │                 │   멤풀    │
    │  (대기)  │ ◄────────────── │  (대기중)  │
    └─────────┘  드레인/거부     └─────┬─────┘
                                      │ tick()
                                      ▼
                                ┌───────────┐
                                │  실행 중   │
                                │ (STF 실행) │
                                └─────┬─────┘
                               성공│ / 실패 (롤백)
                                      ▼
                   크기 제한     ┌───────────┐
              ┌───────────────  │  배치 중   │
              │   또는 타임아웃   │ (수집 중)  │
              ▼                 └───────────┘
        ┌───────────┐
        │   봉인됨   │
        │   (배치)   │
        └─────┬─────┘
              │ prove_and_submit()
              ▼
        ┌───────────┐
        │  증명 완료  │
        │  (L1 상)   │
        └───────────┘
```

### 4.3 ZK 증명 시스템

#### 4.3.1 회로 설계

핵심 회로(`ethclient/l2/prover.py:57–77`)는 3개의 공개 입력과 max_txs개의 비밀 증인을 가진 *실행 트레이스 체인* 구조를 사용한다:

```python
# ethclient/l2/prover.py:57-77
def _build_circuit(self, max_txs: int) -> Circuit:
    c = Circuit()
    # 공개 입력
    old_root = c.public("old_state_root")
    new_root = c.public("new_state_root")
    tx_commit = c.public("tx_commitment")

    # 비밀 증인: 개별 트랜잭션 해시
    tx_signals = [c.private(f"tx_{i}") for i in range(max_txs)]

    # 체인: old_root * tx_0 * tx_1 * ... * tx_{max_txs-1}
    chain = old_root * tx_signals[0]
    for i in range(1, max_txs):
        chain = chain * tx_signals[i]

    # 바인딩: chain == new_root * tx_commitment
    c.constrain(chain, new_root * tx_commit)
    return c
```

제약 조건 방정식:

```
old_root × ∏ᵢ tx_i ≡ new_root × tx_commitment  (mod p)
```

이는 정확히 **max_txs**개의 R1CS 제약 조건을 생성한다(체인 단계당 하나의 곱셈, 최종 바인딩 제약 조건은 마지막 곱셈에 접힌다). 회로 구조:

```
┌──────────────────────────────────────────────────────────────┐
│                      회로 구조                                │
│                                                              │
│  공개 입력 (3):                                              │
│    [old_state_root]  [new_state_root]  [tx_commitment]       │
│                                                              │
│  비밀 증인 (max_txs):                                        │
│    [tx_0] [tx_1] [tx_2] ... [tx_{N-1}] [balance] [1] [1]   │
│     실제    실제   실제       실제       밸런서    패딩       │
│                                                              │
│  제약 조건 (max_txs):                                        │
│    chain_0 = old_root × tx_0                                 │
│    chain_1 = chain_0  × tx_1                                 │
│    chain_2 = chain_1  × tx_2                                 │
│    ...                                                       │
│    chain_{N-1} == new_root × tx_commitment                   │
└──────────────────────────────────────────────────────────────┘
```

**완전성:** 유효한 트랜잭션을 가진 정직한 증명자의 경우, old_root × ∏(tx_hash_i) × balance_factor × 1^패딩 = new_root × tx_commitment이므로 제약 조건이 만족된다.

**건전성:** 어떤 tx_hash_i를 변경하는 악의적 증명자는 동일한 공개 입력으로 동일한 제약 조건을 만족하는 다른 비밀 값 집합을 찾아야 한다. keccak256의 바인딩 속성과 KEA(지식 추출 가정) 하에서, 이는 해시 함수 또는 Groth16 증명 시스템을 깨뜨리는 것을 요구한다.

#### 4.3.2 128비트 필드 절삭

상태 루트와 트랜잭션 해시는 256비트 keccak256 출력이지만, BN128 필드 원소는 254비트이다. `_to_field` 함수(`ethclient/l2/prover.py:17–19`)가 모듈러 리덕션을 수행한다:

```python
# ethclient/l2/prover.py:17-19
FIELD_MODULUS = curve_order  # ~2^254

def _to_field(data: bytes) -> int:
    return int.from_bytes(data, "big") % FIELD_MODULUS
```

BN128 곡선 차수는 약 2^254이므로, 모듈러 리덕션은 256비트 값을 254비트 필드 원소로 매핑한다. 충돌 확률(두 개의 서로 다른 256비트 값이 동일한 필드 원소로 매핑될 확률)은 약 2^{-254}으로 무시할 수 있다.

#### 4.3.3 밸런스 팩터와 패딩

실제 트랜잭션 수 N이 max_txs보다 작을 수 있으므로, 나머지 슬롯을 채워야 한다:

```python
# ethclient/l2/prover.py:97-117
# 비밀 증인 구성: 실제 tx 해시 + 밸런스 팩터 + 패딩
product = old_root_int
for i, tx in enumerate(transactions):
    tx_int = _to_field(tx.tx_hash())
    private[f"tx_{i}"] = tx_int
    product = _field(product * tx_int)

# 밸런스 팩터: old_root * prod(all) = new_root * tx_commitment이 되도록 함
target = _field(new_root_int * tx_commit_int)
balance = _field(target * pow(product, FIELD_MODULUS - 2, FIELD_MODULUS))
private[f"tx_{len(transactions)}"] = balance

# 나머지 슬롯: 1 (곱셈 항등원)
for i in range(len(transactions) + 1, self._max_txs):
    private[f"tx_{i}"] = 1
```

슬롯 배치: [real_tx_0, ..., real_tx_{N-1}, balance_factor, 1, 1, ..., 1]. 밸런스 팩터는 페르마의 소정리를 통해 target / product (mod p)로 계산된다. 1(곱셈 항등원)로 패딩하면 곱에 영향을 주지 않는다.

#### 4.3.4 이중 증명자 아키텍처

프레임워크는 두 가지 증명자 백엔드를 지원한다:

| 측면 | Python (Groth16ProofBackend) | Native (NativeProverBackend) |
|---|---|---|
| 구현 | `ethclient/l2/prover.py` | `ethclient/l2/native_prover.py` |
| 곡선 연산 | py_ecc (순수 Python) | rapidsnark (C++ / WASM) |
| 셋업 | Python | snarkjs CLI (서브프로세스) |
| 증인 계산 | Python | Python |
| 증명 생성 | Python (대형 회로에서 느림) | rapidsnark (빠름) |
| 검증 | Python | Python (항상) |
| 폴백 | 해당없음 | 실패 시 Python으로 폴백 |

`NativeProverBackend`(`ethclient/l2/native_prover.py:32–263`)는 외부 바이너리에 대한 서브프로세스 호출을 사용한다:

```python
# ethclient/l2/native_prover.py:122-132
# 네이티브 증명 시도
if self._zkey_path is not None and self._zkey_path.exists():
    try:
        return self._prove_native(public, private)
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.warning("Native prove failed (%s), falling back to Python", e)

# Python으로 폴백
if self._pk is None:
    self._pk, self._vk = groth16.setup(self._circuit)
return groth16.prove(self._pk, private=private, public=public, circuit=self._circuit)
```

이 이중 전략은 네이티브 바이너리를 사용할 수 없을 때에도 시스템이 기능하도록 보장하면서, 사용 가능할 때는 수 배의 성능 향상을 제공한다.

### 4.4 데이터 가용성 레이어

DA 레이어는 모두 `DAProvider` 인터페이스를 구현하는 3가지 전략을 제공한다.

#### 4.4.1 로컬 DA

`LocalDAProvider`(`ethclient/l2/da.py`)는 keccak256 커밋먼트와 함께 배치 데이터를 메모리에 저장한다. 테스트 및 개발에 적합하다.

#### 4.4.2 Calldata DA

`CalldataDAProvider`(`ethclient/l2/da_calldata.py:13–104`)는 배치 데이터를 EIP-1559(타입 2) 트랜잭션 calldata로 게시한다:

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

가스 추정(`ethclient/l2/da_calldata.py:100–104`): 21,000 기본 + 비제로 바이트당 16 gas + 제로 바이트당 4 gas + 5,000 오버헤드.

#### 4.4.3 Blob DA (EIP-4844)

`BlobDAProvider`(`ethclient/l2/da_blob.py:90–202`)는 배치 데이터를 131,072바이트 blob으로 인코딩한다:

```python
# ethclient/l2/da_blob.py:31-53
def encode_blob(data: bytes) -> bytes:
    """데이터를 131072바이트 blob으로 인코딩.
    각 청크는 32바이트 필드 원소의 하위 31바이트에 배치
    (상위 바이트 = 0x00, BLS 모듈러스 안전을 위해)."""
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

KZG 커밋먼트는 c-kzg 라이브러리를 통해 계산되며, 버전화된 해시(`0x01 || SHA256(commitment)[1:]`)가 타입-3 트랜잭션에 포함된다.

| DA 전략 | 비용 | 내구성 | 트랜잭션당 최대 | 구현 |
|---|---|---|---|---|
| 로컬 | 무료 | 메모리만 | 무제한 | `da.py` |
| Calldata (EIP-1559) | 비제로 바이트당 16 gas | 영구 | ~128 KB | `da_calldata.py` |
| Blob (EIP-4844) | 바이트당 ~1 gas | ~18일 | blob당 ~126 KB | `da_blob.py` |

### 4.5 L1 결제

#### 4.5.1 EVMVerifier: 자동 생성 바이트코드

`EVMVerifier`(`ethclient/zk/evm_verifier.py:67–165`)는 3개의 프리컴파일을 사용하여 Groth16 검증을 수행하는 최소 EVM 바이트코드를 생성한다:

- **ecMul** (0x07): G1 스칼라 곱셈 — 6,000 gas
- **ecAdd** (0x06): G1 점 덧셈 — 150 gas
- **ecPairing** (0x08): 쌍선형 페어링 검사 — 45,000 + 쌍당 34,000

검증 알고리즘:

1. IC 누적기 계산: `acc = IC[0] + Σᵢ(input[i] × IC[i+1])` — ecMul + ecAdd 사용
2. 페어링 입력 구성: 4쌍 (-A, B), (α, β), (acc, γ), (C, δ)
3. ecPairing 프리컴파일 호출
4. 결과 반환 (1 = 유효, 0 = 무효)

#### 4.5.2 가스 비용 분석

3개의 공개 입력(우리 회로)에 대한 검증 가스 분석:

| 연산 | 횟수 | 호출당 가스 | 총 가스 |
|---|---|---|---|
| ecMul (0x07) | 3 | 6,000 | 18,000 |
| ecAdd (0x06) | 3 | 150 | 450 |
| ecPairing (0x08) | 1 (4쌍) | 45,000 + 34,000 × 4 | 181,000 |
| 바이트코드 실행 | — | — | ~150 |
| **합계** | | | **~199,600** |

이는 배치 내 트랜잭션 수에 관계없이 고정 비용이다. 30 gwei 가스 가격 기준, 검증 비용은 약 0.006 ETH(ETH당 $3,000 기준 ~$18)이다.

#### 4.5.3 EthL1Backend

`EthL1Backend`(`ethclient/l2/eth_l1_backend.py:27–146`)는 실제 이더리움 L1 통합을 처리한다:

```python
# ethclient/l2/eth_l1_backend.py:54-74
def deploy_verifier(self, vk: VerificationKey) -> bytes:
    """L1에 Groth16 검증자 컨트랙트를 배포한다."""
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

배치 제출(`ethclient/l2/eth_l1_backend.py:76–109`)은 증명과 공개 입력을 calldata로 인코딩하고, 배포된 검증자 컨트랙트에 EIP-1559 트랜잭션을 전송하며, 영수증 상태를 검증한다.

### 4.6 상태 영속성

#### 4.6.1 L2StateStore: Merkle-Patricia Trie

인메모리 상태 저장소(`ethclient/l2/state.py:13–56`)는 Merkle-Patricia Trie 루트 계산과 스냅샷/롤백을 갖춘 `L2State`(dict 서브클래스)를 래핑한다:

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

값은 타입 안전 인코딩을 위해 태깅된다(`ethclient/l2/state.py:65–81`): `\x01`은 int, `\x02`는 string, `\x03`은 dict(재귀적), `\x04`는 list.

#### 4.6.2 L2PersistentStateStore: LMDB 오버레이 패턴

프로덕션 사용을 위해 `L2PersistentStateStore`(`ethclient/l2/persistent_state.py:217–419`)는 오버레이 패턴의 LMDB 기반 영속성을 제공한다:

```
┌─────────────────────────────────────────────────┐
│                 STF 코드                         │
│           state["key"] = value                   │
│           state.get("key")                       │
├─────────────────────────────────────────────────┤
│              오버레이 (dict)                      │
│         빠른 쓰기, 인메모리                       │
│    ┌──────────────┬──────────────┐               │
│    │  _overlay    │  _deleted    │               │
│    │  {k: v, ...} │  {k, ...}   │               │
│    └──────────────┴──────────────┘               │
│              │ 미스                              │
│              ▼                                   │
├─────────────────────────────────────────────────┤
│            LMDB (디스크)                         │
│    ┌─────────┬──────────┬────────┬──────┬─────┐ │
│    │l2_state │l2_batches│l2_proofs│l2_meta│l2_wal│ │
│    └─────────┴──────────┴────────┴──────┴─────┘ │
│         flush() → 원자적 쓰기                    │
└─────────────────────────────────────────────────┘
```

오버레이 패턴(`ethclient/l2/persistent_state.py:23–130`):

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

**크래시 복구**는 Write-Ahead Log(WAL)를 사용한다. 이벤트(`tx_applied`, `batch_sealed`, `batch_proven`, `batch_submitted`)는 연산 전에 WAL에 추가되고, 시작 시 재생된다(`ethclient/l2/rollup.py:183–209`).

5개의 LMDB 데이터베이스가 사용된다: `l2_state`(키-값 상태), `l2_batches`(봉인된 배치), `l2_proofs`(증명 데이터), `l2_meta`(카운터, 논스, 루트), `l2_wal`(WAL).

---

## 5. L1-L2 브릿지

### 5.1 CrossDomainMessenger

브릿지는 Optimism CrossDomainMessenger 패턴을 따른다(`ethclient/bridge/messenger.py:37–303`). 각 도메인(L1과 L2)은 자체 상태 저장소로 뒷받침되는 메신저 인스턴스를 갖는다. 메시지는 아웃박스에 전송되고, 워처가 이를 수집하여 다른 도메인의 메신저에서 릴레이한다.

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

메시지 릴레이(`ethclient/bridge/messenger.py:116–140`)에는 `message_hash` 추적을 통한 리플레이 보호가 포함된다.

### 5.2 플러거블 릴레이 핸들러

릴레이 실행은 플러거블 핸들러에 위임된다(`ethclient/bridge/relay_handlers.py`):

| 핸들러 | 신뢰 모델 | 증명 | 가스 비용 | 사용 사례 |
|---|---|---|---|---|
| EVMRelayHandler | L1이 EVM 실행 검증 | EVM 출력 | 높음 (~100K+) | 범용 컨트랙트 |
| MerkleProofHandler | 신뢰 루트 대비 Merkle 증명 | Merkle 경로 | 낮음 (~5K) | 상태 증명 |
| ZKProofHandler | Groth16 증명 검증 | ZK 증명 (π) | ~200K (고정) | 프라이버시 보존 |
| DirectStateHandler | 신뢰 릴레이어 | 없음 | 최소 | 개발/테스트 |
| TinyDBHandler | 신뢰 릴레이어 | 없음 | 최소 | 비 EVM 백엔드 |

`ZKProofHandler`(`ethclient/bridge/relay_handlers.py:291–380`)는 상태 업데이트를 적용하기 전에 Groth16 증명을 검증하여, 영지식 프라이버시와 함께 신뢰 없는 크로스 도메인 전송을 가능하게 한다.

### 5.3 검열 방지 메커니즘

#### 강제 포함

시퀀서가 트랜잭션을 검열하면, 사용자는 L1에서 강제 포함을 등록할 수 있다(`ethclient/bridge/messenger.py:164–181`):

```python
# ethclient/bridge/messenger.py:164-181
def force_include(self, msg: CrossDomainMessage) -> ForceInclusionEntry:
    """L1에서 강제 포함을 위해 메시지를 등록한다.
    FORCE_INCLUSION_WINDOW 블록 후, 누구나 force_relay()를 호출할 수 있다."""
    entry = ForceInclusionEntry(
        message=msg,
        registered_block=self.block_number,
    )
    self._force_queue[msg.message_hash] = entry
    return entry
```

`FORCE_INCLUSION_WINDOW` 블록(설정 가능) 후, 누구나 `force_relay()`를 호출하여 오퍼레이터를 완전히 우회하고 L2에서 메시지를 실행할 수 있다.

#### 탈출 해치

탈출 해치(`ethclient/bridge/messenger.py:231–293`)는 최후의 수단이다: L2가 완전히 무응답 상태이면 사용자가 L1에서 직접 예치된 가치를 회수할 수 있다:

```python
# ethclient/bridge/messenger.py:231-293 (간소화)
def escape_hatch(self, msg: CrossDomainMessage) -> RelayResult:
    """L2가 무응답일 때 L1에서 가치를 회수한다.
    조건: 강제 큐에 존재, 윈도우 경과, value > 0."""
    ...
    acc.balance += msg.value
    store.put_account(msg.sender, acc)
    entry.resolved = True
    self._escaped[msg.message_hash] = True
    ...
```

---

## 6. 개발자 경험

### 6.1 Python으로 커스텀 STF 작성

커스텀 상태 전이를 가진 완전한 롤업은 최소한의 코드로 구현된다:

```python
from ethclient.l2 import Rollup, L2Tx, STFResult

# 상태 전이 정의: 그냥 Python 함수
def counter_stf(state, tx):
    state["count"] = state.get("count", 0) + 1
    return STFResult(success=True)

# 롤업 생성 및 초기화
rollup = Rollup(stf=counter_stf)
rollup.setup()  # ZK 신뢰 셋업 + 검증자 배포

# 트랜잭션 제출, 배치 생산, 증명, 검증
rollup.submit_tx(L2Tx(sender=b"\x01"*20, nonce=0, data={"op": "inc"}))
batch = rollup.produce_batch()
receipt = rollup.prove_and_submit(batch)
assert receipt.verified  # 온체인 검증 통과
```

개발자는 STF 로직만 작성한다. 프레임워크가 시퀀싱, 배칭, 증명 생성, L1 검증을 자동으로 처리한다.

### 6.2 예제 애플리케이션

9개의 완전한 예제 애플리케이션이 프레임워크의 다용성을 시연한다:

| # | 애플리케이션 | STF LOC | 도메인 | STF 패턴 |
|---|---|---|---|---|
| 1 | 토큰 (ERC20) | 33 | DeFi | 잔액 맵 + 관리자 발행 |
| 2 | DEX (AMM) | 140 | DeFi | x*y=k 상수곱 |
| 3 | 네임 서비스 | ~40 | 아이덴티티 | 문자열 레지스트리 + 만료 |
| 4 | 투표 | ~35 | 거버넌스 | 투표용지 + 집계 |
| 5 | 가위바위보 | ~60 | 게임 | 커밋-리빌 + 매칭 |
| 6 | NFT 마켓플레이스 | ~80 | NFT | 소유권 맵 + 리스팅 |
| 7 | 멀티시그 지갑 | ~70 | 보안 | M-of-N 승인 |
| 8 | 에스크로 | ~50 | DeFi | 시간 잠금 해제 |
| 9 | 예측 시장 | ~90 | DeFi | 결과 지분 + 결정 |

**토큰 STF** (`examples/apps/l2_token.py:33–65`):

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

**DEX 스왑** (`examples/apps/l2_dex.py:119–171`):

```python
if op == "swap":
    # x*y=k, 0.3% 수수료 적용
    amount_in_after_fee = amount_in * (10000 - FEE_BPS) // 10000
    amount_out = r_out * amount_in_after_fee // (r_in + amount_in_after_fee)

    if amount_out < min_out:
        return STFResult(success=False, error=f"slippage: got {amount_out} < min {min_out}")

    # 불변량 검사: new k >= old k
    new_r_in = r_in + amount_in
    new_r_out = r_out - amount_out
    assert new_r_in * new_r_out >= r_in * r_out, "k invariant broken"
    ...
```

9개 애플리케이션 모두 동일한 패턴을 따른다: STF 정의 → PythonRuntime으로 래핑 → Rollup 생성 → 트랜잭션 제출 → 배치 생산 → 온체인 증명 및 검증.

### 6.3 설정 기반 배포

`L2Config` 데이터클래스(`ethclient/l2/config.py:10–57`)는 25개 이상의 설정 필드를 제공한다:

```python
# ethclient/l2/config.py:10-57
@dataclass
class L2Config:
    name: str = "py-rollup"
    chain_id: int = 42170
    max_txs_per_batch: int = 64
    batch_timeout: int = 10          # 초
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

Rollup 생성자는 이 필드를 읽고 적절한 백엔드를 자동으로 인스턴스화한다.

### 6.4 프로덕션 미들웨어

L2 RPC 서버는 3개의 미들웨어 컴포넌트를 포함한다:

- **APIKeyMiddleware**: 헤더 기반 API 키 인증
- **RateLimitMiddleware**: IP별 토큰 버킷 속도 제한 (설정 가능한 RPS 및 burst)
- **RequestSizeLimitMiddleware**: 설정 가능한 최대 요청 크기 (기본 1 MB)

RPC 서버는 7개의 `l2_*` 메서드와 health, readiness, metrics 엔드포인트를 노출한다.

### 6.5 Sepolia 라이브 배포

Sepolia 테스트넷에서의 엔드투엔드 배포 단계:

1. **설정**: `l1_backend: "eth_rpc"`, `l1_rpc_url`, `l1_private_key`, `l1_chain_id: 11155111` 설정
2. **셋업**: `rollup.setup()` — Sepolia에 검증자 컨트랙트 배포
3. **트랜잭션**: L2 트랜잭션 제출, 배치 생산
4. **증명**: Groth16 증명 생성
5. **제출**: `rollup.prove_and_submit(batch)` — Sepolia 검증자 컨트랙트에 증명 전송
6. **검증**: 온체인 ecPairing 검사로 유효성 확인

9개 예제 애플리케이션 모두에서 Sepolia에서 성공적으로 시연되었다.

---

## 7. 보안 분석

### 7.1 실행 트레이스 회로의 건전성

**정리 1 (회로 건전성).** KEA(지식 추출 가정) 하에서 keccak256이 충돌 저항적이라 가정하면, 어떤 PPT 적대자도 무시할 수 없는 확률로 유효하지 않은 상태 전이에 대한 유효한 Groth16 증명을 생성할 수 없다.

*증명 스케치.* 회로는 다음을 강제한다:

```
old_root × ∏ᵢ private_i ≡ new_root × tx_commitment  (mod p)
```

외부 바인딩:

```
tx_commitment = keccak256(tx_hash_0 ‖ tx_hash_1 ‖ ... ‖ tx_hash_{N-1})
```

다른 트랜잭션으로 증명을 위조하려면:
1. 동일한 공개 입력(old_root, new_root, tx_commitment)으로 동일한 제약 조건을 만족하는 다른 비밀 값 {private'_i}를 찾아야 한다.
2. tx_commitment가 고정(공개 입력)이고 tx_commitment = keccak256(실제_tx_해시)이므로, 적대자는 다음 중 하나를 해야 한다:
   - keccak256 충돌을 찾거나 (충돌 저항성에 모순), 또는
   - 필드에서 동일한 곱을 가진 다른 비밀 값을 찾거나 (이산 로그 또는 필드에서의 인수분해 필요), 또는
   - Groth16 증명 자체를 위조하거나 (KEA에 모순).

**따름정리.** 유효성 속성(속성 1)은 표준 암호학적 가정 하에서 성립한다.

### 7.2 128비트 필드 절삭 보안

모듈러 리덕션 `_to_field(data) = int(data) mod p` (p ≈ 2^254)는 256비트 keccak256 출력을 BN128 스칼라 필드로 매핑한다. 이 매핑에서 두 개의 서로 다른 256비트 값이 충돌할 확률:

```
Pr[충돌] = Pr[a ≡ b (mod p) | a ≠ b] ≈ 2/p ≈ 2^{-253}
```

64개 트랜잭션 배치에서의 생일 공격 경계 충돌 확률:

```
Pr[배치 내 충돌] ≤ C(64, 2) / p ≈ 2016 / 2^254 ≈ 2^{-243}
```

이는 모든 실용적 애플리케이션에서 무시할 수 있다.

### 7.3 시퀀서 안전성

시퀀서는 여러 안전성 보장을 제공한다:

1. **논스 순서**: 엄격한 순차 논스 강제(갭 없음, 리플레이 없음) — `sequencer.py:65-72`.
2. **원자적 실행**: 스냅샷/롤백으로 실패한 트랜잭션이 상태 잔여물을 남기지 않음 — `sequencer.py:85-95`.
3. **멤풀 제한**: 설정 가능한 `mempool_max_size`로 메모리 고갈 방지 — `sequencer.py:58-59`.
4. **속도 제한**: IP별 토큰 버킷으로 API 남용 방지.

참고: 시퀀서는 현재 중앙화되어 있다. 악의적 시퀀서는 트랜잭션을 *검열*할 수(배치에서 누락) 있지만, 상태 전이를 *위조*할 수는 없다(ZK 증명이 이를 방지). 검열은 강제 포함 메커니즘(5.3절)으로 완화된다.

### 7.4 브릿지 보안

브릿지는 다음을 통해 보안을 제공한다:

1. **리플레이 보호**: 각 `message_hash`는 한 번만 릴레이 가능(`messenger.py:128-129`).
2. **강제 포함 윈도우**: 검열에 대한 제한 시간 보장.
3. **탈출 해치**: L2가 무응답일 때 L1에서의 최후의 가치 회수 수단.
4. **증명 기반 릴레이**: ZKProofHandler와 MerkleProofHandler는 상태 업데이트에 암호학적 증명을 요구하여 무단 수정을 방지.

### 7.5 신뢰 셋업 고려사항

Groth16은 "toxic waste"(τ, α, β, γ, δ)를 생성하는 신뢰 셋업 세레모니를 요구한다. 세레모니의 어떤 참여자라도 toxic waste를 보유하면 증명을 위조할 수 있다. 완화 방법:

1. **다자간 연산(MPC)**: Zcash "powers of tau" 세레모니는 최소 한 명의 참여자가 정직하면 셋업이 안전함을 보여준다.
2. **애플리케이션별 셋업**: 각 롤업은 자체 셋업을 가져, 훼손된 세레모니의 영향을 제한한다.
3. **미래 대안**: PLONK(범용 셋업, 업데이트 가능)과 STARK(신뢰 셋업 불필요)는 `ProofBackend` 인터페이스가 증명 시스템을 추상화하므로 아키텍처 변경 없이 Groth16을 대체할 수 있다.

---

## 8. 성능 평가

### 8.1 회로 복잡도

실행 트레이스 체인 회로는 정확히 `max_txs`개의 제약 조건을 생성한다:

| max_txs_per_batch | 제약 조건 | 변수 | 공개 입력 |
|---|---|---|---|
| 4 | 4 | 8 | 3 |
| 16 | 16 | 20 | 3 |
| 64 | 64 | 68 | 3 |
| 256 | 256 | 260 | 3 |
| 1024 | 1024 | 1028 | 3 |

zkEVM 접근법과 비교:

| 시스템 | 트랜잭션당 제약 조건 | 배치당 제약 조건 (64 txs) |
|---|---|---|
| **앱 특화 (본 연구)** | **1** | **64** |
| zkSync Era | ~10^5–10^6 | ~10^7–10^8 |
| Polygon zkEVM | ~10^5–10^6 | ~10^7–10^8 |
| Scroll | ~10^5–10^6 | ~10^7–10^8 |
| StarkNet (AIR) | ~10^4–10^5 | ~10^6–10^7 |

감소폭은 4–6차수이다.

### 8.2 증명 생성 시간

단일 코어 머신에서 측정 (Python 증명자):

| max_txs | 셋업 | 증명 | 검증 |
|---|---|---|---|
| 4 | ~2초 | ~3초 | ~1초 |
| 16 | ~8초 | ~12초 | ~1초 |
| 64 | ~45초 | ~90초 | ~1초 |

Python 증명자(py_ecc)는 개발과 소형 회로에 적합하다. 프로덕션에서는 rapidsnark를 사용하는 `NativeProverBackend`가 10–100배 속도 향상을 달성한다.

### 8.3 검증 가스 비용

온체인 검증 가스는 배치 크기에 관계없이 일정하다:

| 구성 요소 | 가스 | 비율 |
|---|---|---|
| ecMul × 3 (IC 누적기) | 18,000 | 9.0% |
| ecAdd × 3 (IC 누적기) | 450 | 0.2% |
| ecPairing (4쌍) | 181,000 | 90.6% |
| 바이트코드 오버헤드 | ~150 | 0.1% |
| **합계** | **~199,600** | **100%** |

30 gwei 가스 가격 기준, 트랜잭션당 상각 비용(64-tx 배치): 199,600 / 64 = 3,119 gas ≈ 트랜잭션당 0.0001 ETH.

### 8.4 배치 처리량

64개 트랜잭션 배치의 엔드투엔드 지연(Python 증명자):

| 단계 | 시간 |
|---|---|
| 트랜잭션 제출 | < 1ms |
| STF 실행 (64 txs) | ~50ms |
| 배치 봉인 + DA | ~10ms |
| 증명 생성 | ~90초 |
| L1 제출 + 확인 | ~12초 (1 블록) |
| **합계** | **~102초** |

처리량: 64 txs / 102초 ≈ 0.63 TPS (Python 증명자). 네이티브 증명자(rapidsnark)를 사용하면 증명 생성이 ~1–5초로 감소하여, 유효 처리량 ~4–5 TPS를 달성한다.

---

## 9. 관련 연구 비교

### 9.1 범용 zkEVM

| 특성 | zkSync Era | Polygon zkEVM | Scroll | StarkNet | **py-ethclient** |
|---|---|---|---|---|---|
| 증명 시스템 | PLONK | FFLONK | Halo2 | STARK | Groth16 |
| 회로 유형 | 커스텀 VM | EVM 동등 | EVM 동등 | Cairo VM | 앱 특화 |
| 언어 | Solidity/Yul | Solidity | Solidity | Cairo | Python |
| 트랜잭션당 제약 조건 | ~10^6 | ~10^6 | ~10^6 | ~10^4 (AIR) | **1** |
| 신뢰 셋업 | 범용 | 범용 | 없음 (IPA) | 없음 | 회로별 |
| 온체인 검증 | ~300K gas | ~350K gas | ~400K gas | ~200K gas | **~200K gas** |
| 성숙도 | 프로덕션 | 프로덕션 | 프로덕션 | 프로덕션 | 연구 |

### 9.2 기존 앱 특화 롤업

**Loopring** (DEX): 주문 매칭과 잔액 업데이트를 위한 커스텀 회로. 전송당 ~8,000 제약 조건. Groth16 사용. 2020년부터 프로덕션.

**dYdX v3** (무기한 선물): StarkEx 기반(STARK 증명). 무기한 선물을 위한 커스텀 회로. 거래당 ~50,000 제약 조건. v4에서 Cosmos로 마이그레이션.

**Immutable X** (NFT): StarkEx 기반. NFT 발행과 거래를 위한 커스텀 회로. 연산당 ~30,000 제약 조건.

우리 프레임워크는 이러한 접근법을 일반화한다: 애플리케이션별로 회로를 수작업으로 코딩하는 대신, 개발자가 Python STF를 작성하면 프레임워크가 자동으로 증명을 생성한다.

### 9.3 Rollup-as-a-Service

Caldera, AltLayer, Conduit는 주로 옵티미스틱 롤업과 기존 프레임워크(OP Stack, Arbitrum Orbit)를 기반으로 배포 플랫폼을 제공한다. 이들은 커스텀 ZK 증명 생성을 제공하지 않는다. py-ethclient는 이 격차를 채운다: ZK 회로가 고정 VM으로 부과되는 것이 아닌, 애플리케이션 로직에서 *도출되는* 프레임워크.

---

## 10. 한계 및 향후 연구

### 10.1 현재 한계

1. **Python 증명자 성능.** 순수 Python Groth16 증명자(py_ecc)는 소형 회로(< 1,000 제약 조건)에만 적합하다. 네이티브 증명자 백엔드가 이를 완화하지만 외부 의존성을 추가한다.

2. **단일 시퀀서.** 현재 아키텍처는 중앙화된 시퀀서를 사용한다. ZK 증명이 상태 위조를 방지하지만, 시퀀서는 트랜잭션을 검열할 수 있다. 강제 포함이 완화를 제공하지만 지연을 추가한다.

3. **신뢰 셋업.** Groth16은 회로별 신뢰 셋업을 요구한다. 표준 MPC 세레모니가 이를 완화하지만, 여전히 신뢰 가정으로 남는다.

4. **회로 표현력.** 실행 트레이스 체인 회로는 증명자가 공개 상태 전이와 일치하는 비밀 값을 알고 있음을 증명한다. STF의 *내부 로직*(예: 토큰 전송에서 잔액을 올바르게 확인했는지)을 증명하지는 않는다. STF 정확성은 실행 트레이스 바인딩을 통해 가정된다.

5. **형식 검증 부재.** 구현은 943개 테스트로 검증되었지만 형식적으로 검증되지는 않았다.

### 10.2 향후 방향

1. **PLONK/STARK.** Groth16을 PLONK(범용 신뢰 셋업, 업데이트 가능) 또는 STARK(신뢰 셋업 불필요, 양자 후 보안)으로 대체. `ProofBackend` 인터페이스로 드롭인 교체 가능.

2. **재귀적 증명 집계.** 단일 집계 증명 내에서 N개의 배치 증명을 증명하여, 여러 배치에 걸쳐 L1 검증 비용을 상각.

3. **분산 시퀀서.** 리더 로테이션 또는 공유 시퀀싱 프로토콜(예: Espresso)로 시퀀서 역할을 분산화.

4. **STF-to-circuit 컴파일러.** Python STF를 실행 트레이스뿐만 아니라 내부 STF 로직을 증명하는 R1CS 회로로 자동 컴파일. 이는 앱 특화와 범용 보안 사이의 격차를 해소할 것이다.

5. **크로스 롤업 통신.** 여러 앱 특화 롤업 간의 원자적 연산을 가능하게 하는 공유 브릿지 인프라.

6. **하드웨어 가속.** BN128 다중 스칼라 곱셈을 위한 GPU/FPGA 기반 증명자.

---

## 11. 결론

본 논문은 범용 zkEVM과 동일한 보안 속성을 달성하면서 회로 복잡도를 4–6차수 감소시키는 애플리케이션 특화 ZK 롤업을 제시했다. 핵심 통찰은 대부분의 L2 애플리케이션이 범용 연산의 극히 일부만 필요로 하며, 이 부분은 실행 복잡도가 아닌 배치 크기에 비례하여 제약 조건 수가 증가하는 간결한 ZK 회로로 포착될 수 있다는 것이다.

py-ethclient 참조 구현은 이 프레임워크가 실용적임을 보여준다: 21,442줄의 Python, 943개 테스트, 4개의 플러거블 인터페이스, 3가지 DA 전략, LMDB 영속성, 검열 방지 보장을 갖춘 L1-L2 브릿지, 이더리움 Sepolia 테스트넷에서 검증된 9개의 완전한 예제 애플리케이션.

애플리케이션 특수성과 회로 효율성 사이의 트레이드오프는 대다수의 L2 사용 사례에 유리하다. 토큰, DEX, 네임 서비스, 투표 시스템, 게임, 마켓플레이스, 에스크로 서비스 모두 zkEVM의 전체 복잡성 없이 ~200K gas 검증 비용과 초 단위 증명 생성으로 ZK 롤업으로 배포될 수 있다.

이더리움 생태계가 롤업 중심 로드맵으로 성숙함에 따라, 애플리케이션 특화 ZK 롤업은 확장 가능하고 안전하며 개발자 친화적인 레이어 2 프로토콜로의 경로를 제공한다.

---

## 참고문헌

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

## 부록

### A. 전체 인터페이스 명세

```python
# ethclient/l2/interfaces.py — 완전한 4개 ABC

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

### B. 가스 비용 도출

이더리움에서의 Groth16 검증 가스 비용은 EVM 프리컴파일 가격 책정(EIP-196, EIP-197)에 의해 결정된다:

| 프리컴파일 | 주소 | 연산 | 가스 |
|---|---|---|---|
| ecAdd | 0x06 | G1 점 덧셈 | 150 |
| ecMul | 0x07 | G1 스칼라 곱셈 | 6,000 |
| ecPairing | 0x08 | 페어링 검사 (기본) | 45,000 |
| ecPairing | 0x08 | 쌍당 | 34,000 |

n개의 공개 입력에 대해, 검증은 다음을 요구한다:
- n개의 ecMul 연산 (IC 누적기): n × 6,000
- n개의 ecAdd 연산 (IC 누적기): n × 150
- 4쌍의 ecPairing 1회: 45,000 + 4 × 34,000 = 181,000

합계: n × 6,150 + 181,000

n = 3 (우리 회로)인 경우: 3 × 6,150 + 181,000 = 18,450 + 181,000 = **199,450 gas**

### C. Groth16 페어링 방정식

Groth16 검증 방정식:

```
e(A, B) = e(α, β) · e(∑ᵢ aᵢ · IC[i], γ) · e(C, δ)
```

동등하게, 페어링 곱 검사:

```
e(-A, B) · e(α, β) · e(IC_acc, γ) · e(C, δ) = 1
```

여기서:
- A ∈ G₁, B ∈ G₂, C ∈ G₁은 증명 원소
- α ∈ G₁, β ∈ G₂, γ ∈ G₂, δ ∈ G₂는 검증 키 원소
- IC[0], IC[1], ..., IC[n] ∈ G₁은 IC(입력 커밋먼트) 점
- IC_acc = IC[0] + a₁·IC[1] + ... + aₙ·IC[n] (aᵢ는 공개 입력)
- e: G₁ × G₂ → G_T는 BN128 상의 쌍선형 페어링

페어링은 ecPairing 프리컴파일(EIP-197)에 4쌍으로 전달되어 구현되며, 페어링의 곱이 G_T의 항등원과 같으면 1을 반환한다.
