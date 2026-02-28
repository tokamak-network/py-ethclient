# Application-Specific ZK Rollups: 아키텍처, 구현, 분석

**도메인 특화 레이어 2 프로토콜을 위한 Python 네이티브 프레임워크**

저자: Tokamak Network
날짜: 2026

---

## 초록

ZK 롤업 구축의 지배적 접근법인 zkEVM은 모든 EVM 옵코드를 영지식 회로 내에서 재실행하여, 제약 조건 수가 O(실행_복잡도)로 증가하는 증명을 생성한다. 스토리지 읽기, 해싱, 산술 연산에 걸쳐 140개 이상의 옵코드를 사용하는 일반적인 Uniswap 스왑의 경우, 이는 트랜잭션당 수백만 개의 R1CS 제약 조건으로 이어진다. 그러나 대다수의 레이어 2 애플리케이션 — 토큰, DEX, 네임 서비스, 투표, 게임 — 은 범용 연산의 극히 일부만 필요로 한다. 이들은 전체 EVM을 영지식 하에서 재실행할 필요가 없다.

본 논문은 *애플리케이션 특화 ZK 롤업*을 소개한다. 이 프레임워크에서 개발자는 도메인 로직만을 포착하는 일반 프로그래밍 언어의 상태 전이 함수(STF)를 작성하고, 롤업 인프라가 자동으로 O(실행_복잡도)가 아닌 O(배치_크기)로 제약 조건 수가 증가하는 간결한 ZK 회로를 도출한다. 이 접근법이 범용 zkEVM과 동일한 보안 속성 — 유효성, 데이터 가용성, 검열 저항성, 자산 안전성 — 을 달성함을 증명한다.

참조 구현인 py-ethclient는 88개 모듈에 걸친 21,884줄의 Python 소스 코드로 구성되며, 41개 테스트 파일의 987개 단위 테스트로 검증되었다. 이 프레임워크는 4개의 플러거블 추상 인터페이스(StateTransitionFunction, DAProvider, ProofBackend, L1Backend), BN128 상의 Groth16 증명 시스템과 EVM 온체인 검증, ~240개 제약 조건의 R1CS 회로 인코딩을 갖춘 ZK 친화적 Poseidon 해시 함수, 3가지 데이터 가용성 전략(로컬, calldata, EIP-4844 blob), 크래시 복구를 지원하는 LMDB 기반 영속 상태, 강제 포함과 탈출 해치를 갖춘 L1-L2 브릿지, 미들웨어를 포함한 프로덕션급 RPC 서버를 제공한다. 이더리움 Sepolia 테스트넷에서 배포 및 검증된 9개의 완전한 예제 애플리케이션으로 프레임워크를 시연한다.

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
    - [A. 전체 인터페이스 명세](#a-전체-인터페이스-명세)
    - [B. 가스 비용 도출](#b-가스-비용-도출)
    - [C. Groth16 페어링 방정식](#c-groth16-페어링-방정식)
    - [D. 설계 FAQ](#d-설계-faq)
    - [E. 아키텍처 구성 트리](#e-아키텍처-구성-트리)

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

2. **참조 구현.** py-ethclient는 Python으로 된 완전한 작동 구현을 제공한다: 88개 모듈에 걸친 21,884줄의 소스 코드, 41개 테스트 파일의 987개 단위 테스트, BN128 상의 Groth16, EVM 온체인 검증, 회로 인코딩을 갖춘 ZK 친화적 Poseidon 해시, 3가지 DA 전략, LMDB 영속성, L1-L2 브릿지.

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

**Pre-state / Post-state 추적에 관한 참고.** Sequencer는 `_pre_batch_root` 필드(`sequencer.py:36`)를 생성 시 초기화하고 각 봉인 후 갱신한다. `_seal_batch()` (`sequencer.py:116–140`) 실행 시 old root는 `_pre_batch_root`에서 읽고, new root는 `compute_state_root()`로 현재 상태에서 계산한다. 이로써 체인 불변식이 유지된다: `Batch[k].new_state_root == Batch[k+1].old_state_root`. 중요한 점은, state root는 스냅샷이 아니라 현재 dict 기반 상태에서 Merkle-Patricia Trie를 새로 구축하여 온디맨드로 계산된다(`state.py:28–35`).

> 트랜잭션별 Merkle proof, nullifier 모델 등 pre/post-state 추적이 다르게 작동하는 대안 증명 아키텍처에 대해서는 부록 D, FAQ 3–4를 참조하라.

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

Rollup 생성자는 이 필드를 읽고 적절한 백엔드를 자동으로 인스턴스화한다. 4개의 플러거블 인터페이스(STF, DA, ProofBackend, L1Backend)는 조합하여 다양한 아키텍처를 구성할 수 있다 — 신뢰 기반 시퀀서 개발 환경부터 완전한 trustless 클라이언트 사이드 증명 시스템까지. 부록 E에서 모든 의미 있는 조합과 보안 모델을 열거하는 전체 구성 트리를 제공한다.

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

시퀀서가 정직하게 작동할 때 여러 안전성 보장을 제공한다:

1. **논스 순서**: 엄격한 순차 논스 강제(갭 없음, 리플레이 없음) — `sequencer.py:65-72`.
2. **원자적 실행**: 스냅샷/롤백으로 실패한 트랜잭션이 상태 잔여물을 남기지 않음 — `sequencer.py:85-95`.
3. **멤풀 제한**: 설정 가능한 `mempool_max_size`로 메모리 고갈 방지 — `sequencer.py:58-59`.
4. **속도 제한**: IP별 토큰 버킷으로 API 남용 방지.

참고: 시퀀서는 현재 중앙화되어 있다. 검열(배치에서 트랜잭션 누락)은 강제 포함 메커니즘(5.3절)으로 완화된다.

### 7.3.1 악의적 시퀀서 분석: 회로가 보호하는 것과 보호하지 않는 것

**증명 위조**와 **STF 조작** 사이에 결정적인 구분이 필요하다. 실행 트레이스 체인 회로는 전자를 방지하지만 후자를 방지하지 않는다.

**회로가 강제하는 것:**

```
old_root × ∏ᵢ private_i ≡ new_root × tx_commitment  (mod p)
```

이는 *"증명자가 이 세 공개 입력을 대수적으로 연결하는 비밀 값을 안다"*는 것을 증명한다. Groth16 건전성(KEA)과 keccak256 충돌 저항성 하에서, 어떤 적대자도 대응하는 비밀 값을 모르고는 주어진 공개 입력에 대한 유효한 증명을 생성할 수 없다.

**회로가 강제하지 않는 것:**

- `apply_tx(state, tx)`가 올바르게 실행되었는지 여부
- 실패한 트랜잭션이 배치에서 제외되었는지 여부
- 잔액 검사, 접근 제어, 또는 기타 STF 로직이 준수되었는지 여부
- `new_state_root`가 `old_state_root`에 STF를 정직하게 적용한 결과인지 여부

**공격 시나리오 1 — 실패한 트랜잭션 포함:**

악의적 시퀀서가 실패한 트랜잭션에 대한 롤백(`sequencer.py:94-95`)을 건너뛰어, 잘못된 상태 효과와 함께 배치에 포함시킨다. 결과 `new_state_root`는 손상된 상태를 반영하지만, 회로는 `old_root`, `new_root`, `tx_commitment` 사이의 대수적 관계만 검사하므로 증명은 수학적으로 유효하다. L1 검증자는 이를 수용한다.

**공격 시나리오 2 — STF 조작:**

악의적 시퀀서가 STF를 다른 함수로 교체하고(예: 잔액 검사를 건너뛰거나 공격자에게 토큰을 발행), 결과 `new_state_root`를 계산하여 `(old_root, evil_new_root, tx_commitment)` 트리플에 대한 유효한 증명을 생성한다. 해당 공개 입력에 대해 증명이 수학적으로 유효하므로 L1 검증자는 이를 수용한다.

**현재 아키텍처에서 이러한 공격을 방어하는 것:**

| 방어 계층 | 메커니즘 | 신뢰 모델 |
|---|---|---|
| Groth16 증명 | 고정된 공개 입력에 대한 증명 위조 방지 | Trustless (수학적) |
| 데이터 가용성 | L1의 tx 데이터(calldata/blob)로 누구나 재실행 가능 | DA 가정 |
| 오프체인 재실행 | 검증자가 DA 데이터로 STF를 재실행하여 `new_root` 비교 | 1-of-N 정직한 검증자 |
| 사회적 합의 | 커뮤니티가 불일치를 감지하고 대응 | 거버넌스 |

STF 조작에 대한 감지 흐름:

```
1. DA에서 tx 데이터 획득 (calldata/blob — 공개적으로 이용 가능)
2. old_root부터 STF를 통해 tx들을 재실행
3. 계산된 new_root'와 배치의 new_root 비교
4. 불일치 → 시퀀서 조작 감지
```

이는 사실상 **옵티미스틱 검증 모델**이다: ZK 증명은 실행 트레이스 바인딩을 보장하지만, STF 정확성은 오프체인 재실행과 데이터 가용성에 의존한다. 10.2절은 이 격차를 해소하는 세 가지 접근법을 제시하며, 모두 현재 4-인터페이스 프레임워크 내에서 구현 가능하다.

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

이하의 한계는 심각도와 도메인별로 정리된다. 이는 참조 구현의 정직한 엔지니어링 제약을 나타내며, 애플리케이션 특화 ZK 롤업 패러다임 자체의 근본적 결함이 아니다.

#### 10.1.1 보안 및 암호학적 한계

1. **필드 리덕션으로 인한 상태 루트 충돌.** `_to_field()` 함수는 256비트 keccak256 출력을 BN128 스칼라 필드 p ≈ 2^254로 모듈러 리덕션한다(`prover.py:30-33`). 충돌 확률은 무시할 수 있는 수준이지만(64-tx 배치에서 ~2^{-243}, 7.2절), 매핑이 단사가 아니다: [p, 2^256) 범위의 값이 [0, 2^256 - p)로 별칭된다. BN128 필드 내에서 네이티브로 동작하는 Poseidon 해시는 `hash_function: "poseidon"`으로 계산되는 상태 루트에서 이 문제를 완전히 제거한다.

2. **회로 표현력 (STF 무결성 격차).** 실행 트레이스 체인 회로는 증명자가 공개 상태 전이와 일치하는 비밀 값을 알고 있음을 증명한다. STF의 *내부 로직*(예: 토큰 전송에서 잔액을 올바르게 확인했는지)을 증명하지는 않는다. STF 정확성은 실행 트레이스 바인딩을 통해 가정된다. 이는 가장 중요한 보안 한계이며 10.2.1절에서 상세히 다룬다.

#### 10.1.2 증명 시스템 및 ZK 툴킷 한계

3. **Python 증명자 성능.** 순수 Python Groth16 증명자(py_ecc)는 소형 회로(< 1,000 제약 조건)에만 적합하다. `NativeProverBackend`가 subprocess 기반 rapidsnark/snarkjs를 통해 이를 완화하지만, 외부 의존성과 플랫폼별 빌드 요구사항을 추가한다.

4. **신뢰 셋업.** Groth16은 회로별 신뢰 셋업을 요구한다. 표준 MPC 세레모니가 toxic waste 위험을 완화하지만, 여전히 신뢰 가정으로 남는다. `ProofBackend` 인터페이스는 PLONK(범용 셋업) 또는 STARK(셋업 불필요)으로의 향후 마이그레이션을 가능하게 한다.

5. **배치 검증 부재.** 각 Groth16 증명은 독립적으로 검증된다. 배치 검증(무작위 선형 결합을 통해 N개 증명을 개별 검증보다 빠르게 검증)이 구현되어 있지 않아, N개 배치에 대한 L1 가스 비용이 O(N)으로 남는다.

6. **단일 인자 Poseidon.** Poseidon 해시 구현은 t=3(2-to-1 해싱)만 지원한다. 이진 Merkle 트리에는 충분하지만, 더 넓은 fan-out을 요구하는 애플리케이션(예: t=5, t=9)은 추가 파라미터 셋이 필요하다. 회로 인코딩도 t=3(~240 제약 조건)으로 고정되어 있다.

7. **MSM 성능 병목.** `groth16.py`의 다중 스칼라 곱셈(MSM)은 나이브 루프(`sum(multiply(g, s) for g, s in zip(bases, scalars))`)를 사용한다. Pippenger 알고리즘은 O(N·log(N))에서 O(N/log(N)) 그룹 연산으로 점근적 개선을 제공할 것이다.

8. **재귀적 증명 합성 부재.** 증명자가 이전에 생성된 증명에 대한 명제를 증명할 수 없다. 재귀적 SNARK는 증명 집계(N개 배치 증명을 단일 집계 증명으로 증명)와 점진적 검증 가능 연산을 가능하게 할 것이다.

#### 10.1.3 시퀀서 및 트랜잭션 처리 한계

9. **단일 시퀀서.** 현재 아키텍처는 중앙화된 시퀀서를 사용한다. ZK 증명이 상태 위조를 방지하지만, 시퀀서는 트랜잭션을 검열할 수 있다. 강제 포함이 완화를 제공하지만 지연을 추가한다.

10. **스냅샷/롤백 경쟁 조건.** 시퀀서의 `_execute_single_tx` 메서드는 동기화 프리미티브 없이 스냅샷, 실행, 조건부 롤백을 수행한다(`sequencer.py:85-95`). 동시성 환경(예: 비동기 RPC 핸들러)에서 인터리브된 실행이 상태를 손상시킬 수 있다.

11. **시퀀서 생존성 모니터링 부재.** 워치독, 하트비트, 또는 자동 장애 전환 메커니즘이 없다. 시퀀서 프로세스가 중단되면 수동 개입까지 새 배치가 생성되지 않는다.

#### 10.1.4 상태 관리 한계

12. **O(N) 상태 루트 재계산.** `L2StateStore.compute_state_root()`는 매 호출 시 모든 키-값 쌍을 순회하여 새로운 Merkle 트라이를 구축한다(`state.py:30-40`). 상태 크기가 ~10K 엔트리를 초과하면 상당한 병목이 된다. 점진적(영속적) 트라이 업데이트는 상태 변경당 O(log N)으로 감소시킬 것이다.

13. **LMDB 맵 크기 제한.** `L2PersistentStateStore`는 런타임에 동적으로 리사이즈할 수 없는 고정 `map_size`(기본 1 GB)를 사용한다(`persistent_state.py:45`). 소진되면 `MDB_MAP_FULL`로 상태 저장소가 실패한다. 장기 운영 롤업을 위해 지수적 성장의 동적 리사이징이 필요하다.

14. **상태 프루닝 또는 아카이빙 부재.** 모든 이력 상태가 무기한 유지된다. 확정된 상태를 프루닝하거나, 오래된 배치를 아카이빙하거나, 상태 만료를 구현하는 메커니즘이 없어 무한한 스토리지 성장이 발생한다.

15. **WAL 리플레이 불완전.** Write-Ahead Log는 상태 변경과 배치 레코드를 다루지만, 증명 결과나 논스 체크포인트는 포착하지 않는다(`persistent_state.py:180-220`). 증명 생성과 증명 영속화 사이의 크래시는 증명을 손실시켜 비용이 큰 재계산이 필요하다.

#### 10.1.5 데이터 가용성 한계

16. **DA 실패 복구 부재.** `da_provider.submit_batch()`가 실패하면, `BatchSubmitter`는 예외를 발생시키지만 재시도 로직, 데드 레터 큐잉, 또는 대체 DA 레이어로의 폴백을 구현하지 않는다(`submitter.py:35-55`).

17. **Blob 만료 윈도우.** EIP-4844 blob은 ~18일 동안만 이용 가능하다. `BlobDAProvider`는 blob 아카이빙이나 영구 스토리지로의 마이그레이션을 구현하지 않는다. 만료 후 배치 데이터가 복구 불가능해져, 이력 상태 전이 검증 능력이 침해된다.

18. **DA 커밋먼트 검증 부재.** `CalldataDAProvider`와 `BlobDAProvider`는 조회 시 DA 커밋먼트가 제출된 데이터와 일치하는지 검증하지 않는다. 손상되거나 악의적인 DA 레이어가 변조된 배치 데이터를 제공할 수 있다.

#### 10.1.6 브릿지 한계

19. **분쟁 메커니즘 부재.** 브릿지는 증명 검증만으로 릴레이된 메시지를 수락한다. 이의 있는 상태 전이에 대한 챌린지 윈도우나 분쟁 해결 프로토콜이 없다.

20. **L1 최종성 인식 부재.** `EthL1Backend`는 트랜잭션을 제출하고 영수증을 확인하지만 최종성(예: 이더리움 PoS에서 2 에포크)을 대기하지 않는다. 배치 제출 후 L1 리오그가 온체인 상태를 무효화할 수 있으나, L2는 확정되었다고 가정한 배치 위에 계속 빌드한다.

#### 10.1.7 운영 및 인프라 한계

21. **정상 종료 부재.** RPC 서버, 시퀀서, 서밋터에 정상 종료를 위한 SIGTERM/SIGINT 핸들러가 없다. 갑작스런 종료는 처리 중인 배치를 불일치 상태로 남길 수 있다.

22. **속도 제한기 스레드 안전성.** `RateLimitMiddleware`는 잠금 없이 일반 `dict`를 IP별 토큰 버킷에 사용한다(`middleware.py:45-60`). 동시 비동기 요청(FastAPI 기본) 하에서 경쟁 조건이 설정된 제한을 초과하는 버스트 트래픽을 허용할 수 있다.

23. **구성 검증 격차.** `RollupConfig`는 검증 없이 필드 값을 수용한다(`config.py`). 잘못된 조합(예: `max_txs_per_batch: 0`, 알 수 없는 `hash_function` 값, 음수 `batch_timeout`)이 생성 시 포착되지 않아 불명확한 런타임 실패를 유발할 수 있다.

24. **형식 검증 부재.** 구현은 987개 단위 테스트로 검증되었지만 형식적으로 검증되지는 않았다. 핵심 컴포넌트(Groth16 검증자, EVM 검증자 바이트코드 생성, 필드 산술)는 기계 검증된 정확성 증명이 도움이 될 것이다.

#### 10.1.8 STF 구현 고려사항

이하 항목들은 프레임워크의 한계가 아니라 특정 STF 구현에 따라 달라지는 사항이다. 서로 다른 애플리케이션 도메인은 서로 다른 솔루션을 필요로 할 수 있으며, 프레임워크는 의도적으로 이러한 결정을 STF 개발자에게 맡긴다.

25. **트랜잭션 인증.** 프레임워크는 특정 서명 스킴을 강제하지 않는다. STF 개발자는 `validate_tx()`에서 서명 검증을 구현해야 한다 — 이더리움 호환 앱은 ECDSA, ZK 친화적 앱은 EdDSA, 프라이버시 보존 앱은 ZK 증명을 사용한다.

26. **리플레이 보호.** 세션 내 논스 추적은 시퀀서가 제공하지만, 재시작 간 리플레이 보호는 STF의 상태 모델에 의존한다. LMDB 영속성을 사용하는 STF는 자동 논스 복구를 받으며, 그 외의 경우 애플리케이션 수준의 nullifier 또는 시퀀스 번호를 구현해야 한다.

27. **MEV 및 트랜잭션 순서.** 중앙화된 시퀀서가 순서를 결정한다. 순서에 민감한 STF(DEX, 경매)는 STF 로직 내에 커밋-리빌 스킴 또는 배치 경매 메커니즘을 구현해야 한다.

28. **트랜잭션 만료.** 트랜잭션이 만료되어야 하는지는 애플리케이션 도메인에 따라 달라진다. 시간에 민감한 STF(경매, 옵션)는 `validate_tx()`에서 TTL 체크를 구현해야 한다.

29. **우선순위 수수료 및 순서 정책.** FIFO 순서가 모든 애플리케이션에 최적이 아닐 수 있다. 경제적 순서가 필요한 STF는 트랜잭션 포맷에 수수료 필드를 구현하고 `validate_tx()`에서 정렬해야 한다.

30. **토큰 브릿징 표준.** 브릿지는 원시 메시지 릴레이를 제공한다. 토큰 컨트랙트를 구현하는 STF는 `CrossDomainMessenger` API 위에 잠금/발행/소각/잠금 해제 흐름을 구축해야 한다.

31. **메시지 순서 보장.** 브릿지 메시지는 개별적으로 릴레이된다. 인과적 메시지 종속성이 있는 STF는 상태 모델에 시퀀스 번호 또는 종속성 추적을 구현해야 한다.

### 10.2 향후 방향

#### 10.2.1 STF 무결성 격차 해소

현재 아키텍처의 가장 중요한 한계는 ZK 회로가 실행 트레이스 바인딩을 증명하지만 STF 정확성은 증명하지 않는다는 것이다(7.3.1절). 세 가지 접근법이 이 격차를 해소하며, 결정적으로 **세 가지 모두 현재 4-ABC 프레임워크 내에서 구현체 교체만으로 구현 가능하다** — 인터페이스 변경이 필요 없다.

| 접근법 | 교체되는 인터페이스 | STF 무결성 | 신뢰 모델 |
|---|---|---|---|
| STF-to-Circuit 컴파일러 | `ProofBackend` | 회로로 강제 | Trustless |
| Fraud Proof 하이브리드 | `L1Backend` | 재실행 + 챌린지 | 1-of-N 정직한 챌린저 |
| 트랜잭션별 Merkle 증명 | `StateTransitionFunction` | 클라이언트가 증명 | Trustless |

**접근법 1: STF-to-Circuit 컴파일러** — `ProofBackend` 교체.

STF 코드는 동일하게 유지된다. 새로운 `ProofBackend` 구현이 `setup()` 시 STF의 로직을 R1CS 제약 조건으로 컴파일하여, 회로가 실행 트레이스 바인딩뿐만 아니라 각 상태 전이의 내부 정확성(예: 잔액 검사, 접근 제어)을 증명한다.

```python
class CircuitCompilerProofBackend(ProofBackend):
    def setup(self, stf, max_txs_per_batch):
        # STF 로직을 회로 제약 조건으로 컴파일:
        #   "balance >= amount" → R1CS 비교 제약 조건
        #   "state[key] -= amount" → Merkle 갱신 회로
        self._circuit = self._compile_stf_to_circuit(stf, max_txs_per_batch)
        self._pk, self._vk = groth16.setup(self._circuit)

    def prove(self, old_root, new_root, txs, tx_commitment):
        # witness에 Merkle 경로 + 중간 상태 값 포함
        ...
        return groth16.prove(self._pk, private, public, self._circuit)
```

사용법 — prover 인자만 변경:

```python
rollup = Rollup(stf=token_stf, prover=CircuitCompilerProofBackend())
```

`setup(stf, max_txs_per_batch)` 시그니처가 이미 STF를 받으므로 백엔드가 STF를 분석할 수 있다. 실용적 구현은 STF를 제한된 DSL로 작성하거나 symbolic tracing으로 연산 그래프를 추출하는 것을 필요로 하지만, ABC 계약은 변경되지 않는다.

**접근법 2: Fraud Proof 하이브리드** — `L1Backend` 교체.

STF와 ProofBackend는 동일하게 유지된다. 새로운 `L1Backend`가 챌린지 윈도우를 추가한다: 배치는 ZK 증명 검증 후 잠정적으로 수용되며, 어떤 당사자든 윈도우 내에 DA 데이터로 STF를 재실행하여 챌린지할 수 있다.

```python
class FraudProofL1Backend(L1Backend):
    def submit_batch(self, batch_number, old_root, new_root,
                     proof, tx_commitment, da_commitment=b""):
        # 1. ZK 증명 검증 (실행 트레이스 바인딩)
        valid = groth16.verify(self._vk, proof, [...])
        if not valid:
            return reject
        # 2. 배치를 "pending" 상태로 등록 (즉시 확정 안 함)
        self._pending[batch_number] = {
            "new_root": new_root, "submitted_at": time.time()}
        return l1_tx_hash

    def challenge_batch(self, batch_number, stf, da_provider):
        """누구나 호출 가능 — DA 데이터로 STF 재실행"""
        batch = Batch.decode(da_provider.retrieve_batch(batch_number))
        state = load_state(self._pending[batch_number]["old_root"])
        for tx in batch.transactions:
            stf.apply_tx(state, tx)  # 동일한 STF ABC
        if compute_root(state) != self._pending[batch_number]["new_root"]:
            slash_sequencer()        # fraud 증명됨
            return "fraud detected"

    def is_batch_verified(self, batch_number):
        p = self._pending.get(batch_number)
        if not p or p.get("challenged"):
            return False
        return time.time() - p["submitted_at"] >= CHALLENGE_WINDOW
```

STF는 두 맥락에서 사용된다 — 정상 실행 중 시퀀서에 의해, 그리고 fraud 감지 중 챌린저에 의해 — 동일한 `apply_tx()` 인터페이스를 통해.

**접근법 3: 트랜잭션별 Merkle 증명** — `StateTransitionFunction` 교체.

ProofBackend와 L1Backend는 동일하게 유지된다(또는 ProofBackend를 선택적으로 재귀적 집계기로 교체). 새로운 STF 구현이 도메인 로직을 직접 실행하는 대신 클라이언트가 생성한 ZK 증명을 검증한다. (전체 구현 상세는 부록 D, FAQ 3 참조.)

```python
class MerkleProofSTF(StateTransitionFunction):
    def validate_tx(self, state, tx):
        proof = tx.data["proof"]
        if not groth16_verify(self.vk, proof, tx.data["public_inputs"]):
            return "invalid proof"
        if tx.data["public_inputs"]["old_root"] != state["root"]:
            return "stale root"
        return None

    def apply_tx(self, state, tx):
        state["root"] = tx.data["public_inputs"]["new_root"]
        state.setdefault("nullifiers", {})[tx.data["nullifier"]] = True
        return STFResult(success=True)
```

세 가지 접근법에 걸친 핵심 통찰: **4개 ABC(`StateTransitionFunction`, `DAProvider`, `ProofBackend`, `L1Backend`) 중 어느 것도 수정이 필요 없다.** 보안 모델은 인터페이스 뒤의 구현체를 교체하여 업그레이드된다. 이는 pluggable 아키텍처를 검증한다: 동일한 프레임워크가 실행 트레이스 바인딩(현재), 완전한 회로 강제 STF 정확성(접근법 1), 옵티미스틱 검증(접근법 2), 클라이언트 사이드 증명(접근법 3)을 지원한다.

#### 10.2.2 기타 향후 방향

1. **PLONK/STARK.** Groth16을 PLONK(범용 신뢰 셋업, 업데이트 가능) 또는 STARK(신뢰 셋업 불필요, 양자 후 보안)으로 대체. `ProofBackend` 인터페이스로 드롭인 교체 가능.

2. **재귀적 증명 집계.** 단일 집계 증명 내에서 N개의 배치 증명을 증명하여, 여러 배치에 걸쳐 L1 검증 비용을 상각.

3. **분산 시퀀서.** 리더 로테이션 또는 공유 시퀀싱 프로토콜(예: Espresso)로 시퀀서 역할을 분산화하여 MEV 노출과 검열 위험을 해소(10.1.8절, 항목 27 및 10.1.3절, 항목 9).

4. **크로스 롤업 통신.** 여러 앱 특화 롤업 간의 원자적 연산을 가능하게 하는 공유 브릿지 인프라.

5. **하드웨어 가속.** BN128 다중 스칼라 곱셈을 위한 GPU/FPGA 기반 증명자, MSM 병목 해소(10.1.2절, 항목 7).

6. **트랜잭션 서명 검증.** 시퀀서 레이어에서 ECDSA 또는 EdDSA 서명 검증을 강제하여 발신자 인증 격차 해소(10.1.8절, 항목 25). 이는 미들웨어 또는 STF의 `validate_tx` 훅 내에서 구현 가능.

7. **L1 최종성 추적.** L1 블록 확인을 모니터링하고 충분한 최종성에 도달할 때까지(예: 이더리움 PoS에서 2 에포크) 배치 제출을 보류 상태로 처리. 마지막 확정 배치로의 자동 롤백과 함께 L1 리오그 감지 구현.

8. **점진적 상태 루트 계산.** O(N) 전체 트라이 재구축을 상태 변경당 O(log N)의 점진적 업데이트를 적용하는 영속적 Merkle 트라이로 대체. Poseidon 지원 `Trie(hash_fn=poseidon_bytes)`가 ZK 친화적 점진적 상태 루트의 기반을 제공.

9. **Groth16 증명 배치 검증.** 무작위 선형 결합 배치 검증을 구현하여, 추가 증명당 한계 검증 비용을 ~200K gas에서 ~20K gas로 감소.

10. **ERC-20/ERC-721 브릿지 통합.** `CrossDomainMessenger`에 토큰 표준 인식 잠금/발행/소각/잠금 해제 흐름을 구현하여, L1과 L2 간 표준 토큰 브릿징 지원.

11. **상태 프루닝 및 아카이빙.** 확정된 배치로 대체된 상태 엔트리를 폐기하는 최종성 기반 상태 프루닝과, EIP-4844 만료 윈도우 전에 영구 스토리지로의 blob 아카이빙 구현.

---

## 11. 결론

본 논문은 범용 zkEVM과 동일한 보안 속성을 달성하면서 회로 복잡도를 4–6차수 감소시키는 애플리케이션 특화 ZK 롤업을 제시했다. 핵심 통찰은 대부분의 L2 애플리케이션이 범용 연산의 극히 일부만 필요로 하며, 이 부분은 실행 복잡도가 아닌 배치 크기에 비례하여 제약 조건 수가 증가하는 간결한 ZK 회로로 포착될 수 있다는 것이다.

py-ethclient 참조 구현은 이 프레임워크가 실용적임을 보여준다: 88개 모듈에 걸친 21,884줄의 Python, 41개 테스트 파일의 987개 테스트, 4개의 플러거블 인터페이스, ~240개 제약 조건의 회로 인코딩을 갖춘 ZK 친화적 Poseidon 해시, 3가지 DA 전략, LMDB 영속성, 검열 방지 보장을 갖춘 L1-L2 브릿지, 이더리움 Sepolia 테스트넷에서 검증된 9개의 완전한 예제 애플리케이션. 10절은 보안, 증명 시스템, 시퀀서, 상태 관리, 데이터 가용성, 브릿지, 운영 도메인에 걸친 31개의 알려진 한계에 대한 포괄적 분석과 해결을 위한 구체적 경로를 제공한다.

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

[18] Tornado Cash. "Tornado Cash Privacy Solution." https://tornado.ws/audits/TornadoCash_whitepaper.pdf

[19] E. Ben-Sasson, A. Chiesa, C. Garman, M. Green, I. Miers, E. Tromer, M. Virza. "Zerocash: Decentralized Anonymous Payments from Bitcoin." IEEE S&P 2014. https://eprint.iacr.org/2014/349

[20] L. Grassi, D. Khovratovich, C. Rechberger, A. Roy, M. Schofnegger. "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems." USENIX Security 2021. https://eprint.iacr.org/2019/458

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

### D. 설계 FAQ

본 부록은 프레임워크의 설계 결정과 대안적 접근법에 대한 일반적인 아키텍처 질문을 다룬다.

#### FAQ 1: `validate_tx`는 ZK 증명과 관련이 있는가?

**아니다.** `validate_tx` (`interfaces.py:19–21`)는 **mempool 진입 전 애플리케이션 로직 유효성 검사 훅**이다. ZK 증명과는 아무런 관련이 없다.

Sequencer는 `sequencer.py:61`에서 트랜잭션이 mempool에 들어가기 *전에* `validate_tx`를 호출한다:

```
submit_tx() 호출 체인:
  → mempool 용량 검사                     (sequencer.py:58)
  → stf.validate_tx(state, tx)           (sequencer.py:61)  ← 앱 로직 검증
  → nonce 검증                            (sequencer.py:65-69)
  → mempool 삽입                          (sequencer.py:71)
```

이 훅은 도메인 특화 비즈니스 로직 검증을 위한 것이다. 예를 들어 Token STF는 "전송 금액이 0보다 큰가?" 또는 "발신자의 잔액이 충분한가?"를 검사할 수 있다. 기본 구현은 항상 `None`(유효)을 반환한다.

**ZK 증명은 완전히 다른 수준에서 작동한다** — 트랜잭션 단위가 아니라 *배치* 단위로 생성된다. Sequencer가 모든 트랜잭션을 실행하고 배치를 봉인한 후, `Groth16ProofBackend.prove()`가 배치 전체의 상태 전이를 포괄하는 단일 증명을 생성한다. 개별 트랜잭션에 대해 ZK 증명이 수행되지 않는다.

```
트랜잭션 수준:   validate_tx() → 앱 로직 검사 (ZK 없음)
배치 수준:       prove()       → Groth16 ZK 증명 (모든 tx 포괄)
```

#### FAQ 2: L2는 어떤 계정 시스템을 사용하는가?

**프로토콜 수준의 계정 시스템이 없다.** 프로토콜 레이어에서 고정된 Account 모델(nonce, balance, storageRoot, codeHash)을 강제하는 이더리움 L1과 달리, 본 프레임워크는 "계정"이라는 개념 전체를 사용자의 STF에 위임한다.

| 구성요소 | 구현 | 설명 |
|---|---|---|
| 상태 | `L2State(dict)` (`types.py:113`) | 순수 Python dict 서브클래스 |
| 주소 | `L2Tx.sender: bytes` (20 바이트) | 트랜잭션에 포함 |
| Nonce | `Sequencer._nonces` (`sequencer.py:65–69`) | Sequencer가 메모리에서 추적 |
| 잔액/데이터 | **전적으로 STF가 정의** | 프로토콜이 강제하지 않음 |

각 애플리케이션은 자체 상태 스키마를 정의한다:

```python
# Token STF: 잔액 맵
state["balances"][addr] = amount

# DEX STF: 잔액 맵 + 유동성 풀
state["balances"][addr] = amount
state["pools"][pair_id] = {"reserve_a": ..., "reserve_b": ...}

# Voting STF: 투표 기록
state["votes"][voter_addr] = candidate_id

# NameService STF: 이름→소유자 레지스트리
state["names"][name] = owner_addr
```

이것이 "애플리케이션 특화"의 핵심이다: 범용 zkEVM은 이더리움의 Account 모델을 회로 내에서 재현해야 하므로(Merkle Patricia Trie 갱신에 수백만 constraints 필요) 회로가 방대해진다. App-specific 롤업은 STF가 필요로 하는 상태만 순수 dict에 저장하므로 회로가 극적으로 간단해진다.

#### FAQ 3: 상태가 Merkle 트리이고 각 트랜잭션이 ZK 증명인 구조가 가능한가?

**가능하다.** 이는 *트랜잭션별 클라이언트 사이드 증명*이라는 잘 알려진 대안 아키텍처이며, Tornado Cash [18], Zcash [19], Loopring [12] 등의 프로토콜이 사용한다.

**현재 아키텍처 (배치 수준 증명):**

```
상태   = Python dict → keccak256 → state_root
Tx     = 평문 데이터 (sender, op, amount)
증명   = 배치 단위 (old_root × ∏tx ≡ new_root × commitment 증명)
증명자 = 서버 사이드 (Prover 노드)
```

**대안 아키텍처 (트랜잭션별 Merkle 증명):**

```
상태   = Merkle 트리 (각 leaf = 계정/데이터 항목)
Tx     = ZK 증명 (유효한 Merkle 경로 + 상태 전이 + 권한 증명)
증명   = 트랜잭션 단위 (클라이언트가 제출 전 증명 생성)
증명자 = 클라이언트 사이드 (사용자의 기기)
```

트랜잭션별 모델에서 각 트랜잭션은 다음을 입증하는 ZK 증명을 포함한다:

1. **Merkle 경로 유효성**: "나는 `old_root`에서 내 leaf까지의 유효한 경로를 안다"
2. **상태 전이 정확성**: "balance >= transfer_amount"
3. **권한 증명**: "나는 이 leaf의 비밀키를 안다"
4. **새 루트 정확성**: "내 leaf를 갱신한 후 새 루트는 `new_root`이다"

Sequencer의 역할이 *STF 로직 실행*에서 *증명 검증*으로 변경된다:

```python
# 현재: STF가 로직을 실행
class TokenSTF(StateTransitionFunction):
    def apply_tx(self, state, tx):
        state["balances"][sender] -= amount  # sequencer가 이것을 실행
        state["balances"][to] += amount
        return STFResult(success=True)

# 대안: STF가 증명을 검증
class MerkleProofSTF(StateTransitionFunction):
    def validate_tx(self, state, tx):
        proof = deserialize_proof(tx.data["proof"])
        if not groth16_verify(self.vk, proof, tx.data["public_inputs"]):
            return "invalid zk proof"
        return None

    def apply_tx(self, state, tx):
        # 증명이 이미 검증됨 — 새 루트만 적용
        state["root"] = tx.data["public_inputs"]["new_root"]
        state["nullifiers"].add(tx.data["public_inputs"]["nullifier"])
        return STFResult(success=True)
```

**이는 현재 4-인터페이스 프레임워크와 완전히 호환된다.** `StateTransitionFunction` 인터페이스는 두 모델 모두를 지원한다 — STF가 직접 상태를 조작하는 대신 증명 검증을 수행하면 된다.

**트레이드오프:**

| 측면 | 배치 증명 (현재) | 트랜잭션별 Merkle 증명 |
|---|---|---|
| 회로 크기 | 3 constraints (배치당) | O(log n) 해시 × tx당 |
| 증명 생성자 | 서버 (Prover 노드) | 클라이언트 (사용자 기기) |
| Sequencer 신뢰 | STF 실행 → 일정 수준의 신뢰 | 증명 검증만 → 최소 신뢰 |
| 프라이버시 | 없음 (평문 tx) | 가능 (sender/amount를 증명 내에 은닉) |
| 클라이언트 부담 | 경량 (tx 전송만) | 중량 (증명 생성) |
| In-circuit 해시 | 불필요 | 필수 (Poseidon 선호 [20]) |
| 대표 프로토콜 | py-ethclient (현재) | Tornado Cash, Zcash, Loopring |

**핵심 구현 고려사항:** 표준 해시 함수(keccak256, SHA256)는 ZK 회로 내에서 비용이 매우 높다(keccak256 ~150,000 constraints). 트랜잭션별 Merkle 증명 시스템은 거의 항상 **ZK 친화적 해시 함수**인 Poseidon [20](~300 constraints)을 사용하며, 이는 `ethclient/zk/circuit.py`에 추가 회로 컴포넌트를 필요로 한다.

**세 가지 패턴 모두 기존 STF 인터페이스로 구현 가능하다.** `StateTransitionFunction` ABC (`interfaces.py:12–25`)는 세 가지 트랜잭션별 증명 아키텍처 모두를 수용할 수 있다 — `validate_tx`와 `apply_tx`의 내부 로직만 달라질 뿐, 인터페이스 자체는 동일하다:

*패턴 1 — Account subtree STF:*

```python
class AccountSubtreeSTF(StateTransitionFunction):
    def validate_tx(self, state, tx):
        proof = tx.data["proof"]
        old_root, new_root = tx.data["old_root"], tx.data["new_root"]
        if old_root != state["root"]:
            return "stale root"
        if not verify_merkle_update(proof, old_root, new_root):
            return "invalid merkle proof"
        return None

    def apply_tx(self, state, tx):
        state["root"] = tx.data["new_root"]
        return STFResult(success=True)
```

*패턴 2 — Nullifier STF:*

```python
class NullifierSTF(StateTransitionFunction):
    def validate_tx(self, state, tx):
        proof, nullifier = tx.data["proof"], tx.data["nullifier"]
        if nullifier in state.get("nullifiers", {}):
            return "double spend"
        if not groth16_verify(self.vk, proof, [state["commitment_root"], nullifier]):
            return "invalid proof"
        return None

    def apply_tx(self, state, tx):
        state.setdefault("nullifiers", {})[tx.data["nullifier"]] = True
        state["commitment_root"] = tx.data["new_commitment_root"]
        return STFResult(success=True)
```

*패턴 3 — Sequencer-ordered STF:*

```python
class SequencerOrderedSTF(StateTransitionFunction):
    def validate_tx(self, state, tx):
        if tx.data["old_root"] != state["root"]:
            return "root mismatch — regenerate proof"
        if not groth16_verify(self.vk, tx.data["proof"], tx.data["public_inputs"]):
            return "invalid proof"
        return None

    def apply_tx(self, state, tx):
        state["root"] = tx.data["new_root"]
        return STFResult(success=True)
```

세 가지 모두 동일한 파이프라인을 탄다: `submit_tx() → validate_tx() → mempool → tick() → apply_tx() → seal`. 차이는 *증명 생성이 어디서 일어나는가*뿐이다:

| | 증명 생성 | validate_tx | apply_tx | 배치 prove() |
|---|---|---|---|---|
| **현재 (batch)** | 서버, 배치 후 | 앱 로직 | 상태 직접 변경 | 전체 배치 증명 |
| **Account subtree** | 클라이언트, tx 전 | Merkle proof 검증 | Root 갱신 | 선택적 집계 |
| **Nullifier** | 클라이언트, tx 전 | ZK proof + nullifier 검사 | Nullifier 기록 | 선택적 집계 |
| **Sequencer-ordered** | 클라이언트, tx 전 | ZK proof + root 일치 검증 | Root 갱신 | 선택적 집계 |

"선택적 집계"란: 트랜잭션별 증명이 이미 각 트랜잭션의 유효성을 인증하므로 배치 수준 `prove()`는 **필수가 아니다**. 그러나 L1 가스 절약을 위해 N개의 트랜잭션별 증명을 단일 재귀적 집계 증명(recursive aggregation proof)으로 결합할 수 있으며, 이 경우 `ProofBackend`를 배치별 증명이 아닌 집계 용도로 재구현하면 된다.

핵심 통찰은 **4개 ABC 중 어느 것도 수정할 필요가 없다**는 것이다 — 구현체만 교체하면 된다. 이것이 pluggable interface 설계의 핵심 가치이다.

#### FAQ 4: Pre-state와 Post-state는 어떻게 구분하는가?

답은 증명 아키텍처에 따라 다르다.

**현재 구현 (배치 수준):**

Sequencer는 `_pre_batch_root` (`sequencer.py:36`)를 유지하고 봉인 시 `new_root`를 계산한다:

```
Batch #0:
  __init__:  _pre_batch_root = compute_state_root()    → S₀
  tick():    apply_tx(tx₁), apply_tx(tx₂), ...         → 상태 변경
  seal():    old_root = _pre_batch_root                 → S₀
             new_root = compute_state_root()            → S₂
             _pre_batch_root = new_root                 → 다음 배치는 S₂에서 시작

Batch #1:
  old_root = _pre_batch_root                            → S₂ (= 이전 new)
  ...
  new_root = compute_state_root()                       → S₅

체인 불변식: Batch[k].new_root == Batch[k+1].old_root
```

**트랜잭션별 Merkle 증명 모델 — 세 가지 패턴:**

*패턴 1: 계정 수준 서브트리 (Loopring 방식).*

상태를 계정별 서브트리로 분할한다. 트랜잭션은 old leaf와 Merkle 경로를 알고 있음을 증명하고 new leaf를 제공한다. **동일한 sibling 경로**로 양쪽 루트를 모두 검증할 수 있다:

```
동일한 Merkle 경로 sibling으로 검증:
  hash(old_leaf, siblings...) == old_root    ✓ pre-state 유효
  hash(new_leaf, siblings...) == new_root    ✓ post-state 유효
```

*다른* 계정을 건드리는 동시 트랜잭션은 병렬화할 수 있다(서로소 서브트리). *같은* 계정을 건드리는 트랜잭션은 충돌하므로 직렬화해야 한다.

*패턴 2: Nullifier 모델 (Tornado Cash / Zcash 방식).*

상태는 **추가 전용(append-only)** 커밋먼트 트리이다. Pre-state는 Merkle 포함 증명으로, post-state는 nullifier 추가로 기록한다:

```
Pre-state:  Merkle 포함 증명 ("이 커밋먼트가 트리에 존재함")
Post-state: Nullifier 추가 ("이 커밋먼트가 이제 소비됨")
```

트리는 수정되지 않고 확장만 되므로 **충돌이 없다**. 완전한 병렬성을 가능하게 하지만 상태 모델을 UTXO 유사 패턴으로 제한한다.

*패턴 3: Sequencer 순서 지정 (현재 설계의 확장).*

Sequencer가 각 클라이언트에 현재 루트를 할당하고, 클라이언트는 해당 특정 루트에 대한 증명을 생성한다. Sequencer는 증명을 순서대로 적용하여 현재 배치 수준 설계와 동일한 순차적 불변식을 유지한다.

| 모델 | Pre-state | Post-state | 동시성 |
|---|---|---|---|
| **배치 (현재)** | `_pre_batch_root` 저장 | `compute_state_root()` 호출 | 배치 내 순차 |
| **계정 서브트리** | Merkle 경로 + old_leaf | 동일 경로 + new_leaf | 계정 단위 병렬 |
| **Nullifier** | Merkle 포함 증명 | Nullifier 추가 | 완전 병렬 (충돌 없음) |
| **Sequencer 순서 지정** | Sequencer가 루트 할당 | 증명의 공개 출력 | 순차 (현재와 동일) |

### E. 아키텍처 구성 트리

4개의 플러거블 인터페이스(`StateTransitionFunction`, `ProofBackend`, `DAProvider`, `L1Backend`)는 조합하여 다양한 롤업 아키텍처를 구성할 수 있다. 본 부록은 인터페이스별 모든 구현 옵션과 보안 모델별로 분류된 의미 있는 아키텍처 조합을 열거한다.

#### E.1 인터페이스 구현 옵션

```
Rollup(stf, da, prover, l1)
│
├─ STF (StateTransitionFunction)
│   ├─ Plain STF (직접 실행) ──────────── Sequencer가 로직 실행
│   │   ├─ PythonRuntime(callable)        state["balances"][x] -= amount
│   │   └─ Custom ABC subclass            class MySTF(StateTransitionFunction)
│   └─ Proof-verifying STF ───────────── Sequencer는 검증만, Client가 증명
│       ├─ AccountSubtreeSTF              Merkle path + old/new leaf
│       ├─ NullifierSTF                   Commitment tree + nullifier set
│       └─ SequencerOrderedSTF            Sequencer가 root 할당, client 증명
│
├─ ProofBackend
│   ├─ Execution-trace binding ────────── old_root × ∏tx ≡ new_root × commit
│   │   ├─ Groth16ProofBackend (Python)   py_ecc, 개발/테스트용
│   │   └─ NativeProverBackend            rapidsnark subprocess, 프로덕션
│   ├─ STF-to-Circuit compiler ────────── STF 로직을 R1CS로 컴파일
│   │   └─ CircuitCompilerProofBackend    balance check → constraint
│   ├─ Recursive aggregation ─────────── N개 tx/batch proof → 1 proof
│   │   └─ RecursiveAggregationBackend    per-tx proof 집계용
│   └─ (미래 증명 시스템)
│       ├─ PLONKProofBackend              범용 셋업, updateable
│       └─ STARKProofBackend              신뢰 셋업 불필요, 양자 후 보안
│
├─ DAProvider
│   ├─ LocalDA                            메모리, keccak256 commitment
│   ├─ CalldataDA                         EIP-1559, 16 gas/byte, 영구
│   └─ BlobDA                             EIP-4844, ~1 gas/byte, ~18일
│
└─ L1Backend
    ├─ InMemoryL1Backend                  groth16.verify() 직접 호출
    ├─ EthL1Backend                       실제 Ethereum, EVMVerifier contract
    └─ FraudProofL1Backend                ZK + challenge window 하이브리드
```

#### E.2 보안 모델

보안 모델 — 시퀀서를 신뢰해야 하는지 여부를 결정 — 은 최상위 아키텍처 결정이다. STF × ProofBackend × L1Backend의 조합에 의해 결정된다. DAProvider는 직교적이며 어떤 보안 모델과도 조합 가능하다.

```
보안 모델별 아키텍처
│
├─ 모델 1: Sequencer 신뢰 (현재 기본)
│   │
│   │  STF:    Plain (PythonRuntime)
│   │  Prover: Execution-trace (Groth16 또는 Native)
│   │  L1:     InMemory 또는 EthL1
│   │  신뢰:   Sequencer가 STF를 정직하게 실행
│   │  STF 무결성: DA + 오프체인 재실행
│   │
│   ├─ 1a. 개발 / 테스트
│   │   STF=callable, DA=Local, Prover=Python, L1=InMemory
│   │   → 가장 간단: 5줄로 롤업 생성
│   │
│   ├─ 1b. Sepolia / Mainnet (calldata)
│   │   STF=callable, DA=Calldata, Prover=Native, L1=EthL1
│   │   → 프로덕션: ~199K gas 검증
│   │
│   └─ 1c. Sepolia / Mainnet (blob)
│       STF=callable, DA=Blob, Prover=Native, L1=EthL1
│       → EIP-4844: 최저 DA 비용
│
├─ 모델 2: Optimistic + ZK 하이브리드
│   │
│   │  STF:    Plain (PythonRuntime) — 변경 없음
│   │  Prover: Execution-trace — 변경 없음
│   │  L1:     FraudProofL1Backend ← 핵심 교체
│   │  신뢰:   1-of-N 정직한 챌린저
│   │  STF 무결성: 재실행 + 윈도우 내 챌린지
│   │
│   ├─ 2a. 짧은 챌린지 윈도우
│   │   challenge_window=1일, DA=Calldata
│   │   → ZK가 대부분 보장 + 빠른 finality
│   │
│   └─ 2b. 긴 챌린지 윈도우
│       challenge_window=7일, DA=Blob
│       → Optimistic rollup 수준 보안
│
├─ 모델 3: Circuit-Enforced STF (Trustless)
│   │
│   │  STF:    Plain (동일 코드) — 변경 없음
│   │  Prover: CircuitCompilerProofBackend ← 핵심 교체
│   │  L1:     EthL1
│   │  신뢰:   없음 (수학적)
│   │  STF 무결성: 회로가 모든 STF 연산을 강제
│   │
│   ├─ 3a. DSL 기반
│   │   STF를 제한된 DSL로 작성, 자동 R1CS 컴파일
│   │   → 중간 회로 크기, 완전 trustless
│   │
│   └─ 3b. Symbolic tracing
│       기존 Python STF를 symbolic 실행으로 추적
│       → 기존 코드 재사용, 복잡한 컴파일러 필요
│
├─ 모델 4: Client-Side Proving (Trustless)
│   │
│   │  STF:    Proof-verifying STF ← 핵심 교체
│   │  Prover: 선택적 집계 (또는 pass-through)
│   │  L1:     EthL1
│   │  신뢰:   없음 (클라이언트가 증명 생성)
│   │  STF 무결성: 각 tx가 자체 ZK 증명을 포함
│   │
│   ├─ 4a. Account subtree + 배치 집계
│   │   STF=AccountSubtreeSTF, Prover=RecursiveAggregation
│   │   → Loopring 모델, 계정 단위 병렬
│   │
│   ├─ 4b. Nullifier + 배치 집계
│   │   STF=NullifierSTF, Prover=RecursiveAggregation
│   │   → Tornado Cash/Zcash 모델, 프라이버시, 완전 병렬
│   │
│   ├─ 4c. Sequencer-ordered + 배치 집계
│   │   STF=SequencerOrderedSTF, Prover=RecursiveAggregation
│   │   → 순차 실행, 현재 구조와 유사
│   │
│   └─ 4d. Per-tx proof만 (배치 증명 없음)
│       STF=NullifierSTF, Prover=NoOp (pass-through)
│       → 가장 간단한 client-side 모델, 집계 없음
│
└─ 모델 5: 혼합 조합
    │
    ├─ 5a. Client proof + Fraud proof
    │   STF=MerkleProofSTF, L1=FraudProofL1Backend
    │   → 이중 보호: client proof + challenge fallback
    │
    └─ 5b. STF-to-Circuit + Recursive aggregation
        Prover=CircuitCompiler + RecursiveAggregation
        → 완전 trustless + L1 가스 최적화
```

#### E.3 조합 요약

| 인터페이스 | 옵션 수 | 변형 |
|---|---|---|
| STF | 2 계열 | 5 총 (2 plain + 3 proof-verifying) |
| ProofBackend | 4 계열 | 6 총 (2 trace + 1 compiler + 1 recursive + 2 future) |
| DAProvider | 3 | 3 (Local, Calldata, Blob) |
| L1Backend | 3 | 3 (InMemory, EthL1, FraudProof) |

이론적 조합 공간: 5 × 6 × 3 × 3 = **270가지 조합**.

의미 있는 아키텍처 구성(E.2절): 5개 보안 모델에 걸쳐 **~15가지 구성**, DA 레이어는 어떤 모델과도 직교적으로 조합 가능.
