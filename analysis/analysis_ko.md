# ethrex L1 클라이언트 Python 포팅 분석

## 개요

원본 레포지토리: https://github.com/lambdaclass/ethrex

ethrex는 LambdaClass의 Rust 기반 이더리움 프로토콜 구현체로, "미니멀, 안정적, 모듈러, 빠르고 ZK-네이티브"를 지향합니다. 표준 L1 실행 클라이언트와 ZK-롤업 L2 스택 두 가지 모드로 동작합니다.

---

## 레포지토리 구조

```
ethrex/
├── cmd/ethrex/              # 메인 바이너리 진입점
├── crates/
│   ├── blockchain/          # L1: 블록 검증, 실행, mempool
│   ├── common/              # 공유: 타입, RLP, trie, 암호화, serde 유틸리티
│   ├── networking/
│   │   ├── p2p/             # L1: devp2p (RLPx, discv4/5, snap sync)
│   │   └── rpc/             # L1: JSON-RPC + Engine API
│   ├── storage/             # L1: 상태/블록 저장소 (RocksDB + 인메모리)
│   ├── vm/
│   │   ├── levm/            # L1/L2 공유: 자체 EVM ("Lambda EVM")
│   │   └── backends/        # L1: VM 백엔드 연결
│   ├── l2/                  # L2 전용 (분석 제외)
│   └── guest-program/       # ZK 게스트 프로그램 (분석 제외)
```

---

## L1 클라이언트 Rust 코드 규모

| 컴포넌트 | Crate 경로 | 예상 Rust LOC |
|---|---|---:|
| EVM (LEVM) — 옵코드, 프리컴파일, 가스 | `crates/vm/levm/` | ~18,400 |
| P2P 네트워킹 — RLPx, discv4/5, snap sync | `crates/networking/p2p/` | ~30,500 |
| JSON-RPC + Engine API | `crates/networking/rpc/` | ~14,900 |
| 블록체인 엔진 — 검증, 실행, mempool | `crates/blockchain/` | ~8,500 |
| 저장소 — RocksDB / 인메모리 상태 DB | `crates/storage/` | ~6,300 |
| 공통 — 타입, trie, RLP, 암호화 | `crates/common/` | ~26,800 |
| VM 백엔드 + 바이너리 진입점 | `crates/vm/backends/` + `cmd/` | ~7,200 |
| **합계** | | **~112,600** |

### 서브시스템 상세

#### EVM (LEVM) ~18,400 LOC
- 자체 EVM 구현체 (revm 포크 아님)
- 옵코드 핸들러: 산술, 비트, 환경, 스택/메모리/스토리지, 시스템 (CALL, CREATE), 로깅
- 모든 프리컴파일: ecrecover, SHA256, RIPEMD160, modexp, ecadd/ecmul/ecpairing, BLAKE2f, KZG (EIP-4844), BLS12-381 (EIP-2537)
- 모든 옵코드 가스 계산
- 플러그인 훅 시스템 (L1 기본, L2, 백업)

#### P2P 네트워킹 ~30,500 LOC
- **RLPx** (~8,200): ECIES 핸드셰이크, 프레이밍 코덱, tokio 기반 연결 루프
- **Discovery v4 + v5** (~10,100): UDP 피어 탐색, k-bucket 라우팅, ENR 레코드
- **Snap 프로토콜** (~2,700): 상태 다운로드 프로토콜
- **동기화 관리** (~4,500): Full sync + snap sync + trie healing
- **eth/68-69 서브프로토콜**: Status, GetBlockHeaders, GetBlockBodies, Transactions, NewPooledTransactionHashes

#### JSON-RPC + Engine API ~14,900 LOC
- axum HTTP 서버 기반
- `eth_` 네임스페이스: getBalance, getCode, getBlockByHash, sendRawTransaction, call, estimateGas, getLogs, feeHistory 등
- Engine API (합의 계층-실행 계층 인터페이스): newPayload, getPayload, forkchoiceUpdated (V1-V5)
- `debug_`, `admin_`, `net_`, `trace_` 네임스페이스
- 웹소켓 구독, JWT 인증

#### 블록체인 엔진 ~8,500 LOC
- 블록 검증 및 실행 파이프라인
- 논스 정렬 트랜잭션 풀 (mempool)
- 포크 선택 (Merge 이후, Engine API 지시 따름)
- 컨센서스 클라이언트용 페이로드 빌더
- Prometheus 메트릭스

#### 저장소 ~6,300 LOC
- `Store` 구조체: 계정 상태, 코드, 스토리지 trie, 블록 헤더/바디/영수증
- `TrieLayerCache`: 인메모리 write-ahead trie 캐시
- RocksDB + 인메모리 백엔드
- LRU 코드 캐시 (64 MB), 플랫 key-value 인덱스

#### 공통 / 공유 ~26,800 LOC
- 핵심 타입: Block, BlockHeader, Transaction (모든 타입: EIP-155/1559/2930/4844/7702), Receipt, Account, Genesis, ForkId
- 머클 패트리시아 트라이: 노드 인코딩, 병렬 trie 생성, 범위 검증
- RLP 인코딩/디코딩 (derive 매크로 포함)
- 암호화: BLAKE2f (어셈블리 포함), Keccak256, KZG 커밋먼트

---

## Python 포팅 예상치

### 압축 요인

Rust에서 Python으로의 압축 비율은 약 **3~4:1**이며 이유는 다음과 같습니다:

- 타입 선언, 라이프타임 어노테이션, 빌림 검사기 불필요
- `Result<T, E>` / `match` 에러 핸들링 보일러플레이트 불필요
- 동적 타이핑으로 구조체 정의와 derive 매크로 불필요
- 풍부한 라이브러리 생태계 (pyrlp, pycryptodome, py_ecc, asyncio, FastAPI)

### 활용 가능 Python 라이브러리

| 라이브러리 | 대체 대상 |
|---|---|
| `pyrlp` | RLP 인코딩/디코딩 (~1,600 LOC) |
| `pycryptodome` | SHA256, RIPEMD160, AES (ECIES) |
| `py_ecc` | ecrecover, BN128, BLS12-381 프리컴파일 |
| `coincurve` / `eth_keys` | secp256k1 서명, ECIES 핸드셰이크 |
| `pyethash` / `eth_hash` | Keccak256 |
| `ckzg` | KZG 커밋먼트 (EIP-4844) |
| `FastAPI` / `aiohttp` | JSON-RPC HTTP/WS 서버 |
| `asyncio` | 비동기 네트워킹 (tokio 대체) |
| `plyvel` / `rocksdb` | RocksDB 저장소 백엔드 |
| `trie` (ethereum/py-trie) | 머클 패트리시아 트라이 |

### Python 예상 라인수

| 컴포넌트 | 완전 포팅 | 최소 포팅 | 비고 |
|---|---:|---:|---|
| EVM | 4,000-6,000 | 3,000-4,000 | 옵코드 수는 동일, 문법이 간결 |
| P2P 네트워킹 | 8,000-12,000 | 4,000-5,000 | 최소: snap sync 제외, 기본 discovery만 |
| JSON-RPC + Engine API | 2,000-3,000 | 1,000-1,500 | FastAPI로 보일러플레이트 대폭 감소 |
| 블록체인 엔진 | 1,500-2,500 | 1,000-1,500 | 핵심 검증/실행 로직 |
| 저장소 | 1,000-2,000 | 500-1,000 | 최소: 인메모리만 |
| 공통 (타입, trie, RLP) | 3,000-5,000 | 2,000-3,000 | pyrlp + py-trie로 대폭 감소 |
| **합계** | **20,000-30,000** | **12,000-16,000** | |

### 요약 (자체 구현 기준)

| 시나리오 | 예상 LOC | 설명 |
|---|---:|---|
| **초소형** | ~15,000 | 인메모리 저장소, full sync만, 최소 RPC, snap sync 없음 |
| **실용적 완전체** | ~25,000 | 모든 필수 기능, 라이브러리 최대 활용 |
| **풀 기능** | ~30,000 | snap sync, 전체 RPC 엔드포인트, RocksDB, 메트릭스 |

---

## 추가 축소 전략

위 예상치는 대부분의 컴포넌트를 직접 구현하는 것을 전제한다. 기존 Python 이더리움 라이브러리를 적극 활용하거나 서브시스템 자체를 제거하면 코드를 대폭 줄일 수 있다.

### 전략 1: 라이브러리 적극 활용

| 라이브러리 | 제거 가능 코드 | 절감 LOC |
|---|---|---:|
| `py-evm` (이더리움 재단 공식) | EVM 전체 (옵코드, 프리컴파일, 가스) | -3,000~5,000 |
| `py-trie` + `eth-hash` | Trie + 해시 직접 구현 | -1,000~2,000 |
| `devp2p` / Trinity 네트워킹 | RLPx, discovery 일부 | -2,000~3,000 |
| `eth-rlp` + `eth-typing` | 타입 정의 + RLP 인코딩 | -500~1,000 |

### 전략 2: P2P 완전 제거 (Proxy 모드)

P2P 네트워킹이 전체 코드베이스의 **40%**를 차지한다. 기존 Geth/Reth 노드에 JSON-RPC로 연결하여 블록 데이터를 가져오면 P2P를 완전히 제거할 수 있다.

- P2P 30,500 LOC (Rust) / 8,000-12,000 LOC (Python) → **0 LOC**
- 대체로 RPC 클라이언트 코드 ~500줄만 추가

### 전략 3: Engine API 제거

컨센서스 클라이언트(예: Lighthouse)와의 연결이 필요 없으면 Engine API를 통째로 제거 가능 → **-1,000~1,500 LOC**

### 전체 시나리오 비교

| 시나리오 | 예상 LOC | P2P | EVM | 독립성 |
|---|---:|---|---|---|
| **A. 완전 독립** | ~15,000 | 자체 구현 | 자체 구현 | 독립 노드, devp2p로 이더리움 네트워크에 직접 참여 |
| **B. 라이브러리 활용** | ~5,000-8,000 | 자체 구현 | py-evm | 네트워크 참여 가능, EVM은 py-evm에 위임 |
| **C. Proxy 모드** | ~3,000-5,000 | 없음 (기존 노드에 프록시) | py-evm | 외부 노드에서 블록 수신, 자체 검증/실행만 |
| **D. 순수 EVM 실행기** | ~1,500-2,500 | 없음 | py-evm (래퍼) | 로컬 전용 개발/테스트 노드 |

### 시나리오별 상세

#### A. 완전 독립 (~15,000 LOC)
- 모든 컴포넌트를 Python으로 직접 구현
- devp2p를 통한 full sync (snap sync 제외)
- 최소 JSON-RPC, 인메모리 저장소
- 독립적인 실행 클라이언트로 이더리움 네트워크에 참여 가능
- **트레이드오프**: 최대 독립성, 최대 코드량

#### B. 라이브러리 활용 (~5,000-8,000 LOC)
- EVM 실행을 `py-evm`에 위임
- Trie 연산은 `py-trie` 활용
- P2P 네트워킹은 자체 구현 (RLPx, discv4)
- **트레이드오프**: 코드 감소하면서도 네트워크 참여 유지

#### C. Proxy 모드 (~3,000-5,000 LOC)
- 기존 Geth/Reth 노드에 JSON-RPC로 연결하여 블록 수신
- `py-evm`으로 블록을 독자적으로 실행하고 검증
- P2P 스택 없음, Engine API 없음
- 독립적인 블록 검증기 또는 shadow 노드로 활용 가능
- **트레이드오프**: 외부 노드에 의존하지만 검증은 자체적으로 수행

#### D. 순수 EVM 실행기 (~1,500-2,500 LOC)
- `py-evm`의 얇은 래퍼
- 인메모리 상태만 관리
- 최소 JSON-RPC (eth_call, eth_sendTransaction, eth_getBalance)
- 동기화 없음, P2P 없음, Engine API 없음
- Ganache/Hardhat 노드와 같은 로컬 개발 노드 수준
- **트레이드오프**: 최소 코드, 로컬 전용

### 핵심 트레이드오프 스펙트럼

```
코드 줄수 ↓↓↓  ←→  독립성 ↓↓↓

  A. ~15,000줄  │  완전 독립 노드 (P2P, 자체 EVM)
  B.  ~5,000줄  │  네트워크 참여 가능, EVM은 py-evm 활용
  C.  ~3,000줄  │  기존 노드에 기생 (proxy), 자체 검증만
  D.  ~1,500줄  │  사실상 py-evm 래퍼 (로컬 전용)
```

코드 비용의 두 큰 축은 **P2P 네트워킹** (전체의 40%)과 **EVM 구현** (전체의 20%)이다. 둘 다 기존 라이브러리에 위임하면 총 ~3,000줄까지 줄어든다.

---

## 부록: 동기화 방식 설명

### Full Sync (전체 동기화)
- 제네시스 블록부터 **모든 블록을 하나씩 다운로드하고 실행**
- 모든 트랜잭션을 재실행하며 상태를 직접 구성
- 가장 안전하지만 **매우 느림** (수일~수주 소요)

### Snap Sync (스냅 동기화)
Geth v1.10에서 도입된 방식으로 기존 fast sync의 후속이다. 과거 이력을 재실행하는 대신 **최신 상태 트라이(state trie) 스냅샷을 피어로부터 직접 다운로드**한다.

**과정:**
1. 피어에게 계정/스토리지 데이터를 범위(range) 단위로 요청
2. 다운로드한 데이터로 상태 트라이 구성
3. **Trie healing** — 다운로드 중 변경된 부분을 보정
4. 이후부터는 새 블록만 따라감

**비교:**

| | Full Sync | Snap Sync |
|---|---|---|
| 비유 | 회사 창립부터 모든 거래 장부를 한 건씩 다시 계산 | 오늘자 잔고 현황표를 통째로 복사 |
| 속도 | 느림 (수일~수주) | 빠름 (수 시간) |
| 검증 수준 | 모든 트랜잭션 검증 | 상태 루트 해시로 무결성 검증 |

**코드베이스에 미치는 영향:**
- Snap sync 프로토콜 메시지: ~2,700 LOC
- 관련 동기화 관리 + trie healing: ~4,500 LOC
- Snap sync 관련 총 코드: ~7,200 LOC (전체 P2P 네트워킹의 24%)
- Snap sync 제외 시 P2P는 Rust 기준 ~30,500에서 ~23,300 LOC로, Python 최소 포팅 기준 ~8,000-12,000에서 ~4,000-5,000 LOC로 감소

---

## 시나리오 A 구현 계획

상세 구현 계획은 [plan_fully_independent_ko.md](plan_fully_independent_ko.md) 참조 (7개 Phase, 35개 작업, ~13,800-18,800 LOC).

---

## 주요 아키텍처 결정사항

1. **revm 미사용** — ethrex는 플러그인 훅이 있는 자체 EVM (LEVM) 사용
2. **순수 실행 클라이언트** — Merge 이후 설계로 Engine API를 통해 합의 클라이언트와 통신
3. **저장소 계층화** — RocksDB 위에 write-ahead TrieLayerCache 배치
4. **이중 동기화** — Full sync + snap sync, sync 후 trie healing 수행
5. **discv4 + discv5** — 두 디스커버리 프로토콜 모두 구현
6. **L2 분리** — L2 코드는 완전히 별도이며, L1이 L2에 의존하지 않음

---

## 부록: revm vs LEVM — EVM 구현 선택지

### revm이란?

**revm**은 **Rust EVM**의 약자로, Dragan Rakita가 개발한 Rust 기반 범용 EVM 구현체이다. 어떤 프로젝트에서든 가져다 쓸 수 있도록 설계된 독립 라이브러리이다.

### LEVM이란?

**LEVM**은 **Lambda EVM**의 약자로, ethrex 레포지토리 내부(`crates/vm/levm/`)에서 처음부터 직접 구현한 EVM이다. revm의 포크가 아니다.

### 비교

| | revm | LEVM (ethrex) |
|---|---|---|
| 개발자 | Dragan Rakita (개인) | LambdaClass |
| 성격 | 범용 라이브러리 (누구나 가져다 쓸 수 있음) | ethrex 전용 자체 구현 |
| 사용하는 프로젝트 | **Reth**, Foundry, Hardhat, Helios 등 다수 | ethrex만 |
| 위치 | 별도 레포 (`bluealloy/revm`) | ethrex 내부 (`crates/vm/levm/`) |
| 특징 | 성능 최적화 중심, 광범위하게 검증됨 | ZK-proving에 최적화된 훅 시스템 |

### ethrex는 왜 revm을 안 쓰나?

ethrex는 L1 실행뿐 아니라 L2 ZK-롤업 증명도 지원해야 한다. 이를 위해 EVM 실행 도중 **훅(hook) 시스템**으로 서로 다른 동작을 주입할 수 있어야 한다:

- **L1 훅 (기본)**: 표준 이더리움 실행 규칙
- **L2 훅**: 롤업 운영을 위한 추가 수수료 차감 로직
- **백업 훅**: ZK 증명용 체크포인트 메커니즘

revm을 포크해서 대폭 수정하는 대신, LambdaClass는 훅을 1급 개념으로 지원하는 LEVM을 처음부터 만들었다.

### 비유

- **revm** = 도요타 엔진 (범용, 여러 차량에 탑재)
- **LEVM** = 특정 차량의 고유 요구사항에 맞춰 설계된 자체 엔진

### 훅 시스템 동작 방식

EVM이 트랜잭션을 실행하는 과정에서 **특정 시점에 끼어들어 커스텀 로직을 실행**할 수 있게 하는 구조이다. 본질적으로는 콜백 메커니즘이다.

**간략화한 트랜잭션 실행 흐름:**

```
1. 송신자 잔고에서 가스비 차감
2. [HOOK: before_execution]    ← 훅 포인트
3. EVM 바이트코드 실행
4. [HOOK: after_execution]     ← 훅 포인트
5. 남은 가스 환불
6. 수신자에게 ETH 전송
```

**훅 없는 방식** — L1/L2 분기가 EVM 코드 안에 박혀있음 (나쁜 설계):

```python
def execute_tx(tx):
    deduct_gas(tx)
    if is_l2_mode:           # EVM이 L2를 알아야 함
        deduct_l2_fee(tx)
    run_bytecode(tx)
    refund_gas(tx)
```

**훅을 쓰는 방식** — EVM은 L2를 모름. 훅이 알아서 처리:

```python
class DefaultHook:    # L1용
    def before_execution(self, tx):
        pass           # 아무것도 안 함

class L2Hook:         # L2용
    def before_execution(self, tx):
        deduct_l2_fee(tx)  # L2 수수료 차감

def execute_tx(tx, hook):
    deduct_gas(tx)
    hook.before_execution(tx)   # L1이면 패스, L2면 수수료 차감
    run_bytecode(tx)
    refund_gas(tx)
```

**ethrex LEVM의 실제 훅 포인트들:**

| 훅 포인트 | L1 기본 동작 | L2 동작 |
|---|---|---|
| 트랜잭션 실행 전 | 아무것도 안 함 | L2 수수료 차감 |
| CALL/CREATE 전 | 아무것도 안 함 | 추가 검증 |
| 상태 변경 시 | 그대로 적용 | 체크포인트 기록 (ZK 증명용) |

이점: **하나의 EVM 코드**로 L1과 L2를 모두 깔끔하게 지원. 코드 복제나 if/else 분기 없음.

### 훅과 ZK 증명의 관계

주의: **ZKP 자체가 훅은 아니다.** 훅은 ZK 증명을 **만들기 위한 데이터를 수집**하는 역할이다.

ethrex의 L2는 ZK-롤업이다. ZK-롤업의 동작:

```
1. L2에서 트랜잭션 실행 (EVM으로)
2. "이 실행이 올바르게 수행되었다"는 ZK 증명 생성
3. 그 증명을 L1에 제출 → L1은 증명만 검증 (재실행 불필요)
```

2번 단계에서 ZK 증명을 만들려면, EVM이 실행되는 동안 **모든 상태 변화를 기록**(execution trace / witness)해야 한다. 이 기록을 수집하는 것이 바로 훅의 역할이다.

```python
class BackupHook(ExecutionHook):    # ZK 증명용 훅
    def __init__(self):
        self.trace = []             # 실행 추적 기록

    def on_state_change(self, addr, key, old_val, new_val):
        # 상태가 바뀔 때마다 기록
        self.trace.append({
            "address": addr,
            "key": key,
            "before": old_val,
            "after": new_val
        })

    # 나중에 self.trace를 ZK prover에 넘겨서 증명 생성
```

**전체 흐름:**

```
EVM 실행 중                          EVM 실행 후
┌─────────────┐                    ┌─────────────┐
│ 옵코드 실행  │                    │             │
│      │      │                    │  ZK Prover  │
│  [훅 호출]  │ ──→ trace 기록 ──→ │  (SP1 등)   │ ──→ ZK 증명
│      │      │                    │             │
│ 다음 옵코드  │                    └─────────────┘
└─────────────┘
```

| 구성 요소 | 역할 |
|---|---|
| **훅** | EVM 실행 도중 끼어드는 콜백. 상태 변화를 기록 |
| **ZK prover** | 실행이 끝난 후, 기록된 데이터(trace)로 증명을 생성하는 별도 프로그램 (SP1, RISC Zero 등) |
| **ZK 증명** | "이 실행이 정당했다"는 수학적 증거. L1에 제출됨 |

즉 훅은 ZK 증명을 **실행하지 않는다**. ZK 증명을 만들기 위한 **입력 데이터를 모으는 것**이다.

### 이 Python 포팅과의 관계

완전 독립 포팅(시나리오 A)에서는 ethrex가 revm 대신 LEVM을 선택한 것처럼 EVM을 처음부터 직접 구현한다. Python 생태계에는 `py-evm`(이더리움 재단의 Python EVM, revm에 대응하는 존재)이 있지만, 시나리오 A는 최대 독립성을 위해 이를 사용하지 않는다. 시나리오 B-D에서는 `py-evm`을 활용하여 코드량을 줄인다.

L1 전용 포팅에서는 훅 시스템이 필수는 아니다. 하지만 EVM 메인 루프(Phase 2.9)에 훅 포인트를 미리 설계해두면 (~50 LOC 추가) 나중에 L2 확장 시 EVM을 재구조화할 필요가 없다.

---

## 부록: SP1과 zkVM

### SP1이란?

**SP1**은 Succinct Labs가 만든 **zkVM(Zero-Knowledge Virtual Machine)**이다. "일반 프로그램을 실행하고, 그 실행이 올바르다는 ZK 증명을 자동으로 만들어주는 가상 머신"이다.

### 동작 방식

```
┌──────────────┐         ┌─────────┐         ┌──────────┐
│ 일반 Rust     │         │         │         │          │
│ 프로그램 작성  │ ──────→ │   SP1   │ ──────→ │ ZK 증명   │
│ (RISC-V 타겟) │         │  zkVM   │         │ (작고 빠름)│
└──────────────┘         └─────────┘         └──────────┘
```

1. 개발자가 **일반 Rust 코드**를 작성 (ZK 회로 지식 불필요)
2. 그 코드를 **RISC-V 명령어**로 컴파일
3. SP1이 RISC-V 명령어를 실행하면서 **자동으로 ZK 증명 생성**

### 왜 중요한가

예전에는 ZK 증명을 만들려면 "ZK 회로"를 직접 설계해야 했다. 이는 매우 어렵고 전문적인 작업이다.

| 방식 | 난이도 | 비유 |
|---|---|---|
| **직접 회로 설계** | 극도로 어려움 | 어셈블리로 프로그래밍 |
| **SP1 사용** | 일반 개발자도 가능 | Python으로 프로그래밍 |

SP1 덕분에 ZK 전문가가 아니어도 ZK 증명을 활용한 시스템을 구축할 수 있게 되었다.

### ethrex에서의 역할

ethrex의 L2 ZK-롤업에서:

```
1. EVM이 트랜잭션 실행 (훅으로 trace 수집)
2. trace를 SP1 guest program에 입력
3. SP1이 "이 EVM 실행이 올바르다"는 ZK 증명 생성
4. 증명을 L1에 제출
```

ethrex 레포의 `crates/guest-program/` 디렉토리에 SP1용 guest program이 있다. SP1 외에도 여러 zkVM 백엔드를 지원한다.

### zkVM 비교

| zkVM | 개발사 | 기반 ISA | 비고 |
|---|---|---|---|
| **SP1** | Succinct Labs | RISC-V | ethrex 기본 백엔드 |
| **RISC Zero** | RISC Zero Inc. | RISC-V | 가장 오래된 범용 zkVM |
| **ZisK** | Polygon | RISC-V | Polygon 생태계 |
| **OpenVM** | OpenVM | RISC-V | 오픈소스 |

모두 RISC-V 기반이라 일반 Rust 코드를 그대로 증명할 수 있다는 공통점이 있다.

### 이 Python 포팅과의 관계

시나리오 A(완전 독립 포팅)는 L1 전용이므로 SP1/ZK prover와 직접적인 관련이 없다. 다만 훅 시스템을 미리 설계해두면, 나중에 L2 확장 시 SP1 guest program과 연동할 수 있는 기반이 된다.

---

## 부록: zkVM vs 직접 회로 설계 — 에이전틱 코딩 시대에도 zkVM이 필요한가?

### 질문

에이전틱 코딩(AI 에이전트를 활용한 자동화된 소프트웨어 개발)이 가능한 시대에, 개발자가 ZK 회로를 직접 설계할 수 있지 않은가? 그렇다면 SP1 같은 zkVM이 필요한가?

### 에이전틱 코딩으로 가능한 부분

에이전틱 코딩이라면:

```
1. EVM 옵코드 스펙을 읽고
2. 각 옵코드의 circom/halo2 회로를 생성하고
3. 이더리움 공식 테스트 벡터로 검증하고
4. 실패하면 수정하고 반복
```

개별 옵코드 단위로는 실제로 가능하다. 실제로 직접 회로를 설계하는 프로젝트도 있다:

| 프로젝트 | 방식 | 결과 |
|---|---|---|
| **Polygon zkEVM** | 직접 회로 설계 | 증명 속도 빠름, 개발에 수년 소요 |
| **Scroll** | 직접 회로 설계 (halo2) | 증명 효율적, 팀 50명+ 투입 |
| **ethrex (SP1)** | zkVM 사용 | 빠른 개발, 증명 속도는 느림 |

### 핵심 트레이드오프

```
             개발 속도 ←────────────────→ 증명 속도
                │                            │
   SP1/zkVM    ███████████░░░░░░░░░░░        빠른 개발, 느린 증명 (10-100x 오버헤드)
   직접 설계    ░░░░░░░░░░░███████████        느린 개발 (수년), 빠른 증명
```

### 그래도 남는 문제: 형식 검증

에이전틱 코딩의 진짜 병목은 **형식 검증(formal verification)**이다.

#### 형식 검증이란?

"프로그램이 올바르다는 것을 **테스트가 아니라 수학적 증명**으로 보장하는 것"

```
테스트:     입력 10개를 넣어보고 → 10개 다 맞으면 → "아마 맞을 것이다"
형식 검증:  가능한 모든 입력에 대해 → 수학적으로 증명 → "반드시 맞다"
```

| | 테스트 | 형식 검증 |
|---|---|---|
| 방식 | 구체적 입력 몇 개로 확인 | 모든 가능한 입력에 대해 증명 |
| 확신 수준 | "이 케이스에서는 맞다" | "어떤 케이스에서도 맞다" |
| 비유 | 다리에 트럭 10대를 올려봄 | 구조역학으로 하중 한계를 수학적으로 계산 |

#### ZK 회로에서 형식 검증이 필수인 이유

일반 코드 버그는 크래시를 일으켜 발견이 쉽다. ZK 회로 버그는 **조용히 가짜 증명을 통과**시킨다:

```
정상:  "A가 B에게 100 ETH 보냄" → 올바른 증명 → L1 승인
버그:  "A가 100만 ETH를 무에서 생성" → 가짜 증명이 통과 → L1 승인 → 자금 탈취
```

테스트로는 놓칠 수 있다 — 정상 입력에서는 작동하지만, 공격자가 만든 특수 입력에서만 뚫리기 때문이다.

| | 일반 코드 | ZK 회로 |
|---|---|---|
| 버그가 있으면 | 테스트 실패 / 크래시 | **테스트 통과할 수도 있음** |
| 결과 | 서비스 장애 | **수십억 달러 탈취 가능** |
| 발견 방법 | 로그, 디버거 | 형식 검증 필요 |

에이전틱 코딩은 "테스트를 통과하는 코드"를 잘 만든다. 하지만 "모든 가능한 입력에서 soundness가 보장되는 회로"를 만드는 건 다른 문제다.

#### 형식 검증의 현실적 한계

| 장점 | 한계 |
|---|---|
| 수학적 확신 | 검증 자체가 매우 어렵고 느림 |
| 모든 입력 커버 | 검증 속성을 잘못 정의하면 무의미 |
| 한 번 하면 영구적 | 코드가 바뀌면 다시 해야 함 |

현재 형식 검증 도구: Coq, Isabelle, Lean, Z3, Dafny 등

### 결론

SP1 같은 zkVM이 현재 선택되는 이유:

1. **안전성**: 일반 Rust 코드는 감사가 쉽고, 회로 버그는 치명적
2. **유지보수**: 이더리움 하드포크 시 Rust 코드만 수정 (회로 재설계 불필요)
3. **개발 속도**: 소규모 팀도 ZK-롤업 구축 가능
4. **증명 속도 격차 감소 중**: SP1 v2, v3로 갈수록 오버헤드 줄어드는 추세

하지만 장기적으로 에이전틱 코딩 + 형식 검증 도구가 성숙하면, 직접 설계의 진입장벽이 낮아져 zkVM의 존재 의미가 줄어들 수 있다. **양쪽 모두 수렴하는 방향으로 발전 중**이다.

---

## 부록 F: zkVM의 기반 ISA — RISC-V와 대안들

### ISA (Instruction Set Architecture)란?

ISA는 CPU가 이해하는 명령어 집합의 사양이다. 프로그래머가 작성한 고수준 코드(Rust, C 등)는 컴파일러에 의해 특정 ISA의 기계어로 변환된다.

### zkVM에서 RISC-V를 쓴다는 의미

zkVM은 "프로그램을 실행하면서 동시에 그 실행이 올바르다는 ZK 증명을 생성하는 가상 머신"이다.

```
일반 실행: Rust 코드 → RISC-V 기계어 → 실제 CPU에서 실행
zkVM 실행: Rust 코드 → RISC-V 기계어 → zkVM이 "시뮬레이션" 실행 → ZK 증명 생성
```

RISC-V를 기반 ISA로 선택한 이유:

1. **단순성**: RISC-V는 ~47개의 기본 명령어만 가짐 (x86은 ~1,500개+). 명령어가 적을수록 ZK 회로로 변환하기 쉬움
2. **규칙성**: 모든 명령어가 고정 길이(32비트), 디코딩이 단순함
3. **개방성**: 오픈 ISA라 라이센스 비용 없음
4. **생태계**: GCC, LLVM 등 성숙한 컴파일러가 이미 RISC-V를 지원 → Rust, C, C++를 바로 컴파일 가능
5. **범용성**: 이더리움 EVM과 달리 범용 프로그램을 실행할 수 있음

### 대안 ISA 비교

| ISA | 사용 예시 | 특징 |
|---|---|---|
| **RISC-V** | SP1, RISC Zero, ZisK, OpenVM | 가장 인기. 단순하고 범용적 |
| **MIPS** | zkMIPS (ZKM) | MIPS도 RISC 계열로 단순. 기존 MIPS 바이너리 검증에 유리 |
| **WASM** | zkWasm, Delphinus | 웹 생태계와 호환. 브라우저에서 실행되는 프로그램 검증에 적합 |
| **EVM** | zkEVM (Polygon, Scroll, Taiko) | 이더리움 바이트코드를 직접 증명. 범용이 아닌 이더리움 특화 |
| **Cairo VM** | StarkNet (StarkWare) | ZK 증명에 최적화된 전용 ISA. 증명 효율 최고지만 별도 언어(Cairo) 필요 |
| **커스텀 VM** | Valida (Lita Foundation) | ZK 증명 최적화를 위해 완전히 새로운 ISA 설계 |

### 핵심 트레이드오프

```
범용성 (기존 언어 지원)     ←→     증명 효율성
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RISC-V / MIPS / WASM                Cairo VM / 커스텀 VM
"Rust로 짠 코드 그대로 증명"          "전용 언어로 짜야 하지만 증명 10-100배 빠름"
```

- **RISC-V 계열**: 개발자 경험 우선. 기존 Rust/C 코드를 수정 없이 증명 가능. 하지만 범용 ISA라 ZK 회로가 복잡해져 증명 속도가 느림
- **Cairo/커스텀**: 증명 효율 우선. 필드 연산에 최적화된 명령어 설계. 하지만 별도 언어를 배워야 함

### 최근 트렌드

RISC-V가 사실상 표준으로 수렴하는 추세:
- SP1, RISC Zero, ZisK, OpenVM 등 주요 프로젝트가 모두 RISC-V 채택
- "어떤 프로그래밍 언어로든 작성하면 증명 가능"이라는 가치가 개발자 채택에 결정적
- StarkWare도 Cairo에서 점차 범용 지원 확대 중
