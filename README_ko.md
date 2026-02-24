# py-ethclient

**Python L2 개발 플랫폼 — 순수 Python으로 애플리케이션 특화 ZK 롤업을 구축**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-943%20passing-brightgreen)](#testing)
[![LOC](https://img.shields.io/badge/LOC-21%2C442-blue)](#project-stats)

py-ethclient는 **애플리케이션 특화 ZK 롤업**을 구축하기 위한 Python L2 개발 플랫폼입니다. 상태 전이 함수를 일반 Python 함수로 정의하면, py-ethclient가 시퀀싱, 배치 생성, Groth16 증명, L1 검증까지 모두 처리합니다.

[ethrex](https://github.com/lambdaclass/ethrex) (Rust)에서 영감을 받아 완전히 독립적으로 구현한 이더리움 L1 실행 클라이언트를 기반으로 합니다. devp2p/RLPx를 통해 이더리움 P2P 네트워크에 직접 연결하며, 140개 이상의 옵코드를 지원하는 EVM과 full sync/snap sync를 통한 메인넷·Sepolia 동기화를 지원합니다. 내장된 **Groth16 ZK 증명**, **L1↔L2 General State Bridge**, **애플리케이션 특화 롤업 프레임워크**를 통해 L2 프로토콜과 ZK circuit을 가장 빠르게 프로토타이핑할 수 있습니다.

RLP 인코딩, 머클 패트리시아 트라이, EVM 실행, RLPx 전송 암호화, eth/68·snap/1 와이어 프로토콜, Discovery v4, Engine API, Groth16 ZK 증명, L1↔L2 브릿지, L2 롤업 프레임워크 등 모든 핵심 프로토콜 로직을 순수 Python으로 직접 구현했습니다. 외부 의존성은 암호화 프리미티브와 웹 프레임워크만 사용합니다.

> **[English README](./README.md)**

## 목차

- [주요 기능](#주요-기능)
- [왜 py-ethclient인가?](#왜-py-ethclient인가)
- [L2 롤업 프레임워크](#l2-롤업-프레임워크)
- [L2 브릿지](#l2-브릿지)
- [ZK 툴킷](#zk-툴킷)
- [Requirements](#requirements)
- [Installation](#installation)
- [Docker](#docker)
- [Quick Start](#quick-start)
- [JSON-RPC API](#json-rpc-api)
- [Testing](#testing)
- [Architecture](#architecture)
- [Dependencies](#dependencies)
- [Implementation Details](#implementation-details)
- [Project Stats](#project-stats)
- [FAQ](#faq)

## 주요 기능

- **애플리케이션 특화 ZK 롤업** — 롤업 로직을 Python 함수(State Transition Function)로 정의하고 Rollup 오케스트레이터에 연결하면, 시퀀싱, Groth16 증명, L1 검증이 자동으로 처리됩니다
- **4개의 플러거블 인터페이스** — StateTransitionFunction, DAProvider, L1Backend, ProofBackend — 어떤 컴포넌트든 나머지를 건드리지 않고 교체 가능
- **전체 증명-검증 파이프라인** — Sequencer → Batch → Groth16 Proof → L1 Verification, 단일 Python 프로세스에서 완료
- **L2 RPC API** — 트랜잭션 제출, 상태 조회, 배치 생성, 증명 제출을 위한 7개 `l2_*` JSON-RPC 메서드
- **L1↔L2 General State Bridge** — Optimism 스타일 CrossDomainMessenger로 플러거블 릴레이 핸들러 (EVM, Merkle proof, ZK proof, TinyDB, direct state), force inclusion (검열 저항), escape hatch (가치 복구)
- **Groth16 ZK 툴킷** — Circuit 정의, trusted setup, proof 생성, 네이티브 + EVM 검증, gas 프로파일링, snarkjs 호환 — 모두 순수 Python
- **Full EVM** — 140+ 옵코드, 프리컴파일 (ecrecover, SHA-256, RIPEMD-160, modexp, BN128, BLAKE2f, KZG), EIP-1559/2929/2930/4844/7702 지원
- **이더리움 P2P 네트워킹** — RLPx 암호화 전송, eth/68·snap/1 와이어 프로토콜, Discovery v4 Kademlia 라우팅
- **동기화 모드** — Full sync (순차 블록 실행) 및 snap sync (4단계 병렬 상태 다운로드)
- **JSON-RPC 2.0** — `eth_call`, `eth_estimateGas`, 트랜잭션/영수증 조회, 로그 쿼리, `zk_` 및 `l2_` 네임스페이스 등 20개 이상 메서드
- **Engine API V1/V2/V3** — `forkchoiceUpdated`, `getPayload`, `newPayload` + JWT 인증으로 합의 레이어 연동
- **영속 스토리지** — LMDB 기반 디스크 백엔드, 하이브리드 오버레이 패턴으로 원자적 상태 커밋
- **멀티 네트워크** — 메인넷, Sepolia, Holesky 지원 (네트워크별 genesis 및 하드포크 설정)
- **943개 테스트** — RLP부터 ZK 증명, L2 롤업, 통합 테스트까지 전 프로토콜 레이어를 커버하는 포괄적 테스트 스위트
- **Docker 지원** — Docker Compose로 간편 배포

## 왜 py-ethclient인가?

이더리움 네트워크의 건강성을 위해 클라이언트 다양성은 매우 중요합니다. py-ethclient는 Python으로 작성된 유일한 이더리움 실행 클라이언트로, 다음과 같은 고유한 가치를 제공합니다:

- **애플리케이션 특화 L2 개발** — 롤업 로직을 일반 Python 함수로 작성하세요. 프레임워크가 시퀀싱, 배치, Groth16 증명, L1 검증을 처리합니다. Solidity도, circom도, 복잡한 툴체인도 필요 없습니다 — Python만 있으면 됩니다
- **ZK Circuit 개발** — Python으로 circuit을 정의하고, proof를 생성하고, on-chain 검증을 Jupyter 노트북 하나에서 테스트할 수 있습니다. circom/snarkjs/Solidity 툴체인이 필요 없으며, AI 코딩 에이전트와 함께 ZK 애플리케이션을 프로토타이핑하는 가장 빠른 방법입니다
- **교육 & 연구** — Python의 높은 가독성 덕분에 이더리움이 프로토콜 수준에서 어떻게 동작하는지 이해하기 위한 최적의 코드베이스입니다. EVM, RLPx, 머클 트라이, 동기화 등 모든 컴포넌트가 명확하고 읽기 쉬운 Python으로 구현되어 있습니다
- **빠른 프로토타이핑** — 새로운 EIP, 커스텀 옵코드, 합의 변경 사항을 며칠이 아닌 몇 시간 만에 테스트할 수 있습니다. Python의 동적 특성이 프로토콜 실험의 빠른 반복을 가능하게 합니다
- **클라이언트 다양성** — Go, Rust, C#, Java에 이어 Python 클라이언트를 추가함으로써 구현 특화 버그에 대한 네트워크의 복원력을 강화합니다

### 다른 실행 클라이언트와의 비교

| | py-ethclient | [geth](https://github.com/ethereum/go-ethereum) | [reth](https://github.com/paradigmxyz/reth) | [nethermind](https://github.com/NethermindEth/nethermind) |
|---|---|---|---|---|
| **언어** | Python | Go | Rust | C# |
| **목적** | L2 개발, ZK, 교육 | 프로덕션 | 프로덕션 | 프로덕션 |
| **앱 특화 롤업** | 내장 프레임워크 | N/A | N/A | N/A |
| **ZK 증명** | Groth16 내장 | N/A | N/A | N/A |
| **L2 브릿지** | CrossDomainMessenger 내장 | N/A | N/A | N/A |
| **EVM** | 140+ 옵코드 | 전체 | 전체 | 전체 |
| **동기화 모드** | Full + Snap | Full + Snap + Light | Full + Snap | Full + Snap + Fast |
| **Engine API** | V1/V2/V3 | V1/V2/V3 | V1/V2/V3 | V1/V2/V3 |
| **P2P 프로토콜** | eth/68, snap/1 | eth/68, snap/1 | eth/68, snap/1 | eth/68, snap/1 |
| **코드 가독성** | 매우 높음 | 높음 | 보통 | 보통 |

## L2 롤업 프레임워크

py-ethclient에는 완전한 **애플리케이션 특화 ZK 롤업 프레임워크**가 포함되어 있습니다. 상태 전이 로직을 일반 Python 함수로 정의하면, 프레임워크가 시퀀싱, 배치 생성, Groth16 증명, L1 검증을 처리합니다.

### 빠른 예제: Counter 롤업

```python
from ethclient.l2 import Rollup, L2Tx, L2TxType

# 1. State Transition Function 정의 — 일반 Python 함수입니다
def counter_stf(state, tx):
    count = state.get("count", 0)
    if tx.data.get("action") == "increment":
        state["count"] = count + 1
        return {"new_count": count + 1}

# 2. STF로 Rollup 생성
rollup = Rollup(stf=counter_stf)
rollup.setup()  # Groth16 trusted setup + L1 검증자 배포

# 3. 트랜잭션 제출
tx = L2Tx(sender=b"\x01"*20, nonce=0, data={"action": "increment"},
          tx_type=L2TxType.CALL)
rollup.submit_tx(tx)

# 4. 배치 생성 + 증명 + L1 검증
batch = rollup.produce_batch()
receipt = rollup.prove_and_submit(batch)

assert receipt.verified          # L1이 증명을 수락
assert rollup.state["count"] == 1
```

### 동작 원리

```
User Tx → Sequencer → State Transition Function → Batch Assembly
                                                        ↓
                          L1 Verification ← Groth16 Proof ← DA Storage
```

1. **Sequencer**가 트랜잭션을 수신, 논스를 검증하고, 스냅샷/롤백으로 STF를 실행합니다
2. `max_txs_per_batch`에 도달하거나 `force_seal()`이 호출되면 **Batch**가 봉인됩니다
3. **Groth16 Prover**가 old_state_root → new_state_root 전이에 대한 ZK 증명을 생성합니다
4. **L1 Backend**가 증명을 검증하고 새로운 상태 루트를 기록합니다

### 플러거블 컴포넌트

프레임워크는 4개의 플러거블 인터페이스를 사용합니다 — 어떤 컴포넌트든 나머지를 건드리지 않고 교체 가능합니다:

| 인터페이스 | 기본 구현 | 설명 |
|---|---|---|
| `StateTransitionFunction` | `PythonRuntime` (callable 래핑) | 롤업 로직 |
| `DAProvider` | `LocalDAProvider` (인메모리) | 데이터 가용성 저장소 |
| `ProofBackend` | `Groth16ProofBackend` | ZK 증명 생성 및 검증 |
| `L1Backend` | `InMemoryL1Backend` | L1 컨트랙트 상호작용 (검증자) |

```python
from ethclient.l2 import Rollup, L2Config

# 커스텀 설정
config = L2Config(
    name="my-rollup",
    chain_id=42170,
    max_txs_per_batch=128,
    batch_timeout=30,
    rpc_port=9545,
)

# 커스텀 컴포넌트 연결
rollup = Rollup(
    stf=my_stf_function,
    da=my_custom_da,        # DAProvider 구현
    l1=my_l1_backend,       # L1Backend 구현
    prover=my_prover,       # ProofBackend 구현
    config=config,
)
```

### 예제 앱

롤업 프레임워크의 실전 활용법을 보여주는 4개 예제 앱:

| 예제 | 설명 | 실행 |
|---|---|---|
| **ERC20 토큰** | Mint, transfer, burn + 관리자 권한 | `python examples/l2_token.py` |
| **네임 서비스** | ENS 스타일 도메인 등록, 수정, 이전 | `python examples/l2_nameservice.py` |
| **투표/거버넌스** | 제안 생성, 가중 투표, 정족수 기반 확정 | `python examples/l2_voting.py` |
| **가위바위보** | Commit-reveal 방식 게임 + 베팅/정산 | `python examples/l2_rps_game.py` |

모든 예제가 동일한 패턴: STF 정의 → `PythonRuntime` 래핑 → `Rollup` 생성 → tx 제출 → batch 생성 → L1 증명/검증.

### 잔액 이체 예제

```python
def balance_stf(state, tx):
    action = tx.data.get("action")
    if action == "mint":
        addr = tx.data["to"]
        amount = tx.data["amount"]
        state[addr] = state.get(addr, 0) + amount
        return {"minted": amount, "to": addr}
    elif action == "transfer":
        src, dst = tx.data["from"], tx.data["to"]
        amount = tx.data["amount"]
        if state.get(src, 0) < amount:
            raise ValueError("insufficient balance")
        state[src] -= amount
        state[dst] = state.get(dst, 0) + amount
        return {"transferred": amount}

rollup = Rollup(stf=balance_stf)
rollup.setup()
# mint, transfer, 배치 생성, 증명, 검증 — 모두 동작
```

### L2 CLI

```bash
# 새 롤업 프로젝트 스캐폴딩
ethclient l2 init --name my-rollup

# 생성되는 파일:
#   l2.json      — 롤업 설정
#   stf.py       — State Transition Function 템플릿

# 롤업 노드 시작 (stf.py 로드, RPC 서버 기동)
ethclient l2 start --config l2.json --rpc-port 9545

# 봉인된 배치에 대한 ZK 증명 생성
ethclient l2 prove --config l2.json

# 증명된 배치를 L1에 제출
ethclient l2 submit --config l2.json
```

### L2 RPC API

L2 모듈과 함께 실행하면 7개의 추가 JSON-RPC 메서드를 사용할 수 있습니다:

| 메서드 | 설명 |
|---|---|
| `l2_sendTransaction` | 롤업에 트랜잭션 제출 |
| `l2_getState` | 현재 롤업 상태 조회 |
| `l2_getStateRoot` | 현재 Merkle 상태 루트 조회 |
| `l2_getBatch` | 봉인된 배치 번호로 조회 |
| `l2_produceBatch` | 배치 생성 트리거 |
| `l2_proveAndSubmit` | 배치 증명 및 L1 제출 |
| `l2_chainInfo` | 롤업 체인 정보 조회 |

## L2 브릿지

py-ethclient에는 **L1↔L2 General State Bridge**가 내장되어 있습니다 — Optimism 스타일의 `CrossDomainMessenger`로 L1과 L2 간 임의 메시지를 릴레이하며, 타겟 도메인의 EVM에서 실제 상태 변경을 실행합니다.

```python
from ethclient.bridge import BridgeEnvironment

# L1 + L2 환경 생성 (독립 EVM 2개 + watcher)
env = BridgeEnvironment()

# 입금: Alice가 L1에서 Bob에게 1 ETH 전송
env.send_l1(sender=alice, target=bob, value=1000)
result = env.relay()  # watcher가 L1→L2 릴레이
assert result.all_success
assert env.l2_balance(bob) == 1000

# 상태 릴레이: L2 컨트랙트에 임의 calldata 전달
env.send_l1(sender=alice, target=oracle, data=price_calldata)
env.relay()  # L2의 EVM에서 calldata 실행
```

### 검열 저항 (Anti-Censorship)

L2 오퍼레이터가 메시지를 검열할 경우, 사용자가 이를 우회할 수 있습니다:

| 메커니즘 | 설명 |
|---|---|
| **Force Inclusion** | 검열된 메시지를 L1에 등록 → 50블록 후 누구나 L2에 강제 릴레이 가능 |
| **Escape Hatch** | 최후 수단: L2가 무응답일 때 L1에서 직접 입금 가치 복구 |

```python
# 오퍼레이터가 Alice의 메시지를 검열
msg = env.send_l1(sender=alice, target=bob, value=1000)
env.l1_messenger.drain_outbox()  # 오퍼레이터가 가져가고 릴레이 안 함

# Force inclusion 경로
env.force_include(msg)
env.advance_l1_block(50)  # inclusion window 대기
result = env.force_relay(msg)
assert result.success  # 오퍼레이터 우회 성공

# 또는 escape hatch (L1에서 가치 복구)
result = env.escape_hatch(msg)
assert env.l1_balance(alice) == 1000  # 가치 반환
```

### 플러거블 릴레이 핸들러

브릿지는 다양한 릴레이 모드를 지원합니다 — L2가 EVM을 실행할 필요가 없습니다:

| 핸들러 | 신뢰 모델 | EVM 필요 |
|---|---|---|
| `EVMRelayHandler` | On-chain 실행 (기본) | Yes |
| `MerkleProofHandler` | 신뢰된 L1 상태 루트에 대한 Merkle proof | No |
| `ZKProofHandler` | Groth16 영지식 증명 | No |
| `TinyDBHandler` | 문서 DB 백엔드 (TinyDB) | No |
| `DirectStateHandler` | 신뢰 릴레이어 | No |

```python
from ethclient.bridge import BridgeEnvironment, StateUpdate, encode_state_updates

# Direct state 릴레이 (EVM 불필요)
env = BridgeEnvironment.with_direct_state()
updates = [StateUpdate(address=alice, balance=1000)]
env.send_l1(sender=alice, target=bob, data=encode_state_updates(updates))
env.relay()

# ZK proof 릴레이
env = BridgeEnvironment.with_zk_proof(vk)  # Groth16 verification key 전달
```

전체 데모 실행:

```bash
python examples/general_state_bridge.py
```

## ZK 툴킷

py-ethclient에는 **Groth16 ZK 증명 툴킷**이 내장되어 있습니다 — circuit 정의, proof 생성, EVM on-chain 검증을 단일 프로세스에서 실행할 수 있는 유일한 Python 환경입니다.

```python
from ethclient.zk import Circuit, groth16
from ethclient.zk.evm_verifier import EVMVerifier

# 1. Circuit 정의 (Python 표현식)
c = Circuit()
x, y = c.private("x"), c.private("y")
z = c.public("z")
c.constrain(x * y, z)   # R1CS: x * y = z

# 2. Trusted setup
pk, vk = groth16.setup(c)

# 3. Proof 생성
proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)

# 4. 네이티브 검증
assert groth16.verify(vk, proof, [15])

# 5. EVM on-chain 검증 (내장 EVM + ecPairing 프리컴파일 사용)
result = EVMVerifier(vk).verify_on_evm(proof, [15])
assert result.success  # gas_used ≈ 210,000
```

### 포함 구성요소

| 컴포넌트 | 설명 |
|---|---|
| **Circuit Builder** | Python 연산자 오버로딩으로 R1CS constraint 정의 |
| **Groth16 Prover** | 전체 증명 파이프라인: R1CS → QAP → trusted setup → proof 생성 |
| **네이티브 Verifier** | 디버그 모드 지원 (중간 pairing 값 확인 가능) |
| **EVM Verifier** | ecAdd/ecMul/ecPairing 프리컴파일을 사용하는 검증자 바이트코드 자동 생성 |
| **Gas Profiler** | 프리컴파일별 gas 분석으로 on-chain 비용 최적화 |
| **snarkjs 호환** | snarkjs JSON 포맷 (vkey, proof, public inputs) import/export |
| **ZK RPC API** | `zk_verifyGroth16`, `zk_deployVerifier`, `zk_verifyOnChain` 엔드포인트 |

### circom + snarkjs 대비 장점

| | circom + snarkjs + Hardhat | py-ethclient |
|---|---|---|
| **필요한 언어** | circom (DSL) + Node.js + Solidity | Python만 |
| **설치할 도구** | Rust 컴파일러 + Node.js + Solidity 툴체인 | `pip install py-ethclient` |
| **Circuit → Proof → Verify** | 5개 CLI 명령, 3개 도구 | Python 함수 호출 3줄 |
| **EVM 테스트** | 테스트넷 배포 필요 | 인메모리 EVM, 즉시 실행 |
| **실패 디버깅** | hex 덤프 분석 | Python traceback + pairing 값 |
| **AI 에이전트 친화성** | 여러 도구, 니치 DSL | Python (AI 에이전트가 가장 잘 쓰는 언어) |
| **반복 속도** | 분 단위 (컴파일 → 셋업 → 증명 → 배포) | 초 단위 |

전체 데모 실행:

```bash
python examples/zk_notebook_demo.py
```

## Requirements

- Python 3.12+
- 시스템 의존성: `snappy` 라이브러리 (python-snappy 빌드에 필요)

### macOS

```bash
brew install snappy
```

### Ubuntu/Debian

```bash
sudo apt install libsnappy-dev
```

## Installation

```bash
# 저장소 클론
git clone https://github.com/tokamak-network/py-ethclient.git
cd py-ethclient

# 가상환경 생성 및 활성화
python -m venv .venv
source .venv/bin/activate

# 패키지 설치 (editable mode)
pip install -e ".[dev]"
```

## Docker

```bash
# 빌드 및 실행 (메인넷)
docker compose up -d

# Sepolia 테스트넷
NETWORK=sepolia docker compose up -d

# 디버그 로깅
LOG_LEVEL=DEBUG docker compose up -d

# 로그 확인
docker compose logs -f

# 종료
docker compose down
```

수동 빌드:

```bash
docker build -t py-ethclient .
docker run -p 30303:30303 -p 8545:8545 py-ethclient --network sepolia
```

## Quick Start

### L2 롤업 모드

```bash
# 새 롤업 프로젝트 스캐폴딩
ethclient l2 init --name my-rollup

# stf.py를 편집하여 State Transition Function 정의
# 그 다음 롤업 노드 시작
ethclient l2 start --config l2.json
```

### L1 노드 모드

```bash
# 기본 실행 (mainnet, snap sync, 포트 30303/8545)
ethclient

# Sepolia 테스트넷 연결
ethclient --network sepolia

# Full sync 모드 (snap sync 대신)
ethclient --network sepolia --sync-mode full

# 커스텀 설정
ethclient --network sepolia --port 30304 --rpc-port 8546 --max-peers 10

# 커스텀 genesis 파일로 실행
ethclient --genesis ./genesis.json --port 30303
```

### CLI Options

**L2 명령어**

| 명령어 | 설명 |
|---|---|
| `ethclient l2 init --name <name>` | 새 롤업 프로젝트 스캐폴딩 (l2.json + stf.py 생성) |
| `ethclient l2 start --config <path>` | L2 롤업 노드 시작 (STF 로드, RPC 서버 기동) |
| `ethclient l2 prove --config <path>` | 봉인된 배치에 대한 ZK 증명 생성 |
| `ethclient l2 submit --config <path>` | 증명된 배치를 L1에 제출 |

**L1 노드 옵션**

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `--network` | `mainnet` | 네트워크 선택 (`mainnet`, `sepolia`, `holesky`) |
| `--genesis` | - | 커스텀 genesis.json 파일 경로 |
| `--port` | `30303` | P2P TCP/UDP 리슨 포트 |
| `--rpc-port` | `8545` | JSON-RPC HTTP 리슨 포트 |
| `--max-peers` | `25` | 최대 피어 연결 수 |
| `--bootnodes` | 네트워크 기본값 | 부트노드 enode URL (콤마 구분) |
| `--private-key` | 자동 생성 | 노드 ID용 secp256k1 private key (hex) |
| `--log-level` | `INFO` | 로그 레벨 (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `--sync-mode` | `snap` | 동기화 모드: `snap` (빠른 상태 다운로드) 또는 `full` (순차 블록 실행) |
| `--data-dir` | - | 영속 저장소용 데이터 디렉토리 (미설정 시 인메모리) |
| `--datadir` | - | `--data-dir` 별칭 (geth 호환) |
| `--engine-port` | `8551` | Engine API JSON-RPC 리슨 포트 |
| `--metrics-port` | `6060` | Prometheus 메트릭 리슨 포트 |
| `--bootnode-only` | off | 설정된 부트노드에만 다이얼 |
| `--archive` | off | 히스토리컬 상태 조회를 위한 아카이브 모드 활성화 |
| `--jwt-secret` | - | Engine API 인증용 JWT 시크릿 또는 파일 경로 |

## JSON-RPC API

`http://localhost:8545` 에서 JSON-RPC 2.0 엔드포인트를 제공합니다.

### 지원 메서드

**l2_ namespace** (L2 롤업 작업)

| 메서드 | 설명 |
|---|---|
| `l2_sendTransaction` | 롤업에 트랜잭션 제출 |
| `l2_getState` | 현재 롤업 상태 dict 조회 |
| `l2_getStateRoot` | 현재 Merkle 상태 루트 조회 (hex) |
| `l2_getBatch` | 봉인된 배치 번호로 조회 |
| `l2_produceBatch` | 배치 생성 트리거 |
| `l2_proveAndSubmit` | 배치 증명 및 L1 제출 |
| `l2_chainInfo` | 롤업 체인 정보 조회 |

**eth_ namespace**

| 메서드 | 설명 |
|---|---|
| `eth_blockNumber` | 최신 블록 번호 |
| `eth_getBlockByNumber` | 블록 번호로 블록 조회 |
| `eth_getBlockByHash` | 블록 해시로 블록 조회 |
| `eth_getBalance` | 계정 잔액 조회 |
| `eth_getTransactionCount` | 계정 논스 조회 |
| `eth_getCode` | 컨트랙트 코드 조회 |
| `eth_getStorageAt` | 스토리지 슬롯 조회 |
| `eth_sendRawTransaction` | 서명된 트랜잭션 제출 |
| `eth_call` | EVM을 통한 읽기 전용 컨트랙트 호출 |
| `eth_estimateGas` | EVM 실행 기반 가스 추정 |
| `eth_gasPrice` | 현재 가스 가격 |
| `eth_maxPriorityFeePerGas` | 우선순위 수수료 |
| `eth_feeHistory` | 수수료 히스토리 |
| `eth_chainId` | 체인 ID |
| `eth_syncing` | 동기화 상태 |
| `eth_getTransactionByHash` | 트랜잭션 해시로 조회 |
| `eth_getTransactionReceipt` | 트랜잭션 영수증 조회 |
| `eth_getBlockTransactionCountByNumber` | 블록 내 트랜잭션 수 (번호) |
| `eth_getBlockTransactionCountByHash` | 블록 내 트랜잭션 수 (해시) |
| `eth_getLogs` | 로그 필터 조회 |
| `eth_getBlockReceipts` | 블록 영수증 조회 |

**net_ namespace**

| 메서드 | 설명 |
|---|---|
| `net_version` | 네트워크 ID |
| `net_peerCount` | 연결된 피어 수 |
| `net_listening` | 리스닝 상태 |

**web3_ namespace**

| 메서드 | 설명 |
|---|---|
| `web3_clientVersion` | 클라이언트 버전 |
| `web3_sha3` | Keccak-256 해시 |

**engine_ namespace** (`--engine-port`에서 제공, JWT 인증)

| 메서드 | 설명 |
|---|---|
| `engine_exchangeCapabilities` | Capability 협상 |
| `engine_getClientVersionV1` | 클라이언트 버전 정보 |
| `engine_forkchoiceUpdatedV1/V2/V3` | Fork choice 상태 업데이트 + 페이로드 빌드 트리거 |
| `engine_getPayloadV1/V2/V3` | 빌드된 실행 페이로드 조회 |
| `engine_newPayloadV1/V2/V3` | 실행 페이로드 검증 및 임포트 |

**zk_ namespace**

| 메서드 | 설명 |
|---|---|
| `zk_verifyGroth16` | Groth16 proof 검증 (snarkjs 및 네이티브 포맷 지원) |
| `zk_deployVerifier` | 검증자 컨트랙트 배포 및 바이트코드 + gas 추정 반환 |
| `zk_verifyOnChain` | 인메모리 EVM에서 on-chain proof 검증 |

### 사용 예시

```bash
# L2 트랜잭션 제출
curl -X POST http://localhost:9545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"l2_sendTransaction","params":[{"sender":"0x01","data":{"action":"increment"}}],"id":1}'

# L2 상태 루트 조회
curl -X POST http://localhost:9545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"l2_getStateRoot","params":[],"id":1}'

# 최신 블록 번호 조회 (L1)
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

## Testing

```bash
# 전체 테스트 실행 (943개)
pytest

# L2 롤업 테스트
pytest tests/test_l2_types.py            # L2 타입, 인코딩, 상태 스냅샷
pytest tests/test_l2_da.py               # 데이터 가용성 프로바이더
pytest tests/test_l2_da_providers.py     # 프로덕션 DA 프로바이더 (S3, Calldata, Blob)
pytest tests/test_l2_runtime.py          # Python STF 런타임 래퍼
pytest tests/test_l2_sequencer.py        # 시퀀서, mempool, 배치 조립
pytest tests/test_l2_sequencer_hardening.py # 시퀀서 입력 검증, 방어적 검사
pytest tests/test_l2_prover.py           # Groth16 증명 백엔드
pytest tests/test_l2_native_prover.py    # 네이티브 프로버 (rapidsnark/snarkjs subprocess)
pytest tests/test_l2_l1.py               # L1 백엔드, 증명 검증
pytest tests/test_l2_eth_l1_backend.py   # 실제 이더리움 L1 백엔드 (JSON-RPC)
pytest tests/test_l2_rpc.py              # L2 RPC API (l2_* 메서드)
pytest tests/test_l2_state.py            # 상태 저장소 경계 검사, 결정론성
pytest tests/test_l2_persistent_state.py # LMDB 영속 상태, 오버레이, WAL
pytest tests/test_l2_health.py           # Health/ready 엔드포인트
pytest tests/test_l2_middleware.py       # RPC 미들웨어 (API key, rate limit, request size)
pytest tests/test_l2_integration.py      # 전체 사이클: STF → 배치 → 증명 → L1 검증

# L1 클라이언트 테스트
pytest tests/test_rlp.py                 # RLP 인코딩/디코딩
pytest tests/test_trie.py                # 머클 패트리시아 트라이
pytest tests/test_trie_proofs.py         # 트라이 머클 증명 & 범위 검증
pytest tests/test_evm.py                 # EVM 옵코드 실행
pytest tests/test_storage.py             # 상태 저장소
pytest tests/test_blockchain.py          # 블록 검증/실행
pytest tests/test_p2p.py                 # P2P 네트워킹
pytest tests/test_protocol_registry.py   # 멀티 프로토콜 capability 협상
pytest tests/test_snap_messages.py       # snap/1 메시지 인코딩/디코딩
pytest tests/test_snap_sync.py           # Snap sync 상태 머신
pytest tests/test_rpc.py                 # JSON-RPC 서버 + Engine API
pytest tests/test_disk_backend.py        # LMDB 영속 스토리지

# ZK 테스트
pytest tests/test_zk_circuit.py          # ZK circuit 빌더 (R1CS)
pytest tests/test_zk_groth16.py          # Groth16 prove/verify + snarkjs 호환
pytest tests/test_zk_evm.py              # EVM 기반 ZK 검증

# 브릿지 테스트
pytest tests/test_bridge_messenger.py    # L2 브릿지 메신저 전송/릴레이
pytest tests/test_bridge_e2e.py          # L2 브릿지 E2E 시나리오
pytest tests/test_bridge_censorship.py   # Force inclusion + escape hatch
pytest tests/test_bridge_proof_relay.py  # Proof 기반 릴레이 핸들러

# 통합 테스트
pytest tests/test_integration.py         # 모듈 간 통합

# 상세 출력
pytest -v
```

## Architecture

```
ethclient/
├── main.py                          # CLI 진입점, 노드 초기화
├── l2/                              # 애플리케이션 특화 ZK 롤업 프레임워크
│   ├── types.py                     # L2Tx, L2State, Batch, BatchReceipt, STFResult
│   ├── config.py                    # L2Config (chain_id, 배치 크기, 타임아웃)
│   ├── interfaces.py                # 4개 ABC: STF, DAProvider, L1Backend, ProofBackend
│   ├── state.py                     # L2StateStore (Trie 기반 Merkle 상태 루트)
│   ├── runtime.py                   # PythonRuntime (callable → STF 래핑)
│   ├── da.py                        # LocalDAProvider (인메모리 DA)
│   ├── da_s3.py                     # S3DAProvider (AWS S3 DA)
│   ├── da_calldata.py               # CalldataDAProvider (EIP-1559 L1 calldata DA)
│   ├── da_blob.py                   # BlobDAProvider (EIP-4844 blob DA)
│   ├── sequencer.py                 # Sequencer (mempool, 논스 추적, 배치 조립)
│   ├── prover.py                    # Groth16ProofBackend (circuit → proof → verify)
│   ├── native_prover.py             # NativeProverBackend (rapidsnark/snarkjs subprocess)
│   ├── l1_backend.py                # InMemoryL1Backend (검증자 시뮬레이션)
│   ├── eth_l1_backend.py            # EthL1Backend (실제 이더리움 L1 JSON-RPC 연동)
│   ├── eth_rpc.py                   # 경량 이더리움 JSON-RPC 클라이언트
│   ├── persistent_state.py          # L2PersistentStateStore (LMDB 상태, 오버레이, WAL)
│   ├── submitter.py                 # BatchSubmitter (prove → submit → verify 파이프라인)
│   ├── rollup.py                    # Rollup 오케스트레이터 (메인 사용자 API)
│   ├── rpc_api.py                   # l2_* JSON-RPC 메서드 등록
│   ├── health.py                    # /health, /ready, /metrics 엔드포인트
│   ├── metrics.py                   # L2MetricsCollector (운영 메트릭)
│   ├── middleware.py                # APIKey, RateLimit, RequestSize 미들웨어
│   └── cli.py                       # CLI: ethclient l2 {init|start|prove|submit}
├── common/                          # 공통 기반 모듈
│   ├── rlp.py                       # RLP 인코딩/디코딩
│   ├── types.py                     # Block, BlockHeader, Transaction, Account 등
│   ├── trie.py                      # 머클 패트리시아 트라이 + 증명 생성/검증
│   ├── crypto.py                    # keccak256, secp256k1 ECDSA, 주소 도출
│   └── config.py                    # 체인 설정, 하드포크, Genesis
├── vm/                              # EVM (Ethereum Virtual Machine)
│   ├── evm.py                       # EVM 메인 루프, 트랜잭션 실행
│   ├── opcodes.py                   # 전체 옵코드 핸들러 (140+)
│   ├── precompiles.py               # 프리컴파일 컨트랙트 (ecrecover, SHA256 등)
│   ├── gas.py                       # 가스 계산 (EIP-2929, EIP-2200)
│   ├── memory.py                    # 256비트 스택, 바이트 메모리
│   ├── call_frame.py                # 콜 프레임, JUMPDEST 유효성
│   └── hooks.py                     # 실행 훅 (L2 확장 대비)
├── storage/                         # 상태 저장소
│   ├── store.py                     # 추상 Store 인터페이스 (+ snap sync 메서드)
│   ├── memory_backend.py            # 인메모리 구현, 상태 루트 계산
│   └── disk_backend.py              # LMDB 기반 영속 스토리지 (오버레이 패턴)
├── blockchain/                      # 블록체인 엔진
│   ├── chain.py                     # 블록 검증, 트랜잭션/블록 실행, simulate_call
│   ├── mempool.py                   # 트랜잭션 풀 (논스 정렬, 교체 정책)
│   └── fork_choice.py               # Canonical chain 관리, 리오그
├── zk/                              # ZK 증명 툴킷
│   ├── circuit.py                   # R1CS circuit 빌더 (Signal, Circuit, R1CS)
│   ├── groth16.py                   # Groth16 prover, verifier, debug verifier
│   ├── evm_verifier.py              # EVM 검증자 바이트코드 생성 + 실행
│   ├── snarkjs_compat.py            # snarkjs JSON 포맷 import/export
│   ├── r1cs_export.py               # R1CS 바이너리 export (snarkjs/circom 호환)
│   └── types.py                     # G1Point, G2Point, Proof, VerificationKey
├── bridge/                          # L1↔L2 General State Bridge
│   ├── types.py                     # CrossDomainMessage, RelayResult, ForceInclusionEntry
│   ├── relay_handlers.py            # RelayHandler ABC + EVM/Merkle/ZK/TinyDB/Direct 핸들러
│   ├── messenger.py                 # CrossDomainMessenger (전송, 릴레이, 플러거블 핸들러)
│   ├── watcher.py                   # BridgeWatcher (outbox 드레인 + 릴레이 + force queue)
│   └── environment.py               # BridgeEnvironment (L1+L2+Watcher + 팩토리 메서드)
├── networking/                      # P2P 네트워킹
│   ├── server.py                    # P2P 서버 — 멀티 프로토콜 디스패치
│   ├── protocol_registry.py         # 동적 capability 협상 & 오프셋 계산
│   ├── rlpx/
│   │   ├── handshake.py             # ECIES 핸드셰이크 (auth/ack)
│   │   ├── framing.py               # RLPx 프레임 암호화/복호화
│   │   └── connection.py            # 암호화된 TCP 연결 관리
│   ├── eth/
│   │   ├── protocol.py              # p2p/eth 메시지 코드, 프로토콜 상수
│   │   └── messages.py              # eth/68 메시지 인코딩/디코딩
│   ├── snap/
│   │   ├── protocol.py              # snap/1 메시지 코드 (SnapMsg enum)
│   │   └── messages.py              # snap/1 메시지 인코딩/디코딩 (8종)
│   ├── discv4/
│   │   ├── discovery.py             # Discovery v4 UDP 프로토콜
│   │   └── routing.py               # Kademlia k-bucket 라우팅 테이블
│   └── sync/
│       ├── full_sync.py             # Full sync 파이프라인 (+ head discovery)
│       └── snap_sync.py             # Snap sync 4단계 상태 머신
├── rpc/                             # JSON-RPC 서버
│   ├── server.py                    # FastAPI 기반 JSON-RPC 2.0 디스패처
│   ├── eth_api.py                   # eth_/net_/web3_ API 핸들러
│   ├── engine_api.py                # Engine API V1/V2/V3 핸들러
│   ├── engine_types.py              # Engine API 요청/응답 타입
│   └── zk_api.py                    # zk_ 네임스페이스 RPC 핸들러
└── examples/
    ├── l2_token.py                  # L2 ERC20 토큰 (mint/transfer/burn)
    ├── l2_nameservice.py            # L2 ENS 스타일 네임 서비스
    ├── l2_voting.py                 # L2 거버넌스 (제안/투표/확정)
    ├── l2_rps_game.py               # L2 commit-reveal 가위바위보
    ├── zk_notebook_demo.py          # ZK 툴킷 end-to-end 데모
    ├── bridge_relay_modes.py        # Proof 기반 릴레이 모드 비교 데모
    └── general_state_bridge.py      # L2 브릿지 end-to-end 데모
```

## Dependencies

| 패키지 | 용도 |
|---|---|
| [pycryptodome](https://pypi.org/project/pycryptodome/) | AES 암호화, SHA-256, RIPEMD-160 |
| [coincurve](https://pypi.org/project/coincurve/) | secp256k1 ECDSA 서명/복구, ECDH |
| [eth-hash](https://pypi.org/project/eth-hash/) | Keccak-256 해시 |
| [FastAPI](https://pypi.org/project/fastapi/) | JSON-RPC HTTP 서버 |
| [uvicorn](https://pypi.org/project/uvicorn/) | ASGI 서버 |
| [python-snappy](https://pypi.org/project/python-snappy/) | RLPx 메시지 Snappy 압축 |
| [py-ecc](https://pypi.org/project/py-ecc/) | BN128 타원곡선 연산 (ecAdd, ecMul, ecPairing) |
| [ckzg](https://pypi.org/project/ckzg/) | KZG point evaluation (EIP-4844) |
| [lmdb](https://pypi.org/project/lmdb/) | LMDB 키-값 스토어 (영속 저장소) |

**개발용:**

| 패키지 | 용도 |
|---|---|
| [pytest](https://pypi.org/project/pytest/) | 테스트 프레임워크 |
| [pytest-asyncio](https://pypi.org/project/pytest-asyncio/) | 비동기 테스트 지원 |

## Implementation Details

### 직접 구현한 컴포넌트

- **애플리케이션 특화 ZK 롤업 프레임워크** — 플러거블 STF/DA/Prover/L1 인터페이스, mempool과 논스 추적을 갖춘 Sequencer, 자동 봉인 배치 조립, 128비트 필드 절삭을 적용한 Groth16 증명 백엔드, BatchSubmitter 파이프라인, Rollup 오케스트레이터, L2 RPC API, CLI 스캐폴딩
- **L2 상태 관리** — 임의 키-값 상태에 대한 Trie 기반 Merkle 상태 루트 계산, 원자적 배치 실행을 위한 스냅샷/롤백, 혼합 타입 상태 값을 위한 태그 기반 인코딩
- **RLP (Recursive Length Prefix)** — 이더리움 직렬화 포맷: 인코딩/디코딩, 리스트/바이트 구분
- **Merkle Patricia Trie** — Branch/Extension/Leaf 노드, hex-prefix 인코딩, 상태 루트 계산, 머클 증명 생성/검증, 범위 증명
- **EVM** — 140+ 옵코드, 256비트 스택, 바이트 메모리, EIP-2929 cold/warm 추적, EIP-1559 base fee
- **프리컴파일** — ecrecover, SHA-256, RIPEMD-160, identity, modexp (EIP-2565), BN128 ecAdd/ecMul/ecPairing (EIP-196/197), BLAKE2f (EIP-152), KZG point evaluation (EIP-4844)
- **RLPx 전송** — ECIES 암호화, AES-256-CTR 프레임 암호화, SHA3 MAC 인증
- **프로토콜 레지스트리** — 동적 멀티 프로토콜 capability 협상 및 메시지 ID 오프셋 계산
- **eth/68 프로토콜** — Status, GetBlockHeaders, BlockHeaders, Transactions 등 전체 메시지 타입
- **snap/1 프로토콜** — GetAccountRange, AccountRange, GetStorageRanges, StorageRanges, GetByteCodes, ByteCodes, GetTrieNodes, TrieNodes
- **Discovery v4** — UDP Ping/Pong/FindNeighbours/Neighbours, Kademlia 라우팅 테이블
- **Full Sync** — best_hash 기반 피어 head 발견 → 헤더 다운로드 → 바디 다운로드 → 블록 실행 파이프라인
- **Snap Sync** — 4단계 상태 머신: 계정 다운로드 → 스토리지 다운로드 → 바이트코드 다운로드 → 트라이 힐링
- **Engine API** — V1/V2/V3 forkchoiceUpdated, getPayload, newPayload; 결정적 payload ID, payload 큐, JWT 인증
- **JSON-RPC 2.0** — 요청 파싱, 배치 지원, 에러 핸들링, 메서드 디스패치
- **Groth16 ZK 증명** — 연산자 오버로딩 기반 R1CS circuit 빌더, Lagrange 보간법으로 QAP 변환, toxic waste 기반 trusted setup, 랜덤화된 proof 생성, pairing 기반 검증
- **EVM ZK 검증자** — ecAdd/ecMul/ecPairing 프리컴파일을 사용하는 on-chain Groth16 검증 EVM 바이트코드 자동 생성, gas 프로파일링, 실행 트레이싱
- **snarkjs 호환** — snarkjs vkey.json, proof.json 포맷 라운드트립 import/export
- **L1↔L2 General State Bridge** — Optimism 스타일 CrossDomainMessenger, 임의 메시지 릴레이, 타겟 도메인 EVM 실행, 리플레이 보호, force inclusion (50블록 윈도우 검열 저항), escape hatch (L1 가치 복구)
- **플러거블 릴레이 핸들러** — EVM 실행, Merkle proof 검증, Groth16 ZK proof 검증, TinyDB 문서 DB 백엔드, 신뢰 릴레이어 직접 상태 적용 — L2가 EVM이 아닌 아무 런타임이어도 가능
- **Bridge Watcher** — 자동 outbox 드레인, 양방향 메시지 릴레이, force queue 처리

### 지원 EIP

| EIP | 설명 |
|---|---|
| EIP-155 | 리플레이 보호 (체인 ID) |
| EIP-1559 | Base fee, 동적 수수료 |
| EIP-2718 | Typed transaction envelope |
| EIP-2929 | Cold/warm 스토리지 접근 가스 |
| EIP-2930 | Access list 트랜잭션 |
| EIP-2200/3529 | SSTORE 가스 리펀드 |
| EIP-2565 | ModExp 가스 비용 |
| EIP-152 | BLAKE2f 프리컴파일 |
| EIP-196/197 | BN128 타원곡선 add, mul, pairing |
| EIP-4844 | Blob 트랜잭션, KZG point evaluation 프리컴파일 |
| EIP-7702 | Set EOA account code (Prague) |

### 실행 훅 시스템

EVM에 훅 포인트가 내장되어 있어, L2 확장 시 EVM 코드 수정 없이 `ExecutionHook`을 구현하면 됩니다:

```python
from ethclient.vm.hooks import ExecutionHook

class L2Hook(ExecutionHook):
    def before_execution(self, tx, env): ...
    def before_call(self, msg, env): ...
    def on_state_change(self, addr, key, value, env): ...
```

## Project Stats

### 소스 코드

| 모듈 | 파일 | LOC | 설명 |
|---|---:|---:|---|
| `l2/` | 24 | 3,024 | 앱 특화 ZK 롤업: STF, 시퀀서, 프로버, L1 백엔드, 롤업 오케스트레이터, RPC, CLI, 프로덕션 DA (S3/Calldata/Blob), 네이티브 프로버, LMDB 상태, 미들웨어 |
| `common/` | 6 | 2,282 | RLP, types, trie (+ 증명), crypto, config |
| `vm/` | 8 | 2,690 | EVM, opcodes, precompiles, gas |
| `storage/` | 4 | 1,431 | Store 인터페이스, 인메모리 & LMDB 백엔드 |
| `blockchain/` | 4 | 1,291 | 블록 검증, mempool, fork choice, simulate_call |
| `networking/` | 19 | 5,075 | RLPx, discovery, eth/68, snap/1, 프로토콜 레지스트리, sync, server |
| `zk/` | 7 | 1,929 | Groth16 circuit 빌더, prover, verifier, EVM 검증자, snarkjs 호환, R1CS export |
| `bridge/` | 6 | 1,241 | CrossDomainMessenger, BridgeWatcher, BridgeEnvironment, 플러거블 릴레이 핸들러, force inclusion, escape hatch |
| `rpc/` | 6 | 1,832 | JSON-RPC 서버, eth API, Engine API, ZK API |
| `main.py` | 1 | 647 | CLI 진입점 |
| **합계** | **86** | **21,442** | |

### 테스트 코드

| 테스트 파일 | LOC | 테스트 수 | 커버 모듈 |
|---|---:|---:|---|
| `test_l2_types.py` | 153 | 20 | L2 tx 타입, 인코딩/디코딩, 상태 스냅샷, 입력 검증 |
| `test_l2_da.py` | 56 | 8 | 데이터 가용성 프로바이더 |
| `test_l2_da_providers.py` | 611 | 40 | 프로덕션 DA 프로바이더 (S3, Calldata, Blob) |
| `test_l2_runtime.py` | 99 | 9 | Python STF 런타임 래퍼 |
| `test_l2_sequencer.py` | 198 | 12 | 시퀀서, mempool, 배치 조립, 자동 봉인, nonce gap, 멀티 발신자 |
| `test_l2_sequencer_hardening.py` | 173 | 12 | 시퀀서 입력 검증, 방어적 검사 |
| `test_l2_prover.py` | 193 | 17 | Groth16 증명 백엔드, 필드 절삭, 변조 거부 |
| `test_l2_native_prover.py` | 243 | 14 | 네이티브 프로버 (rapidsnark/snarkjs subprocess) |
| `test_l2_l1.py` | 86 | 6 | L1 백엔드, 증명 검증, 배치 추적 |
| `test_l2_eth_l1_backend.py` | 229 | 12 | 실제 이더리움 L1 백엔드 (EIP-1559 tx, EVMVerifier) |
| `test_l2_rpc.py` | 133 | 14 | L2 RPC API (l2_* 메서드), 입력 검증 |
| `test_l2_state.py` | 32 | 3 | 상태 저장소 경계 검사, 상태 루트 결정론성 |
| `test_l2_persistent_state.py` | 269 | 34 | LMDB 영속 상태, 오버레이, WAL, 배치/증명 영속 |
| `test_l2_health.py` | 56 | 3 | Health/ready 엔드포인트 |
| `test_l2_middleware.py` | 141 | 13 | RPC 미들웨어 (API key, rate limit, request size) |
| `test_l2_integration.py` | 274 | 13 | 전체 사이클: counter STF, 잔액 이체, 멀티 배치, 상태 지속성 |
| `test_rlp.py` | 207 | 56 | RLP 인코딩/디코딩 |
| `test_trie.py` | 213 | 26 | 머클 패트리시아 트라이 |
| `test_trie_proofs.py` | 254 | 23 | 트라이 증명 생성/검증, 범위 증명 |
| `test_crypto.py` | 113 | 14 | keccak256, ECDSA, 주소 |
| `test_evm.py` | 821 | 88 | 스택, 메모리, 옵코드, 프리컴파일 |
| `test_storage.py` | 387 | 65 | Store CRUD, 상태 루트 (양 백엔드 parametrize) |
| `test_blockchain.py` | 617 | 37 | 헤더 검증, 블록 실행, mempool, fork choice |
| `test_p2p.py` | 1,624 | 90 | RLPx, 핸드셰이크, eth 메시지, head discovery |
| `test_rpc.py` | 909 | 76 | JSON-RPC 엔드포인트, eth_call/estimateGas, Engine API, tx/receipt 조회 |
| `test_protocol_registry.py` | 177 | 17 | 멀티 프로토콜 capability 협상 |
| `test_snap_messages.py` | 267 | 21 | snap/1 메시지 encode/decode 라운드트립 |
| `test_snap_sync.py` | 446 | 29 | Snap sync 상태 머신, 응답 핸들러 |
| `test_zk_circuit.py` | 292 | 26 | ZK circuit 빌더, R1CS, 필드 연산 |
| `test_zk_groth16.py` | 267 | 18 | Groth16 prove/verify, debug verify, snarkjs 호환 |
| `test_zk_evm.py` | 162 | 13 | EVM 검증, gas 프로파일링, 실행 트레이스 |
| `test_bridge_messenger.py` | 225 | 11 | 브릿지 메신저 전송/릴레이, 리플레이 보호 |
| `test_bridge_e2e.py` | 174 | 10 | 브릿지 E2E: 입금, 출금, 왕복, 상태 릴레이 |
| `test_bridge_censorship.py` | 270 | 14 | Force inclusion + escape hatch (검열 저항) |
| `test_bridge_proof_relay.py` | 585 | 28 | Proof 기반 릴레이 핸들러 (EVM, Merkle, ZK, TinyDB, Direct) |
| `test_integration.py` | 272 | 14 | 모듈 간 통합 |
| `test_disk_backend.py` | 543 | 31 | LMDB 영속성, flush, 오버레이, 상태 루트 일치 |
| `integration/` | 68 | 6 | 아카이브 모드, 체인데이터, Fusaka 호환 |
| **합계** | **11,839** | **943** | |

## FAQ

**py-ethclient로 애플리케이션 특화 롤업을 만들 수 있나요?**
네 — py-ethclient에는 완전한 애플리케이션 특화 ZK 롤업 프레임워크가 포함되어 있습니다. 상태 전이 로직을 일반 Python 함수로 정의하면, 프레임워크가 시퀀싱, 배치 생성, Groth16 증명, L1 검증을 처리합니다. [L2 롤업 프레임워크](#l2-롤업-프레임워크) 섹션을 참고하세요.

**롤업 프레임워크는 어떻게 동작하나요?**
State Transition Function(STF)을 작성합니다 — `(state, tx)`를 받아 state를 변경하는 Python 함수입니다. Sequencer가 트랜잭션을 수집하고 STF를 실행하여 배치를 조립합니다. Groth16 prover가 상태 전이에 대한 ZK 증명을 생성하고, L1 backend가 이를 검증합니다. 4개 컴포넌트(STF, DA, Prover, L1)는 모두 플러거블 인터페이스입니다.

**Python으로 만든 이더리움 실행 클라이언트가 있나요?**
네 — py-ethclient는 순수 Python으로 작성된 완전한 이더리움 실행 클라이언트입니다. 140개 이상의 옵코드를 지원하는 EVM을 구현하고, RLPx(eth/68, snap/1)를 통해 이더리움 P2P 네트워크에 연결하며, 메인넷과 Sepolia에서 full sync와 snap sync를 모두 지원합니다.

**py-ethclient로 이더리움 메인넷 동기화가 가능한가요?**
네. py-ethclient는 이더리움 메인넷과 Sepolia 테스트넷 피어에 연결하고, Discovery v4를 통해 피어를 발견하며, full sync(순차 블록 실행) 또는 snap sync(병렬 상태 다운로드)로 동기화합니다. 양쪽 네트워크의 Geth 노드에 대해 라이브 테스트를 완료했습니다.

**py-ethclient와 geth의 차이점은 무엇인가요?**
geth(Go Ethereum)는 가장 널리 사용되는 프로덕션 실행 클라이언트입니다. py-ethclient는 동일한 핵심 프로토콜(EVM, eth/68, snap/1, Engine API)을 구현하지만 가독성과 연구 목적으로 Python으로 작성되었습니다. geth가 프로덕션 성능에 최적화된 반면, py-ethclient는 코드 명확성을 우선시하여 이더리움이 프로토콜 수준에서 어떻게 동작하는지 학습하기에 이상적입니다.

**L2 브릿지란?**
Optimism 스타일의 `CrossDomainMessenger`로 L1과 L2 간 임의 메시지를 릴레이합니다. 메시지는 타겟 도메인의 EVM에서 실행되어 실제 상태 변경을 수행합니다. Force inclusion(50블록 윈도우 후 검열 오퍼레이터 우회)과 escape hatch(L2 무응답 시 L1에서 입금 가치 복구)를 포함합니다. [L2 브릿지](#l2-브릿지) 섹션을 참고하세요.

**어떤 릴레이 모드를 지원하나요?**
브릿지는 5가지 릴레이 핸들러를 지원합니다: EVMRelayHandler (기본, 전체 EVM 실행), MerkleProofHandler (신뢰된 L1 상태 루트에 대한 Merkle proof 검증), ZKProofHandler (Groth16 영지식 증명 검증), TinyDBHandler (비-EVM L2를 위한 문서 DB 백엔드), DirectStateHandler (신뢰 릴레이어, 직접 상태 적용). Proof 기반 릴레이를 사용하면 L2는 EVM이 아닌 어떤 런타임이든 사용할 수 있습니다.

**py-ethclient로 ZK 개발을 할 수 있나요?**
네. py-ethclient에는 Groth16 ZK 증명 툴킷이 내장되어 있습니다. Python 표현식으로 R1CS circuit을 정의하고, proof를 생성하고, 네이티브 또는 인메모리 EVM에서 검증하고, gas 비용을 프로파일링하고, snarkjs 포맷으로 내보낼 수 있습니다 — circom, snarkjs, Solidity 툴체인 설치 없이. [ZK 툴킷](#zk-툴킷) 섹션을 참고하세요.

**ZK prover가 프로덕션에서 사용 가능한가요?**
prover는 순수 Python(BN128 곡선 연산에 py_ecc 사용)으로 구현되어 있어 교육, 프로토타이핑, 소규모 circuit(< 1000 constraints)에 적합합니다. 프로덕션 증명 생성에는 snarkjs나 rapidsnark를 사용하고, py-ethclient의 네이티브 또는 EVM 검증자로 proof를 검증하는 것을 권장합니다.

**py-ethclient는 어떤 EIP를 지원하나요?**
EIP-155(리플레이 보호), EIP-1559(동적 수수료), EIP-2718(typed 트랜잭션), EIP-2929/2930(access list), EIP-4844(blob 트랜잭션 + KZG), EIP-7702(Prague EOA 코드 설정)을 지원합니다. 전체 목록은 [지원 EIP](#지원-eip) 섹션을 참고하세요.

## 현재 제한사항

- **Engine API** — V1/V2/V3 구현 완료; 블록 생산 흐름 동작 중이나 최적화 진행 중
- **eth_getLogs** — 스텁 구현; 로그 필터링 미구현
- **contractAddress** — 트랜잭션 영수증에서 CREATE 컨트랙트 주소 미계산

## License

MIT
