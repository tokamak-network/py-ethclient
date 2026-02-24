# AGENTS.md — py-ethclient 가이드

애플리케이션 특화 ZK 롤업을 위한 Python L2 개발 플랫폼. State Transition Function을 일반 Python 함수로 정의하면 — 프레임워크가 시퀀싱, 배치 조립, Groth16 증명, L1 검증을 처리합니다. 완전 독립 구현된 이더리움 L1 실행 클라이언트(EVM, RLPx, eth/68, snap/1, full+snap sync, Engine API), L1↔L2 브릿지, Groth16 ZK 툴킷을 포함합니다 — 전부 순수 Python.

## 빠른 시작

```bash
# 설치
pip install -e ".[dev]"

# 단위 테스트 (943개)
pytest

# 특정 모듈 테스트
pytest tests/test_rlp.py
pytest tests/test_l2_sequencer.py -v

# L2 롤업 실행
ethclient l2 start --config l2.json

# L1 노드 실행
ethclient --network mainnet --port 30303

# Snap sync (기본값)
ethclient --network sepolia

# Docker
docker compose up -d                        # 메인넷
NETWORK=sepolia docker compose up -d        # Sepolia
```

### L2 롤업 빠른 예제

```python
from ethclient.l2.rollup import Rollup

def counter_stf(state, tx):
    count = state.get("count", 0) + 1
    return {"count": count, "result": f"count={count}"}

rollup = Rollup(stf=counter_stf, name="counter")
rollup.submit_tx({"action": "increment"})
rollup.submit_tx({"action": "increment"})
batch = rollup.seal_batch()       # 대기 중인 tx 실행
receipt = rollup.prove_batch(batch)  # Groth16 증명 생성
result = rollup.submit_batch(receipt)  # L1 검증
assert result["l1_verified"] is True
```

### Sepolia 노드 운영

```bash
# Snap sync (권장)
ethclient --network sepolia --sync-mode snap --port 30303 --rpc-port 8545 --engine-port 8551 --max-peers 25 --data-dir data/sepolia --log-level INFO

# Full sync 모드
ethclient --network sepolia --sync-mode full --port 30303 --rpc-port 8545 --engine-port 8551 --max-peers 25 --data-dir data/sepolia --log-level INFO
```

모니터링:

```bash
watch -n 5 '
  echo "peerCount:";
  curl -s -H "content-type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"net_peerCount\",\"params\":[],\"id\":1}" \
    http://127.0.0.1:8545;
  echo;
  echo "blockNumber:";
  curl -s -H "content-type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":2}" \
    http://127.0.0.1:8545;
  echo
'
```

## 프로젝트 구조

```
py-ethclient/                    # ~33,200 LOC (소스 21,442 + 테스트 11,839)
├── ethclient/
│   ├── main.py                  # CLI 진입점 (argparse, asyncio 이벤트 루프)
│   ├── l2/                      # L2 롤업 프레임워크 (24파일, 3,024 LOC)
│   │   ├── rollup.py            # 메인 API — STF, Sequencer, Prover, L1Backend 래핑
│   │   ├── types.py             # L2Tx, L2TxType, L2State, STFResult, Batch, BatchReceipt
│   │   ├── interfaces.py        # 4개 플러거블 ABC — STF, DAProvider, L1Backend, ProofBackend
│   │   ├── sequencer.py         # 멤풀 + 논스 추적 + STF 실행 + 배치 조립
│   │   ├── prover.py            # Groth16ProofBackend — 회로 빌드, 증명, 검증
│   │   ├── l1_backend.py        # InMemoryL1Backend — 검증자 배포 + 증명 검증
│   │   ├── state.py             # 트라이 기반 머클 상태 루트 (키-값 상태)
│   │   ├── da.py                # LocalDAProvider — 인메모리 DA + keccak256 커밋먼트
│   │   ├── runtime.py           # PythonRuntime — Python callable을 STF로 래핑
│   │   ├── submitter.py         # BatchSubmitter — 증명 → 제출 → 검증 파이프라인
│   │   ├── rpc_api.py           # 7개 l2_* JSON-RPC 메서드
│   │   ├── cli.py               # ethclient l2 {init|start|prove|submit}
│   │   ├── config.py            # L2 체인 설정
│   │   ├── da_s3.py              # S3 DA 프로바이더
│   │   ├── da_calldata.py        # Calldata DA 프로바이더 (EIP-1559)
│   │   ├── da_blob.py            # Blob DA 프로바이더 (EIP-4844)
│   │   ├── native_prover.py      # NativeProverBackend (rapidsnark/snarkjs)
│   │   ├── eth_l1_backend.py     # 실제 이더리움 L1 백엔드 (JSON-RPC)
│   │   ├── eth_rpc.py            # 경량 이더리움 JSON-RPC 클라이언트
│   │   ├── persistent_state.py   # LMDB 기반 L2 상태 (오버레이, WAL)
│   │   ├── health.py             # /health, /ready, /metrics 엔드포인트
│   │   ├── metrics.py            # L2 메트릭 수집기
│   │   └── middleware.py         # API key 인증, rate limit, request size
│   ├── zk/                      # ZK 툴킷 (7파일)
│   │   ├── circuit.py           # 연산자 오버로딩 기반 R1CS 회로 빌더
│   │   ├── groth16.py           # 완전한 Groth16 파이프라인 — R1CS → QAP → 셋업 → 증명 → 검증
│   │   ├── evm_verifier.py      # 온체인 검증용 EVM 바이트코드 자동 생성
│   │   ├── snarkjs_compat.py    # snarkjs JSON 포맷 임포트/익스포트
│   │   ├── r1cs_export.py       # R1CS 익스포트 유틸리티
│   │   └── types.py             # G1Point, G2Point, Proof, VerificationKey
│   ├── bridge/                  # L1↔L2 브릿지 (5파일)
│   │   ├── messenger.py         # Optimism 스타일 CrossDomainMessenger
│   │   ├── relay_handlers.py    # EVM, 머클 증명, ZK 증명, TinyDB, Direct 핸들러
│   │   ├── environment.py       # L1+L2+Watcher 편의 래퍼
│   │   ├── watcher.py           # 자동 outbox 드레인, 릴레이, 포스 큐 처리
│   │   └── types.py             # CrossDomainMessage, MessageStatus, Domain
│   ├── common/                  # 기초 모듈 (의존성 없음)
│   │   ├── rlp.py               # RLP 인코딩/디코딩
│   │   ├── types.py             # BlockHeader, Transaction, Receipt, Account, TxType
│   │   ├── trie.py              # 머클 패트리시아 트라이 (상태 루트, 증명, 범위 증명)
│   │   ├── crypto.py            # keccak256, secp256k1, ECDSA, 주소 도출
│   │   └── config.py            # 체인 설정, 하드포크, ForkID, genesis
│   ├── vm/                      # EVM 구현
│   │   ├── evm.py               # fetch-decode-execute 메인 루프
│   │   ├── opcodes.py           # 140+ 옵코드 핸들러
│   │   ├── precompiles.py       # 프리컴파일 (ecrecover, modexp, BN128, KZG)
│   │   ├── gas.py               # 가스 계산 (EIP-2929 cold/warm)
│   │   ├── memory.py            # 바이트 메모리
│   │   ├── call_frame.py        # 256비트 스택 + 콜 프레임
│   │   └── hooks.py             # 실행 훅 인터페이스 (L2 확장)
│   ├── storage/                 # 상태 저장소
│   │   ├── store.py             # Store 인터페이스 (계정/코드/스토리지 CRUD + snap sync)
│   │   ├── memory_backend.py    # dict 기반 인메모리 백엔드
│   │   └── disk_backend.py      # LMDB 기반 영속 스토리지 (오버레이 패턴)
│   ├── blockchain/              # 블록체인 엔진
│   │   ├── chain.py             # 블록 검증/실행, base fee, simulate_call
│   │   ├── mempool.py           # 트랜잭션 풀 (논스 정렬, replacement)
│   │   └── fork_choice.py       # Canonical chain, 리오그 처리
│   ├── networking/              # P2P 네트워킹
│   │   ├── server.py            # P2P 서버 — 멀티 프로토콜 디스패치
│   │   ├── protocol_registry.py # 동적 capability 협상 & 오프셋 계산
│   │   ├── rlpx/                # RLPx 암호화 전송 계층
│   │   │   ├── handshake.py     # ECIES 핸드셰이크 (EIP-8 지원)
│   │   │   ├── framing.py       # 메시지 프레이밍 + Snappy 압축
│   │   │   └── connection.py    # TCP 연결 관리
│   │   ├── eth/                 # eth/68 서브프로토콜
│   │   │   ├── protocol.py      # 메시지 코드, 상수
│   │   │   └── messages.py      # Status, GetBlockHeaders, BlockBodies 등
│   │   ├── snap/                # snap/1 서브프로토콜
│   │   │   ├── protocol.py      # SnapMsg enum (상대 코드 0-7)
│   │   │   └── messages.py      # 8종 메시지 타입 (encode/decode)
│   │   ├── discv4/              # Discovery v4 (UDP 피어 탐색)
│   │   │   ├── discovery.py     # Ping/Pong/FindNeighbours/Neighbours
│   │   │   └── routing.py       # k-bucket 라우팅 테이블
│   │   └── sync/                # 동기화 엔진
│   │       ├── full_sync.py     # Full sync 파이프라인 (+ head discovery)
│   │       └── snap_sync.py     # Snap sync 4단계 상태 머신
│   └── rpc/                     # JSON-RPC 서버
│       ├── server.py            # FastAPI 기반 디스패처
│       ├── eth_api.py           # eth_ 네임스페이스 핸들러
│       ├── engine_api.py        # Engine API V1/V2/V3 핸들러
│       ├── engine_types.py      # Engine API 요청/응답 타입
│       └── zk_api.py            # zk_ 네임스페이스 (verifyGroth16, deployVerifier, verifyOnChain)
├── tests/                       # pytest 단위 테스트 (943개)
│   ├── test_l2_types.py         # L2 타입, 상태, 직렬화
│   ├── test_l2_sequencer.py     # 시퀀서, 멤풀, 배치 조립
│   ├── test_l2_prover.py        # Groth16 증명 백엔드
│   ├── test_l2_l1.py            # L1 백엔드, 검증자 배포
│   ├── test_l2_da.py            # DA 프로바이더, 커밋먼트
│   ├── test_l2_runtime.py       # Python 런타임, STF 래핑
│   ├── test_l2_integration.py   # 엔드투엔드 롤업 파이프라인
│   ├── test_zk_circuit.py       # R1CS 회로 빌더
│   ├── test_zk_groth16.py       # Groth16 셋업/증명/검증
│   ├── test_zk_evm.py           # EVM 온체인 검증
│   ├── test_bridge_messenger.py # CrossDomainMessenger
│   ├── test_bridge_e2e.py       # 브릿지 엔드투엔드
│   ├── test_bridge_proof_relay.py # 증명 릴레이 핸들러
│   ├── test_bridge_censorship.py # 강제 포함, 이스케이프 해치
│   ├── test_rlp.py              # RLP 인코딩/디코딩
│   ├── test_trie.py             # MPT + 이더리움 공식 테스트 벡터
│   ├── test_trie_proofs.py      # 트라이 머클 증명 & 범위 검증
│   ├── test_crypto.py           # 암호화, ECDSA, 주소 도출
│   ├── test_evm.py              # 스택, 메모리, 가스, 옵코드, 프리컴파일
│   ├── test_storage.py          # Store CRUD, 상태 루트
│   ├── test_blockchain.py       # 블록 검증/실행, mempool, fork choice
│   ├── test_p2p.py              # RLPx, 핸드셰이크, eth 메시지
│   ├── test_protocol_registry.py # 멀티 프로토콜 capability 협상
│   ├── test_snap_messages.py    # snap/1 메시지 encode/decode 라운드트립
│   ├── test_snap_sync.py        # Snap sync 상태 머신, 응답 핸들러
│   ├── test_rpc.py              # JSON-RPC 엔드포인트 + Engine API
│   ├── test_disk_backend.py     # LMDB 영속 스토리지
│   └── test_integration.py      # 모듈 간 통합 테스트
├── tests/integration/           # 통합 테스트 스위트
│   ├── archive_mode_test.py     # 아카이브 모드 RPC
│   ├── chaindata_test.py        # 체인데이터 영속성
│   └── fusaka_compliance_test.py # Fusaka 포크 호환
├── tests/live/                  # 라이브 네트워크 테스트 (실제 피어 필요)
│   ├── test_full_sync.py        # 메인넷 검증 sync
│   ├── test_tx_lookup.py        # Sepolia tx hash 조회
│   └── test_mainnet_discovery.py # 메인넷 discv4 discovery
├── Dockerfile                   # Ubuntu 기반 컨테이너 이미지
├── docker-compose.yml           # 원커맨드 배포
└── pyproject.toml               # Python 3.12+, 의존성 정의
```

## 모듈 의존성 그래프

```
common (rlp, types, trie, crypto, config)
  ↓
vm (evm, opcodes, precompiles, gas, hooks)
  ↓
storage (store, memory_backend, disk_backend)
  ↓
blockchain (chain, mempool, fork_choice)
  ↓                            ↓
networking (rlpx, discv4,      rpc (server, eth_api, engine_api, zk_api)
  eth, snap, sync, server)       ↓
  ↓                            l2/rpc_api (7개 l2_* 메서드)
main.py                         ↓
                          ┌─── l2 (rollup, sequencer, prover, submitter, ...)
                          │      ↓ 사용
                          ├─── zk (circuit, groth16, evm_verifier)
                          │      ↓ 사용됨
                          └─── bridge (messenger, relay_handlers, watcher)
```

하위 모듈은 상위 모듈에 의존하지 않음. `common`은 어디서든 안전하게 import 가능.
`l2`는 Groth16 증명을 위해 `zk`에, 머클 상태 루트를 위해 `common/trie`에 의존.
`bridge`는 EVM 릴레이 실행을 위해 `vm`에 의존.

## L2 롤업 아키텍처

### 동작 방식

```
사용자 Python STF → Rollup.submit_tx() → Sequencer (멤풀 + 순서 지정)
    → seal_batch() → STF 실행 (스냅샷/롤백)
    → prove_batch() → Groth16 증명 (회로 → 셋업 → 증명)
    → submit_batch() → L1 검증 (검증자 배포 → 온체인 검증)
```

### 플러거블 인터페이스 (`l2/interfaces.py`)

| 인터페이스 | 목적 | 기본 구현체 |
|-----------|------|-----------|
| `StateTransitionFunction` | `execute(state, tx) → STFResult` | `PythonRuntime` (임의 callable) |
| `DAProvider` | `submit(data) → commitment` | `LocalDAProvider` (인메모리) |
| `ProofBackend` | `prove(batch) → proof` | `Groth16ProofBackend` |
| `L1Backend` | `deploy_verifier()`, `verify_proof()` | `InMemoryL1Backend` |

### 핵심 L2 타입 (`l2/types.py`)

- `L2Tx` — 트랜잭션: sender, nonce, L2TxType (TRANSFER/CALL/DEPLOY/SYSTEM)
- `L2State` — 트라이 기반 상태: `get(key)`, `set(key, value)`, `root()` (머클 루트)
- `Batch` — 봉인된 배치: txs + pre_state_root + post_state_root + results
- `BatchReceipt` — 배치 + Groth16 증명 + DA 커밋먼트
- `STFResult` — 개별 tx 결과: success, output, state_diff, gas_used

## 테스트

### 단위 테스트 (오프라인)

```bash
pytest                           # 전체 (943개)
pytest tests/test_l2_*.py        # L2 롤업 테스트 (230개)
pytest tests/test_zk_*.py        # ZK 툴킷 테스트 (57개)
pytest tests/test_bridge_*.py    # 브릿지 테스트 (63개)
pytest tests/test_rlp.py         # 특정 모듈
pytest -v                        # 상세 출력
pytest --tb=short                # 짧은 트레이스백
```

테스트 파일별 커버리지:

| 파일 | 테스트 수 | 커버하는 모듈 |
|------|--------:|-------------|
| **L2 롤업** | **230** | |
| test_l2_types.py | 17 | L2 타입, 상태, 직렬화 |
| test_l2_sequencer.py | 10 | 시퀀서, 멤풀, 배치 조립 |
| test_l2_prover.py | 10 | Groth16 증명 백엔드 |
| test_l2_l1.py | 6 | L1 백엔드, 검증자 배포 |
| test_l2_da.py | 8 | DA 프로바이더, 커밋먼트 |
| test_l2_runtime.py | 9 | Python 런타임, STF 래핑 |
| test_l2_integration.py | 12 | 엔드투엔드 롤업 파이프라인 |
| test_l2_da_providers.py | 40 | 프로덕션 DA 프로바이더 (S3, Calldata, Blob) |
| test_l2_sequencer_hardening.py | 12 | 시퀀서 입력 검증, 방어적 체크 |
| test_l2_native_prover.py | 14 | 네이티브 프로버 (rapidsnark/snarkjs) |
| test_l2_eth_l1_backend.py | 12 | 실제 이더리움 L1 백엔드 |
| test_l2_persistent_state.py | 34 | LMDB 영속 상태, 오버레이 |
| test_l2_health.py | 3 | Health/ready 엔드포인트 |
| test_l2_middleware.py | 13 | RPC 미들웨어 |
| **ZK 툴킷** | **57** | |
| test_zk_circuit.py | 26 | R1CS 회로 빌더 |
| test_zk_groth16.py | 18 | Groth16 셋업/증명/검증 |
| test_zk_evm.py | 13 | EVM 온체인 검증 |
| **L1↔L2 브릿지** | **63** | |
| test_bridge_messenger.py | 11 | CrossDomainMessenger |
| test_bridge_e2e.py | 10 | 브릿지 엔드투엔드 |
| test_bridge_proof_relay.py | 28 | 증명 릴레이 핸들러 |
| test_bridge_censorship.py | 14 | 강제 포함, 이스케이프 해치 |
| **L1 코어** | **593** | |
| test_rlp.py | 56 | RLP 인코딩/디코딩, 라운드트립 |
| test_trie.py | 26 | MPT, 이더리움 공식 벡터 |
| test_trie_proofs.py | 23 | 증명 생성/검증, 범위 증명, 순회 |
| test_crypto.py | 14 | keccak256, ECDSA, 주소 |
| test_evm.py | 88 | 스택, 메모리, 모든 옵코드, 프리컴파일 (BN128, KZG) |
| test_storage.py | 65 | Store CRUD, 상태 루트, snap 저장소 (양 백엔드 parametrize) |
| test_blockchain.py | 37 | 헤더 검증, base fee, 블록 실행, mempool, fork choice |
| test_p2p.py | 90 | RLPx, 핸드셰이크, eth 메시지, head discovery |
| test_protocol_registry.py | 17 | Capability 협상, 오프셋 계산 |
| test_snap_messages.py | 21 | snap/1 메시지 encode/decode 라운드트립 |
| test_snap_sync.py | 29 | Snap sync 상태 머신, 응답 핸들러 |
| test_rpc.py | 76 | JSON-RPC, eth_call/estimateGas EVM, Engine API, tx/receipt 조회 |
| test_integration.py | 14 | 모듈 간 통합 |
| test_disk_backend.py | 31 | LMDB 영속성, flush, 오버레이, 상태 루트 |
| integration/ | 6 | 아카이브 모드, 체인데이터, Fusaka 호환 |

### 라이브 네트워크 테스트

```bash
python3 tests/live/test_full_sync.py   # 메인넷 피어 연결 + 블록 검증
```

검증 항목: 헤더 체인 링크, 트랜잭션 루트 (MPT), ECDSA sender 복구, EIP-1559 base fee, 모든 5가지 tx 타입 (Legacy/AccessList/FeeMarket/Blob/SetCode).

## 핵심 타입

### L2 타입 (`l2/types.py`)

```python
class L2TxType(IntEnum):
    TRANSFER = 0
    CALL = 1
    DEPLOY = 2
    SYSTEM = 3

@dataclass
class L2Tx:
    sender: str
    nonce: int
    tx_type: L2TxType
    payload: dict
    # ...

@dataclass
class Batch:
    batch_id: int
    txs: list[L2Tx]
    pre_state_root: bytes
    post_state_root: bytes
    results: list[STFResult]
```

### BlockHeader (`common/types.py`)

21개 RLP 필드 (post-Prague). `block_hash()`는 `keccak256(rlp(header))`로 계산.

주요 필드: `parent_hash`, `coinbase`, `state_root`, `transactions_root`, `number`, `gas_limit`, `gas_used`, `base_fee_per_gas`, `withdrawals_root`, `blob_gas_used`, `excess_blob_gas`, `parent_beacon_block_root`, `requests_hash`.

### Transaction (`common/types.py`)

5가지 트랜잭션 타입:
- `TxType.LEGACY = 0` — EIP-155
- `TxType.ACCESS_LIST = 1` — EIP-2930
- `TxType.FEE_MARKET = 2` — EIP-1559
- `TxType.BLOB = 3` — EIP-4844
- `TxType.SET_CODE = 4` — EIP-7702 (Prague)

인코딩: Legacy는 순수 RLP, 나머지는 `type_byte || rlp(fields)`.

## 주요 패턴 및 주의사항

### L2 롤업 패턴

**STF는 순수해야 함**: State Transition Function은 결정론적이어야 합니다 — 동일한 `(state, tx)`는 유효한 ZK 증명을 위해 항상 동일한 출력을 내야 합니다.

**시퀀서 스냅샷/롤백**: 시퀀서는 각 tx 실행 전 상태 스냅샷을 생성합니다. STF가 실패하면 롤백하고 tx를 실패로 표시합니다 — 상태를 오염시키지 않습니다.

**배치 봉인**: `seal_batch()`는 멤풀에서 대기 중인 tx를 수집하고, STF로 실행하며, pre/post 상태 루트를 포함한 `Batch`를 생성합니다. 봉인된 배치는 불변입니다.

### EthMsg vs SnapMsg 오프셋

`EthMsg` enum 값에 이미 `0x10` 오프셋이 포함되어 있음:
```python
class EthMsg(IntEnum):
    STATUS = 0x10
    GET_BLOCK_HEADERS = 0x13
    BLOCK_HEADERS = 0x14
```
절대 `0x10 + EthMsg.XXX` 하지 말 것. 이중 오프셋 버그 발생.

`SnapMsg` enum은 **상대 코드** (0-7) 사용. 절대 와이어 코드는 `NegotiatedCapabilities`가 런타임에 계산:
```python
class SnapMsg(IntEnum):
    GET_ACCOUNT_RANGE = 0
    ACCOUNT_RANGE = 1
    # ... (0-7)
```
프로토콜 레지스트리가 snap/1 오프셋을 동적으로 할당 (일반적으로 eth/68의 0x10-0x20 다음인 0x21-0x28).

### 프로토콜 레지스트리

멀티 프로토콜 capability 협상은 RLPx 명세를 따름:
1. Capability를 이름 알파벳순으로 정렬
2. 0x10부터 연속 메시지 ID 범위 할당
3. `negotiate_capabilities(local, remote)` → `NegotiatedCapabilities`
4. `resolve_msg_code(abs_code)` → `(protocol_name, relative_code)`
5. `absolute_code(protocol_name, relative_code)` → 절대 와이어 코드

### Post-Prague 헤더

Prague 이후 블록 헤더는 21개 RLP 필드. `requests_hash` (EIP-7685)가 인덱스 20에 추가됨. 이 필드가 빠지면 `block_hash()`가 틀림.

### BlockBodies 위드로얼

Post-Shanghai 블록 바디는 `[txs, ommers, withdrawals]` 3원소 튜플. Shanghai 이전은 `[txs, ommers]` 2원소.

### RLP 디코딩

`rlp.decode_list()` — 최상위 리스트 디코딩. 숫자는 `rlp.decode_uint()`로 변환 필요.
빈 바이트 `b""` = 0으로 해석 (`decode_uint`가 처리).

### Snappy 압축

RLPx에서 `msg_code >= 0x10`인 모든 서브프로토콜 메시지는 Snappy 압축/해제 적용. eth (0x10+)와 snap (0x21+) 모두 해당. p2p 메시지(Hello=0x00, Disconnect=0x01 등)는 압축하지 않음.

## Snap Sync 아키텍처

### 4단계 상태 머신

```
IDLE → ACCOUNT_DOWNLOAD → STORAGE_DOWNLOAD → BYTECODE_DOWNLOAD → TRIE_HEALING → COMPLETE
```

1. **계정 다운로드** — GetAccountRange/AccountRange: 전체 계정 trie를 범위 단위로 순회, 머클 증명 검증
2. **스토리지 다운로드** — GetStorageRanges/StorageRanges: 비어있지 않은 스토리지를 가진 계정의 슬롯 다운로드
3. **바이트코드 다운로드** — GetByteCodes/ByteCodes: 유니크 코드 해시로 컨트랙트 바이트코드 일괄 요청
4. **트라이 힐링** — GetTrieNodes/TrieNodes: 체인 진행으로 인한 누락 트라이 노드 보완

### 핵심 클래스

- `SnapSyncState` — 진행 상태 (커서, 큐, 카운터)
- `SnapSync` — 동기화 엔진, `start(peers, target_root, target_block)`
- 응답 핸들러: `handle_account_range`, `handle_storage_ranges`, `handle_byte_codes`, `handle_trie_nodes`

## CLI 레퍼런스

### L2 커맨드

```bash
ethclient l2 init --name my-rollup                 # L2 프로젝트 스캐폴딩
ethclient l2 start --config l2.json                 # 시퀀서 시작
ethclient l2 prove --config l2.json                 # Groth16 증명 생성
ethclient l2 submit --config l2.json                # L1에 제출
```

### L1 노드 커맨드

```bash
ethclient --network mainnet --port 30303
ethclient --network sepolia --sync-mode snap
ethclient --network sepolia --sync-mode full
ethclient --network sepolia --data-dir data/sepolia  # 영속 스토리지
ethclient --network sepolia --engine-port 8551 --jwt-secret jwt.hex  # Engine API
```

## JSON-RPC API

### L2 네임스페이스

| 메서드 | 설명 |
|--------|------|
| `l2_submitTransaction` | L2 트랜잭션 제출 |
| `l2_getState` | 키로 L2 상태 조회 |
| `l2_getBatch` | 배치 ID로 조회 |
| `l2_getBatchReceipt` | 증명 포함 배치 영수증 |
| `l2_getTransactionResult` | 개별 tx 결과 조회 |
| `l2_pendingTransactions` | 멤풀 tx 목록 |
| `l2_chainInfo` | L2 체인 정보 |

### ZK 네임스페이스

| 메서드 | 설명 |
|--------|------|
| `zk_verifyGroth16` | 오프체인 Groth16 검증 |
| `zk_deployVerifier` | EVM 검증자 컨트랙트 배포 |
| `zk_verifyOnChain` | 온체인 증명 검증 |

### eth/net/web3 네임스페이스

20+ 표준 이더리움 JSON-RPC 메서드 지원: `eth_call`, `eth_estimateGas`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getBlockByNumber`, `eth_blockNumber` 등.

### Engine API

`engine_forkchoiceUpdatedV1/V2/V3`, `engine_getPayloadV1/V2/V3`, `engine_newPayloadV1/V2/V3`, `engine_exchangeCapabilities` — JWT 인증, 별도 포트(기본 8551).

## 의존성

| 패키지 | 용도 |
|--------|------|
| pycryptodome | AES, SHA256, RIPEMD160 |
| coincurve | secp256k1 (ECDSA, ECDH) |
| eth-hash[pycryptodome] | keccak256 |
| fastapi + uvicorn | JSON-RPC 서버 |
| python-snappy | RLPx 메시지 압축 |
| py-ecc | BN128 ecAdd/ecMul/ecPairing (Groth16, 프리컴파일) |
| ckzg | KZG point evaluation (EIP-4844) |
| lmdb | LMDB 영속 스토리지 |
| tinydb | TinyDB 릴레이 핸들러 (브릿지) |
| pytest + pytest-asyncio | 테스트 (dev) |

## 네트워크 연결

```python
# 메인넷 부트노드
MAINNET_BOOTNODES = [
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666d@18.138.108.67:30303",
    "enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",
    # ...
]

# Sepolia 부트노드
SEPOLIA_BOOTNODES = [
    "enode://4e5e92199ee224a01932a377160aa432f31d0b351f84ab413a8e0a42f4f36476f8fb1cbe914af0d9aef0d51571571c4f3e910c9719571f16ae5e168d9b09f8258@138.197.51.181:30303",
    # ...
]
```

CLI: `ethclient --network sepolia --bootnodes enode://...`

## 코드 수정 시 체크리스트

1. `l2/` 수정 시 → `test_l2_*.py` 실행 (230개)
2. `l2/sequencer.py` 수정 시 → `test_l2_sequencer.py`, `test_l2_integration.py` 실행
3. `l2/prover.py` 수정 시 → `test_l2_prover.py`, `test_l2_integration.py` 실행
4. `zk/` 수정 시 → `test_zk_*.py` 실행 (57개)
5. `zk/groth16.py` 수정 시 → `test_zk_groth16.py`, `test_l2_prover.py` 실행
6. `bridge/` 수정 시 → `test_bridge_*.py` 실행 (63개)
7. `common/types.py` 수정 시 → `test_rlp.py`, `test_blockchain.py` 실행
8. `common/trie.py` 수정 시 → `test_trie.py`, `test_trie_proofs.py` 실행
9. `vm/` 수정 시 → `test_evm.py`, `test_zk_evm.py` 실행
10. `networking/` 수정 시 → `test_p2p.py`, `test_protocol_registry.py`, `test_snap_messages.py` 실행
11. `networking/sync/` 수정 시 → `test_snap_sync.py` + `tests/live/test_full_sync.py` 실행
12. `blockchain/` 수정 시 → `test_blockchain.py` + `test_integration.py` + `test_rpc.py` 실행
13. `rpc/` 수정 시 → `test_rpc.py` 실행
14. 새 하드포크 지원 시 → `config.py`에 포크 블록/타임스탬프 추가, `types.py`에 새 필드 추가
15. 전체 회귀 테스트: `pytest && python3 tests/live/test_full_sync.py`
