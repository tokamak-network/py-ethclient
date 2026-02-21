# py-ethclient

**순수 Python으로 처음부터 구현한 이더리움 실행 클라이언트**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-593%20passing-brightgreen)](#testing)
[![LOC](https://img.shields.io/badge/LOC-15%2C271-blue)](#project-stats)

py-ethclient는 [ethrex](https://github.com/lambdaclass/ethrex) (Rust)에서 영감을 받아 완전히 독립적으로 구현한 Python 이더리움 Layer 1 실행 클라이언트입니다. devp2p/RLPx를 통해 이더리움 P2P 네트워크에 직접 연결하며, 140개 이상의 옵코드를 지원하는 EVM(Ethereum Virtual Machine)과 full sync/snap sync를 통한 메인넷·Sepolia 동기화를 지원합니다.

RLP 인코딩, 머클 패트리시아 트라이, EVM 실행, RLPx 전송 암호화, eth/68·snap/1 와이어 프로토콜, Discovery v4, Engine API 등 모든 핵심 프로토콜 로직을 순수 Python으로 직접 구현했습니다. 외부 의존성은 암호화 프리미티브와 웹 프레임워크만 사용합니다.

> **[English README](./README.md)**

## 주요 기능

- **Full EVM** — 140+ 옵코드, 프리컴파일 (ecrecover, SHA-256, RIPEMD-160, modexp, BN128, BLAKE2f, KZG), EIP-1559/2929/2930/4844/7702 지원
- **이더리움 P2P 네트워킹** — RLPx 암호화 전송, eth/68·snap/1 와이어 프로토콜, Discovery v4 Kademlia 라우팅
- **동기화 모드** — Full sync (순차 블록 실행) 및 snap sync (4단계 병렬 상태 다운로드)
- **JSON-RPC 2.0** — `eth_call`, `eth_estimateGas`, 트랜잭션/영수증 조회, 로그 쿼리 등 20개 이상 메서드
- **Engine API V1/V2/V3** — `forkchoiceUpdated`, `getPayload`, `newPayload` + JWT 인증으로 합의 레이어 연동
- **영속 스토리지** — LMDB 기반 디스크 백엔드, 하이브리드 오버레이 패턴으로 원자적 상태 커밋
- **멀티 네트워크** — 메인넷, Sepolia, Holesky 지원 (네트워크별 genesis 및 하드포크 설정)
- **593개 테스트** — RLP부터 통합 테스트까지 전 프로토콜 레이어를 커버하는 포괄적 테스트 스위트
- **Docker 지원** — Docker Compose로 간편 배포
- **L2 확장성** — EVM 코어 수정 없이 Layer 2를 커스터마이징할 수 있는 실행 훅 시스템 내장

## 왜 py-ethclient인가?

이더리움 네트워크의 건강성을 위해 클라이언트 다양성은 매우 중요합니다. py-ethclient는 Python으로 작성된 유일한 이더리움 실행 클라이언트로, 다음과 같은 고유한 가치를 제공합니다:

- **교육 & 연구** — Python의 높은 가독성 덕분에 이더리움이 프로토콜 수준에서 어떻게 동작하는지 이해하기 위한 최적의 코드베이스입니다. EVM, RLPx, 머클 트라이, 동기화 등 모든 컴포넌트가 명확하고 읽기 쉬운 Python으로 구현되어 있습니다
- **빠른 프로토타이핑** — 새로운 EIP, 커스텀 옵코드, 합의 변경 사항을 며칠이 아닌 몇 시간 만에 테스트할 수 있습니다. Python의 동적 특성이 프로토콜 실험의 빠른 반복을 가능하게 합니다
- **L2 개발** — 내장된 실행 훅 시스템을 통해 EVM 코어 코드를 수정하지 않고도 Layer 2 실행 환경을 구축할 수 있습니다
- **클라이언트 다양성** — Go, Rust, C#, Java에 이어 Python 클라이언트를 추가함으로써 구현 특화 버그에 대한 네트워크의 복원력을 강화합니다

### 다른 실행 클라이언트와의 비교

| | py-ethclient | [geth](https://github.com/ethereum/go-ethereum) | [reth](https://github.com/paradigmxyz/reth) | [nethermind](https://github.com/NethermindEth/nethermind) |
|---|---|---|---|---|
| **언어** | Python | Go | Rust | C# |
| **목적** | 교육, 연구, L2 | 프로덕션 | 프로덕션 | 프로덕션 |
| **EVM** | 140+ 옵코드 | 전체 | 전체 | 전체 |
| **동기화 모드** | Full + Snap | Full + Snap + Light | Full + Snap | Full + Snap + Fast |
| **Engine API** | V1/V2/V3 | V1/V2/V3 | V1/V2/V3 | V1/V2/V3 |
| **P2P 프로토콜** | eth/68, snap/1 | eth/68, snap/1 | eth/68, snap/1 | eth/68, snap/1 |
| **코드 가독성** | 매우 높음 | 높음 | 보통 | 보통 |
| **확장성** | 훅 시스템 | 플러그인 | 모듈러 | 플러그인 |

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

### 사용 예시

```bash
# 최신 블록 번호 조회
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# 계정 잔액 조회
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","latest"],"id":1}'
```

## Testing

```bash
# 전체 테스트 실행
pytest

# 특정 모듈 테스트
pytest tests/test_rlp.py              # RLP 인코딩/디코딩
pytest tests/test_trie.py             # 머클 패트리시아 트라이
pytest tests/test_trie_proofs.py      # 트라이 머클 증명 & 범위 검증
pytest tests/test_evm.py              # EVM 옵코드 실행
pytest tests/test_storage.py          # 상태 저장소
pytest tests/test_blockchain.py       # 블록 검증/실행
pytest tests/test_p2p.py              # P2P 네트워킹
pytest tests/test_protocol_registry.py # 멀티 프로토콜 capability 협상
pytest tests/test_snap_messages.py    # snap/1 메시지 인코딩/디코딩
pytest tests/test_snap_sync.py        # Snap sync 상태 머신
pytest tests/test_rpc.py              # JSON-RPC 서버 + Engine API
pytest tests/test_disk_backend.py     # LMDB 영속 스토리지
pytest tests/test_integration.py      # 통합 테스트

# 상세 출력
pytest -v
```

## Architecture

```
ethclient/
├── main.py                          # CLI 진입점, 노드 초기화
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
└── rpc/                             # JSON-RPC 서버
    ├── server.py                    # FastAPI 기반 JSON-RPC 2.0 디스패처
    ├── eth_api.py                   # eth_/net_/web3_ API 핸들러
    ├── engine_api.py                # Engine API V1/V2/V3 핸들러
    └── engine_types.py              # Engine API 요청/응답 타입
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
| `common/` | 6 | 2,374 | RLP, types, trie (+ 증명), crypto, config |
| `vm/` | 8 | 2,703 | EVM, opcodes, precompiles, gas |
| `storage/` | 4 | 1,431 | Store 인터페이스, 인메모리 & LMDB 백엔드 |
| `blockchain/` | 4 | 1,353 | 블록 검증, mempool, fork choice, simulate_call |
| `networking/` | 19 | 5,117 | RLPx, discovery, eth/68, snap/1, 프로토콜 레지스트리, sync, server |
| `rpc/` | 5 | 1,660 | JSON-RPC 서버, eth API, Engine API |
| `main.py` | 1 | 633 | CLI 진입점 |
| **합계** | **47** | **15,271** | |

### 테스트 코드

| 테스트 파일 | LOC | 테스트 수 | 커버 모듈 |
|---|---:|---:|---|
| `test_rlp.py` | 206 | 56 | RLP 인코딩/디코딩 |
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
| `test_integration.py` | 272 | 14 | 모듈 간 통합 |
| `test_disk_backend.py` | 543 | 31 | LMDB 영속성, flush, 오버레이, 상태 루트 일치 |
| `integration/` | 68 | 6 | 아카이브 모드, 체인데이터, Fusaka 호환 |
| **합계** | **6,917** | **593** | |

## FAQ

**Python으로 만든 이더리움 실행 클라이언트가 있나요?**
네 — py-ethclient는 순수 Python으로 작성된 완전한 이더리움 실행 클라이언트입니다. 140개 이상의 옵코드를 지원하는 EVM을 구현하고, RLPx(eth/68, snap/1)를 통해 이더리움 P2P 네트워크에 연결하며, 메인넷과 Sepolia에서 full sync와 snap sync를 모두 지원합니다.

**py-ethclient로 이더리움 메인넷 동기화가 가능한가요?**
네. py-ethclient는 이더리움 메인넷과 Sepolia 테스트넷 피어에 연결하고, Discovery v4를 통해 피어를 발견하며, full sync(순차 블록 실행) 또는 snap sync(병렬 상태 다운로드)로 동기화합니다. 양쪽 네트워크의 Geth 노드에 대해 라이브 테스트를 완료했습니다.

**py-ethclient와 geth의 차이점은 무엇인가요?**
geth(Go Ethereum)는 가장 널리 사용되는 프로덕션 실행 클라이언트입니다. py-ethclient는 동일한 핵심 프로토콜(EVM, eth/68, snap/1, Engine API)을 구현하지만 가독성과 연구 목적으로 Python으로 작성되었습니다. geth가 프로덕션 성능에 최적화된 반면, py-ethclient는 코드 명확성을 우선시하여 이더리움이 프로토콜 수준에서 어떻게 동작하는지 학습하기에 이상적입니다.

**py-ethclient로 L2를 만들 수 있나요?**
네. py-ethclient에는 내장된 실행 훅 시스템(`ExecutionHook`)이 있어 EVM 동작을 커스터마이징할 수 있습니다. 실행 전/후 훅, 호출 인터셉트, 상태 변경 추적 등이 가능하며, 코어 코드를 수정할 필요가 없습니다. 이를 통해 L2 실행 레이어 개발의 실질적인 기반으로 활용할 수 있습니다.

**py-ethclient는 어떤 EIP를 지원하나요?**
EIP-155(리플레이 보호), EIP-1559(동적 수수료), EIP-2718(typed 트랜잭션), EIP-2929/2930(access list), EIP-4844(blob 트랜잭션 + KZG), EIP-7702(Prague EOA 코드 설정)을 지원합니다. 전체 목록은 [지원 EIP](#지원-eip) 섹션을 참고하세요.

## 현재 제한사항

- **Engine API** — V1/V2/V3 구현 완료; 블록 생산 흐름 동작 중이나 최적화 진행 중
- **eth_getLogs** — 스텁 구현; 로그 필터링 미구현
- **contractAddress** — 트랜잭션 영수증에서 CREATE 컨트랙트 주소 미계산

## License

MIT
