# py-ethclient

Python Ethereum L1 execution client — [ethrex](https://github.com/lambdaclass/ethrex) (Rust) 기반 완전 독립 포팅.

devp2p를 통해 이더리움 네트워크에 직접 참여할 수 있는 노드를 목표로 하며, 암호화 프리미티브와 웹 프레임워크를 제외한 모든 로직을 직접 구현합니다.

> **[English README](./README.md)**

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

## Quick Start

```bash
# 기본 실행 (mainnet, 포트 30303/8545)
ethclient

# Sepolia 테스트넷 연결
ethclient --network sepolia

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
| `eth_call` | 읽기 전용 컨트랙트 호출 |
| `eth_estimateGas` | 가스 추정 |
| `eth_gasPrice` | 현재 가스 가격 |
| `eth_maxPriorityFeePerGas` | 우선순위 수수료 |
| `eth_feeHistory` | 수수료 히스토리 |
| `eth_chainId` | 체인 ID |
| `eth_syncing` | 동기화 상태 |
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
pytest tests/test_rlp.py      # RLP 인코딩/디코딩
pytest tests/test_trie.py     # 머클 패트리시아 트라이
pytest tests/test_evm.py      # EVM 옵코드 실행
pytest tests/test_storage.py  # 상태 저장소
pytest tests/test_blockchain.py # 블록 검증/실행
pytest tests/test_p2p.py      # P2P 네트워킹
pytest tests/test_rpc.py      # JSON-RPC 서버
pytest tests/test_integration.py # 통합 테스트

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
│   ├── trie.py                      # 머클 패트리시아 트라이
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
│   ├── store.py                     # 추상 Store 인터페이스
│   └── memory_backend.py            # 인메모리 구현, 상태 루트 계산
├── blockchain/                      # 블록체인 엔진
│   ├── chain.py                     # 블록 검증, 트랜잭션/블록 실행
│   ├── mempool.py                   # 트랜잭션 풀 (논스 정렬, 교체 정책)
│   └── fork_choice.py               # Canonical chain 관리, 리오그
├── networking/                      # P2P 네트워킹
│   ├── server.py                    # P2P 서버 메인 루프
│   ├── rlpx/
│   │   ├── handshake.py             # ECIES 핸드셰이크 (auth/ack)
│   │   ├── framing.py               # RLPx 프레임 암호화/복호화
│   │   └── connection.py            # 암호화된 TCP 연결 관리
│   ├── eth/
│   │   ├── protocol.py              # p2p/eth 메시지 코드, 프로토콜 상수
│   │   └── messages.py              # eth/68 메시지 인코딩/디코딩
│   ├── discv4/
│   │   ├── discovery.py             # Discovery v4 UDP 프로토콜
│   │   └── routing.py               # Kademlia k-bucket 라우팅 테이블
│   └── sync/
│       └── full_sync.py             # Full sync 파이프라인
└── rpc/                             # JSON-RPC 서버
    ├── server.py                    # FastAPI 기반 JSON-RPC 2.0 디스패처
    └── eth_api.py                   # eth_/net_/web3_ API 핸들러
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

**개발용:**

| 패키지 | 용도 |
|---|---|
| [pytest](https://pypi.org/project/pytest/) | 테스트 프레임워크 |
| [pytest-asyncio](https://pypi.org/project/pytest-asyncio/) | 비동기 테스트 지원 |

## Implementation Details

### 직접 구현한 컴포넌트

- **RLP (Recursive Length Prefix)**: 이더리움 직렬화 포맷 — 인코딩/디코딩, 리스트/바이트 구분
- **Merkle Patricia Trie**: Branch/Extension/Leaf 노드, hex-prefix 인코딩, 상태 루트 계산
- **EVM**: 140+ 옵코드, 256비트 스택, 바이트 메모리, EIP-2929 cold/warm 추적, EIP-1559 base fee
- **프리컴파일**: ecrecover, SHA-256, RIPEMD-160, identity, modexp (EIP-2565), BLAKE2f (EIP-152)
- **RLPx 전송**: ECIES 암호화, AES-256-CTR 프레임 암호화, SHA3 MAC 인증
- **eth/68 프로토콜**: Status, GetBlockHeaders, BlockHeaders, Transactions 등 전체 메시지 타입
- **Discovery v4**: UDP Ping/Pong/FindNeighbours/Neighbours, Kademlia 라우팅 테이블
- **Full Sync**: 헤더 다운로드 → 바디 다운로드 → 블록 실행 파이프라인
- **JSON-RPC 2.0**: 요청 파싱, 배치 지원, 에러 핸들링, 메서드 디스패치

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
| EIP-4844 | Blob 트랜잭션 타입 (타입 정의) |

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

| 항목 | 수치 |
|---|---|
| 소스 코드 | ~9,100 LOC |
| 테스트 코드 | ~3,400 LOC |
| 총 LOC | ~12,500 |
| 테스트 수 | 337 |
| 소스 파일 | 29 |
| 테스트 파일 | 8 |

## Current Limitations

- **저장소**: 인메모리 전용 (디스크 백엔드 미구현, 재시작 시 상태 유실)
- **eth_call / estimateGas**: 실제 EVM 실행 미연결 (스텁 응답)
- **BN128 / KZG**: 프리컴파일 스텁 (pairing 연산 미구현)
- **Engine API**: 미구현 (PoS 컨센서스 레이어 연동 없음)
- **Snap sync**: 미구현 (Full sync만 지원)
- **트랜잭션 인덱싱**: 해시 기반 트랜잭션/영수증 조회 미구현

## License

MIT
