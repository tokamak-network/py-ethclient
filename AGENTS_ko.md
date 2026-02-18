# AGENTS.md — py-ethclient 가이드

Python으로 구현한 이더리움 L1 실행 클라이언트. ethrex (Rust)를 참조하여 완전 독립 포팅.

## 빠른 시작

```bash
# 설치
pip install -e ".[dev]"

# 단위 테스트 (445개, ~7초)
pytest

# 특정 모듈 테스트
pytest tests/test_rlp.py
pytest tests/test_evm.py -v

# 라이브 네트워크 검증 (메인넷 연결, ~30초)
python3 test_full_sync.py

# 노드 실행
ethclient --network mainnet --port 30303

# Snap sync (기본값)
ethclient --network sepolia

# Full sync 모드
ethclient --network sepolia --sync-mode full

# Docker
docker compose up -d                        # 메인넷
NETWORK=sepolia docker compose up -d        # Sepolia
docker compose logs -f                      # 로그 확인
docker compose down                         # 종료
```

## 프로젝트 구조

```
py-ethclient/                    # ~15,900 LOC (소스 + 테스트)
├── ethclient/
│   ├── main.py                  # CLI 진입점 (argparse, asyncio 이벤트 루프)
│   ├── common/                  # 기초 모듈 (의존성 없음)
│   │   ├── rlp.py               # RLP 인코딩/디코딩
│   │   ├── types.py             # BlockHeader, Transaction, Receipt, Account, TxType
│   │   ├── trie.py              # 머클 패트리시아 트라이 (상태 루트, 증명, 범위 증명)
│   │   ├── crypto.py            # keccak256, secp256k1, ECDSA, 주소 도출
│   │   └── config.py            # 체인 설정, 하드포크, ForkID, genesis
│   ├── vm/                      # EVM 구현
│   │   ├── evm.py               # fetch-decode-execute 메인 루프
│   │   ├── opcodes.py           # 옵코드 핸들러 (전체 Istanbul 지원)
│   │   ├── precompiles.py       # 프리컴파일 컨트랙트 (ecrecover, modexp 등)
│   │   ├── gas.py               # 가스 계산 (EIP-2929 cold/warm)
│   │   ├── memory.py            # 바이트 메모리
│   │   ├── call_frame.py        # 256비트 스택 + 콜 프레임
│   │   └── hooks.py             # 실행 훅 인터페이스 (L2 확장 대비)
│   ├── storage/                 # 상태 저장소
│   │   ├── store.py             # Store 인터페이스 (계정/코드/스토리지 CRUD + snap sync)
│   │   ├── memory_backend.py    # dict 기반 인메모리 백엔드
│   │   └── disk_backend.py     # LMDB 기반 영속 스토리지 (오버레이 패턴)
│   ├── blockchain/              # 블록체인 엔진
│   │   ├── chain.py             # 블록 검증/실행, PoW 보상, base fee, simulate_call
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
│   │       ├── full_sync.py     # Full sync 파이프라인
│   │       └── snap_sync.py     # Snap sync 4단계 상태 머신
│   └── rpc/                     # JSON-RPC 서버
│       ├── server.py            # FastAPI 기반 디스패처
│       └── eth_api.py           # eth_ 네임스페이스 핸들러
├── tests/                       # pytest 단위 테스트 (445개)
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
│   ├── test_rpc.py              # JSON-RPC 엔드포인트
│   └── test_integration.py      # 모듈 간 통합 테스트
├── test_full_sync.py            # 라이브 메인넷 검증 테스트 (별도 실행)
├── Dockerfile                   # Ubuntu 기반 컨테이너 이미지
├── docker-compose.yml           # 원커맨드 배포
├── .dockerignore                # 빌드 컨텍스트 제외 목록
└── pyproject.toml               # Python 3.12+, 의존성 정의
```

## 모듈 의존성 그래프

```
common (rlp, types, trie, crypto, config)
  ↓
vm (evm, opcodes, precompiles, gas)
  ↓
storage (store, memory_backend, disk_backend)
  ↓
blockchain (chain, mempool, fork_choice)
  ↓
networking (rlpx, discv4, eth, snap, sync, server)  +  rpc (server, eth_api)
  ↓
main.py (통합 진입점)
```

하위 모듈은 상위 모듈에 의존하지 않음. common은 어디서든 안전하게 import 가능.

## 테스트

### 단위 테스트 (오프라인)

```bash
pytest                           # 전체 (445개, ~7초)
pytest tests/test_rlp.py         # RLP만
pytest tests/test_evm.py -k "test_add"  # 특정 테스트
pytest -v                        # 상세 출력
pytest --tb=short                # 짧은 트레이스백
```

테스트 파일별 커버리지:

| 파일 | 테스트 수 | 커버하는 모듈 |
|------|--------:|-------------|
| test_rlp.py | 56 | RLP 인코딩/디코딩, 라운드트립 |
| test_trie.py | 26 | MPT, 이더리움 공식 벡터 |
| test_trie_proofs.py | 23 | 증명 생성/검증, 범위 증명, 순회 |
| test_crypto.py | 14 | keccak256, ECDSA, 주소 |
| test_evm.py | 84 | 스택, 메모리, 모든 옵코드, 프리컴파일 (BN128, KZG) |
| test_storage.py | 33 | Store CRUD, 상태 루트, snap 저장소 |
| test_blockchain.py | 31 | 헤더 검증, base fee, 블록 실행, mempool |
| test_p2p.py | 51 | RLPx, 핸드셰이크, eth 메시지 |
| test_protocol_registry.py | 16 | Capability 협상, 오프셋 계산 |
| test_snap_messages.py | 21 | snap/1 메시지 encode/decode 라운드트립 |
| test_snap_sync.py | 21 | Snap sync 상태 머신, 응답 핸들러 |
| test_rpc.py | 57 | JSON-RPC, eth_call/estimateGas EVM 실행 |
| test_integration.py | 12 | 모듈 간 통합 |

### 라이브 네트워크 테스트

```bash
python3 test_full_sync.py        # 메인넷 피어 연결 + 블록 검증
```

검증 항목: 헤더 체인 링크, 트랜잭션 루트 (MPT), ECDSA sender 복구, EIP-1559 base fee, 모든 5가지 tx 타입 (Legacy/AccessList/FeeMarket/Blob/SetCode).

## 핵심 타입

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

각 타입마다 서명 대상 필드가 다름. `recover_sender()`로 ECDSA 복구.

## 주요 패턴 및 주의사항

### EthMsg vs SnapMsg 오프셋

`EthMsg` enum 값에 이미 `0x10` 오프셋이 포함되어 있음:
```python
class EthMsg(IntEnum):
    STATUS = 0x10
    GET_BLOCK_HEADERS = 0x13
    BLOCK_HEADERS = 0x14
    # ...
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

### 피어 선택

```python
snap_peers = [p for p in peers if p.snap_supported]
# snap 미지원 피어만 있으면 full sync 폴백
```

## 개선 가능 영역

1. **Genesis 상태 초기화** — go-ethereum의 genesis alloc 데이터를 파싱하여 초기 상태 구축
2. **Engine API** — Beacon Chain 연동을 위한 `engine_` 네임스페이스
4. **EVM 테스트 스위트** — ethereum/tests 공식 벡터로 EVM 정합성 검증 확대
5. **성능 최적화** — 트라이 캐싱, 병렬 트랜잭션 검증, asyncio 최적화

## 의존성

| 패키지 | 용도 |
|--------|------|
| pycryptodome | AES, SHA256, RIPEMD160 |
| coincurve | secp256k1 (ECDSA, ECDH) |
| eth-hash[pycryptodome] | keccak256 |
| fastapi + uvicorn | JSON-RPC 서버 |
| python-snappy | RLPx 메시지 압축 |
| py-ecc | BN128 ecAdd/ecMul/ecPairing |
| ckzg | KZG point evaluation (EIP-4844) |
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

1. `common/types.py` 수정 시 → `test_rlp.py`, `test_blockchain.py` 실행
2. `common/trie.py` 수정 시 → `test_trie.py`, `test_trie_proofs.py` 실행
3. `vm/` 수정 시 → `test_evm.py` 실행
4. `networking/` 수정 시 → `test_p2p.py`, `test_protocol_registry.py`, `test_snap_messages.py` 실행
5. `networking/sync/` 수정 시 → `test_snap_sync.py` + `test_full_sync.py` 실행
6. `blockchain/` 수정 시 → `test_blockchain.py` + `test_integration.py` + `test_rpc.py` 실행
7. 새 하드포크 지원 시 → `config.py`에 포크 블록/타임스탬프 추가, `types.py`에 새 필드 추가
8. 전체 회귀 테스트: `pytest && python3 test_full_sync.py`
