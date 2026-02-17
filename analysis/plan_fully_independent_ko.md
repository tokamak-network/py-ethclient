# 시나리오 A 구현 계획: 완전 독립 포팅 (~15,000 LOC)

모든 컴포넌트를 직접 구현하여 devp2p로 이더리움 네트워크에 독립적으로 참여 가능한 노드를 만든다.

외부 라이브러리는 암호화 프리미티브(pycryptodome, coincurve)와 웹 프레임워크(FastAPI)만 사용. py-evm, py-trie, pyrlp 사용하지 않음.

---

## 프로젝트 구조

```
py-ethclient/
├── pyproject.toml
├── ethclient/
│   ├── main.py                  # 진입점
│   ├── common/                  # Phase 1
│   │   ├── types.py             # Block, Header, Transaction, Receipt, Account
│   │   ├── rlp.py               # RLP 인코딩/디코딩
│   │   ├── trie.py              # 머클 패트리시아 트라이
│   │   ├── crypto.py            # Keccak256, BLAKE2f, secp256k1
│   │   └── config.py            # 체인 설정, 하드포크 파라미터
│   ├── vm/                      # Phase 2
│   │   ├── evm.py               # EVM 메인 루프
│   │   ├── opcodes.py           # 옵코드 핸들러
│   │   ├── precompiles.py       # 프리컴파일 컨트랙트
│   │   ├── gas.py               # 가스 계산
│   │   ├── memory.py            # 스택/메모리 관리
│   │   ├── call_frame.py        # 콜 프레임
│   │   └── hooks.py             # 실행 훅 인터페이스 (L2 확장 대비)
│   ├── storage/                 # Phase 3
│   │   ├── store.py             # 상태 저장소 인터페이스
│   │   └── memory_backend.py    # 인메모리 백엔드
│   ├── blockchain/              # Phase 4
│   │   ├── chain.py             # 블록 검증/실행
│   │   ├── mempool.py           # 트랜잭션 풀
│   │   └── fork_choice.py       # 포크 선택
│   ├── networking/              # Phase 5
│   │   ├── rlpx/
│   │   │   ├── connection.py    # RLPx 암호화 전송
│   │   │   ├── handshake.py     # ECIES 핸드셰이크
│   │   │   └── framing.py       # 메시지 프레이밍
│   │   ├── discv4/
│   │   │   ├── discovery.py     # UDP 피어 탐색
│   │   │   └── routing.py       # k-bucket 라우팅 테이블
│   │   ├── eth/
│   │   │   ├── protocol.py      # eth/68 서브프로토콜
│   │   │   └── messages.py      # eth 메시지 타입
│   │   ├── sync/
│   │   │   └── full_sync.py     # Full sync 관리
│   │   └── server.py            # P2P 서버 메인 루프
│   └── rpc/                     # Phase 6
│       ├── server.py            # JSON-RPC 서버
│       ├── eth_api.py           # eth_ 네임스페이스
│       └── engine_api.py        # Engine API (선택적)
└── tests/
    ├── test_rlp.py
    ├── test_trie.py
    ├── test_evm.py
    ├── test_blockchain.py
    └── test_p2p.py
```

---

## 구현 단계 및 의존성

```
Phase 1 (공통) ──────────────────────────────┐
    │                                         │
    ├── Phase 2 (EVM)                         │
    │       │                                 │
    │       ├── Phase 3 (저장소)               │
    │       │       │                         │
    │       │       └── Phase 4 (블록체인) ────┤
    │       │               │                 │
    │       │               ├── Phase 5 (P2P) │
    │       │               │                 │
    │       │               └── Phase 6 (RPC) │
    │       │                       │         │
    │       └───────────────────────┴── Phase 7 (통합)
```

---

## Phase별 작업 상세

### Phase 1: 공통 기반 (~2,500-3,500 LOC)

의존성 없는 기초 모듈. 이후 모든 Phase에서 사용.

| # | 작업 | 예상 LOC | 참조 (ethrex) | 설명 |
|---|---|---:|---|---|
| 1.1 | RLP 인코딩/디코딩 | ~400 | `crates/common/rlp/` | encode, decode, 리스트/바이트 구분 |
| 1.2 | 핵심 타입 정의 | ~800 | `crates/common/types/` | Block, BlockHeader, Transaction (EIP-155/1559/2930/4844), Receipt, Account, Genesis |
| 1.3 | 암호화 유틸리티 | ~200 | `crates/common/crypto/` | keccak256 래퍼, secp256k1 서명/복구, 주소 도출 |
| 1.4 | 머클 패트리시아 트라이 | ~800 | `crates/common/trie/` | Node (Branch/Extension/Leaf), get/put/delete, 상태 루트 계산 |
| 1.5 | 체인 설정 | ~300 | `crates/common/types/genesis.rs` | 하드포크 블록번호, 체인 ID, genesis 파싱 |

**검증**: RLP 라운드트립 테스트, 이더리움 공식 trie 테스트 벡터 통과

---

### Phase 2: EVM (~3,500-4,500 LOC)

Phase 1에 의존. 가장 로직이 밀집된 모듈.

| # | 작업 | 예상 LOC | 참조 (ethrex) | 설명 |
|---|---|---:|---|---|
| 2.1 | 스택/메모리/콜프레임 | ~300 | `crates/vm/levm/call_frame.rs` | 256비트 스택, 바이트 메모리, 콜 깊이 관리 |
| 2.2 | 가스 계산 | ~400 | `crates/vm/levm/gas_cost.rs` | 옵코드별 가스, 메모리 확장 비용, EIP-2929 cold/warm |
| 2.3 | 산술/비트/비교 옵코드 | ~400 | `crates/vm/levm/opcode_handlers/arithmetic.rs`, `bitwise_comparison.rs` | ADD, MUL, SUB, DIV, MOD, EXP, LT, GT, EQ, AND, OR, XOR 등 |
| 2.4 | 환경/블록 옵코드 | ~300 | `crates/vm/levm/opcode_handlers/environment.rs`, `block.rs` | ADDRESS, BALANCE, CALLER, CALLVALUE, GASPRICE, BLOCKHASH, COINBASE, TIMESTAMP 등 |
| 2.5 | 스택/메모리/스토리지/흐름 옵코드 | ~400 | `crates/vm/levm/opcode_handlers/stack_memory_storage_flow.rs` | POP, MLOAD, MSTORE, SLOAD, SSTORE, JUMP, JUMPI, PC, MSIZE 등 |
| 2.6 | 시스템 옵코드 | ~500 | `crates/vm/levm/opcode_handlers/system.rs` | CALL, CALLCODE, DELEGATECALL, STATICCALL, CREATE, CREATE2, SELFDESTRUCT, RETURN, REVERT |
| 2.7 | 로깅/PUSH/DUP/SWAP | ~200 | `crates/vm/levm/opcode_handlers/logging.rs`, `push.rs`, `dup.rs`, `exchange.rs` | LOG0-4, PUSH1-32, DUP1-16, SWAP1-16 |
| 2.8 | 프리컴파일 | ~600 | `crates/vm/levm/precompiles.rs` | ecrecover, SHA256, RIPEMD160, identity, modexp, ecadd, ecmul, ecpairing, BLAKE2f, KZG point eval |
| 2.9 | EVM 메인 루프 | ~400 | `crates/vm/levm/vm.rs` | fetch-decode-execute, substate (access lists, transient storage), 체크포인트/롤백 |
| 2.10 | 실행 훅 시스템 | ~50 | `crates/vm/levm/hooks/` | ExecutionHook 인터페이스 + DefaultHook(L1). 훅 포인트: before_tx, before_call, on_state_change. L2 확장 시 L2Hook 추가만으로 대응 |

**검증**: 이더리움 재단 EVM 테스트 스위트 (ethereum/tests) 통과

**설계 참고 — 훅 시스템:**
EVM 메인 루프의 주요 실행 시점(트랜잭션 실행 전, CALL/CREATE 전, 상태 변경 시)에 훅 포인트를 배치한다. L1 전용에서는 DefaultHook(no-op)만 사용. ~50 LOC 추가로 향후 L2 확장 시 EVM 재구조화 없이 대응 가능.

```python
# hooks.py (~50 LOC)
class ExecutionHook:
    def before_execution(self, tx): pass
    def before_call(self, msg): pass
    def on_state_change(self, addr, key, value): pass

class DefaultHook(ExecutionHook):
    pass  # L1: 모든 훅이 no-op
```

---

### Phase 3: 저장소 (~500-800 LOC)

Phase 1에 의존. 인메모리 우선 구현.

| # | 작업 | 예상 LOC | 참조 (ethrex) | 설명 |
|---|---|---:|---|---|
| 3.1 | Store 인터페이스 | ~200 | `crates/storage/store.rs` | 계정/코드/스토리지 CRUD, 블록 헤더/바디/영수증 저장/조회 |
| 3.2 | 인메모리 백엔드 | ~300 | `crates/storage/backend/in_memory.rs` | dict 기반 구현 |
| 3.3 | 상태 관리 | ~200 | `crates/storage/layering.rs` | 블록 단위 상태 커밋/롤백 |

**검증**: 상태 루트 계산 정합성 테스트

---

### Phase 4: 블록체인 엔진 (~1,500-2,000 LOC)

Phase 1, 2, 3에 의존.

| # | 작업 | 예상 LOC | 참조 (ethrex) | 설명 |
|---|---|---:|---|---|
| 4.1 | 블록 헤더 검증 | ~300 | `crates/blockchain/blockchain.rs` | 타임스탬프, 가스 리밋, 난이도/base fee 검증 |
| 4.2 | 트랜잭션 실행 | ~400 | `crates/blockchain/vm.rs` | tx → EVM 호출, 가스 차감, 상태 변경, 영수증 생성 |
| 4.3 | 블록 실행 | ~300 | `crates/blockchain/blockchain.rs` | 헤더 검증 → tx 순차 실행 → 상태 루트 비교 → 커밋 |
| 4.4 | Mempool | ~300 | `crates/blockchain/mempool.rs` | 송신자별 논스 정렬 큐, pending/queued 관리 |
| 4.5 | 포크 선택 | ~200 | `crates/blockchain/fork_choice.rs` | canonical chain 관리, 리오그 처리 |

**검증**: 알려진 블록(메인넷 블록 일부)에 대해 실행 결과 비교

---

### Phase 5: P2P 네트워킹 (~4,000-5,500 LOC)

Phase 1, 4에 의존. 가장 큰 모듈.

| # | 작업 | 예상 LOC | 참조 (ethrex) | 설명 |
|---|---|---:|---|---|
| 5.1 | ECIES 암호화 | ~300 | `crates/networking/p2p/rlpx/connection/` | secp256k1 ECDH + AES-256-CTR + HMAC-SHA256 |
| 5.2 | RLPx 핸드셰이크 | ~400 | `crates/networking/p2p/rlpx/connection/handshake.rs` | auth/ack 메시지, 세션 키 도출 |
| 5.3 | RLPx 프레이밍 | ~300 | `crates/networking/p2p/rlpx/connection/codec.rs` | 메시지 분할, 암호화/복호화, snappy 압축 |
| 5.4 | p2p 서브프로토콜 | ~200 | `crates/networking/p2p/rlpx/p2p.rs` | Hello, Disconnect, Ping/Pong |
| 5.5 | eth 서브프로토콜 메시지 | ~400 | `crates/networking/p2p/rlpx/eth/` | Status, GetBlockHeaders, BlockHeaders, GetBlockBodies, BlockBodies, Transactions, NewPooledTransactionHashes |
| 5.6 | Discovery v4 | ~800 | `crates/networking/p2p/discv4/` | Ping/Pong/FindNeighbours/Neighbours UDP 메시지, k-bucket 테이블 |
| 5.7 | 피어 관리 | ~400 | `crates/networking/p2p/network.rs`, `peer_handler.rs` | 피어 연결 풀, 이벤트 루프, 연결/해제 관리 |
| 5.8 | Full Sync | ~500 | `crates/networking/p2p/sync/full.rs` | 헤더 다운로드 → 바디 다운로드 → 블록 실행 파이프라인 |
| 5.9 | TX 브로드캐스트 | ~200 | `crates/networking/p2p/tx_broadcaster.rs` | 연결된 피어에게 트랜잭션 전파 |
| 5.10 | P2P 서버 | ~500 | `crates/networking/p2p/` | asyncio 기반 TCP/UDP 서버, 전체 조율 |

**검증**: devp2p 테스트 도구(hive)로 핸드셰이크/메시지 교환 테스트, 테스트넷 피어 연결

---

### Phase 6: JSON-RPC 서버 (~1,500-2,000 LOC)

Phase 1, 3, 4에 의존.

| # | 작업 | 예상 LOC | 참조 (ethrex) | 설명 |
|---|---|---:|---|---|
| 6.1 | RPC 서버 프레임워크 | ~200 | `crates/networking/rpc/rpc.rs` | FastAPI 기반 JSON-RPC 디스패처 |
| 6.2 | eth_ 계정 API | ~200 | `crates/networking/rpc/eth/account.rs` | getBalance, getCode, getStorageAt, getTransactionCount |
| 6.3 | eth_ 블록 API | ~300 | `crates/networking/rpc/eth/block.rs` | getBlockByHash, getBlockByNumber, getBlockReceipts, blockNumber |
| 6.4 | eth_ 트랜잭션 API | ~300 | `crates/networking/rpc/eth/transaction.rs` | sendRawTransaction, call, estimateGas, getTransactionByHash, getTransactionReceipt |
| 6.5 | eth_ 필터/로그 API | ~200 | `crates/networking/rpc/eth/filter.rs` | getLogs, newFilter, getFilterChanges |
| 6.6 | eth_ 기타 API | ~150 | `crates/networking/rpc/eth/` | gasPrice, feeHistory, chainId, syncing |
| 6.7 | net_/web3_ API | ~50 | `crates/networking/rpc/` | net_version, net_peerCount, web3_clientVersion |
| 6.8 | Engine API (선택) | ~500 | `crates/networking/rpc/engine/` | newPayload, forkchoiceUpdated, getPayload |

**검증**: curl/httpie로 RPC 호출 테스트, web3.py 연결 확인

---

### Phase 7: 통합 및 진입점 (~300-500 LOC)

모든 Phase 의존.

| # | 작업 | 예상 LOC | 설명 |
|---|---|---:|---|
| 7.1 | CLI 진입점 | ~100 | argparse 기반 설정 (포트, bootnodes, datadir 등) |
| 7.2 | 노드 초기화 | ~200 | genesis 로드 → storage 초기화 → P2P 시작 → RPC 시작 → sync 시작 |
| 7.3 | 시그널 처리 | ~50 | graceful shutdown |

**검증**: 테스트넷 부트노드 연결 → 블록 동기화 → RPC 응답 확인

---

## Phase별 예상 LOC 합계

| Phase | 범위 |
|---|---:|
| 1. 공통 기반 | 2,500-3,500 |
| 2. EVM | 3,500-4,500 |
| 3. 저장소 | 500-800 |
| 4. 블록체인 | 1,500-2,000 |
| 5. P2P | 4,000-5,500 |
| 6. RPC | 1,500-2,000 |
| 7. 통합 | 300-500 |
| **합계** | **13,800-18,800** |

---

## 기술 스택

- Python 3.12+
- `pycryptodome` — AES, SHA256, RIPEMD160
- `coincurve` — secp256k1 (ECDSA, ECDH)
- `eth-hash[pycryptodome]` — keccak256
- `fastapi` + `uvicorn` — JSON-RPC 서버
- `python-snappy` — RLPx 메시지 압축
- `asyncio` — 비동기 네트워킹

---

## 검증 전략

1. **단위 테스트**: 각 Phase마다 pytest 기반 테스트
2. **이더리움 공식 테스트**: ethereum/tests 레포의 RLP, Trie, EVM 테스트 벡터
3. **테스트넷 연결**: Sepolia/Holesky 테스트넷 부트노드에 연결하여 실제 동기화
4. **RPC 호환성**: web3.py로 연결하여 표준 API 동작 확인
