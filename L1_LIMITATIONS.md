# py-ethclient L1 Client: Limitations and Future Work

**L1 Ethereum 클라이언트 한계점, 제한사항, 개선 방향**

py-ethclient의 L1 클라이언트는 EVM(140+ opcodes), RLPx/devp2p, eth/68, snap/1, full+snap sync, Engine API V1/V2/V3를 순수 Python으로 구현한 참조 구현체이다. 본 문서는 L2 롤업 프레임워크와 분리된 L1 클라이언트 고유의 한계점을 카테고리별로 정리한다.

> L2 롤업 프레임워크의 한계점은 [WHITEPAPER.md Section 10](./WHITEPAPER.md#10-limitations-and-future-work)을 참고.

---

## 목차

1. [EVM 실행 엔진](#1-evm-실행-엔진)
2. [P2P 네트워킹](#2-p2p-네트워킹)
3. [동기화 (Full Sync / Snap Sync)](#3-동기화)
4. [코어 모듈 (RLP, Trie, Crypto)](#4-코어-모듈)
5. [스토리지 백엔드](#5-스토리지-백엔드)
6. [JSON-RPC / Engine API](#6-json-rpc--engine-api)
7. [성능 병목](#7-성능-병목)
8. [EIP 호환성 매트릭스](#8-eip-호환성-매트릭스)
9. [종합 요약](#9-종합-요약)

---

## 1. EVM 실행 엔진

### 1.1 Critical

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 1 | CALL 계열 가스 계산 미흡 | `vm/gas.py:176-204` | EIP-150 63/64 규칙만 구현. EIP-2929 warm/cold access 비용이 CALL/STATICCALL/DELEGATECALL 가스에 일관되게 반영되는지 검증 필요 |
| 2 | Memory offset 오버플로우 | `vm/gas.py:53-83` | `calc_memory_cost()`에서 uint256 범위의 offset에 대한 상한 검사 없음. offset ≥ 2^30 시 즉시 Out-of-Gas 처리 필요 (Geth 방식) |
| 3 | Initcode 크기 제한 부재 | `vm/evm.py:237` | EIP-170 (deployed code ≤ 24,576 bytes) 적용됨. 그러나 EIP-3860 initcode 크기 제한 (≤ 49,152 bytes) 미적용 |

### 1.2 High

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 4 | Snapshot 깊은 복사 오버헤드 | `vm/evm.py:149-173` | 매 CALL마다 전체 state dict 복사. depth=1024 call chain에서 메모리 폭발. Copy-on-Write 또는 undo log 전략 필요 |
| 5 | 가스 계산 Geth 호환성 미검증 | `vm/gas.py` 전체 | 메모리 확장, SELFDESTRUCT 리펀드(EIP-3529), SSTORE 가스(EIP-2200) 등이 Geth 테스트 벡터와 정확히 일치하는지 체계적 검증 부재 |
| 6 | EIP-2929 Access List 일관성 | `vm/gas.py:90-122` | `mark_warm_address`/`mark_warm_storage` 호출이 모든 관련 opcode에서 일관되게 적용되는지 전수 감사 필요 |
| 7 | STATICCALL 전파 검증 부족 | `vm/opcodes.py:931-963` | `is_static=True` 전파가 내부 호출 체인 전체에서 보장되는지 검증 불충분 |

### 1.3 Medium

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 8 | CREATE/CREATE2 nonce 타이밍 | `vm/evm.py:180-200` | 주소 생성 후 nonce 증분 타이밍(라인 200)이 Ethereum 스펙과 정확히 일치하는지 확인 필요 |
| 9 | 향후 EVM 버전 미지원 | `vm/opcodes.py` | Shanghai opcodes (PUSH0, TLOAD/TSTORE, MCOPY) 구현됨. 그러나 Dencun 이후 EOF (EIP-3540: CALLF, RETURNF 등) 미지원 |
| 10 | Precompile P256VERIFY 미확정 | `vm/precompiles.py:207-244` | EIP-7212 P256VERIFY 구현되었으나 표준 확정 전. 최종 스펙과 차이 가능 |
| 11 | KZG versioned_hash 검증 | `vm/precompiles.py:404-434` | EIP-4844 Point Evaluation precompile에서 versioned_hash 검증이 스펙과 정확히 일치하는지 확인 필요 |

---

## 2. P2P 네트워킹

### 2.1 Critical

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 12 | RLPx 핸드셰이크 타임아웃 부재 | `networking/rlpx/handshake.py` | 핸드셰이크 완료 대기에 타임아웃 미설정. 악의적 피어가 무한 대기 유발 가능 |
| 13 | eth/69 BlockRangeUpdate 미구현 | `networking/eth/protocol.py:45` | BLOCK_RANGE_UPDATE (0x21) 메시지 타입 정의만 존재. 실제 처리 핸들러 구현 불명확 |
| 14 | Discovery V5 미지원 | `networking/discv4/` | Discovery V4만 구현. ENR (EIP-778) 기반 Discovery V5 미지원으로 최신 클라이언트와의 피어 발견 제한 |

### 2.2 High

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 15 | Snappy 자동 활성화 미흡 | `networking/rlpx/connection.py:36` | `use_snappy` 기본값 False. eth/68+ 에서는 snappy 필수이나 프로토콜 버전 기반 자동 활성화 로직 불명확 |
| 16 | Peer 관리 backoff 부족 | `networking/server.py:83-100` | 연결 실패 시 `DIAL_COOLDOWN_SECONDS=30` 고정. Exponential backoff 미구현으로 불안정 피어에 반복 연결 시도 |
| 17 | Framing MAC 검증 | `networking/rlpx/framing.py` | AES-256-CTR 프레임 암호화의 MAC 계산이 EIP-8 스펙과 정확히 일치하는지 검증 필요 |
| 18 | Capability 협상 제한 | `networking/protocol_registry.py` | 미지원 capability 감지 시 disconnect 처리만 존재. 버전 다운그레이드 협상 로직 미흡 |

### 2.3 Medium

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 19 | MAX_PEERS 하드코딩 | `networking/server.py:87` | 최대 25개 피어 고정. 네트워크 상황에 따른 동적 조정 미지원 |
| 20 | UDP 소켓 타임아웃 | `networking/discv4/discovery.py` | Discovery V4 UDP 소켓에 타임아웃 미설정. FIND_NODE 응답 없을 시 무한 대기 가능 |

---

## 3. 동기화

### 3.1 Critical

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 21 | Full sync header 검증 강도 | `networking/sync/full_sync.py` | Header 다운로드 후 PoW/PoS 검증, difficulty 검증, timestamp 검증의 완성도 불명확 |
| 22 | Snap sync range proof 검증 | `networking/sync/snap_sync.py:73-89` | Range proof 검증 실패 시 peer ban (3회 임계) 처리만 존재. 근본 원인 분석이나 대체 피어 선택 로직 부재 |

### 3.2 High

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 23 | Full sync uncle 블록 미처리 | `networking/sync/full_sync.py` | Uncle (ommer) 블록 수신 및 보상 계산 구현 불명확. PoW 체인 동기화에 영향 |
| 24 | 동적 타임아웃 미지원 | `full_sync.py:48`, `snap_sync.py:54` | `SYNC_TIMEOUT=20s`, `SNAP_TIMEOUT=15s` 고정. 네트워크 지연 변동성 미반영, 피어별 적응형 타임아웃 부재 |
| 25 | Hedging 전략 불명확 | `full_sync.py:57` | `HEDGE_HEADER_ATTEMPTS=2`로 설정되었으나 실제 hedging(여러 피어에 동시 요청) 동작 검증 필요 |

### 3.3 Medium

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 26 | 동기화 진행률 보고 부재 | sync 전체 | 현재 동기화 진행률(블록 높이, 남은 시간, 다운로드 속도)을 외부에 보고하는 메커니즘 없음 |
| 27 | Checkpoint sync 미지원 | sync 전체 | Weak subjectivity checkpoint 기반 빠른 동기화 미지원. 처음부터 전체 체인 동기화 필요 |

---

## 4. 코어 모듈

### 4.1 High

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 28 | Trie 노드 캐싱 부재 | `common/trie.py:138-141` | In-memory dict 기반. LRU 캐시 미지원. 메인넷 규모(수천만 노드)에서 메모리 부족 |
| 29 | Trie branch 노드 최적화 | `common/trie.py` | 16개 child 모두 저장하여 희소성 미활용. 대규모 트라이에서 메모리 낭비 |
| 30 | Hex-Prefix 인코딩 검증 | `common/trie.py:44-78` | hex_prefix_encode/decode가 Yellow Paper 스펙과 정확히 일치하는지 테스트 벡터 기반 검증 부족 |

### 4.2 Medium

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 31 | RLP 대형 정수 엣지 케이스 | `common/rlp.py:24-74` | 2^256 초과 정수 인코딩 시 동작 미정의. 음수 정수는 에러 처리됨 |
| 32 | Crypto 라이브러리 폴백 | `common/crypto.py` | coincurve, pycryptodome 의존. 라이브러리 로드 실패 시 fallback 미구현 |
| 33 | Chain config 외부화 부재 | `common/config.py:52-101` | Mainnet/Sepolia/Holesky 하드코딩. JSON 기반 custom chain config 로더 미지원 |

---

## 5. 스토리지 백엔드

### 5.1 High

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 34 | LMDB 맵 크기 고정 | `storage/disk_backend.py:61` | 1GB 기본 맵 크기. 메인넷 전체 상태 동기화에 부족. 동적 리사이징 미지원 |
| 35 | 동시성 제어 부재 | `storage/disk_backend.py` | Multi-process LMDB 접근 시 동시성 제어 미구현. 단일 프로세스 전용 |
| 36 | State iterator 메모리 | `storage/store.py:145-150` | iter_accounts, iter_storage가 generator 기반인지 불명확. 전체 로드 시 메인넷 규모에서 OOM |

### 5.2 Medium

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 37 | Nonce increment 경쟁 조건 | `storage/store.py:81-82` | increment_nonce가 read-modify-write 패턴이나 동기화 프리미티브 없음 |
| 38 | Code deduplication 부재 | `storage/store.py:84-95` | 동일 바이트코드가 여러 주소에 배포 시 중복 저장. Content-addressed 저장 미구현 |
| 39 | Garbage collection 부재 | `storage/disk_backend.py` | LMDB는 자동 정리 미지원. 삭제된 키의 디스크 공간 재활용 안 됨 |
| 40 | Original storage snapshot | `storage/store.py:131-138` | Block-level vs tx-level 스냅샷 적용 범위 불명확. EIP-2200 SSTORE 가스 계산에 영향 |

---

## 6. JSON-RPC / Engine API

### 6.1 Critical

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 41 | eth_getLogs 미구현 | `rpc/eth_api.py` | 이벤트 로그 필터링(address, topics, block range) 미구현. DApp 호환성에 심각한 영향 |
| 42 | eth_estimateGas 미확인 | `rpc/eth_api.py` | 가스 추정 구현 여부 불명확. 트랜잭션 제출 전 가스 추정 불가 시 DApp 사용 불가 |

### 6.2 High

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 43 | Engine API 통합 검증 부족 | `rpc/engine_api.py:112-150` | forkchoiceUpdated, newPayload, getPayload 구현되었으나 Consensus Layer 클라이언트(Prysm, Lighthouse 등)와의 통합 테스트 부재 |
| 44 | JWT 만료 검증 미흡 | `rpc/server.py:46-48` | Engine API JWT 인증에서 iat/exp claim 검증 여부 불명확. 만료된 토큰 수락 가능성 |
| 45 | Receipt 생성 정확성 | `rpc/eth_api.py` | status, logs, cumulative_gas_used, contract_address 파생 정확도 검증 필요 |
| 46 | Bloom filter 미지원 | `rpc/eth_api.py` | 로그 검색을 위한 bloom filter 인덱싱 미구현. eth_getLogs 구현 시 전수 검색 필요 |

### 6.3 Medium

| # | 한계점 | 위치 | 설명 |
|---|--------|------|------|
| 47 | eth_pendingTransactions 미지원 | `rpc/eth_api.py` | 멤풀 조회 RPC 미구현. 트랜잭션 대기 상태 확인 불가 |
| 48 | trace_* 메서드 미지원 | `rpc/` | debug_traceTransaction, trace_call 등 디버깅 RPC 미지원. 개발자 도구 호환성 제한 |
| 49 | WebSocket 구독 미지원 | `rpc/server.py` | eth_subscribe/eth_unsubscribe 미구현. 실시간 이벤트 수신 불가 |

---

## 7. 성능 병목

| # | 병목 | 위치 | 영향 | 개선 방향 |
|---|------|------|------|----------|
| 50 | 인터프리터 기반 EVM | `vm/evm.py:380-424` | Geth 대비 10-100배 느림 | PyPy 호환성 확보, Cython/Rust binding 고려 |
| 51 | Trie 노드 전체 메모리 적재 | `common/trie.py` | 메인넷 규모에서 OOM | LRU 캐시 + disk-backed trie 구현 |
| 52 | 매 opcode 메모리 비용 재계산 | `vm/gas.py:53-83` | 대형 메모리 접근 시 병목 | 이전 크기 캐싱, 변경 시에만 재계산 |
| 53 | CALL snapshot 전체 복사 | `vm/evm.py:149-159` | 깊은 호출 체인에서 O(depth × state_size) | Copy-on-Write 또는 undo log |
| 54 | Python GIL | 전체 | 멀티코어 활용 불가 | 핵심 연산 multiprocessing 또는 C extension |

---

## 8. EIP 호환성 매트릭스

### 지원됨 (Confirmed)

| EIP | 이름 | 영역 |
|-----|------|------|
| EIP-155 | Simple Replay Attack Protection | Tx signing |
| EIP-170 | Contract Code Size Limit (24,576) | EVM |
| EIP-196/197 | BN128 Add/Mul/Pairing | Precompile |
| EIP-1559 | Fee Market | Transaction |
| EIP-2718 | Typed Transactions | Transaction |
| EIP-2929 | Access Lists Gas Cost | EVM Gas |
| EIP-2930 | Access List Transaction Type | Transaction |
| EIP-3529 | Refund Limit Reduction | EVM Gas |
| EIP-3541 | Reject Code Starting with 0xEF | EVM |
| EIP-4844 | Shard Blob Transactions | Transaction, Precompile |
| EIP-5656 | MCOPY | EVM Opcode |
| EIP-1153 | Transient Storage (TLOAD/TSTORE) | EVM Opcode |
| EIP-3855 | PUSH0 | EVM Opcode |
| EIP-7702 | Set EOA Account Code | Transaction |

### 미지원 / 미확인

| EIP | 이름 | 상태 |
|-----|------|------|
| EIP-3540 | EOF v1 (CALLF, RETURNF) | 미지원 |
| EIP-3860 | Initcode Size Limit | 미지원 |
| EIP-6110 | Supply Validator Deposits on Chain | 미확인 |
| EIP-4788 | Beacon Block Root in EVM | 미확인 |
| EIP-7685 | General Purpose Execution Layer Requests | 미확인 |
| Verkle Trie | State Trie Migration | 미지원 |

---

## 9. 종합 요약

### 심각도별 분포

| 심각도 | 건수 | 주요 영역 |
|--------|------|----------|
| Critical | 8 | EVM 가스, P2P 보안, 동기화 검증, RPC 누락 |
| High | 16 | EVM 호환성, 피어 관리, 스토리지 확장성, Engine API |
| Medium | 18 | 엣지 케이스, 구성, 개발자 도구 |
| Performance | 5 | 인터프리터, 메모리, GIL |

### 우선순위 Top 10

| 순위 | 항목 | 심각도 | 영향 |
|------|------|--------|------|
| 1 | eth_getLogs / eth_estimateGas 구현 | Critical | DApp 호환성 |
| 2 | Memory offset 오버플로우 방지 | Critical | DoS 방어 |
| 3 | EIP-3860 initcode 크기 제한 | Critical | 스펙 준수 |
| 4 | RLPx 핸드셰이크 타임아웃 | Critical | P2P 보안 |
| 5 | CALL 가스 계산 Geth 호환 검증 | Critical | 블록 검증 |
| 6 | Snap sync range proof 강화 | Critical | 동기화 안정성 |
| 7 | LMDB 동적 맵 크기 | High | 스토리지 확장 |
| 8 | Snapshot Copy-on-Write | High | EVM 메모리 |
| 9 | Engine API CL 통합 테스트 | High | CL 호환성 |
| 10 | Discovery V5 / ENR 지원 | High | 피어 발견 |

### 참고

- 본 문서는 py-ethclient의 L1 클라이언트(EVM, P2P, Sync, Storage, RPC) 범위만 다룬다
- L2 롤업 프레임워크(Sequencer, Prover, DA, Bridge)의 한계점은 [WHITEPAPER.md Section 10](./WHITEPAPER.md#10-limitations-and-future-work) 참고
- 전체 테스트: `pytest tests/ -v` (987 tests)
