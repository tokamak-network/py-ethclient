# py-ethclient L2 지원 구현 계획

## Context

ethrex(Rust)는 동일한 EVM/블록체인 코어를 L1과 L2에서 공유하는 ZK-rollup을 구현함. py-ethclient도 이 접근법을 따라 **최소한의 L1 코드 변경**으로 L2 모드를 추가함.

이미 구현된 기반:
- `TxType.DEPOSIT = 0x7E` — RLP 인코딩/디코딩 + 실행 (`chain.py:330-494`)
- `ExecutionHook` 시스템 — EVM 후킹 6개 메서드 (`hooks.py`)
- Engine API V1/V2/V3 — payload build/execute/forkchoice (`engine_api.py`)
- eth_ RPC에 deposit tx 포맷팅 지원 (`eth_api.py:76-87`)
- 플러거블 Store (MemoryBackend/DiskBackend)

## 전체 아키텍처

```
┌─────────────────────────────────────────────────┐
│                 py-ethclient (L2 mode)           │
│                                                   │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Sequencer│  │L1 Watcher│  │ L1 Committer  │  │
│  │(블록 생산)│  │(입금 감시)│  │(배치 커밋)    │  │
│  └────┬─────┘  └────┬─────┘  └──────┬────────┘  │
│       │              │               │            │
│       v              v               │            │
│  ┌─────────┐  ┌──────────┐          │            │
│  │ Mempool │  │  deposit  │          │            │
│  │(기존)   │←─│  queue    │          │            │
│  └────┬────┘  └──────────┘          │            │
│       v                              │            │
│  ┌──────────────────────┐            │            │
│  │ chain.execute_block()│ (기존 EVM) │            │
│  └──────────┬───────────┘            │            │
│             v                        │            │
│  ┌──────────────────────┐            │            │
│  │   Store (기존)       │────────────┘            │
│  │ + RollupStore (L2)   │                         │
│  └──────────────────────┘                         │
│                                                   │
│  ┌──────────────────────┐                         │
│  │ RPC (eth_ + engine_) │ (기존, 그대로 유지)      │
│  └──────────────────────┘                         │
└─────────────────────────────────────────────────┘
        │                    ▲
        │  L1 tx 전송        │  L1 이벤트 조회
        v                    │
┌───────────────────────────────────┐
│          Ethereum L1               │
│  ┌─────────────┐ ┌──────────────┐ │
│  │CommonBridge  │ │OnChainProposer│ │
│  │(입금/출금)   │ │(배치 관리)    │ │
│  └─────────────┘ └──────────────┘ │
└───────────────────────────────────┘
```

## Phase 1: L2 코어 인프라

**새 파일:**
- `ethclient/l2/__init__.py`
- `ethclient/l2/config.py` (~120 lines) — `L2Config` 데이터클래스, L2 ChainConfig 프리셋
- `ethclient/l2/rollup_store.py` (~150 lines) — `Batch` 데이터클래스, `RollupStore` (배치 메타데이터 + L1 watcher 상태)

**수정 파일:**
- `ethclient/main.py` — `--l2`, `--l2-l1-rpc`, `--l2-bridge-address`, `--l2-proposer-address`, `--l2-block-time`, `--l2-sequencer-key` CLI 플래그 추가. L2 모드일 때 P2P 비활성, sequencer/watcher/committer 태스크 시작

**핵심 설계:**
```python
@dataclass
class L2Config:
    l1_rpc_url: str = "http://localhost:8545"
    common_bridge_address: bytes = b"\x00" * 20
    on_chain_proposer_address: bytes = b"\x00" * 20
    block_time_ms: int = 2000
    batch_size: int = 10
    sequencer_coinbase: bytes = b"\x00" * 20
    sequencer_private_key: Optional[bytes] = None
    l1_watcher_check_interval_s: float = 12.0
    commit_interval_s: float = 60.0

@dataclass
class Batch:
    number: int
    block_numbers: list[int]
    state_root: bytes
    committed: bool = False
    commit_tx_hash: Optional[bytes] = None
```

## Phase 2: Sequencer (블록 생산)

**새 파일:**
- `ethclient/l2/sequencer.py` (~300 lines)

**수정 파일:**
- `ethclient/blockchain/mempool.py` — `inject_deposit_tx()`, `drain_deposit_queue()` 추가 (~25 lines)

**핵심 흐름** (ethrex `block_producer.rs` 참조):
1. 현재 head 헤더 조회
2. `calc_base_fee(parent, config)` 로 base fee 계산 (기존 함수 재사용)
3. `mempool.drain_deposit_queue()` → deposit tx 우선 수집
4. `mempool.get_pending()` → 일반 tx 수집 (gas limit까지)
5. `BlockHeader` 구성 (sequencer coinbase, 타임스탬프, 빈 withdrawals)
6. **`execute_block()` 호출** (기존 chain.py 그대로 재사용)
7. 실행 결과로 헤더 필드 업데이트 (state_root, receipts_root, gas_used, logs_bloom)
8. `store.put_block()` + `fork_choice.set_head()` + mempool 정리
9. 배치 블록 수 도달 시 `rollup_store.put_batch()` 로 배치 확정

**재사용하는 기존 함수들:**
- `chain.py:execute_block()` — 트랜잭션 실행 (deposit 포함)
- `chain.py:calc_base_fee()` — EIP-1559 base fee
- `trie.py:ordered_trie_root()` — tx/receipts root 계산
- `mempool.py:Mempool.get_pending()` — 트랜잭션 수집
- `fork_choice.py:ForkChoice.set_head()` — canonical chain 업데이트

## Phase 3: L1 Watcher (입금 감시)

**새 파일:**
- `ethclient/l2/l1_client.py` (~150 lines) — 비동기 JSON-RPC 클라이언트 (L1 호출용)
- `ethclient/l2/bridge_abi.py` (~80 lines) — 이벤트 토픽, deposit event 파싱
- `ethclient/l2/l1_watcher.py` (~250 lines) — L1 감시 루프

**핵심 흐름** (ethrex `l1_watcher.rs` 참조):
1. `eth_blockNumber` 로 L1 현재 블록 조회
2. finality delay 적용 (6블록)
3. `eth_getLogs` 로 CommonBridge deposit 이벤트 조회
4. 이벤트 → `Transaction(tx_type=TxType.DEPOSIT, ...)` 변환 (기존 타입 그대로)
5. `mempool.inject_deposit_tx()` 로 주입
6. 처리된 L1 블록 번호 `rollup_store`에 저장

**L1 HTTP 클라이언트:** `aiohttp` 의존성 추가 (또는 stdlib `urllib` + `asyncio.to_thread()`)

## Phase 4: L1 Committer (배치 커밋)

**새 파일:**
- `ethclient/l2/abi_encoder.py` (~100 lines) — 최소 ABI 인코딩 (uint256, bytes32, address)
- `ethclient/l2/l1_committer.py` (~300 lines) — 배치 커밋 루프

**핵심 흐름** (ethrex `l1_committer.rs` 참조):
1. `rollup_store`에서 미커밋 배치 조회
2. 배치의 마지막 블록 state_root 추출
3. `OnChainProposer.commitBatch(batchNum, stateRoot, lastBlockHash, blockCount)` calldata 인코딩
4. EIP-1559 트랜잭션 구성 + 서명 (기존 `Transaction` + `crypto.py` 재사용)
5. `l1_client.send_raw_transaction()` 으로 전송
6. receipt 확인 후 `rollup_store` 업데이트

## Phase 5: L1 스마트 컨트랙트

**새 파일:**
- `contracts/CommonBridge.sol` (~150 lines) — 입금/출금 브릿지
- `contracts/OnChainProposer.sol` (~200 lines) — 배치 관리 + 검증

배포는 외부 도구(Foundry/Hardhat) 사용. 파이썬 클라이언트는 배포된 주소를 설정으로 받음.

## Phase 6: Prover (미래)

ZK 증명 생성은 별도 프로세스. Python에서는 Rust 바이너리를 subprocess로 호출하는 형태. 이 단계는 Phase 1-5 완료 후 별도 계획.

---

## 파일 목록 요약

| Phase | 파일 | 예상 LOC | 설명 |
|-------|------|---------|------|
| 1 | `ethclient/l2/__init__.py` | 5 | 패키지 init |
| 1 | `ethclient/l2/config.py` | 120 | L2Config, 체인 설정 |
| 1 | `ethclient/l2/rollup_store.py` | 150 | 배치/L2 상태 관리 |
| 2 | `ethclient/l2/sequencer.py` | 300 | 블록 생산 루프 |
| 3 | `ethclient/l2/l1_client.py` | 150 | L1 JSON-RPC 클라이언트 |
| 3 | `ethclient/l2/bridge_abi.py` | 80 | ABI 상수, 이벤트 파싱 |
| 3 | `ethclient/l2/l1_watcher.py` | 250 | L1 입금 감시 |
| 4 | `ethclient/l2/abi_encoder.py` | 100 | ABI 인코딩 유틸 |
| 4 | `ethclient/l2/l1_committer.py` | 300 | L1 배치 커밋 |
| 5 | `contracts/CommonBridge.sol` | 150 | L1 브릿지 컨트랙트 |
| 5 | `contracts/OnChainProposer.sol` | 200 | L1 배치 관리 컨트랙트 |
| | **합계** | **~1,805** | |

**수정 파일:** `main.py` (+80 lines), `mempool.py` (+25 lines)

## 구현 순서

```
Phase 1 (인프라) → Phase 2 (Sequencer) ─┐
                 → Phase 3 (L1 Watcher) ─┼→ Phase 4 (Committer) → Phase 5 (컨트랙트)
                                          │
                              Phase 2, 3은 병렬 가능
```

## 검증 방법

1. **Phase 1-2 단위 테스트**: sequencer가 빈 mempool에서 빈 블록 생산, tx 있을 때 블록 생산 + state root 검증
2. **Phase 3 단위 테스트**: mock L1 응답으로 deposit event 파싱 → deposit tx 생성 검증
3. **Phase 4 단위 테스트**: 배치 커밋 calldata 인코딩 검증
4. **통합 테스트**: 로컬 L1 (Hardhat/Anvil) + L2 노드 → 입금 → L2 블록 생성 → 배치 커밋 → L1에서 확인
5. **라이브 테스트**: Sepolia L1에 컨트랙트 배포 → py-ethclient L2 모드 실행 → E2E 입금/블록생산/커밋 확인

## 핵심 설계 원칙 (ethrex 참조)

1. **EVM 동등성** — L2 전용 프리컴파일/옵코드 변경 없음. 동일 EVM 그대로 사용
2. **최대 코드 재사용** — sequencer가 `chain.execute_block()` 직접 호출 (Engine API 거치지 않음)
3. **L1 코드 비침범** — L2는 `ethclient/l2/` 디렉토리에 격리. 기존 L1 동작 변경 없음
4. **점진적 구현** — sequencer만으로도 동작 가능. L1 watcher/committer는 독립적으로 추가
