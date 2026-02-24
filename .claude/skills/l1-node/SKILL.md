---
description: "L1 Ethereum 노드 운영 — EVM, eth/68, snap/1, Engine API, P2P"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "노드 관련 작업이나 질문"
user-invocable: true
---

# L1 Ethereum 노드 운영 스킬

Python으로 구현된 Ethereum L1 클라이언트의 EVM 실행, eth/68 프로토콜, snap/1 동기화, Engine API, P2P 네트워킹을 안내한다.

## 핵심 파일 참조

| 디렉토리/파일 | 역할 |
|---------------|------|
| `ethclient/vm/` | EVM 실행 엔진 |
| `ethclient/vm/opcodes.py` | 140+ opcode 구현 |
| `ethclient/vm/precompiles.py` | 11개 precompile (ecrecover ~ kzg_point_eval) |
| `ethclient/vm/evm.py` | EVM 인터프리터, CallFrame, ExecutionEnvironment |
| `ethclient/networking/rlpx/` | RLPx 프로토콜, ECIES 핸드셰이크 |
| `ethclient/networking/eth/` | eth/68 프로토콜 메시지 |
| `ethclient/networking/snap/` | snap/1 상태 동기화 |
| `ethclient/networking/discv4/` | Discovery v4 노드 탐색 |
| `ethclient/networking/sync/` | Full sync, Snap sync 전략 |
| `ethclient/blockchain/` | Block, Header, Transaction 관리 |
| `ethclient/rpc/server.py` | JSON-RPC 2.0 서버 (FastAPI) |
| `ethclient/rpc/engine_api.py` | Engine API V1/V2/V3 (PoS) |

## EVM 실행 엔진

### 지원 Opcode (140+)

**산술**: ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND
**비교/비트**: LT, GT, SLT, SGT, EQ, ISZERO, AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR
**해시**: KECCAK256
**환경**: ADDRESS, BALANCE, ORIGIN, CALLER, CALLVALUE, CALLDATALOAD, CALLDATASIZE, CALLDATACOPY, CODESIZE, CODECOPY, GASPRICE, EXTCODESIZE, EXTCODECOPY, RETURNDATASIZE, RETURNDATACOPY, EXTCODEHASH, BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, PREVRANDAO, GASLIMIT, CHAINID, SELFBALANCE, BASEFEE, BLOBHASH, BLOBBASEFEE
**메모리/스토리지**: MLOAD, MSTORE, MSTORE8, SLOAD, SSTORE, MSIZE, MCOPY, TLOAD, TSTORE
**스택**: POP, PUSH0~PUSH32, DUP1~DUP16, SWAP1~SWAP16
**흐름**: JUMP, JUMPI, PC, GAS, JUMPDEST, STOP, RETURN, REVERT, INVALID, SELFDESTRUCT
**로그**: LOG0~LOG4
**호출**: CALL, CALLCODE, DELEGATECALL, STATICCALL, CREATE, CREATE2

### Precompile (11개)

| 주소 | 이름 | 기능 |
|------|------|------|
| 0x01 | ecrecover | ECDSA 서명 복구 |
| 0x02 | sha256 | SHA-256 해시 |
| 0x03 | ripemd160 | RIPEMD-160 해시 |
| 0x04 | identity | 데이터 복사 |
| 0x05 | modexp | 모듈러 지수 연산 |
| 0x06 | ecadd | BN128 G1 점 덧셈 |
| 0x07 | ecmul | BN128 G1 스칼라 곱셈 |
| 0x08 | ecpairing | BN128 페어링 체크 |
| 0x09 | blake2f | BLAKE2b 압축 함수 |
| 0x0a | kzg_point_eval | KZG 점 평가 (EIP-4844) |
| 0x100 | p256verify | P-256 서명 검증 (RIP-7212) |

### EVM 실행

```python
from ethclient.vm.evm import run_bytecode, ExecutionEnvironment, CallFrame

env = ExecutionEnvironment(
    caller=b"\x01" * 20,
    address=b"\x02" * 20,
    value=0,
    data=b"",
    gas=30_000_000,
)

result = run_bytecode(bytecode=b"\x60\x01\x60\x02\x01", env=env)
# PUSH1 1, PUSH1 2, ADD → stack top = 3
```

## eth/68 프로토콜

### 메시지 타입

| 코드 | 메시지 | 방향 | 설명 |
|------|--------|------|------|
| 0x00 | Status | 양방향 | 핸드셰이크 (network_id, genesis, head, forkid) |
| 0x01 | NewBlockHashes | → | 새 블록 해시 알림 |
| 0x02 | Transactions | → | 트랜잭션 전파 |
| 0x03 | GetBlockHeaders | → | 블록 헤더 요청 |
| 0x04 | BlockHeaders | ← | 블록 헤더 응답 |
| 0x05 | GetBlockBodies | → | 블록 바디 요청 |
| 0x06 | BlockBodies | ← | 블록 바디 응답 |
| 0x07 | NewBlock | → | 새 블록 전파 |
| 0x08 | NewPooledTransactionHashes | → | 풀 TX 해시 알림 (eth/68) |
| 0x09 | GetPooledTransactions | → | 풀 TX 요청 |
| 0x0a | PooledTransactions | ← | 풀 TX 응답 |
| 0x0d | GetReceipts | → | 영수증 요청 |
| 0x0e | Receipts | ← | 영수증 응답 |

### eth/68 Status 핸드셰이크
```python
# Status 메시지 필드:
# version: 68
# network_id: 1 (mainnet) 또는 11155111 (sepolia)
# td: total difficulty
# head: best block hash
# genesis: genesis hash
# forkid: [fork_hash(4B), fork_next(8B)]
```

## snap/1 동기화

### 메시지

| 코드 | 메시지 | 설명 |
|------|--------|------|
| 0x00 | GetAccountRange | 계정 범위 요청 (root, origin, limit, bytes) |
| 0x01 | AccountRange | 계정 범위 응답 + proof |
| 0x02 | GetStorageRanges | 스토리지 범위 요청 |
| 0x03 | StorageRanges | 스토리지 범위 응답 |
| 0x04 | GetByteCodes | 코드 해시로 바이트코드 요청 |
| 0x05 | ByteCodes | 바이트코드 응답 |
| 0x06 | GetTrieNodes | trie 노드 경로 요청 |
| 0x07 | TrieNodes | trie 노드 응답 |

### Snap Sync 전략
1. 피봇 블록 결정 (head - 64)
2. GetAccountRange로 계정 트리 다운로드
3. GetStorageRanges로 스토리지 다운로드
4. GetByteCodes로 컨트랙트 코드 다운로드
5. GetTrieNodes로 누락 노드 보충
6. 피봇 이후 블록 full sync

## Discovery v4

### 프로토콜

| 패킷 | 타입 | 설명 |
|------|------|------|
| Ping | 0x01 | 생존 확인 (version, from, to, expiration, enr_seq) |
| Pong | 0x02 | Ping 응답 (to, ping_hash, expiration, enr_seq) |
| FindNode | 0x03 | 타겟에 가까운 노드 탐색 |
| Neighbours | 0x04 | FindNode 응답 |

### Kademlia 라우팅 테이블
```python
BUCKET_SIZE = 16      # k-bucket 용량
NUM_BUCKETS = 256     # 256-bit node ID
ALPHA = 3             # 동시 조회 수
MAX_REPLACEMENTS = 10 # 교체 리스트 크기
```

- 거리 = keccak256(pubkey_A) XOR keccak256(pubkey_B)
- log_distance: 0 (동일) ~ 256

## Engine API (PoS)

### V1 메서드
- `engine_newPayloadV1(payload)` — 새 실행 페이로드 검증
- `engine_forkchoiceUpdatedV1(state, attrs)` — 포크 선택 업데이트
- `engine_getPayloadV1(id)` — 블록 빌드 결과 반환

### V2 메서드 (Shanghai/Capella)
- `engine_newPayloadV2` — withdrawals 포함
- `engine_forkchoiceUpdatedV2`
- `engine_getPayloadV2`

### V3 메서드 (Cancun/Deneb)
- `engine_newPayloadV3` — blob versioned hashes 포함
- `engine_forkchoiceUpdatedV3`
- `engine_getPayloadV3`

### JWT 인증
```python
rpc = RPCServer()
rpc.set_engine_jwt_secret(secret_bytes)
# engine_* 메서드 호출 시 Bearer JWT 필수
# JWT: HS256, iat 기반, 120초 skew 허용
```

## RPC 서버

```python
from ethclient.rpc.server import RPCServer

rpc = RPCServer()  # FastAPI 기반

# 메서드 등록
rpc.register("eth_blockNumber", lambda: hex(chain.height))

@rpc.method("eth_getBalance")
def get_balance(address: str, block: str = "latest"):
    return hex(state.get_balance(address))

# 실행
import uvicorn
uvicorn.run(rpc.app, host="0.0.0.0", port=8545)
```

## 부트노드 정보

### Sepolia (EF DevOps)
```
138.197.51.181:30303
146.190.1.103:30303
```

### Mainnet
- TOO_MANY_PEERS 빈번 → discv4 discovery 사용 권장
- Geth v1.17.0+: eth/68 + eth/69 + snap/1

## 동기화 전략

### Full Sync
```python
from ethclient.networking.sync.full_sync import FullSync

syncer = FullSync(chain, peer_pool)
# GetBlockHeaders → GetBlockBodies → EVM 실행 → 상태 갱신
```

### Snap Sync
```python
from ethclient.networking.sync.snap_sync import SnapSync

syncer = SnapSync(chain, peer_pool)
# 피봇 블록 → 계정 다운로드 → 스토리지 → 바이트코드 → full sync
```

## 주의사항

1. **Snappy 압축 필수**: Geth v1.17.0+ 와 통신 시 `conn.use_snappy = True`
2. **eth/68 vs eth/69**: 최신 Geth는 둘 다 지원. py-ethclient는 eth/68 구현
3. **EVM gas 계산**: Berlin/London/Shanghai 가격표 반영
4. **EIP-2929**: 접근 목록(access list) 지원 — warm/cold 스토리지 슬롯
5. **EIP-4844**: blob tx, kzg_point_eval precompile 지원
6. **Transient Storage**: TLOAD/TSTORE (EIP-1153) 지원
7. **MCOPY**: EIP-5656 메모리 복사 opcode 지원
