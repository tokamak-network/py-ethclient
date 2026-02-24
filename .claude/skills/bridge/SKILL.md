---
description: "L1↔L2 Bridge 구축 — CrossDomainMessenger, force inclusion, escape hatch"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "브릿지 유스케이스나 방향(L1→L2 또는 L2→L1)"
user-invocable: true
---

# L1↔L2 Bridge 구축 스킬

CrossDomainMessenger 기반의 L1↔L2 양방향 메시지 패싱, 5종 relay handler, force inclusion/escape hatch 안전장치를 안내한다.

## 핵심 파일 참조

| 파일 | 역할 |
|------|------|
| `ethclient/bridge/messenger.py` | CrossDomainMessenger — 메시지 송수신 |
| `ethclient/bridge/relay_handlers.py` | 5종 RelayHandler 구현 |
| `ethclient/bridge/types.py` | CrossDomainMessage, Domain, RelayResult, StateUpdate |
| `ethclient/bridge/watcher.py` | BridgeWatcher — 자동 릴레이 |
| `ethclient/bridge/environment.py` | BridgeEnvironment — 통합 테스트 환경 |
| `ethclient/l2/l1_backend.py` | InMemoryL1Backend |
| `ethclient/l2/eth_l1_backend.py` | EthL1Backend (실제 Ethereum) |

## 빠른 시작: EVM 브릿지

```python
from ethclient.bridge.environment import BridgeEnvironment

# 1. EVM 릴레이 기반 브릿지 환경 생성
env = BridgeEnvironment.with_evm(l1_chain_id=1, l2_chain_id=42170)

ALICE = b"\x01" * 20
L2_CONTRACT = b"\xca\xfe" + b"\x00" * 18

# 2. L1 → L2 예금 (ETH 전송)
msg = env.send_l1(
    sender=ALICE,
    target=L2_CONTRACT,
    data=b"",           # calldata
    value=1_000_000,    # wei
)

# 3. 릴레이 실행 (Watcher가 L1 outbox → L2 relay)
result = env.relay()
assert result.all_success

# 4. L2 잔액 확인
assert env.l2_balance(L2_CONTRACT) == 1_000_000
```

## 메시지 구조

```python
@dataclass
class CrossDomainMessage:
    nonce: int              # 도메인별 자동 증가, 리플레이 방지
    sender: bytes           # 20바이트 발신자
    target: bytes           # 20바이트 수신자
    data: bytes             # 임의 calldata (ABI 인코딩)
    value: int = 0          # ETH 전송량 (수신 도메인에서 mint)
    gas_limit: int = 1_000_000
    source_domain: Domain   # Domain.L1 또는 Domain.L2
    block_number: int = 0   # 발신 블록 (messenger 설정)
    message_hash: bytes     # keccak256(RLP([nonce, sender, target, ...]))
```

## 5종 Relay Handler

### 1. EVMRelayHandler (기본)
```python
env = BridgeEnvironment.with_evm()
```
- EVM 바이트코드 실행, 스마트 컨트랙트 호출
- `msg.value > 0`이면 target에 잔액 mint
- 성공 시 상태 변경 커밋, 실패 시 전체 롤백
- 30M gas limit, MESSENGER_ADDRESS(`0x4200...42`)를 caller로 사용

### 2. MerkleProofHandler
```python
env = BridgeEnvironment.with_merkle_proof()
```
- L1 state root에 대한 Merkle proof 검증 후 상태 적용
- `add_trusted_root(root)` → 신뢰 루트 등록 필수
- Data 포맷: `RLP([state_root, address, account_rlp, [proof_nodes], [storage_proofs]])`

### 3. ZKProofHandler
```python
from ethclient.zk.types import VerificationKey
env = BridgeEnvironment.with_zk_proof(vk=my_verification_key)
```
- Groth16 증명 검증 후 상태 업데이트 적용
- Data 포맷: `RLP([proof_a(64B), proof_b(128B), proof_c(64B), [public_inputs], [state_updates]])`

### 4. DirectStateHandler
```python
env = BridgeEnvironment.with_direct_state()
```
- 검증 없이 직접 상태 적용 (신뢰 relayer 가정)
- 테스트/프로토타입용

### 5. TinyDBHandler
```python
from ethclient.bridge.relay_handlers import TinyDBHandler
handler = TinyDBHandler()
```
- JSON document DB에 상태 저장 (비EVM 런타임)
- `get_account(address)` → dict 조회

## Deposit/Withdrawal 플로우

### L1 → L2 Deposit
```
User → l1_messenger.send_message(target=L2_contract, value=ETH)
  → L1 outbox에 메시지 큐잉
  → Watcher가 drain_outbox() 후 l2_messenger.relay_message(msg) 호출
  → EVMRelayHandler: target에 value mint + calldata 실행
  → 리플레이 방지 마킹
```

### L2 → L1 Withdrawal
```
L2_contract → l2_messenger.send_message(target=User, value=ETH)
  → L2 outbox에 메시지 큐잉
  → Watcher가 l1_messenger.relay_message(msg) 호출
  → L1에서 value mint + 실행
```

## Force Inclusion (검열 저항)

L2 오퍼레이터가 메시지 릴레이를 거부할 때 사용자가 직접 강제 포함:

```python
# FORCE_INCLUSION_WINDOW = 50 블록 (하드코딩)

# 1. L1에 강제 포함 등록
entry = env.force_include(msg)

# 2. 50 블록 대기
env.advance_l1_block(50)

# 3. 누구나 강제 릴레이 실행 가능
result = env.force_relay(msg)
assert result.success
```

## Escape Hatch (최후 수단)

L2가 완전히 다운되어 릴레이 불가능할 때 L1에서 예금 회수:

```python
# 조건: force_include 완료 + 50블록 경과 + msg.value > 0
result = env.escape_hatch(msg)
assert result.success
# → msg.sender의 L1 잔액에 msg.value 환불
```

**에러 케이스:**
- "message not in force queue"
- "force inclusion window not elapsed"
- "already resolved (relayed or escaped)"
- "no value to recover" (value=0인 메시지)

## BridgeWatcher 직접 사용

```python
from ethclient.bridge.watcher import BridgeWatcher

watcher = BridgeWatcher(l1_messenger, l2_messenger)

# 한 사이클: L1→L2 + L2→L1 + force queue 처리
result = watcher.tick()
# BatchRelayResult { l1_to_l2, l2_to_l1, forced, all_success, total_relayed }
```

## StateUpdate 구조

MerkleProof, ZKProof, DirectState 핸들러가 사용:

```python
@dataclass
class StateUpdate:
    address: bytes              # 20바이트
    balance: int | None = None  # 변경할 잔액
    nonce: int | None = None    # 변경할 nonce
    storage: dict[int, int] = {}  # slot → value

# 인코딩/디코딩
from ethclient.bridge.types import encode_state_updates, decode_state_updates
data = encode_state_updates([StateUpdate(address=ALICE, balance=1000)])
```

## 상태 조회

```python
env.l1_balance(ALICE)           # L1 잔액
env.l2_balance(ALICE)           # L2 잔액
env.l1_storage(contract, slot)  # L1 스토리지
env.l2_storage(contract, slot)  # L2 스토리지
env.l1_state_root()             # L1 상태 루트
env.l2_state_root()             # L2 상태 루트
```

## 주의사항

1. **Value는 mint**: escrow가 아닌 목적 도메인에서 mint. 단일 오퍼레이터 신뢰 모델
2. **Outbox drain은 파괴적**: `drain_outbox()` 후 실패 시 메시지 소실. 프로덕션에선 영속 큐 필요
3. **Block number 수동**: `advance_l1_block(n)` 호출 필요. JSON-RPC 블록 높이와 자동 동기화 안 됨
4. **Nonce는 도메인별 독립**: L1, L2 각각 0부터 시작
5. **EVM relay atomicity**: 전체 성공 또는 전체 롤백. 부분 상태 업데이트 없음
6. **Trusted root 만료 없음**: `add_trusted_root()`로 등록된 루트는 영구 유효
7. **Gas limit**: EVM relay는 msg.gas_limit 사용, 비EVM handler는 gas_used=0 보고
