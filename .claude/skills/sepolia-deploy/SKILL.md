---
description: "Sepolia 테스트넷 배포 — verifier 배포, batch 제출, on-chain 검증"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "배포할 앱이나 컨트랙트 설명"
user-invocable: true
---

# Sepolia 테스트넷 배포 스킬

Sepolia 테스트넷에 Groth16 verifier 컨트랙트를 배포하고, L2 rollup batch를 on-chain 검증하는 전체 과정을 안내한다.

## 핵심 파일 참조

| 파일 | 역할 |
|------|------|
| `ethclient/l2/eth_l1_backend.py` | EthL1Backend — 실제 Ethereum L1 연동 |
| `ethclient/l2/eth_rpc.py` | EthRPCClient — JSON-RPC 클라이언트 |
| `ethclient/l2/rollup.py` | Rollup 오케스트레이터 |
| `ethclient/l2/config.py` | L2Config |
| `examples/l2_sepolia_hello.py` | 최소 Sepolia 예제 |
| `examples/l2_sepolia_all.py` | 4개 앱 Sepolia 배포 예제 |

## 환경 설정

### 필수 환경변수
```bash
export SEPOLIA_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
export SEPOLIA_PRIVATE_KEY="abcdef1234..."  # 0x 접두사 없이 64자 hex
```

### 무료 RPC 엔드포인트
| 제공자 | URL |
|--------|-----|
| PublicNode | `https://ethereum-sepolia-rpc.publicnode.com` |
| 1RPC | `https://1rpc.io/sepolia` |

### Sepolia ETH 획득
- Google Cloud Faucet: https://cloud.google.com/application/web3/faucet/ethereum/sepolia
- 최소 0.001 ETH 권장 (verifier 배포 + batch 제출)

## 빠른 시작: Sepolia 배포

```python
import os
from ethclient.l2.types import L2Tx, STFResult
from ethclient.l2.rollup import Rollup
from ethclient.l2.runtime import PythonRuntime
from ethclient.l2.eth_l1_backend import EthL1Backend
from ethclient.l2.eth_rpc import EthRPCClient

# 1. 환경변수 로드
RPC_URL = os.environ.get("SEPOLIA_RPC_URL", "https://1rpc.io/sepolia")
PRIVATE_KEY = bytes.fromhex(os.environ["SEPOLIA_PRIVATE_KEY"])

# 2. 잔액 확인
rpc = EthRPCClient(RPC_URL)
from ethclient.common.crypto import private_key_to_address
addr = private_key_to_address(PRIVATE_KEY)
balance_wei = int(rpc._call("eth_getBalance", [f"0x{addr.hex()}", "latest"]), 16)
balance_eth = balance_wei / 1e18
print(f"Balance: {balance_eth:.6f} ETH")
assert balance_eth >= 0.001, "Insufficient Sepolia ETH"

# 3. STF 정의
def my_stf(state: dict, tx: L2Tx) -> STFResult:
    state["counter"] = state.get("counter", 0) + 1
    return STFResult(success=True, output={"counter": state["counter"]})

# 4. L1 Backend 설정
l1_backend = EthL1Backend(
    rpc_url=RPC_URL,
    private_key=PRIVATE_KEY,
    chain_id=11155111,       # Sepolia
    gas_multiplier=1.5,      # 빠른 확인을 위해 1.5배
    receipt_timeout=180,     # Sepolia 블록 타임 고려
)

# 5. Rollup 생성 + Setup (verifier 배포)
rollup = Rollup(stf=my_stf, l1=l1_backend)
rollup.setup()  # Verifier 컨트랙트 Sepolia에 배포

# 6. 트랜잭션 + Batch + 증명 + 제출
USER = b"\xde\xad" + b"\x00" * 18
rollup.submit_tx(L2Tx(sender=USER, nonce=0, data={"op": "increment"}))
batch = rollup.produce_batch()
receipt = rollup.prove_and_submit(batch)

assert receipt.verified, "On-chain verification failed!"
print(f"L1 TX: 0x{receipt.l1_tx_hash.hex()}")
```

## EthL1Backend 상세

### 생성자
```python
EthL1Backend(
    rpc_url: str,              # Ethereum JSON-RPC URL
    private_key: bytes,        # 32바이트 서명 키
    chain_id: int = 1,         # 11155111 for Sepolia
    gas_multiplier: float = 1.2,  # base_fee + priority_fee에 곱할 배율
    receipt_timeout: int = 120,   # 영수증 대기 시간(초)
)
```

### EIP-1559 트랜잭션 구성
```python
# 자동으로 수행됨:
nonce = rpc.get_nonce(sender_hex)
base_fee = rpc.get_base_fee()
priority_fee = rpc.get_max_priority_fee()
max_fee = int((base_fee + priority_fee) * gas_multiplier)

# Gas limits:
#   Verifier 배포: 5,000,000
#   Batch 제출:    500,000
```

### 메서드
| 메서드 | Gas Limit | 설명 |
|--------|-----------|------|
| `deploy_verifier(vk)` | 5M | Verifier 바이트코드 배포, 컨트랙트 주소 반환 |
| `submit_batch(...)` | 500K | 증명 + public inputs calldata 전송, tx hash 반환 |
| `is_batch_verified(n)` | - | batch 검증 여부 |
| `get_verified_state_root()` | - | 최신 검증된 state root |

## EthRPCClient

```python
rpc = EthRPCClient(rpc_url, timeout=30)
# User-Agent: "py-ethclient/1.0"  (일부 RPC 노드에서 필요)

rpc.get_chain_id()           # → 11155111
rpc.get_nonce("0x...")       # pending nonce
rpc.get_base_fee()           # EIP-1559 base fee (wei)
rpc.get_max_priority_fee()   # priority fee (wei)
rpc.send_raw_transaction(raw_bytes)  # tx hash 반환
rpc.wait_for_receipt(tx_hash, timeout=120)  # 폴링 (1초 간격)
```

에러: `EthRPCError(message, code)` — JSON-RPC 에러 또는 네트워크 에러

## L2Config로 Sepolia 설정

```python
from ethclient.l2.config import L2Config

config = L2Config(
    name="my-sepolia-rollup",
    chain_id=42170,
    max_txs_per_batch=32,
    l1_backend="eth_rpc",           # EthL1Backend 자동 생성
    l1_rpc_url=RPC_URL,
    l1_private_key=PRIVATE_KEY.hex(),
    l1_chain_id=11155111,
    state_backend="lmdb",           # 영속 상태 (선택)
    data_dir="./data/sepolia-rollup",
    prover_backend="python",        # 또는 "native"
)
rollup = Rollup(stf=my_stf, config=config)
```

## 4개 앱 배포 예제 패턴

`examples/l2_sepolia_all.py` 참조:

```python
# 각 앱별 독립 Rollup 인스턴스 + verifier 배포
ALICE = b"\x01" * 20
BOB = b"\x02" * 20

def run_app(name, stf_runtime, scenario_fn):
    l1 = EthL1Backend(rpc_url=RPC_URL, private_key=PRIVATE_KEY,
                       chain_id=11155111, gas_multiplier=1.5, receipt_timeout=180)
    rollup = Rollup(stf=stf_runtime, l1=l1)
    rollup.setup()
    results = scenario_fn(rollup)
    return all(r["verified"] for r in results)

# 앱: ERC20 Token, NameService, Voting, Rock-Paper-Scissors
```

## Gas 최적화 팁

1. **gas_multiplier**: Sepolia에서 1.5 권장. Mainnet에서는 1.2
2. **receipt_timeout**: Sepolia 블록 ~12초. 180초면 ~15블록 대기
3. **Batch 크기**: 트랜잭션 많을수록 batch당 증명 비용 동일 (verifier gas는 public input 수에 비례)
4. **Verifier 배포는 1회**: 같은 circuit이면 verifier 재사용 가능
5. **Calldata 최적화**: 3개 public input × 32바이트 = 96바이트 + proof 256바이트 = ~352바이트

## Etherscan 확인

```python
# 배포 확인
print(f"Verifier: https://sepolia.etherscan.io/address/0x{verifier_addr.hex()}")

# TX 확인
print(f"TX: https://sepolia.etherscan.io/tx/0x{receipt.l1_tx_hash.hex()}")
```

## 주의사항

1. **Private key 보안**: 환경변수로만 관리. 코드에 하드코딩 금지
2. **Nonce 충돌**: 같은 키로 동시 트랜잭션 전송 시 nonce 충돌 가능
3. **Sepolia 불안정**: 공용 RPC는 rate limit 있음. 중요 테스트는 Alchemy/Infura 사용
4. **EIP-1559 필수**: pre-London 체인 미지원 (base_fee 필요)
5. **User-Agent 헤더**: `"py-ethclient/1.0"` — 일부 RPC가 빈 UA 거부
6. **실패 시 재시도**: `EthRPCError` 발생 시 nonce 확인 후 재전송 필요
