---
description: "테스트 실행 & 작성 — pytest 실행, 새 테스트 작성, coverage 확인"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "테스트 대상 모듈이나 기능"
user-invocable: true
---

# 테스트 실행 & 작성 스킬

py-ethclient의 943개 테스트 실행, 새 테스트 작성, coverage 확인을 안내한다.

## 핵심 참조

| 항목 | 값 |
|------|-----|
| 테스트 디렉토리 | `tests/` |
| 테스트 파일 수 | 40개 |
| 총 테스트 수 | 943개 |
| 프레임워크 | pytest >= 8.0 |
| Python | >= 3.12 |

## 테스트 실행 명령

```bash
# 전체 테스트
python -m pytest tests/ -v

# 특정 모듈
python -m pytest tests/test_l2_integration.py -v

# 특정 클래스
python -m pytest tests/test_l2_integration.py::TestFullCycleCounter -v

# 특정 테스트
python -m pytest tests/test_l2_integration.py::TestFullCycleCounter::test_single_batch -v

# 키워드 필터링
python -m pytest tests/ -k "sequencer" -v
python -m pytest tests/ -k "bridge and not escape" -v

# 실패 시 즉시 중단
python -m pytest tests/ -x

# 병렬 실행 (pytest-xdist 설치 필요)
python -m pytest tests/ -n auto

# 상세 출력 (실패 정보)
python -m pytest tests/ -v --tb=short

# Coverage
python -m pytest tests/ --cov=ethclient --cov-report=term-missing
```

## 테스트 파일 구조

```
tests/
├── test_crypto.py          # keccak256, ECDSA, 주소 변환
├── test_rlp.py             # RLP 인코딩/디코딩
├── test_evm.py             # EVM opcodes, 실행
├── test_trie.py            # Merkle Patricia Trie
├── test_p2p.py             # RLPx, devp2p, full sync
├── test_snap_sync.py       # snap/1 동기화
├── test_discv4.py          # Discovery v4
├── test_l2_integration.py  # L2 전체 사이클
├── test_l2_sequencer.py    # Sequencer, mempool, batch
├── test_l2_state.py        # L2 상태 관리
├── test_l2_persistent_state.py  # LMDB 상태
├── test_l2_eth_l1_backend.py    # EthL1Backend (mock)
├── test_l2_rpc.py          # L2 RPC API
├── test_l2_cli.py          # L2 CLI
├── test_bridge_*.py        # Bridge 테스트들
├── test_zk_*.py            # ZK 회로/증명 테스트들
└── ...
```

## 네이밍 규칙

### 파일
```
tests/test_<module>.py
tests/test_l2_<feature>.py
tests/test_bridge_<feature>.py
tests/test_zk_<feature>.py
```

### 클래스 & 메서드
```python
class Test<Feature>:
    """기능 그룹별 테스트."""

    def test_<scenario>_<expectation>(self):
        """하나의 시나리오, 하나의 검증."""
        pass

    def test_<scenario>_raises(self):
        """에러 케이스."""
        with pytest.raises(SomeException, match="pattern"):
            ...
```

예시:
- `class TestKeccak256: test_empty, test_hello, test_deterministic`
- `class TestSequencer: test_submit_tx, test_force_seal, test_nonce_enforcement`
- `class TestDeployVerifier: test_successful_deployment, test_deployment_revert`

## 테스트 작성 패턴

### L2 Integration 테스트

```python
from ethclient.l2.types import L2Tx, STFResult
from ethclient.l2.rollup import Rollup


def _counter_stf(state: dict, tx: L2Tx) -> STFResult:
    state["counter"] = state.get("counter", 0) + 1
    return STFResult(success=True)


class TestMyFeature:
    def test_single_batch_verified(self):
        rollup = Rollup(stf=_counter_stf)
        rollup.setup()

        sender = b"\x01" * 20
        error = rollup.submit_tx(L2Tx(sender=sender, nonce=0, data={}))
        assert error is None

        batch = rollup.produce_batch()
        assert batch.sealed
        assert len(batch.transactions) == 1

        receipt = rollup.prove_and_submit(batch)
        assert receipt.verified
        assert receipt.batch_number == 0
        assert rollup.state.get("counter") == 1

    def test_multi_batch_chaining(self):
        rollup = Rollup(stf=_counter_stf)
        rollup.setup()

        sender = b"\x01" * 20

        # Batch 0
        rollup.submit_tx(L2Tx(sender=sender, nonce=0, data={}))
        batch0 = rollup.produce_batch()
        receipt0 = rollup.prove_and_submit(batch0)
        assert receipt0.verified

        # Batch 1
        rollup.submit_tx(L2Tx(sender=sender, nonce=1, data={}))
        batch1 = rollup.produce_batch()
        receipt1 = rollup.prove_and_submit(batch1)
        assert receipt1.verified
        assert batch1.old_state_root == batch0.new_state_root
```

### Mock RPC 패턴 (EthL1Backend 테스트)

```python
from unittest.mock import MagicMock
from ethclient.l2.eth_l1_backend import EthL1Backend


def _mock_rpc():
    rpc = MagicMock()
    rpc.get_nonce.return_value = 0
    rpc.get_base_fee.return_value = 1_000_000_000  # 1 gwei
    rpc.get_max_priority_fee.return_value = 100_000_000  # 0.1 gwei
    rpc.send_raw_transaction.return_value = b"\xaa" * 32
    rpc.wait_for_receipt.return_value = {
        "status": "0x1",
        "contractAddress": "0x" + "bb" * 20,
        "gasUsed": "0x5208",
    }
    return rpc


class TestDeployVerifier:
    def _setup_backend(self):
        backend = EthL1Backend(
            rpc_url="http://localhost:8545",
            private_key=b"\x01" * 32,
            chain_id=11155111,
        )
        backend._rpc = _mock_rpc()
        return backend

    def test_successful_deployment(self):
        backend = self._setup_backend()
        vk = _make_vk()  # 테스트용 VerificationKey 생성
        addr = backend.deploy_verifier(vk)
        assert len(addr) == 20
        backend._rpc.send_raw_transaction.assert_called_once()
```

### RPC 테스트 패턴

```python
from ethclient.l2.l2_api import register_l2_api
from ethclient.rpc.server import RPCServer


def _make_rpc_rollup():
    rollup = Rollup(stf=_counter_stf)
    rollup.setup()
    rpc = RPCServer()
    register_l2_api(rpc, rollup)
    return rpc, rollup


class TestL2RPC:
    def test_send_transaction(self):
        rpc, rollup = _make_rpc_rollup()
        handler = rpc._methods["l2_sendTransaction"]
        result = handler({"sender": "0x" + "01" * 20, "nonce": 0, "data": {}})
        assert "txHash" in result

    def test_invalid_sender(self):
        rpc, rollup = _make_rpc_rollup()
        handler = rpc._methods["l2_sendTransaction"]
        result = handler({"sender": "not-hex", "nonce": 0})
        assert "error" in result
```

### Bridge 테스트 패턴

```python
from ethclient.bridge.environment import BridgeEnvironment


class TestDeposit:
    def test_l1_to_l2_deposit(self):
        env = BridgeEnvironment.with_evm()
        ALICE = b"\x01" * 20
        TARGET = b"\xca\xfe" + b"\x00" * 18

        msg = env.send_l1(sender=ALICE, target=TARGET, value=1000)
        result = env.relay()
        assert result.all_success
        assert env.l2_balance(TARGET) == 1000
```

## 테스트 상수

```python
# 테스트용 주소
ALICE = b"\x01" * 20
BOB = b"\x02" * 20
CHARLIE = b"\x03" * 20

# 테스트용 키
TEST_PRIVATE_KEY = b"\x01" * 32

# Gas 값 (mock)
BASE_FEE = 1_000_000_000       # 1 gwei
PRIORITY_FEE = 100_000_000     # 0.1 gwei
```

## 주의사항

1. **pytest 설정**: `pyproject.toml`에 `[tool.pytest]` 섹션 없음 — pytest 기본값 사용
2. **fixture 미사용**: 대부분 헬퍼 함수 + setup 메서드 패턴 사용
3. **Mock 패턴**: `unittest.mock.MagicMock`으로 RPC 클라이언트 대체
4. **ZK 테스트 속도**: Groth16 setup/prove가 느릴 수 있음 (pure Python). `-x`로 실패 즉시 중단 권장
5. **LMDB 테스트**: `test_l2_persistent_state.py`는 임시 디렉토리 사용
6. **Live 테스트**: `tests/live/` 디렉토리는 실제 네트워크 연결 필요 (환경변수 설정)
