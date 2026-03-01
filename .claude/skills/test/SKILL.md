---
description: "Test Execution & Writing — run pytest, write new tests, check coverage"
allowed-tools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Task"]
argument-hint: "target module or feature"
user-invocable: true
---

# Test Execution & Writing Skill

Guides running the 1,031 tests in py-ethclient, writing new tests, and checking coverage.

## Key References

| Item | Value |
|------|-------|
| Test directory | `tests/` |
| Test file count | 42 |
| Total tests | 1,031 |
| Framework | pytest >= 8.0 |
| Python | >= 3.12 |

## Test Execution Commands

```bash
# Full test suite
python -m pytest tests/ -v

# Specific module
python -m pytest tests/test_l2_integration.py -v

# Specific class
python -m pytest tests/test_l2_integration.py::TestFullCycleCounter -v

# Specific test
python -m pytest tests/test_l2_integration.py::TestFullCycleCounter::test_single_batch -v

# Keyword filtering
python -m pytest tests/ -k "sequencer" -v
python -m pytest tests/ -k "bridge and not escape" -v

# Stop on first failure
python -m pytest tests/ -x

# Parallel execution (requires pytest-xdist)
python -m pytest tests/ -n auto

# Verbose output (failure details)
python -m pytest tests/ -v --tb=short

# Coverage
python -m pytest tests/ --cov=ethclient --cov-report=term-missing
```

## Test File Structure

```
tests/
├── test_crypto.py              # keccak256, ECDSA, address conversion
├── test_rlp.py                 # RLP encoding/decoding
├── test_evm.py                 # EVM opcodes, execution
├── test_trie.py                # Merkle Patricia Trie
├── test_p2p.py                 # RLPx, devp2p, full sync
├── test_snap_sync.py           # snap/1 synchronization
├── test_discv4.py              # Discovery v4
├── test_l2_integration.py      # L2 full cycle
├── test_l2_sequencer.py        # Sequencer, mempool, batch
├── test_l2_state.py            # L2 state management
├── test_l2_persistent_state.py # LMDB state
├── test_l2_eth_l1_backend.py   # EthL1Backend (mock)
├── test_l2_rpc.py              # L2 RPC API
├── test_l2_cli.py              # L2 CLI
├── test_l2_framework_hardening.py  # Config validation, thread safety, liveness, LMDB resize
├── test_poseidon.py            # Poseidon hash circuit tests
├── test_bridge_*.py            # Bridge tests
├── test_zk_*.py                # ZK circuit/proof tests
└── ...
```

## Naming Conventions

### Files
```
tests/test_<module>.py
tests/test_l2_<feature>.py
tests/test_bridge_<feature>.py
tests/test_zk_<feature>.py
```

### Classes & Methods
```python
class Test<Feature>:
    """Tests grouped by feature."""

    def test_<scenario>_<expectation>(self):
        """One scenario, one assertion."""
        pass

    def test_<scenario>_raises(self):
        """Error case."""
        with pytest.raises(SomeException, match="pattern"):
            ...
```

Examples:
- `class TestKeccak256: test_empty, test_hello, test_deterministic`
- `class TestSequencer: test_submit_tx, test_force_seal, test_nonce_enforcement`
- `class TestDeployVerifier: test_successful_deployment, test_deployment_revert`

## Test Writing Patterns

### L2 Integration Test

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

### Mock RPC Pattern (EthL1Backend Tests)

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
        vk = _make_vk()  # Create test VerificationKey
        addr = backend.deploy_verifier(vk)
        assert len(addr) == 20
        backend._rpc.send_raw_transaction.assert_called_once()
```

### RPC Test Pattern

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

### Bridge Test Pattern

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

## Security Test Patterns

```python
import pytest
from ethclient.l2.types import L2Tx, STFResult
from ethclient.l2.rollup import Rollup


class TestSTFSecurity:
    """Security-focused tests for STF implementations."""

    def test_replay_protection(self):
        """Verify that replaying a transaction with the same nonce is rejected."""
        rollup = Rollup(stf=_counter_stf)
        rollup.setup()
        sender = b"\x01" * 20
        assert rollup.submit_tx(L2Tx(sender=sender, nonce=0, data={})) is None
        rollup.produce_batch()
        rollup.prove_and_submit(rollup.produce_batch() if False else
                                 rollup._last_batch)
        # Replay same nonce
        error = rollup.submit_tx(L2Tx(sender=sender, nonce=0, data={}))
        assert error is not None and "nonce" in error.lower()

    def test_invalid_sender_length(self):
        """Verify that sender address must be exactly 20 bytes."""
        with pytest.raises(ValueError):
            L2Tx(sender=b"\x01" * 19, nonce=0, data={})

    def test_negative_nonce_rejected(self):
        """Verify that negative nonces are rejected."""
        with pytest.raises(ValueError):
            L2Tx(sender=b"\x01" * 20, nonce=-1, data={})

    def test_stf_exception_does_not_corrupt_state(self):
        """Verify that an STF exception triggers rollback."""
        def failing_stf(state, tx):
            state["dirty"] = True
            raise RuntimeError("intentional failure")

        rollup = Rollup(stf=failing_stf)
        rollup.setup()
        sender = b"\x01" * 20
        rollup.submit_tx(L2Tx(sender=sender, nonce=0, data={}))
        batch = rollup.produce_batch()
        # State should not contain "dirty" after rollback
        assert "dirty" not in rollup.state
```

## Test Constants

```python
# Test addresses
ALICE = b"\x01" * 20
BOB = b"\x02" * 20
CHARLIE = b"\x03" * 20

# Test keys
TEST_PRIVATE_KEY = b"\x01" * 32

# Gas values (mock)
BASE_FEE = 1_000_000_000       # 1 gwei
PRIORITY_FEE = 100_000_000     # 0.1 gwei
```

## Caveats

1. **pytest config**: No `[tool.pytest]` section in `pyproject.toml` — uses pytest defaults
2. **No fixtures**: Most tests use helper functions + setup methods pattern
3. **Mock pattern**: `unittest.mock.MagicMock` used to replace RPC clients
4. **ZK test speed**: Groth16 setup/prove can be slow (pure Python). Use `-x` to stop on first failure
5. **LMDB tests**: `test_l2_persistent_state.py` uses temporary directories
6. **Live tests**: `tests/live/` directory requires real network connections (environment variables)
