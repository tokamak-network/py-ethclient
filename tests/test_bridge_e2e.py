"""End-to-end bridge tests — full L1 → L2 → L1 cycle."""

import pytest
from ethclient.bridge import BridgeEnvironment
from ethclient.common.types import Account
from ethclient.common.crypto import keccak256


ALICE = b"\x01" * 20
BOB = b"\x02" * 20
ORACLE = b"\x0a" * 20


class TestValueTransfer:
    """L1 → L2 ETH bridging via value transfer."""

    def test_deposit_eth_l1_to_l2(self):
        env = BridgeEnvironment()

        msg = env.send_l1(sender=ALICE, target=BOB, value=1000)
        result = env.relay()

        assert result.total_relayed == 1
        assert result.all_success
        assert env.l2_balance(BOB) == 1000

    def test_withdraw_eth_l2_to_l1(self):
        env = BridgeEnvironment()

        msg = env.send_l2(sender=BOB, target=ALICE, value=500)
        result = env.relay()

        assert result.total_relayed == 1
        assert result.all_success
        assert env.l1_balance(ALICE) == 500

    def test_roundtrip_deposit_then_withdraw(self):
        env = BridgeEnvironment()

        # Deposit L1 → L2
        env.send_l1(sender=ALICE, target=BOB, value=1000)
        r1 = env.relay()
        assert r1.all_success
        assert env.l2_balance(BOB) == 1000

        # Withdraw L2 → L1
        env.send_l2(sender=BOB, target=ALICE, value=300)
        r2 = env.relay()
        assert r2.all_success
        assert env.l1_balance(ALICE) == 300

    def test_multiple_deposits(self):
        env = BridgeEnvironment()

        env.send_l1(sender=ALICE, target=BOB, value=100)
        env.send_l1(sender=ALICE, target=BOB, value=200)
        env.send_l1(sender=ALICE, target=BOB, value=300)
        result = env.relay()

        assert result.total_relayed == 3
        assert result.all_success
        assert env.l2_balance(BOB) == 600


class TestStateRelay:
    """Relay arbitrary storage slots via contract execution."""

    def _deploy_sstore_contract(self, env: BridgeEnvironment, domain: str):
        """Deploy a contract that stores calldata[0:32] at slot 0."""
        code = bytes([
            0x60, 0x00, 0x35,  # CALLDATALOAD(0)
            0x60, 0x00, 0x55,  # SSTORE(0, value)
            0x00,              # STOP
        ])
        store = env.l2_store if domain == "l2" else env.l1_store
        acc = Account()
        acc.code_hash = keccak256(code)
        store.put_account(ORACLE, acc)
        store.put_code(acc.code_hash, code)

    def test_relay_state_l1_to_l2(self):
        """Send arbitrary state (e.g., oracle price) from L1 to L2 contract."""
        env = BridgeEnvironment()
        self._deploy_sstore_contract(env, "l2")

        # Send price=1850 as calldata to oracle contract on L2
        price = (1850).to_bytes(32, "big")
        env.send_l1(sender=ALICE, target=ORACLE, data=price)
        result = env.relay()

        assert result.all_success
        assert env.l2_storage(ORACLE, 0) == 1850

    def test_relay_state_l2_to_l1(self):
        """Send state back from L2 to L1 contract."""
        env = BridgeEnvironment()
        self._deploy_sstore_contract(env, "l1")

        result_data = (99).to_bytes(32, "big")
        env.send_l2(sender=BOB, target=ORACLE, data=result_data)
        result = env.relay()

        assert result.all_success
        assert env.l1_storage(ORACLE, 0) == 99

    def test_bidirectional_state_relay(self):
        """L1→L2 state, then L2→L1 state in separate ticks."""
        env = BridgeEnvironment()

        # Deploy on both sides
        code = bytes([0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00])
        for store in [env.l1_store, env.l2_store]:
            acc = Account()
            acc.code_hash = keccak256(code)
            store.put_account(ORACLE, acc)
            store.put_code(acc.code_hash, code)

        # L1 → L2
        env.send_l1(sender=ALICE, target=ORACLE, data=(42).to_bytes(32, "big"))
        r1 = env.relay()
        assert r1.all_success
        assert env.l2_storage(ORACLE, 0) == 42

        # L2 → L1
        env.send_l2(sender=BOB, target=ORACLE, data=(77).to_bytes(32, "big"))
        r2 = env.relay()
        assert r2.all_success
        assert env.l1_storage(ORACLE, 0) == 77


class TestReplayProtection:
    """Ensure messages cannot be replayed."""

    def test_replay_rejected(self):
        env = BridgeEnvironment()

        msg = env.send_l1(sender=ALICE, target=BOB, value=100)
        r1 = env.relay()
        assert r1.all_success
        assert env.l2_balance(BOB) == 100

        # Manually try to replay
        r2 = env.l2_messenger.relay_message(msg)
        assert not r2.success
        assert r2.error == "message already relayed"
        assert env.l2_balance(BOB) == 100  # no double-credit


class TestStateRoot:
    """State roots change after bridge operations."""

    def test_state_root_changes(self):
        env = BridgeEnvironment()

        root_before = env.l2_state_root()

        env.send_l1(sender=ALICE, target=BOB, value=1000)
        env.relay()

        root_after = env.l2_state_root()
        assert root_before != root_after

    def test_independent_state_roots(self):
        """L1 and L2 have independent state roots."""
        env = BridgeEnvironment()

        env.send_l1(sender=ALICE, target=BOB, value=1000)
        env.relay()

        # L1 state unchanged (no value minted on L1)
        # L2 state changed (value minted on L2)
        l1_root = env.l1_state_root()
        l2_root = env.l2_state_root()
        assert l1_root != l2_root
