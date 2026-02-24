"""Tests for anti-censorship mechanisms: force inclusion + escape hatch.

Scenarios:
  1. Operator censors a message → user force-includes → relayed after window
  2. Operator censors selectively → specific user's message force-included
  3. Force relay before window → rejected
  4. L2 completely down → escape hatch recovers value on L1
  5. Escape hatch for zero-value message → rejected
  6. Double escape → rejected
"""

import pytest
from ethclient.bridge import (
    BridgeEnvironment,
    FORCE_INCLUSION_WINDOW,
)
from ethclient.common.types import Account
from ethclient.common.crypto import keccak256


ALICE = b"\x01" * 20
BOB = b"\x02" * 20
CHARLIE = b"\x03" * 20
ORACLE = b"\x0a" * 20


class TestForceInclusion:
    """Force inclusion when operator censors messages."""

    def test_normal_relay_no_force_needed(self):
        """When operator is honest, force inclusion is not needed."""
        env = BridgeEnvironment()
        env.send_l1(sender=ALICE, target=BOB, value=1000)
        result = env.relay()

        assert result.all_success
        assert len(result.forced) == 0
        assert env.l2_balance(BOB) == 1000

    def test_force_include_after_censorship(self):
        """Operator censors → user force-includes → relayed after window."""
        env = BridgeEnvironment()

        # Alice sends L1→L2, but operator doesn't relay
        msg = env.send_l1(sender=ALICE, target=BOB, value=1000)

        # Simulate operator censoring: drain outbox but don't relay
        env.l1_messenger.drain_outbox()  # message removed from outbox
        # (watcher.tick() would normally relay, but operator skipped it)

        assert env.l2_balance(BOB) == 0  # not relayed

        # Alice registers for force inclusion on L1
        entry = env.force_include(msg)
        assert entry.registered_block == 0
        assert not entry.resolved

        # Window not elapsed yet → force relay rejected
        result = env.force_relay(msg)
        assert not result.success
        assert "not elapsed" in result.error

        # Advance L1 blocks past the window
        env.advance_l1_block(FORCE_INCLUSION_WINDOW)

        # Now force relay succeeds
        result = env.force_relay(msg)
        assert result.success
        assert env.l2_balance(BOB) == 1000

    def test_selective_censorship(self):
        """Operator relays Bob's message but censors Alice's."""
        env = BridgeEnvironment()

        msg_alice = env.send_l1(sender=ALICE, target=ALICE, value=500)
        msg_bob = env.send_l1(sender=BOB, target=BOB, value=500)

        # Operator selectively relays only Bob's
        msgs = env.l1_messenger.drain_outbox()
        for m in msgs:
            if m.sender == BOB:
                env.l2_messenger.relay_message(m)

        assert env.l2_balance(BOB) == 500
        assert env.l2_balance(ALICE) == 0  # censored

        # Alice force-includes
        env.force_include(msg_alice)
        env.advance_l1_block(FORCE_INCLUSION_WINDOW)
        result = env.force_relay(msg_alice)

        assert result.success
        assert env.l2_balance(ALICE) == 500

    def test_force_relay_too_early(self):
        """Force relay before window elapsed is rejected."""
        env = BridgeEnvironment()
        msg = env.send_l1(sender=ALICE, target=BOB, value=100)
        env.l1_messenger.drain_outbox()

        env.force_include(msg)
        env.advance_l1_block(FORCE_INCLUSION_WINDOW - 1)  # one block short

        result = env.force_relay(msg)
        assert not result.success
        assert "not elapsed" in result.error

    def test_force_relay_not_registered(self):
        """Force relay without prior force_include() is rejected."""
        env = BridgeEnvironment()
        msg = env.send_l1(sender=ALICE, target=BOB, value=100)
        env.l1_messenger.drain_outbox()

        # Skip force_include(), go straight to force_relay()
        env.advance_l1_block(FORCE_INCLUSION_WINDOW)
        result = env.force_relay(msg)
        assert not result.success
        assert "not in force queue" in result.error

    def test_force_relay_idempotent(self):
        """Force relay of already-relayed message is rejected."""
        env = BridgeEnvironment()
        msg = env.send_l1(sender=ALICE, target=BOB, value=100)
        env.l1_messenger.drain_outbox()

        env.force_include(msg)
        env.advance_l1_block(FORCE_INCLUSION_WINDOW)

        r1 = env.force_relay(msg)
        assert r1.success

        r2 = env.force_relay(msg)
        assert not r2.success  # already resolved or already relayed

    def test_force_include_with_contract(self):
        """Force inclusion executes contract code on L2."""
        env = BridgeEnvironment()

        # Deploy SSTORE contract on L2
        code = bytes([0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00])
        acc = Account()
        acc.code_hash = keccak256(code)
        env.l2_store.put_account(ORACLE, acc)
        env.l2_store.put_code(acc.code_hash, code)

        # Send state relay, operator censors
        calldata = (1850).to_bytes(32, "big")
        msg = env.send_l1(sender=ALICE, target=ORACLE, data=calldata)
        env.l1_messenger.drain_outbox()

        assert env.l2_storage(ORACLE, 0) == 0  # not relayed

        # Force include
        env.force_include(msg)
        env.advance_l1_block(FORCE_INCLUSION_WINDOW)
        result = env.force_relay(msg)

        assert result.success
        assert env.l2_storage(ORACLE, 0) == 1850

    def test_watcher_processes_force_queue(self):
        """Watcher.tick() automatically processes eligible force inclusions."""
        env = BridgeEnvironment()

        msg = env.send_l1(sender=ALICE, target=BOB, value=777)
        env.l1_messenger.drain_outbox()  # operator censors

        env.force_include(msg)
        env.advance_l1_block(FORCE_INCLUSION_WINDOW)

        result = env.relay()  # watcher.tick() includes force queue processing
        assert len(result.forced) == 1
        assert result.forced[0].success
        assert env.l2_balance(BOB) == 777


class TestEscapeHatch:
    """Escape hatch — last resort value recovery on L1."""

    def test_escape_hatch_basic(self):
        """L2 completely unresponsive → recover value on L1."""
        env = BridgeEnvironment()

        # Alice deposits
        msg = env.send_l1(sender=ALICE, target=BOB, value=5000)
        env.l1_messenger.drain_outbox()

        # Register force inclusion
        env.force_include(msg)
        env.advance_l1_block(FORCE_INCLUSION_WINDOW)

        # Escape hatch: recover on L1 (instead of force relay to L2)
        result = env.escape_hatch(msg)
        assert result.success
        assert env.l1_balance(ALICE) == 5000  # value returned to sender

    def test_escape_hatch_before_window(self):
        """Escape hatch before window elapsed is rejected."""
        env = BridgeEnvironment()
        msg = env.send_l1(sender=ALICE, target=BOB, value=1000)
        env.l1_messenger.drain_outbox()

        env.force_include(msg)
        env.advance_l1_block(FORCE_INCLUSION_WINDOW - 1)

        result = env.escape_hatch(msg)
        assert not result.success
        assert "not elapsed" in result.error

    def test_escape_hatch_no_value(self):
        """Escape hatch for zero-value message is rejected."""
        env = BridgeEnvironment()
        msg = env.send_l1(sender=ALICE, target=ORACLE, data=b"\xaa")
        env.l1_messenger.drain_outbox()

        env.force_include(msg)
        env.advance_l1_block(FORCE_INCLUSION_WINDOW)

        result = env.escape_hatch(msg)
        assert not result.success
        assert "no value" in result.error

    def test_escape_hatch_double_rejected(self):
        """Cannot escape the same message twice."""
        env = BridgeEnvironment()
        msg = env.send_l1(sender=ALICE, target=BOB, value=1000)
        env.l1_messenger.drain_outbox()

        env.force_include(msg)
        env.advance_l1_block(FORCE_INCLUSION_WINDOW)

        r1 = env.escape_hatch(msg)
        assert r1.success
        assert env.l1_balance(ALICE) == 1000

        r2 = env.escape_hatch(msg)
        assert not r2.success
        assert "resolved" in r2.error
        assert env.l1_balance(ALICE) == 1000  # no double credit

    def test_escape_hatch_not_registered(self):
        """Escape without force_include() is rejected."""
        env = BridgeEnvironment()
        msg = env.send_l1(sender=ALICE, target=BOB, value=1000)
        env.l1_messenger.drain_outbox()

        env.advance_l1_block(FORCE_INCLUSION_WINDOW)

        result = env.escape_hatch(msg)
        assert not result.success
        assert "not in force queue" in result.error

    def test_cannot_escape_after_force_relay(self):
        """Once force-relayed successfully, escape is rejected."""
        env = BridgeEnvironment()
        msg = env.send_l1(sender=ALICE, target=BOB, value=1000)
        env.l1_messenger.drain_outbox()

        env.force_include(msg)
        env.advance_l1_block(FORCE_INCLUSION_WINDOW)

        # Force relay succeeds
        r1 = env.force_relay(msg)
        assert r1.success
        assert env.l2_balance(BOB) == 1000

        # Escape now rejected (already resolved)
        r2 = env.escape_hatch(msg)
        assert not r2.success
        assert "resolved" in r2.error
