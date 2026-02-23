"""Tests for CrossDomainMessenger — message send, relay, and replay protection."""

import pytest
from ethclient.storage.memory_backend import MemoryBackend
from ethclient.bridge.types import Domain, CrossDomainMessage
from ethclient.bridge.messenger import CrossDomainMessenger


ALICE = b"\x01" * 20
BOB = b"\x02" * 20
CONTRACT = b"\x03" * 20


class TestSendMessage:
    """Test message queuing."""

    def test_send_message_basic(self):
        store = MemoryBackend()
        m = CrossDomainMessenger(Domain.L1, store)

        msg = m.send_message(sender=ALICE, target=BOB, data=b"\xaa\xbb")

        assert msg.nonce == 0
        assert msg.sender == ALICE
        assert msg.target == BOB
        assert msg.data == b"\xaa\xbb"
        assert msg.source_domain == Domain.L1
        assert msg.message_hash != b""
        assert len(msg.message_hash) == 32

    def test_nonce_increments(self):
        store = MemoryBackend()
        m = CrossDomainMessenger(Domain.L1, store)

        msg0 = m.send_message(sender=ALICE, target=BOB, data=b"")
        msg1 = m.send_message(sender=ALICE, target=BOB, data=b"")

        assert msg0.nonce == 0
        assert msg1.nonce == 1
        assert msg0.message_hash != msg1.message_hash

    def test_outbox_populated(self):
        store = MemoryBackend()
        m = CrossDomainMessenger(Domain.L1, store)

        m.send_message(sender=ALICE, target=BOB, data=b"hello")
        m.send_message(sender=ALICE, target=CONTRACT, data=b"world")

        assert m.pending_count() == 2

    def test_drain_outbox(self):
        store = MemoryBackend()
        m = CrossDomainMessenger(Domain.L1, store)

        m.send_message(sender=ALICE, target=BOB, data=b"1")
        m.send_message(sender=ALICE, target=BOB, data=b"2")

        msgs = m.drain_outbox()
        assert len(msgs) == 2
        assert m.pending_count() == 0

    def test_send_with_value(self):
        store = MemoryBackend()
        m = CrossDomainMessenger(Domain.L1, store)

        msg = m.send_message(sender=ALICE, target=BOB, data=b"", value=1000)
        assert msg.value == 1000


class TestRelayMessage:
    """Test message relay with EVM execution."""

    def test_relay_value_transfer(self):
        """Relay a message that transfers ETH value to target."""
        store = MemoryBackend()
        m = CrossDomainMessenger(Domain.L2, store)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=b"",
            value=500, gas_limit=100_000, source_domain=Domain.L1,
        )
        msg.message_hash = b"\x01" * 32

        result = m.relay_message(msg)

        assert result.success
        assert store.get_balance(BOB) == 500

    def test_relay_no_code_target(self):
        """Relay to an address with no code — value transfer only."""
        store = MemoryBackend()
        m = CrossDomainMessenger(Domain.L2, store)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=b"\xde\xad",
            value=100, gas_limit=100_000, source_domain=Domain.L1,
        )
        msg.message_hash = b"\x02" * 32

        result = m.relay_message(msg)
        assert result.success  # no code → success (just value transfer)
        assert store.get_balance(BOB) == 100

    def test_replay_protection(self):
        """Same message cannot be relayed twice."""
        store = MemoryBackend()
        m = CrossDomainMessenger(Domain.L2, store)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=b"",
            value=100, gas_limit=100_000, source_domain=Domain.L1,
        )
        msg.message_hash = b"\x03" * 32

        r1 = m.relay_message(msg)
        assert r1.success
        assert store.get_balance(BOB) == 100

        r2 = m.relay_message(msg)
        assert not r2.success
        assert r2.error == "message already relayed"
        # Balance should NOT double
        assert store.get_balance(BOB) == 100

    def test_is_relayed(self):
        store = MemoryBackend()
        m = CrossDomainMessenger(Domain.L2, store)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=b"",
            value=0, gas_limit=100_000, source_domain=Domain.L1,
        )
        msg.message_hash = b"\x04" * 32

        assert not m.is_relayed(msg)
        m.relay_message(msg)
        assert m.is_relayed(msg)


class TestRelayWithContract:
    """Test relay executing contract code."""

    def test_relay_sstore_contract(self):
        """Relay a message that triggers SSTORE in target contract.

        Deploy a simple contract that stores calldata[0:32] at slot 0:
            PUSH1 0x00   CALLDATALOAD   PUSH1 0x00   SSTORE   STOP
        """
        # Bytecode: CALLDATALOAD(0) → SSTORE(0, value)
        # 60 00 35 60 00 55 00
        code = bytes([
            0x60, 0x00,  # PUSH1 0
            0x35,        # CALLDATALOAD → stack: [calldata[0:32]]
            0x60, 0x00,  # PUSH1 0
            0x55,        # SSTORE(0, calldata[0:32])
            0x00,        # STOP
        ])

        store = MemoryBackend()
        # "Deploy" the contract by putting code at CONTRACT address
        from ethclient.common.types import Account
        from ethclient.common.crypto import keccak256
        acc = Account()
        acc.code_hash = keccak256(code)
        store.put_account(CONTRACT, acc)
        store.put_code(acc.code_hash, code)

        m = CrossDomainMessenger(Domain.L2, store)

        # Send calldata = 42 (as uint256)
        calldata = (42).to_bytes(32, "big")
        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=CONTRACT, data=calldata,
            gas_limit=100_000, source_domain=Domain.L1,
        )
        msg.message_hash = b"\x05" * 32

        result = m.relay_message(msg)
        assert result.success
        assert result.gas_used > 0

        # Verify storage was updated
        assert store.get_storage(CONTRACT, 0) == 42

    def test_relay_multiple_slots(self):
        """Relay writes to multiple storage slots via sequential SSTORE.

        Contract: stores calldata[0:32] at slot 0, calldata[32:64] at slot 1.
        """
        code = bytes([
            # slot 0 = calldata[0:32]
            0x60, 0x00,  # PUSH1 0
            0x35,        # CALLDATALOAD
            0x60, 0x00,  # PUSH1 0
            0x55,        # SSTORE
            # slot 1 = calldata[32:64]
            0x60, 0x20,  # PUSH1 32
            0x35,        # CALLDATALOAD
            0x60, 0x01,  # PUSH1 1
            0x55,        # SSTORE
            0x00,        # STOP
        ])

        store = MemoryBackend()
        from ethclient.common.types import Account
        from ethclient.common.crypto import keccak256
        acc = Account()
        acc.code_hash = keccak256(code)
        store.put_account(CONTRACT, acc)
        store.put_code(acc.code_hash, code)

        m = CrossDomainMessenger(Domain.L2, store)

        calldata = (1850).to_bytes(32, "big") + (1650).to_bytes(32, "big")
        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=CONTRACT, data=calldata,
            gas_limit=200_000, source_domain=Domain.L1,
        )
        msg.message_hash = b"\x06" * 32

        result = m.relay_message(msg)
        assert result.success

        assert store.get_storage(CONTRACT, 0) == 1850
        assert store.get_storage(CONTRACT, 1) == 1650
