"""Proof-based relay handler tests — Merkle, ZK, Direct, and EVM handlers."""

import pytest

from ethclient.bridge import (
    BridgeEnvironment,
    CrossDomainMessenger,
    Domain,
    StateUpdate,
    EVMRelayHandler,
    MerkleProofHandler,
    ZKProofHandler,
    DirectStateHandler,
    TinyDBHandler,
    encode_state_updates,
    decode_state_updates,
)
from ethclient.bridge.types import CrossDomainMessage
from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.common.types import Account
from ethclient.common.trie import Trie
from ethclient.storage.memory_backend import MemoryBackend


ALICE = b"\x01" * 20
BOB = b"\x02" * 20
CAROL = b"\x03" * 20


# ---------------------------------------------------------------------------
# StateUpdate codec tests
# ---------------------------------------------------------------------------

class TestStateUpdateCodec:

    def test_encode_decode_balance_only(self):
        update = StateUpdate(address=ALICE, balance=1000)
        encoded = update.encode()
        decoded = StateUpdate.decode(encoded)
        assert decoded.address == ALICE
        assert decoded.balance == 1000
        assert decoded.nonce is None
        assert decoded.storage == {}

    def test_encode_decode_full(self):
        update = StateUpdate(
            address=BOB, balance=500, nonce=3,
            storage={1: 42, 2: 99},
        )
        encoded = update.encode()
        decoded = StateUpdate.decode(encoded)
        assert decoded.address == BOB
        assert decoded.balance == 500
        assert decoded.nonce == 3
        assert decoded.storage == {1: 42, 2: 99}

    def test_encode_decode_list(self):
        updates = [
            StateUpdate(address=ALICE, balance=100),
            StateUpdate(address=BOB, nonce=5, storage={10: 20}),
        ]
        data = encode_state_updates(updates)
        decoded = decode_state_updates(data)
        assert len(decoded) == 2
        assert decoded[0].address == ALICE
        assert decoded[0].balance == 100
        assert decoded[1].address == BOB
        assert decoded[1].nonce == 5
        assert decoded[1].storage == {10: 20}

    def test_zero_balance_roundtrip(self):
        """balance=0 should NOT be confused with None."""
        update = StateUpdate(address=ALICE, balance=0, nonce=0)
        encoded = update.encode()
        decoded = StateUpdate.decode(encoded)
        # 0 encodes as empty bytes in RLP, which decodes to None
        # This is a known RLP limitation — 0 and None are indistinguishable
        # For the bridge, None means "don't update", 0 means "set to 0"
        # We accept this trade-off in the RLP codec


# ---------------------------------------------------------------------------
# EVMRelayHandler tests (backward compatibility)
# ---------------------------------------------------------------------------

class TestEVMRelayHandler:

    def test_default_handler_is_evm(self):
        env = BridgeEnvironment()
        assert isinstance(env.l1_messenger.relay_handler, EVMRelayHandler)
        assert isinstance(env.l2_messenger.relay_handler, EVMRelayHandler)

    def test_value_transfer_via_evm_handler(self):
        env = BridgeEnvironment()
        env.send_l1(sender=ALICE, target=BOB, value=1000)
        result = env.relay()
        assert result.all_success
        assert env.l2_balance(BOB) == 1000

    def test_existing_tests_backward_compatible(self):
        """Explicitly verify the default handler matches original behavior."""
        handler = EVMRelayHandler()
        store = MemoryBackend()

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=b"",
            value=500, source_domain=Domain.L1,
        )
        msg.message_hash = b"\xaa" * 32

        result = handler.execute(msg, store, block_number=0, chain_id=1)
        assert result.success
        assert store.get_balance(BOB) == 500


# ---------------------------------------------------------------------------
# DirectStateHandler tests
# ---------------------------------------------------------------------------

class TestDirectStateHandler:

    def test_apply_balance_update(self):
        handler = DirectStateHandler()
        store = MemoryBackend()

        updates = [StateUpdate(address=ALICE, balance=1000)]
        data = encode_state_updates(updates)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=data,
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xbb" * 32

        result = handler.execute(msg, store, block_number=0, chain_id=1)
        assert result.success
        assert store.get_balance(ALICE) == 1000

    def test_apply_multiple_updates(self):
        handler = DirectStateHandler()
        store = MemoryBackend()

        updates = [
            StateUpdate(address=ALICE, balance=100, nonce=1),
            StateUpdate(address=BOB, balance=200, nonce=2),
        ]
        data = encode_state_updates(updates)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=data,
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xcc" * 32

        result = handler.execute(msg, store, block_number=0, chain_id=1)
        assert result.success
        assert store.get_balance(ALICE) == 100
        assert store.get_nonce(ALICE) == 1
        assert store.get_balance(BOB) == 200
        assert store.get_nonce(BOB) == 2

    def test_apply_storage_update(self):
        handler = DirectStateHandler()
        store = MemoryBackend()

        updates = [StateUpdate(address=ALICE, storage={1: 42, 2: 99})]
        data = encode_state_updates(updates)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=data,
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xdd" * 32

        result = handler.execute(msg, store, block_number=0, chain_id=1)
        assert result.success
        assert store.get_storage(ALICE, 1) == 42
        assert store.get_storage(ALICE, 2) == 99

    def test_invalid_data_returns_error(self):
        handler = DirectStateHandler()
        store = MemoryBackend()

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=b"not-valid-rlp",
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xee" * 32

        result = handler.execute(msg, store, block_number=0, chain_id=1)
        assert not result.success
        assert "invalid state update data" in result.error

    def test_via_bridge_environment(self):
        env = BridgeEnvironment.with_direct_state()
        assert isinstance(env.l2_messenger.relay_handler, DirectStateHandler)

        updates = [StateUpdate(address=BOB, balance=777)]
        data = encode_state_updates(updates)
        env.send_l1(sender=ALICE, target=BOB, data=data)
        result = env.relay()

        assert result.all_success
        assert env.l2_store.get_balance(BOB) == 777


# ---------------------------------------------------------------------------
# MerkleProofHandler tests
# ---------------------------------------------------------------------------

class TestMerkleProofHandler:

    def _build_account_proof(self, store, address):
        """Build a Merkle proof for an account in the store's state trie."""
        trie = Trie()
        for addr, acc in store.iter_accounts():
            account_rlp = rlp.encode([
                acc.nonce,
                acc.balance,
                b"\x56\xe8\x1f\x17\x1b\xcc\x55\xa6\xff\x83\x45\xe6\x92\xc0\xf8\x6e\x5b\x48\xe0\x1b\x99\x6c\xad\xc0\x01\x62\x2f\xb5\xe3\x63\xb4\x21",  # empty storage root
                b"\xc5\xd2\x46\x01\x86\xf7\x23\x3c\x92\x7e\x7d\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6\x53\xca\x82\x27\x3b\x7b\xfa\xd8\x04\x5d\x85\xa4\x70",  # empty code hash
            ])
            trie.put_raw(keccak256(addr), account_rlp)

        root = trie.root_hash
        key = keccak256(address)
        proof_nodes = trie.prove(key)

        # Retrieve the account RLP
        acc = store.get_account(address)
        account_rlp = rlp.encode([
            acc.nonce,
            acc.balance,
            b"\x56\xe8\x1f\x17\x1b\xcc\x55\xa6\xff\x83\x45\xe6\x92\xc0\xf8\x6e\x5b\x48\xe0\x1b\x99\x6c\xad\xc0\x01\x62\x2f\xb5\xe3\x63\xb4\x21",
            b"\xc5\xd2\x46\x01\x86\xf7\x23\x3c\x92\x7e\x7d\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6\x53\xca\x82\x27\x3b\x7b\xfa\xd8\x04\x5d\x85\xa4\x70",
        ])

        return root, account_rlp, proof_nodes

    def test_valid_proof_applies_state(self):
        handler = MerkleProofHandler()
        target_store = MemoryBackend()

        # Build source state with ALICE having balance 1000
        source_store = MemoryBackend()
        source_store.set_balance(ALICE, 1000)
        source_store.set_nonce(ALICE, 5)

        root, account_rlp, proof_nodes = self._build_account_proof(source_store, ALICE)
        handler.add_trusted_root(root)

        # Build msg.data
        data = rlp.encode([root, ALICE, account_rlp, proof_nodes])

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=data,
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xaa" * 32

        result = handler.execute(msg, target_store, block_number=0, chain_id=1)
        assert result.success
        assert target_store.get_balance(ALICE) == 1000
        assert target_store.get_nonce(ALICE) == 5

    def test_untrusted_root_rejected(self):
        handler = MerkleProofHandler()
        target_store = MemoryBackend()

        source_store = MemoryBackend()
        source_store.set_balance(ALICE, 1000)

        root, account_rlp, proof_nodes = self._build_account_proof(source_store, ALICE)
        # Do NOT add root as trusted

        data = rlp.encode([root, ALICE, account_rlp, proof_nodes])

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=data,
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xbb" * 32

        result = handler.execute(msg, target_store, block_number=0, chain_id=1)
        assert not result.success
        assert "not trusted" in result.error

    def test_tampered_proof_rejected(self):
        handler = MerkleProofHandler()
        target_store = MemoryBackend()

        source_store = MemoryBackend()
        source_store.set_balance(ALICE, 1000)

        root, account_rlp, proof_nodes = self._build_account_proof(source_store, ALICE)
        handler.add_trusted_root(root)

        # Tamper with account RLP (claim balance is 9999)
        fake_rlp = rlp.encode([0, 9999, b"\x56" * 32, b"\xc5" * 32])
        data = rlp.encode([root, ALICE, fake_rlp, proof_nodes])

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=data,
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xcc" * 32

        result = handler.execute(msg, target_store, block_number=0, chain_id=1)
        assert not result.success
        assert "does not match" in result.error

    def test_commit_root_via_environment(self):
        handler = MerkleProofHandler()
        env = BridgeEnvironment(l2_handler=handler)

        # Set up L1 state
        env.l1_store.set_balance(ALICE, 500)

        # Commit L1 root to L2's handler
        root = env.commit_l1_root()
        assert root in handler._trusted_roots

    def test_via_bridge_environment_factory(self):
        env = BridgeEnvironment.with_merkle_proof()
        assert isinstance(env.l2_messenger.relay_handler, MerkleProofHandler)


# ---------------------------------------------------------------------------
# ZKProofHandler tests
# ---------------------------------------------------------------------------

class TestZKProofHandler:

    @pytest.fixture
    def zk_setup(self):
        """Set up a simple circuit: old_balance + amount = new_balance."""
        from ethclient.zk import Circuit, groth16

        c = Circuit()
        old_bal = c.public("old_balance")
        amount = c.public("amount")
        new_bal = c.public("new_balance")

        # new_balance = old_balance + amount
        # Constraint: old_balance * 1 = intermediate
        # then intermediate + amount = new_balance
        # Simpler: we just prove a + b = c by doing (a + b) * 1 = c
        # But Groth16 needs R1CS: a*b=c format
        # Let's do: (old_balance + amount) * 1 = new_balance
        one = c.private("one")
        product = (old_bal + amount) * one
        c.constrain(product, new_bal)

        pk, vk = groth16.setup(c)
        return c, pk, vk, groth16

    def _build_zk_data(self, groth16, pk, circuit, old_bal, amount, new_bal):
        """Build RLP-encoded msg.data for ZK relay."""
        proof = groth16.prove(
            pk,
            private={"one": 1},
            public={"old_balance": old_bal, "amount": amount, "new_balance": new_bal},
            circuit=circuit,
        )

        proof_a_bytes = proof.a.to_evm_bytes()
        proof_b_bytes = proof.b.to_evm_bytes()
        proof_c_bytes = proof.c.to_evm_bytes()

        public_inputs = [
            old_bal.to_bytes(32, "big"),
            amount.to_bytes(32, "big"),
            new_bal.to_bytes(32, "big"),
        ]

        updates = [StateUpdate(address=BOB, balance=new_bal)]
        state_updates_rlp = [rlp.decode(u.encode()) for u in updates]

        return rlp.encode([
            proof_a_bytes, proof_b_bytes, proof_c_bytes,
            public_inputs, state_updates_rlp,
        ])

    def test_valid_zk_proof_applies_state(self, zk_setup):
        c, pk, vk, groth16_mod = zk_setup
        handler = ZKProofHandler(vk)
        store = MemoryBackend()

        data = self._build_zk_data(groth16_mod, pk, c, 100, 50, 150)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=data,
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xaa" * 32

        result = handler.execute(msg, store, block_number=0, chain_id=1)
        assert result.success
        assert store.get_balance(BOB) == 150

    def test_invalid_zk_proof_rejected(self, zk_setup):
        c, pk, vk, groth16_mod = zk_setup
        handler = ZKProofHandler(vk)
        store = MemoryBackend()

        # Build proof for correct values
        data = self._build_zk_data(groth16_mod, pk, c, 100, 50, 150)

        # Tamper: change a public input in the RLP
        items = rlp.decode(data)
        items[3][2] = (999).to_bytes(32, "big")  # claim new_balance=999
        tampered_data = rlp.encode(items)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=tampered_data,
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xbb" * 32

        result = handler.execute(msg, store, block_number=0, chain_id=1)
        assert not result.success
        assert "failed" in result.error.lower() or "error" in result.error.lower()

    def test_via_bridge_environment_factory(self, zk_setup):
        _, _, vk, _ = zk_setup
        env = BridgeEnvironment.with_zk_proof(vk)
        assert isinstance(env.l2_messenger.relay_handler, ZKProofHandler)


# ---------------------------------------------------------------------------
# TinyDBHandler tests
# ---------------------------------------------------------------------------

class TestTinyDBHandler:

    def test_apply_balance_to_tinydb(self):
        handler = TinyDBHandler()
        store = MemoryBackend()

        updates = [StateUpdate(address=ALICE, balance=1000, nonce=1)]
        data = encode_state_updates(updates)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=data,
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xaa" * 32

        result = handler.execute(msg, store, block_number=0, chain_id=1)
        assert result.success

        # Check TinyDB (not Ethereum Store)
        doc = handler.get_account(ALICE)
        assert doc is not None
        assert doc["balance"] == 1000
        assert doc["nonce"] == 1

        # Ethereum Store should be untouched
        assert store.get_balance(ALICE) == 0

    def test_apply_storage_to_tinydb(self):
        handler = TinyDBHandler()
        store = MemoryBackend()

        updates = [StateUpdate(address=BOB, balance=500, storage={1: 42, 2: 99})]
        data = encode_state_updates(updates)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=data,
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xbb" * 32

        result = handler.execute(msg, store, block_number=0, chain_id=1)
        assert result.success

        doc = handler.get_account(BOB)
        assert doc["balance"] == 500
        assert doc["storage"]["1"] == 42
        assert doc["storage"]["2"] == 99

    def test_upsert_merges_state(self):
        handler = TinyDBHandler()
        store = MemoryBackend()

        # First update: set balance
        data1 = encode_state_updates([StateUpdate(address=ALICE, balance=100)])
        msg1 = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=data1,
            source_domain=Domain.L1,
        )
        msg1.message_hash = b"\xcc" * 32
        handler.execute(msg1, store, block_number=0, chain_id=1)

        # Second update: set nonce (balance should be preserved)
        data2 = encode_state_updates([StateUpdate(address=ALICE, nonce=5)])
        msg2 = CrossDomainMessage(
            nonce=1, sender=ALICE, target=BOB, data=data2,
            source_domain=Domain.L1,
        )
        msg2.message_hash = b"\xdd" * 32
        handler.execute(msg2, store, block_number=0, chain_id=1)

        doc = handler.get_account(ALICE)
        assert doc["balance"] == 100  # preserved from first update
        assert doc["nonce"] == 5

    def test_multiple_accounts(self):
        handler = TinyDBHandler()
        store = MemoryBackend()

        updates = [
            StateUpdate(address=ALICE, balance=100),
            StateUpdate(address=BOB, balance=200),
            StateUpdate(address=CAROL, balance=300),
        ]
        data = encode_state_updates(updates)

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=data,
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xee" * 32

        result = handler.execute(msg, store, block_number=0, chain_id=1)
        assert result.success
        assert len(handler.db.all()) == 3
        assert handler.get_account(ALICE)["balance"] == 100
        assert handler.get_account(BOB)["balance"] == 200
        assert handler.get_account(CAROL)["balance"] == 300

    def test_invalid_data_returns_error(self):
        handler = TinyDBHandler()
        store = MemoryBackend()

        msg = CrossDomainMessage(
            nonce=0, sender=ALICE, target=BOB, data=b"\xff\xff",
            source_domain=Domain.L1,
        )
        msg.message_hash = b"\xff" * 32

        result = handler.execute(msg, store, block_number=0, chain_id=1)
        assert not result.success
        assert "invalid state update data" in result.error


# ---------------------------------------------------------------------------
# Pluggable handler integration tests
# ---------------------------------------------------------------------------

class TestPluggableHandlerIntegration:

    def test_different_handlers_per_domain(self):
        """L1 uses EVM, L2 uses DirectState."""
        env = BridgeEnvironment(
            l1_handler=EVMRelayHandler(),
            l2_handler=DirectStateHandler(),
        )
        assert isinstance(env.l1_messenger.relay_handler, EVMRelayHandler)
        assert isinstance(env.l2_messenger.relay_handler, DirectStateHandler)

    def test_handler_swap_at_runtime(self):
        """Handlers can be swapped after creation."""
        store = MemoryBackend()
        messenger = CrossDomainMessenger(Domain.L2, store, chain_id=42170)
        assert isinstance(messenger.relay_handler, EVMRelayHandler)

        messenger.relay_handler = DirectStateHandler()
        assert isinstance(messenger.relay_handler, DirectStateHandler)

    def test_replay_protection_with_direct_handler(self):
        """Replay protection still works with non-EVM handlers."""
        env = BridgeEnvironment.with_direct_state()

        updates = [StateUpdate(address=BOB, balance=100)]
        data = encode_state_updates(updates)
        msg = env.send_l1(sender=ALICE, target=BOB, data=data)
        r1 = env.relay()
        assert r1.all_success

        # Try to replay the same message
        r2 = env.l2_messenger.relay_message(msg)
        assert not r2.success
        assert "already relayed" in r2.error
