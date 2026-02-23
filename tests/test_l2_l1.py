"""Tests for InMemoryL1Backend: verifier deployment, proof verification."""

import pytest
from ethclient.l2.l1_backend import InMemoryL1Backend
from ethclient.l2.prover import Groth16ProofBackend
from ethclient.l2.runtime import PythonRuntime
from ethclient.l2.types import STFResult


def _noop_stf(state, tx):
    return STFResult(success=True)


class TestInMemoryL1Backend:
    def _setup_prover(self):
        prover = Groth16ProofBackend()
        stf = PythonRuntime(_noop_stf)
        prover.setup(stf, max_txs_per_batch=4)
        return prover

    def test_deploy_verifier(self):
        l1 = InMemoryL1Backend()
        prover = self._setup_prover()
        addr = l1.deploy_verifier(prover.verification_key)
        assert len(addr) == 20

    def test_submit_without_deploy_raises(self):
        l1 = InMemoryL1Backend()
        prover = self._setup_prover()
        proof = prover.prove(b"\x11" * 32, b"\x22" * 32, [], b"\x33" * 32)
        with pytest.raises(RuntimeError, match="Verifier not deployed"):
            l1.submit_batch(0, b"\x11" * 32, b"\x22" * 32, proof, b"\x33" * 32)

    def test_valid_proof_verified(self):
        l1 = InMemoryL1Backend()
        prover = self._setup_prover()
        l1.deploy_verifier(prover.verification_key)

        old_root = b"\x11" * 32
        new_root = b"\x22" * 32
        tx_commitment = b"\x33" * 32

        proof = prover.prove(old_root, new_root, [], tx_commitment)
        l1_hash = l1.submit_batch(0, old_root, new_root, proof, tx_commitment)

        assert len(l1_hash) == 32
        assert l1.is_batch_verified(0)
        assert l1.get_verified_state_root() == new_root

    def test_tampered_root_rejected(self):
        l1 = InMemoryL1Backend()
        prover = self._setup_prover()
        l1.deploy_verifier(prover.verification_key)

        old_root = b"\x11" * 32
        new_root = b"\x22" * 32
        tx_commitment = b"\x33" * 32

        proof = prover.prove(old_root, new_root, [], tx_commitment)

        # Submit with wrong new_root — verification should fail
        wrong_root = b"\x99" * 32
        l1.submit_batch(0, old_root, wrong_root, proof, tx_commitment)
        assert not l1.is_batch_verified(0)

    def test_multiple_batches(self):
        l1 = InMemoryL1Backend()
        prover = self._setup_prover()
        l1.deploy_verifier(prover.verification_key)

        roots = [b"\x10" * 32, b"\x20" * 32, b"\x30" * 32]
        commits = [b"\xa0" * 32, b"\xb0" * 32]

        proof0 = prover.prove(roots[0], roots[1], [], commits[0])
        l1.submit_batch(0, roots[0], roots[1], proof0, commits[0])
        assert l1.is_batch_verified(0)

        proof1 = prover.prove(roots[1], roots[2], [], commits[1])
        l1.submit_batch(1, roots[1], roots[2], proof1, commits[1])
        assert l1.is_batch_verified(1)
        assert l1.get_verified_state_root() == roots[2]

    def test_unverified_batch(self):
        l1 = InMemoryL1Backend()
        assert not l1.is_batch_verified(0)
        assert l1.get_verified_state_root() is None
