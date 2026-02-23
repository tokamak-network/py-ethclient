"""Tests for Groth16ProofBackend: circuit setup, prove/verify roundtrip."""

import pytest
from ethclient.l2.prover import Groth16ProofBackend, _to_field
from ethclient.l2.runtime import PythonRuntime
from ethclient.l2.types import L2Tx, STFResult
from ethclient.zk.circuit import FIELD_MODULUS


def _noop_stf(state, tx):
    return STFResult(success=True)


class TestToField:
    def test_full_range_reduction(self):
        data = b"\xff" * 32
        val = _to_field(data)
        assert 0 < val < FIELD_MODULUS

    def test_deterministic(self):
        data = b"\xab\xcd" * 16
        assert _to_field(data) == _to_field(data)

    def test_different_data(self):
        d1 = b"\x01" * 32
        d2 = b"\x02" * 32
        assert _to_field(d1) != _to_field(d2)

    def test_modular_reduction(self):
        data = b"\xff" * 32
        val = _to_field(data)
        expected = int.from_bytes(data, "big") % FIELD_MODULUS
        assert val == expected


class TestGroth16ProofBackend:
    def test_setup(self):
        prover = Groth16ProofBackend()
        stf = PythonRuntime(_noop_stf)
        prover.setup(stf, max_txs_per_batch=4)
        assert prover._is_setup
        assert prover._vk is not None
        assert prover._pk is not None
        assert prover._max_txs == 4

    def test_circuit_constraints(self):
        prover = Groth16ProofBackend()
        stf = PythonRuntime(_noop_stf)
        prover.setup(stf, max_txs_per_batch=4)
        # max_txs + 1 constraints
        assert prover._circuit.num_constraints == 5

    def test_prove_before_setup_raises(self):
        prover = Groth16ProofBackend()
        with pytest.raises(RuntimeError, match="setup"):
            prover.prove(b"\x00" * 32, b"\x01" * 32, [], b"\x02" * 32)

    def test_verify_before_setup_raises(self):
        prover = Groth16ProofBackend()
        with pytest.raises(RuntimeError, match="setup"):
            prover.verify(None, b"\x00" * 32, b"\x01" * 32, b"\x02" * 32)

    def test_vk_before_setup_raises(self):
        prover = Groth16ProofBackend()
        with pytest.raises(RuntimeError, match="setup"):
            _ = prover.verification_key

    def test_prove_too_many_txs_raises(self):
        prover = Groth16ProofBackend()
        stf = PythonRuntime(_noop_stf)
        prover.setup(stf, max_txs_per_batch=2)
        txs = [
            L2Tx(sender=b"\x01" * 20, nonce=0, data={}),
            L2Tx(sender=b"\x01" * 20, nonce=1, data={}),
        ]
        with pytest.raises(ValueError, match="free slot"):
            prover.prove(b"\x00" * 32, b"\x01" * 32, txs, b"\x02" * 32)

    def test_prove_and_verify_roundtrip(self):
        prover = Groth16ProofBackend()
        stf = PythonRuntime(_noop_stf)
        prover.setup(stf, max_txs_per_batch=4)

        old_root = b"\x11" * 32
        new_root = b"\x22" * 32
        txs = [L2Tx(sender=b"\x01" * 20, nonce=0, data={"v": "a"})]
        tx_commitment = b"\x33" * 32

        proof = prover.prove(old_root, new_root, txs, tx_commitment)
        assert proof is not None

        valid = prover.verify(proof, old_root, new_root, tx_commitment)
        assert valid

    def test_prove_and_verify_empty_batch(self):
        prover = Groth16ProofBackend()
        stf = PythonRuntime(_noop_stf)
        prover.setup(stf, max_txs_per_batch=4)

        old_root = b"\x11" * 32
        new_root = b"\x22" * 32
        tx_commitment = b"\x33" * 32

        proof = prover.prove(old_root, new_root, [], tx_commitment)
        assert proof is not None

        valid = prover.verify(proof, old_root, new_root, tx_commitment)
        assert valid

    def test_wrong_root_rejected(self):
        prover = Groth16ProofBackend()
        stf = PythonRuntime(_noop_stf)
        prover.setup(stf, max_txs_per_batch=4)

        old_root = b"\x11" * 32
        new_root = b"\x22" * 32
        txs = [L2Tx(sender=b"\x01" * 20, nonce=0, data={"v": "a"})]
        tx_commitment = b"\x33" * 32

        proof = prover.prove(old_root, new_root, txs, tx_commitment)

        # Tamper with the new root
        wrong_root = b"\x99" * 32
        valid = prover.verify(proof, old_root, wrong_root, tx_commitment)
        assert not valid

    def test_verification_key_accessible_after_setup(self):
        prover = Groth16ProofBackend()
        stf = PythonRuntime(_noop_stf)
        prover.setup(stf, max_txs_per_batch=4)

        vk = prover.verification_key
        assert vk is not None
        assert vk.num_public_inputs == 3  # old_root, new_root, tx_commitment
