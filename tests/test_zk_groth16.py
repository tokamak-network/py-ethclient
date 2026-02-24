"""Tests for Groth16 prover/verifier."""

import pytest

from ethclient.zk.circuit import Circuit
from ethclient.zk import groth16
from ethclient.zk.types import G1Point, G2Point, Proof, VerificationKey
from ethclient.zk.snarkjs_compat import (
    export_snarkjs_vkey,
    export_snarkjs_proof,
    parse_snarkjs_vkey,
    parse_snarkjs_proof,
    verify_snarkjs,
)


def _make_simple_circuit():
    """Create a simple x * y = z circuit."""
    c = Circuit()
    x = c.private("x")
    y = c.private("y")
    z = c.public("z")
    c.constrain(x * y, z)
    return c


def _make_two_constraint_circuit():
    """Create a circuit with two multiplication constraints: x*y=z1, x*x=z2."""
    c = Circuit()
    x = c.private("x")
    y = c.private("y")
    z1 = c.public("z1")
    z2 = c.public("z2")
    c.constrain(x * y, z1)
    c.constrain(x * x, z2)
    return c


class TestGroth16Setup:
    """Test trusted setup."""

    def test_setup_returns_keys(self):
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)

        assert pk is not None
        assert vk is not None
        assert vk.num_public_inputs == 1
        assert len(vk.ic) == 2  # IC[0] + IC[1] for 1 public input

    def test_setup_key_types(self):
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)

        assert isinstance(vk.alpha, G1Point)
        assert isinstance(vk.beta, G2Point)
        assert isinstance(vk.gamma, G2Point)
        assert isinstance(vk.delta, G2Point)
        assert all(isinstance(p, G1Point) for p in vk.ic)

    def test_setup_two_constraints(self):
        c = _make_two_constraint_circuit()
        pk, vk = groth16.setup(c)

        assert vk.num_public_inputs == 2
        assert len(vk.ic) == 3  # IC[0] + IC[1] + IC[2]
        assert pk.num_constraints == 2


class TestGroth16ProveVerify:
    """Test proof generation and verification round-trip."""

    def test_simple_prove_verify(self):
        """x * y = z with x=3, y=5, z=15."""
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)

        proof = groth16.prove(
            pk,
            private={"x": 3, "y": 5},
            public={"z": 15},
            circuit=c,
        )

        assert isinstance(proof, Proof)
        assert isinstance(proof.a, G1Point)
        assert isinstance(proof.b, G2Point)
        assert isinstance(proof.c, G1Point)

        # Verify
        assert groth16.verify(vk, proof, [15])

    def test_wrong_public_input_fails(self):
        """Proof for z=15 should not verify with z=16."""
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)

        proof = groth16.prove(
            pk,
            private={"x": 3, "y": 5},
            public={"z": 15},
            circuit=c,
        )

        # Should fail with wrong public input
        assert not groth16.verify(vk, proof, [16])

    def test_two_constraints_prove_verify(self):
        """x*y=z1, x*x=z2 with x=3, y=5."""
        c = _make_two_constraint_circuit()
        pk, vk = groth16.setup(c)

        proof = groth16.prove(
            pk,
            private={"x": 3, "y": 5},
            public={"z1": 15, "z2": 9},
            circuit=c,
        )

        assert groth16.verify(vk, proof, [15, 9])
        assert not groth16.verify(vk, proof, [15, 10])

    def test_invalid_witness_raises(self):
        """Inconsistent private/public should raise."""
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)

        with pytest.raises(ValueError, match="Witness does not satisfy"):
            groth16.prove(
                pk,
                private={"x": 3, "y": 5},
                public={"z": 16},  # 3*5 != 16
                circuit=c,
            )

    def test_prove_without_circuit_raises(self):
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)

        with pytest.raises(ValueError, match="Circuit required"):
            groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15})

    def test_wrong_number_of_inputs_raises(self):
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)

        proof = groth16.prove(
            pk,
            private={"x": 3, "y": 5},
            public={"z": 15},
            circuit=c,
        )

        with pytest.raises(ValueError, match="Expected 1"):
            groth16.verify(vk, proof, [15, 16])

    def test_different_witnesses_different_proofs(self):
        """Two different valid witnesses should produce different proofs."""
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)

        proof1 = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)
        proof2 = groth16.prove(pk, private={"x": 5, "y": 3}, public={"z": 15}, circuit=c)

        # Both should verify
        assert groth16.verify(vk, proof1, [15])
        assert groth16.verify(vk, proof2, [15])

        # Proofs should be different (due to randomization)
        assert proof1.a != proof2.a or proof1.c != proof2.c

    def test_public_inputs_as_dict(self):
        """verify() should accept dict of public inputs."""
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)

        proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)
        assert groth16.verify(vk, proof, {"z": 15})


class TestDebugVerify:
    """Test debug_verify for detailed pairing information."""

    def test_valid_proof_debug(self):
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)
        proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)

        result = groth16.debug_verify(vk, proof, [15])
        assert result.valid
        assert result.e_ab is not None
        assert result.e_alpha_beta is not None
        assert result.e_ab == result.e_alpha_beta * result.e_ic_gamma * result.e_c_delta

    def test_invalid_proof_debug(self):
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)
        proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)

        result = groth16.debug_verify(vk, proof, [16])
        assert not result.valid
        assert result.e_ab != result.e_alpha_beta * result.e_ic_gamma * result.e_c_delta


class TestSnarkjsCompat:
    """Test snarkjs JSON format round-trip."""

    def test_vkey_export_import(self):
        c = _make_simple_circuit()
        _, vk = groth16.setup(c)

        exported = export_snarkjs_vkey(vk)
        imported = parse_snarkjs_vkey(exported)

        assert imported.alpha.x == vk.alpha.x
        assert imported.alpha.y == vk.alpha.y
        assert imported.beta.x_real == vk.beta.x_real
        assert imported.beta.x_imag == vk.beta.x_imag
        assert imported.num_public_inputs == vk.num_public_inputs

    def test_proof_export_import(self):
        c = _make_simple_circuit()
        pk, _ = groth16.setup(c)
        proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)

        exported = export_snarkjs_proof(proof)
        imported = parse_snarkjs_proof(exported)

        assert imported.a.x == proof.a.x
        assert imported.a.y == proof.a.y
        assert imported.b.x_real == proof.b.x_real
        assert imported.c.x == proof.c.x

    def test_verify_snarkjs_format(self):
        """Full round-trip: setup → prove → export → re-import → verify."""
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)
        proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)

        vk_json = export_snarkjs_vkey(vk)
        proof_json = export_snarkjs_proof(proof)
        public_json = ["15"]

        assert verify_snarkjs(vk_json, proof_json, public_json)

    def test_verify_snarkjs_wrong_input(self):
        c = _make_simple_circuit()
        pk, vk = groth16.setup(c)
        proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)

        vk_json = export_snarkjs_vkey(vk)
        proof_json = export_snarkjs_proof(proof)

        assert not verify_snarkjs(vk_json, proof_json, ["16"])

    def test_snarkjs_format_fields(self):
        """Check that exported JSON has the expected fields."""
        c = _make_simple_circuit()
        _, vk = groth16.setup(c)

        exported = export_snarkjs_vkey(vk)
        assert exported["protocol"] == "groth16"
        assert exported["curve"] == "bn128"
        assert exported["nPublic"] == 1
        assert "vk_alpha_1" in exported
        assert "vk_beta_2" in exported
        assert "IC" in exported
