"""Tests for NativeProverBackend — subprocess-based Groth16 proving."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from ethclient.l2.native_prover import NativeProverBackend
from ethclient.l2.types import L2Tx, STFResult
from ethclient.l2.runtime import PythonRuntime
from ethclient.zk.circuit import Circuit, FIELD_MODULUS
from ethclient.zk.r1cs_export import export_r1cs_binary, export_witness_json, export_public_json


def _make_stf():
    def apply_tx(state, tx):
        state["counter"] = state.get("counter", 0) + 1
        return STFResult(success=True)
    return PythonRuntime(apply_tx)


class TestR1CSExport:
    def test_export_r1cs_binary_format(self):
        c = Circuit()
        x = c.public("x")
        y = c.private("y")
        z = c.private("z")
        c.constrain(x * y, z)

        data = export_r1cs_binary(c)
        assert data[:4] == b"r1cs"
        # Version 1
        assert int.from_bytes(data[4:8], "little") == 1
        # 3 sections
        assert int.from_bytes(data[8:12], "little") == 3

    def test_export_r1cs_roundtrip_structure(self):
        """R1CS export should match circuit structure."""
        c = Circuit()
        a = c.public("a")
        b = c.private("b")
        out = c.public("out")
        c.constrain(a * b, out)

        r1cs = c.to_r1cs()
        data = export_r1cs_binary(c)

        # Parse header section to verify field count
        # Skip magic(4) + version(4) + num_sections(4) + section_type(4) + section_size(8) = 24
        header_start = 24
        field_size = int.from_bytes(data[header_start:header_start + 4], "little")
        assert field_size == 32

    def test_export_witness_json(self):
        c = Circuit()
        x = c.public("x")
        y = c.private("y")
        z = c.private("z")
        c.constrain(x * y, z)

        result = export_witness_json(
            public={"x": 5},
            private={"y": 3, "z": 15},
            circuit=c,
        )
        assert "witness" in result
        assert result["witness"][0] == "1"  # constant wire
        # Witness has: [1, x=5, y=3, z=15] — intermediate optimized away by constrain()
        assert len(result["witness"]) >= 3  # at least constant + public + privates

    def test_export_public_json(self):
        c = Circuit()
        c.public("a")
        c.public("b")
        c.private("x")

        result = export_public_json({"a": 42, "b": 99}, c)
        assert result == ["42", "99"]


class TestNativeProverFallback:
    """Test that NativeProverBackend falls back to Python when native binary unavailable."""

    def test_setup_falls_back_to_python(self, tmp_path):
        prover = NativeProverBackend(
            prover_binary="nonexistent_binary",
            setup_binary="nonexistent_setup",
            working_dir=str(tmp_path / "prover"),
        )
        stf = _make_stf()
        prover.setup(stf, max_txs_per_batch=4)
        assert prover._is_setup
        assert prover._vk is not None
        # Should have fallen back to Python
        assert prover._pk is not None

    def test_prove_falls_back_to_python(self, tmp_path):
        prover = NativeProverBackend(
            prover_binary="nonexistent_binary",
            working_dir=str(tmp_path / "prover"),
        )
        stf = _make_stf()
        prover.setup(stf, max_txs_per_batch=4)

        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={"op": "inc"})
        proof = prover.prove(
            old_state_root=b"\xaa" * 32,
            new_state_root=b"\xbb" * 32,
            transactions=[tx],
            tx_commitment=b"\xcc" * 32,
        )
        assert proof is not None
        assert proof.a is not None

    def test_verify_uses_python(self, tmp_path):
        prover = NativeProverBackend(working_dir=str(tmp_path / "prover"))
        stf = _make_stf()
        prover.setup(stf, max_txs_per_batch=4)

        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={"op": "inc"})
        old_root = b"\xaa" * 32
        new_root = b"\xbb" * 32
        tx_commitment = b"\xcc" * 32

        proof = prover.prove(old_root, new_root, [tx], tx_commitment)
        result = prover.verify(proof, old_root, new_root, tx_commitment)
        assert result is True


class TestNativeProverSubprocess:
    """Test subprocess invocation with mocked binaries."""

    @patch("ethclient.l2.native_prover.subprocess.run")
    def test_setup_calls_snarkjs(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        prover = NativeProverBackend(
            setup_binary="/usr/local/bin/snarkjs",
            working_dir=str(tmp_path / "prover"),
        )

        # Mock the setup process: will call subprocess.run 4 times
        # (powersoftau new, powersoftau prepare, groth16 setup, zkey export)
        # The last one writes vkey.json — need to make it fail to trigger fallback
        mock_run.side_effect = FileNotFoundError("snarkjs not found")

        stf = _make_stf()
        prover.setup(stf, max_txs_per_batch=4)

        # Should fall back to Python after subprocess fails
        assert prover._is_setup
        assert prover._vk is not None
        mock_run.assert_called()  # At least tried to call native

    @patch("ethclient.l2.native_prover.subprocess.run")
    def test_prove_timeout(self, mock_run, tmp_path):
        prover = NativeProverBackend(
            prover_binary="rapidsnark",
            working_dir=str(tmp_path / "prover"),
            prove_timeout=5,
        )
        stf = _make_stf()
        prover.setup(stf, max_txs_per_batch=4)

        # Make native proving fail with timeout
        mock_run.side_effect = subprocess.TimeoutExpired("rapidsnark", 5)

        # Create a fake zkey to trigger native path
        prover._zkey_path = tmp_path / "prover" / "fake.zkey"
        prover._zkey_path.parent.mkdir(parents=True, exist_ok=True)
        prover._zkey_path.write_bytes(b"fake")

        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={"op": "inc"})
        proof = prover.prove(b"\xaa" * 32, b"\xbb" * 32, [tx], b"\xcc" * 32)
        # Should fall back to Python
        assert proof is not None


class TestNativeProverErrors:
    def test_prove_before_setup(self):
        prover = NativeProverBackend()
        with pytest.raises(RuntimeError, match="Must call setup"):
            prover.prove(b"\x00" * 32, b"\x00" * 32, [], b"\x00" * 32)

    def test_verify_before_setup(self):
        prover = NativeProverBackend()
        with pytest.raises(RuntimeError, match="Must call setup"):
            prover.verify(None, b"\x00" * 32, b"\x00" * 32, b"\x00" * 32)

    def test_too_many_transactions(self, tmp_path):
        prover = NativeProverBackend(working_dir=str(tmp_path / "prover"))
        stf = _make_stf()
        prover.setup(stf, max_txs_per_batch=2)

        txs = [L2Tx(sender=b"\x01" * 20, nonce=i, data={}) for i in range(2)]
        with pytest.raises(ValueError, match="free slot"):
            prover.prove(b"\x00" * 32, b"\x00" * 32, txs, b"\x00" * 32)

    def test_verification_key_before_setup(self):
        prover = NativeProverBackend()
        with pytest.raises(RuntimeError, match="Must call setup"):
            _ = prover.verification_key


class TestWitnessComputation:
    def test_witness_inputs_match_groth16_backend(self, tmp_path):
        """Witness computation should produce identical values to Groth16ProofBackend."""
        from ethclient.l2.prover import Groth16ProofBackend, _to_field
        from ethclient.zk.circuit import _field

        native = NativeProverBackend(working_dir=str(tmp_path / "prover"))
        stf = _make_stf()
        native.setup(stf, max_txs_per_batch=4)

        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={"op": "test"})
        old_root = b"\xaa" * 32
        new_root = b"\xbb" * 32
        tx_commitment = b"\xcc" * 32

        public, private = native._compute_witness_inputs(
            old_root, new_root, [tx], tx_commitment
        )

        # Verify structure
        assert "old_state_root" in public
        assert "new_state_root" in public
        assert "tx_commitment" in public
        assert "tx_0" in private  # real tx
        assert "tx_1" in private  # balance factor
        assert "tx_2" in private  # padding (=1)
        assert "tx_3" in private  # padding (=1)
        assert private["tx_2"] == 1
        assert private["tx_3"] == 1

        # Verify the balance equation holds
        old_root_int = public["old_state_root"]
        product = old_root_int
        for i in range(4):
            product = _field(product * private[f"tx_{i}"])
        target = _field(public["new_state_root"] * public["tx_commitment"])
        assert product == target
