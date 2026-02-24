"""Tests for EVM-based Groth16 verification."""

import pytest

from ethclient.zk.circuit import Circuit
from ethclient.zk import groth16
from ethclient.zk.evm_verifier import EVMVerifier
from ethclient.zk.types import EVMResult, GasProfile


def _setup_simple():
    """Create circuit, keys, and proof for x * y = z."""
    c = Circuit()
    x = c.private("x")
    y = c.private("y")
    z = c.public("z")
    c.constrain(x * y, z)

    pk, vk = groth16.setup(c)
    proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15}, circuit=c)
    return vk, proof


class TestEVMVerifierBytecode:
    """Test bytecode generation."""

    def test_bytecode_generated(self):
        vk, _ = _setup_simple()
        verifier = EVMVerifier(vk)
        code = verifier.bytecode
        assert isinstance(code, bytes)
        assert len(code) > 0

    def test_bytecode_cached(self):
        vk, _ = _setup_simple()
        verifier = EVMVerifier(vk)
        code1 = verifier.bytecode
        code2 = verifier.bytecode
        assert code1 is code2  # same object (cached)


class TestEVMVerifierCalldata:
    """Test calldata encoding."""

    def test_calldata_length_one_public(self):
        vk, proof = _setup_simple()
        verifier = EVMVerifier(vk)
        calldata = verifier.encode_calldata(proof, [15])
        # 64 (A) + 128 (B) + 64 (C) + 32 (1 input) = 288
        assert len(calldata) == 288

    def test_calldata_length_two_publics(self):
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z1 = c.public("z1")
        z2 = c.public("z2")
        c.constrain(x * y, z1)
        c.constrain(x * x, z2)

        pk, vk = groth16.setup(c)
        proof = groth16.prove(
            pk, private={"x": 3, "y": 5}, public={"z1": 15, "z2": 9}, circuit=c
        )

        verifier = EVMVerifier(vk)
        calldata = verifier.encode_calldata(proof, [15, 9])
        # 64 + 128 + 64 + 64 = 320
        assert len(calldata) == 320


class TestEVMVerification:
    """Test full EVM verification."""

    def test_valid_proof_passes(self):
        vk, proof = _setup_simple()
        verifier = EVMVerifier(vk)
        result = verifier.verify_on_evm(proof, [15])

        assert isinstance(result, EVMResult)
        assert result.success is True
        assert result.gas_used > 0

    def test_wrong_input_fails(self):
        vk, proof = _setup_simple()
        verifier = EVMVerifier(vk)
        result = verifier.verify_on_evm(proof, [16])

        assert result.success is False

    def test_native_and_evm_agree(self):
        """Native verify and EVM verify should give the same result."""
        vk, proof = _setup_simple()

        native_result = groth16.verify(vk, proof, [15])
        evm_result = EVMVerifier(vk).verify_on_evm(proof, [15])

        assert native_result == evm_result.success

    def test_native_and_evm_agree_on_failure(self):
        vk, proof = _setup_simple()

        native_result = groth16.verify(vk, proof, [16])
        evm_result = EVMVerifier(vk).verify_on_evm(proof, [16])

        assert native_result == evm_result.success


class TestGasProfile:
    """Test gas profiling."""

    def test_gas_profile_has_pairing(self):
        vk, proof = _setup_simple()
        verifier = EVMVerifier(vk)
        profile = verifier.gas_profile(proof, [15])

        assert isinstance(profile, GasProfile)
        # Should have exactly 1 pairing call
        assert profile.ecpairing_calls == 1
        # Pairing with 4 pairs: 45000 + 34000*4 = 181000
        assert profile.ecpairing_gas == 181000

    def test_gas_profile_ecmul_calls(self):
        """For 1 public input, expect 1 ecMul call."""
        vk, proof = _setup_simple()
        verifier = EVMVerifier(vk)
        profile = verifier.gas_profile(proof, [15])

        assert profile.ecmul_calls == 1
        assert profile.ecmul_gas == 6000

    def test_gas_profile_ecadd_calls(self):
        """For 1 public input, expect 1 ecAdd call."""
        vk, proof = _setup_simple()
        verifier = EVMVerifier(vk)
        profile = verifier.gas_profile(proof, [15])

        assert profile.ecadd_calls == 1
        assert profile.ecadd_gas == 150


class TestEVMTrace:
    """Test EVM execution tracing."""

    def test_trace_has_precompile_calls(self):
        vk, proof = _setup_simple()
        verifier = EVMVerifier(vk)
        trace = verifier.trace_on_evm(proof, [15])

        # Should have ecMul, ecAdd, ecPairing calls
        targets = [s.target for s in trace if s.target]
        assert "0x07" in targets  # ecMul
        assert "0x06" in targets  # ecAdd
        assert "0x08" in targets  # ecPairing

    def test_trace_gas_costs(self):
        vk, proof = _setup_simple()
        verifier = EVMVerifier(vk)
        trace = verifier.trace_on_evm(proof, [15])

        for step in trace:
            assert step.gas_cost >= 0
