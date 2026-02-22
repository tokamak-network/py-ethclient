"""ZK RPC API — Groth16 verification services via JSON-RPC.

Methods:
- zk_verifyGroth16(vkey, proof, public_inputs) -> {valid, gas_estimate}
- zk_deployVerifier(vkey) -> {address, bytecode_hex}
- zk_verifyOnChain(vkey, proof, public_inputs) -> {valid, gas_used}
"""

from __future__ import annotations

import logging
from typing import Optional

from ethclient.rpc.server import RPCServer, RPCError

logger = logging.getLogger(__name__)


def _hex_to_int(s: str) -> int:
    """Parse hex string or decimal string to int."""
    if s.startswith("0x"):
        return int(s, 16)
    return int(s)


def _parse_g1(data: dict) -> tuple[int, int]:
    """Parse G1 point from RPC: {"x": "0x...", "y": "0x..."}."""
    return _hex_to_int(data["x"]), _hex_to_int(data["y"])


def _parse_g2(data: dict) -> tuple[int, int, int, int]:
    """Parse G2 point from RPC: {"x_real": ..., "x_imag": ..., "y_real": ..., "y_imag": ...}."""
    return (
        _hex_to_int(data["x_real"]),
        _hex_to_int(data["x_imag"]),
        _hex_to_int(data["y_real"]),
        _hex_to_int(data["y_imag"]),
    )


def register_zk_api(rpc: RPCServer) -> None:
    """Register all zk_ namespace methods on the RPC server."""

    @rpc.method("zk_verifyGroth16")
    def verify_groth16(vkey: dict, proof: dict, public_inputs: list) -> dict:
        """Verify a Groth16 proof natively.

        Args:
            vkey: Verification key (snarkjs format or native format)
            proof: Proof (snarkjs format or native format)
            public_inputs: List of public inputs (hex or decimal strings)

        Returns:
            {"valid": bool, "gas_estimate": int}
        """
        try:
            from ethclient.zk.types import G1Point, G2Point, Proof, VerificationKey
            from ethclient.zk import groth16
            from ethclient.zk.evm_verifier import EVMVerifier

            # Parse inputs — support both snarkjs and native format
            if "vk_alpha_1" in vkey:
                # snarkjs format
                from ethclient.zk.snarkjs_compat import parse_snarkjs_vkey, parse_snarkjs_proof
                vk = parse_snarkjs_vkey(vkey)
                pf = parse_snarkjs_proof(proof)
                pub = [int(x) for x in public_inputs]
            else:
                # Native format
                vk = _parse_vkey_native(vkey)
                pf = _parse_proof_native(proof)
                pub = [_hex_to_int(str(x)) for x in public_inputs]

            valid = groth16.verify(vk, pf, pub)

            # Estimate gas via EVM
            gas_estimate = 0
            try:
                verifier = EVMVerifier(vk)
                result = verifier.verify_on_evm(pf, pub)
                gas_estimate = result.gas_used
            except Exception:
                pass

            return {"valid": valid, "gas_estimate": gas_estimate}

        except Exception as e:
            raise RPCError(-32000, f"zk_verifyGroth16 failed: {e}")

    @rpc.method("zk_deployVerifier")
    def deploy_verifier(vkey: dict) -> dict:
        """Generate verifier bytecode for a verification key.

        Args:
            vkey: Verification key (snarkjs or native format)

        Returns:
            {"address": "0x...", "bytecode_hex": "0x..."}
        """
        try:
            from ethclient.zk.evm_verifier import EVMVerifier, VERIFIER_ADDR

            if "vk_alpha_1" in vkey:
                from ethclient.zk.snarkjs_compat import parse_snarkjs_vkey
                vk = parse_snarkjs_vkey(vkey)
            else:
                vk = _parse_vkey_native(vkey)

            verifier = EVMVerifier(vk)
            bytecode = verifier.bytecode

            return {
                "address": "0x" + VERIFIER_ADDR.hex(),
                "bytecode_hex": "0x" + bytecode.hex(),
            }

        except Exception as e:
            raise RPCError(-32000, f"zk_deployVerifier failed: {e}")

    @rpc.method("zk_verifyOnChain")
    def verify_on_chain(vkey: dict, proof: dict, public_inputs: list) -> dict:
        """Verify a proof on the EVM (simulated on-chain execution).

        Args:
            vkey: Verification key
            proof: Proof
            public_inputs: List of public inputs

        Returns:
            {"valid": bool, "gas_used": int}
        """
        try:
            from ethclient.zk.evm_verifier import EVMVerifier

            if "vk_alpha_1" in vkey:
                from ethclient.zk.snarkjs_compat import parse_snarkjs_vkey, parse_snarkjs_proof
                vk = parse_snarkjs_vkey(vkey)
                pf = parse_snarkjs_proof(proof)
                pub = [int(x) for x in public_inputs]
            else:
                vk = _parse_vkey_native(vkey)
                pf = _parse_proof_native(proof)
                pub = [_hex_to_int(str(x)) for x in public_inputs]

            verifier = EVMVerifier(vk)
            result = verifier.verify_on_evm(pf, pub)

            return {
                "valid": result.success,
                "gas_used": result.gas_used,
            }

        except Exception as e:
            raise RPCError(-32000, f"zk_verifyOnChain failed: {e}")


def _parse_vkey_native(data: dict) -> "VerificationKey":
    """Parse a native-format verification key from RPC."""
    from ethclient.zk.types import G1Point, G2Point, VerificationKey

    alpha = G1Point(*_parse_g1(data["alpha"]))
    beta = G2Point(*_parse_g2(data["beta"]))
    gamma = G2Point(*_parse_g2(data["gamma"]))
    delta = G2Point(*_parse_g2(data["delta"]))
    ic = [G1Point(*_parse_g1(p)) for p in data["ic"]]

    return VerificationKey(alpha=alpha, beta=beta, gamma=gamma, delta=delta, ic=ic)


def _parse_proof_native(data: dict) -> "Proof":
    """Parse a native-format proof from RPC."""
    from ethclient.zk.types import G1Point, G2Point, Proof

    a = G1Point(*_parse_g1(data["a"]))
    b = G2Point(*_parse_g2(data["b"]))
    c = G1Point(*_parse_g1(data["c"]))

    return Proof(a=a, b=b, c=c)
