"""EVM Verifier Generator — Groth16 on-chain verification via precompiles.

Generates minimal EVM bytecode that performs Groth16 verification using:
- ecAdd (0x06): G1 point addition
- ecMul (0x07): G1 scalar multiplication
- ecPairing (0x08): Pairing check

Usage:
    from ethclient.zk.evm_verifier import EVMVerifier
    verifier = EVMVerifier(vk)
    result = verifier.verify_on_evm(proof, [15])
"""

from __future__ import annotations

from ethclient.vm.call_frame import CallFrame
from ethclient.vm.evm import ExecutionEnvironment, run_bytecode
from ethclient.zk.types import (
    EVMResult,
    GasProfile,
    Proof,
    TraceStep,
    VerificationKey,
)

# Precompile addresses
ECADD_ADDR = b"\x00" * 19 + b"\x06"
ECMUL_ADDR = b"\x00" * 19 + b"\x07"
ECPAIRING_ADDR = b"\x00" * 19 + b"\x08"

# Contract address for the verifier
VERIFIER_ADDR = b"\x00" * 12 + b"\xde\xad\xbe\xef\xca\xfe\x00\x00\x00\x01"

# EVM opcodes
_SUB = 0x03
_CALLDATALOAD = 0x35
_CALLDATACOPY = 0x37
_POP = 0x50
_MLOAD = 0x51
_MSTORE = 0x52
_PUSH0 = 0x5F
_PUSH1 = 0x60
_PUSH20 = 0x73
_PUSH32 = 0x7F
_STATICCALL = 0xFA
_RETURN = 0xF3


def _push(value: int) -> bytes:
    """Generate a PUSH instruction with automatic width."""
    if value == 0:
        return bytes([_PUSH0])
    n = max(1, (value.bit_length() + 7) // 8)
    return bytes([_PUSH1 + n - 1]) + value.to_bytes(n, "big")


def _push32(value: int) -> bytes:
    """Generate a PUSH32 instruction."""
    return bytes([_PUSH32]) + value.to_bytes(32, "big")


def _push_addr(addr: bytes) -> bytes:
    """Generate PUSH20 for an address."""
    return bytes([_PUSH20]) + addr


class EVMVerifier:
    """Generates and executes a Groth16 verifier contract on the EVM."""

    def __init__(self, vk: VerificationKey):
        self.vk = vk
        self._bytecode: bytes | None = None

    @property
    def bytecode(self) -> bytes:
        """Get or generate the verifier bytecode."""
        if self._bytecode is None:
            self._bytecode = self._generate_bytecode()
        return self._bytecode

    def _generate_bytecode(self) -> bytes:
        """Generate EVM bytecode for Groth16 verification.

        Calldata layout:
            [0:64]    proof.A   (G1: x, y)
            [64:192]  proof.B   (G2: x_imag, x_real, y_imag, y_real)
            [192:256] proof.C   (G1: x, y)
            [256:]    public inputs (each 32 bytes)

        Algorithm:
            1. Compute IC accumulator: acc = IC[0] + sum(input[i] * IC[i+1])
            2. Build pairing input: (-A, B, alpha, beta, acc, gamma, C, delta)
            3. Call ecPairing precompile
            4. Return result
        """
        vk = self.vk
        num_pub = vk.num_public_inputs
        code = bytearray()

        # ── Compute IC accumulator at memory 0x00..0x3F ──
        code += _mstore_const(0x00, vk.ic[0].x)
        code += _mstore_const(0x20, vk.ic[0].y)

        for i in range(num_pub):
            input_offset = 256 + i * 32

            # IC[i+1] at 0x40..0x5F
            code += _mstore_const(0x40, vk.ic[i + 1].x)
            code += _mstore_const(0x60, vk.ic[i + 1].y)

            # public input at 0x80
            code += _calldataload_to_mem(0x80, input_offset)

            # ecMul(IC[i+1], input[i]) → 0x40
            code += _staticcall_precompile(ECMUL_ADDR, 0x40, 96, 0x40, 64, gas_limit=10_000)
            code += bytes([_POP])  # drop success

            # ecAdd(acc, result) → 0x00
            code += _staticcall_precompile(ECADD_ADDR, 0x00, 128, 0x00, 64, gas_limit=1_000)
            code += bytes([_POP])

        # ── Build pairing input at 0x100 (4 pairs, 768 bytes) ──
        base = 0x100

        # Pair 1: (-A, B)
        code += _calldataload_to_mem(base, 0)              # A.x
        code += _negate_g1_y(base + 0x20, 32)              # -A.y
        code += _calldatacopy_to_mem(base + 0x40, 64, 128) # B

        # Pair 2: (alpha, beta)
        p2 = base + 192
        code += _mstore_const(p2, vk.alpha.x)
        code += _mstore_const(p2 + 0x20, vk.alpha.y)
        code += _mstore_const(p2 + 0x40, vk.beta.x_imag)
        code += _mstore_const(p2 + 0x60, vk.beta.x_real)
        code += _mstore_const(p2 + 0x80, vk.beta.y_imag)
        code += _mstore_const(p2 + 0xA0, vk.beta.y_real)

        # Pair 3: (IC_acc, gamma)
        p3 = base + 384
        code += _mcopy(p3, 0x00, 64)  # copy IC accumulator
        code += _mstore_const(p3 + 0x40, vk.gamma.x_imag)
        code += _mstore_const(p3 + 0x60, vk.gamma.x_real)
        code += _mstore_const(p3 + 0x80, vk.gamma.y_imag)
        code += _mstore_const(p3 + 0xA0, vk.gamma.y_real)

        # Pair 4: (C, delta)
        p4 = base + 576
        code += _calldatacopy_to_mem(p4, 192, 64)  # C from calldata
        code += _mstore_const(p4 + 0x40, vk.delta.x_imag)
        code += _mstore_const(p4 + 0x60, vk.delta.x_real)
        code += _mstore_const(p4 + 0x80, vk.delta.y_imag)
        code += _mstore_const(p4 + 0xA0, vk.delta.y_real)

        # ── ecPairing → 0x00 ──
        pairing_gas = 45_000 + 34_000 * 4 + 10_000  # 4 pairs + margin
        code += _staticcall_precompile(ECPAIRING_ADDR, base, 768, 0x00, 32, gas_limit=pairing_gas)
        code += bytes([_POP])

        # ── RETURN 32 bytes from 0x00 ──
        code += _push(32)
        code += _push(0)
        code += bytes([_RETURN])

        return bytes(code)

    def encode_calldata(self, proof: Proof, public_inputs: list[int]) -> bytes:
        """Encode proof and public inputs as calldata for the verifier."""
        data = bytearray()
        data += proof.a.x.to_bytes(32, "big")
        data += proof.a.y.to_bytes(32, "big")
        data += proof.b.to_evm_bytes()
        data += proof.c.x.to_bytes(32, "big")
        data += proof.c.y.to_bytes(32, "big")
        for inp in public_inputs:
            data += inp.to_bytes(32, "big")
        return bytes(data)

    def verify_on_evm(self, proof: Proof, public_inputs: list[int]) -> EVMResult:
        """Run Groth16 verification on the in-memory EVM."""
        calldata = self.encode_calldata(proof, public_inputs)

        env = ExecutionEnvironment()
        env.gas_limit = 30_000_000
        env.set_code(VERIFIER_ADDR, self.bytecode)

        frame = CallFrame(
            caller=b"\x00" * 20,
            address=VERIFIER_ADDR,
            code_address=VERIFIER_ADDR,
            origin=b"\x00" * 20,
            code=self.bytecode,
            gas=10_000_000,
            calldata=calldata,
            depth=0,
        )

        success, return_data = run_bytecode(frame, env)

        evm_success = False
        if success and len(return_data) >= 32:
            result_val = int.from_bytes(return_data[:32], "big")
            evm_success = result_val == 1

        return EVMResult(
            success=evm_success,
            gas_used=frame.gas_used,
            return_data=return_data,
        )

    def trace_on_evm(self, proof: Proof, public_inputs: list[int]) -> list[TraceStep]:
        """Run verification and compute trace from precompile gas costs.

        Note: EVM hooks don't fire for precompile calls (they bypass run_bytecode).
        We compute the trace analytically from the verification key structure.
        """
        num_pub = self.vk.num_public_inputs
        trace: list[TraceStep] = []

        # For each public input: 1 ecMul + 1 ecAdd
        for _ in range(num_pub):
            trace.append(TraceStep(opcode="STATICCALL", target="0x07", gas_cost=6000))
            trace.append(TraceStep(opcode="STATICCALL", target="0x06", gas_cost=150))

        # 1 ecPairing with 4 pairs
        trace.append(TraceStep(
            opcode="STATICCALL", target="0x08",
            gas_cost=45000 + 34000 * 4,
        ))

        return trace

    def gas_profile(self, proof: Proof, public_inputs: list[int]) -> GasProfile:
        """Get gas breakdown for verification."""
        trace = self.trace_on_evm(proof, public_inputs)

        profile = GasProfile()
        for step in trace:
            if step.target == "0x06":
                profile.ecadd_gas += step.gas_cost
                profile.ecadd_calls += 1
            elif step.target == "0x07":
                profile.ecmul_gas += step.gas_cost
                profile.ecmul_calls += 1
            elif step.target == "0x08":
                profile.ecpairing_gas += step.gas_cost
                profile.ecpairing_calls += 1

        profile.total_gas = sum(s.gas_cost for s in trace)
        profile.other_gas = profile.total_gas - profile.ecadd_gas - profile.ecmul_gas - profile.ecpairing_gas
        return profile


# ── Bytecode generation helpers ──────────────────────────────────────

BN128_FIELD_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583


def _mstore_const(offset: int, value: int) -> bytes:
    """MSTORE a 256-bit constant at the given memory offset."""
    code = bytearray()
    code += _push32(value)
    code += _push(offset)
    code += bytes([_MSTORE])
    return bytes(code)


def _calldataload_to_mem(mem_offset: int, cd_offset: int) -> bytes:
    """Load 32 bytes from calldata to memory."""
    code = bytearray()
    code += _push(cd_offset)
    code += bytes([_CALLDATALOAD])
    code += _push(mem_offset)
    code += bytes([_MSTORE])
    return bytes(code)


def _calldatacopy_to_mem(mem_offset: int, cd_offset: int, size: int) -> bytes:
    """Copy bytes from calldata to memory."""
    code = bytearray()
    code += _push(size)
    code += _push(cd_offset)
    code += _push(mem_offset)
    code += bytes([_CALLDATACOPY])
    return bytes(code)


def _mcopy(dest: int, src: int, size: int) -> bytes:
    """Copy memory from src to dest (using MLOAD/MSTORE pairs)."""
    code = bytearray()
    for i in range(0, size, 32):
        code += _push(src + i)
        code += bytes([_MLOAD])
        code += _push(dest + i)
        code += bytes([_MSTORE])
    return bytes(code)


def _negate_g1_y(mem_offset: int, cd_offset: int) -> bytes:
    """Load G1.y from calldata and store (field_modulus - y) at mem_offset."""
    code = bytearray()
    code += _push(cd_offset)
    code += bytes([_CALLDATALOAD])
    code += _push32(BN128_FIELD_MODULUS)
    code += bytes([_SUB])  # field_modulus - y
    code += _push(mem_offset)
    code += bytes([_MSTORE])
    return bytes(code)


def _staticcall_precompile(
    addr: bytes, mem_in: int, in_size: int, mem_out: int, out_size: int,
    gas_limit: int = 200_000,
) -> bytes:
    """Generate STATICCALL to a precompile with an explicit gas limit.

    Uses a tight gas limit to avoid the 63/64 rule consuming most of the
    caller's gas. The gas_limit should be slightly above the precompile's cost.
    """
    code = bytearray()
    code += _push(out_size)
    code += _push(mem_out)
    code += _push(in_size)
    code += _push(mem_in)
    code += _push_addr(addr)
    code += _push(gas_limit)
    code += bytes([_STATICCALL])
    return bytes(code)
