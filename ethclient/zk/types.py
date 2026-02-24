"""ZK proof types for Groth16 over BN128."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from py_ecc.bn128 import FQ, FQ2, FQ12, curve_order

# BN128 curve order (scalar field)
FIELD_MODULUS = curve_order


@dataclass
class G1Point:
    """A point on the BN128 G1 curve (over FQ)."""

    x: int
    y: int

    @classmethod
    def infinity(cls) -> G1Point:
        return cls(0, 0)

    @property
    def is_infinity(self) -> bool:
        return self.x == 0 and self.y == 0

    def to_py_ecc(self):
        """Convert to py_ecc tuple format."""
        if self.is_infinity:
            return None  # py_ecc uses None for Z1
        return (FQ(self.x), FQ(self.y))

    @classmethod
    def from_py_ecc(cls, point) -> G1Point:
        """Convert from py_ecc tuple format."""
        if point is None:
            return cls.infinity()
        return cls(int(point[0]), int(point[1]))

    def to_evm_bytes(self) -> bytes:
        """Encode as 64 bytes for EVM precompile input."""
        return self.x.to_bytes(32, "big") + self.y.to_bytes(32, "big")


@dataclass
class G2Point:
    """A point on the BN128 G2 curve (over FQ2)."""

    x_real: int
    x_imag: int
    y_real: int
    y_imag: int

    @classmethod
    def infinity(cls) -> G2Point:
        return cls(0, 0, 0, 0)

    @property
    def is_infinity(self) -> bool:
        return self.x_real == 0 and self.x_imag == 0 and self.y_real == 0 and self.y_imag == 0

    def to_py_ecc(self):
        """Convert to py_ecc tuple format."""
        if self.is_infinity:
            return None  # py_ecc uses None for Z2
        return (FQ2([self.x_real, self.x_imag]), FQ2([self.y_real, self.y_imag]))

    @classmethod
    def from_py_ecc(cls, point) -> G2Point:
        """Convert from py_ecc tuple format."""
        if point is None:
            return cls.infinity()
        x_real = int(point[0].coeffs[0])
        x_imag = int(point[0].coeffs[1])
        y_real = int(point[1].coeffs[0])
        y_imag = int(point[1].coeffs[1])
        return cls(x_real, x_imag, y_real, y_imag)

    def to_evm_bytes(self) -> bytes:
        """Encode as 128 bytes for EVM precompile input (Ethereum format)."""
        return (
            self.x_imag.to_bytes(32, "big")
            + self.x_real.to_bytes(32, "big")
            + self.y_imag.to_bytes(32, "big")
            + self.y_real.to_bytes(32, "big")
        )


@dataclass
class Proof:
    """Groth16 proof: three curve points."""

    a: G1Point  # pi_a in G1
    b: G2Point  # pi_b in G2
    c: G1Point  # pi_c in G1


@dataclass
class VerificationKey:
    """Groth16 verification key."""

    alpha: G1Point  # alpha in G1
    beta: G2Point  # beta in G2
    gamma: G2Point  # gamma in G2
    delta: G2Point  # delta in G2
    ic: list[G1Point] = field(default_factory=list)  # IC[0..num_public]

    @property
    def num_public_inputs(self) -> int:
        return len(self.ic) - 1


@dataclass
class ProvingKey:
    """Groth16 proving key for proof generation."""

    alpha: G1Point
    beta_g1: G1Point  # beta in G1 (for proving)
    beta_g2: G2Point  # beta in G2
    delta_g1: G1Point  # delta in G1
    delta_g2: G2Point  # delta in G2

    # Per-variable points (indexed by witness variable)
    a_query: list  # [G1] query points for A
    b_g1_query: list  # [G1] query points for B in G1
    b_g2_query: list  # [G2] query points for B in G2
    c_query: list  # [G1] query points for C (private vars only)
    h_query: list  # [G1] query points for H polynomial

    # IC points (public input commitments)
    ic: list  # [G1] — same as vk.ic

    # R1CS metadata
    num_variables: int = 0
    num_public: int = 0  # includes constant "1"
    num_constraints: int = 0


@dataclass
class DebugResult:
    """Detailed verification result for debugging."""

    valid: bool
    pairing_result: Optional[FQ12] = None
    e_ab: Optional[FQ12] = None
    e_alpha_beta: Optional[FQ12] = None
    e_ic_gamma: Optional[FQ12] = None
    e_c_delta: Optional[FQ12] = None


@dataclass
class EVMResult:
    """Result of EVM-based verification."""

    success: bool
    gas_used: int = 0
    return_data: bytes = b""


@dataclass
class TraceStep:
    """A single step in an EVM execution trace."""

    pc: int = 0
    opcode: str = ""
    gas_cost: int = 0
    gas_remaining: int = 0
    stack_top: Optional[int] = None
    target: str = ""  # for CALL-like ops: precompile address
    input_size: int = 0


@dataclass
class GasProfile:
    """Gas breakdown for EVM verification."""

    total_gas: int = 0
    ecadd_gas: int = 0
    ecadd_calls: int = 0
    ecmul_gas: int = 0
    ecmul_calls: int = 0
    ecpairing_gas: int = 0
    ecpairing_calls: int = 0
    other_gas: int = 0
