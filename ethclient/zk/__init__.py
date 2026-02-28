"""ZK proof toolkit — Groth16 over BN128 with EVM verification."""

from ethclient.zk.circuit import Circuit, R1CS, Signal
from ethclient.zk import groth16
from ethclient.zk.poseidon_circuit import poseidon_circuit
from ethclient.zk.types import (
    DebugResult,
    EVMResult,
    G1Point,
    G2Point,
    GasProfile,
    Proof,
    ProvingKey,
    TraceStep,
    VerificationKey,
)

__all__ = [
    "Circuit",
    "R1CS",
    "Signal",
    "groth16",
    "poseidon_circuit",
    "G1Point",
    "G2Point",
    "Proof",
    "ProvingKey",
    "VerificationKey",
    "DebugResult",
    "EVMResult",
    "TraceStep",
    "GasProfile",
]
