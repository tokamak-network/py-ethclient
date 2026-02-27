"""Poseidon circuit — R1CS encoding of Poseidon hash over BN128.

Encodes the Poseidon permutation as R1CS constraints using the Circuit/Signal API.
Total constraints: 4*9 + 57*3 + 4*9 = 243 (for t=3, RF=8, RP=57).
"""

from __future__ import annotations

from ethclient.common.hash import (
    _MDS_MATRIX,
    _ROUND_CONSTANTS,
    _RF,
    _RP,
    _T,
    _CAP,
    _RATE,
)
from ethclient.zk.circuit import Circuit, Signal


def _sbox_circuit(c: Circuit, x: Signal) -> Signal:
    """S-box: x^5 using 3 R1CS constraints.

    x2 = x * x       (1 constraint)
    x4 = x2 * x2     (1 constraint)
    x5 = x4 * x      (1 constraint)
    """
    x2 = x * x
    x4 = x2 * x2
    x5 = x4 * x
    return x5


def _mds_circuit(state: list[Signal], mds: list[list[int]]) -> list[Signal]:
    """MDS matrix multiplication — pure linear, 0 constraints."""
    t = len(state)
    result: list[Signal] = []
    for i in range(t):
        acc = state[0] * mds[i][0]
        for j in range(1, t):
            acc = acc + state[j] * mds[i][j]
        result.append(acc)
    return result


def _add_rc_circuit(state: list[Signal], constants: list[int]) -> list[Signal]:
    """Add round constants — pure linear, 0 constraints."""
    return [state[i] + constants[i] for i in range(len(state))]


def _poseidon_permutation_circuit(c: Circuit, state: list[Signal]) -> list[Signal]:
    """Poseidon permutation as R1CS.

    4 full rounds (4 * 3 * 3 = 36 constraints) +
    57 partial rounds (57 * 1 * 3 = 171 constraints) +
    4 full rounds (4 * 3 * 3 = 36 constraints) = 243 constraints.
    """
    rc_offset = 0

    # First RF/2 = 4 full rounds
    for _ in range(_RF // 2):
        state = _add_rc_circuit(state, _ROUND_CONSTANTS[rc_offset:rc_offset + _T])
        rc_offset += _T
        state = [_sbox_circuit(c, s) for s in state]
        state = _mds_circuit(state, _MDS_MATRIX)

    # RP = 57 partial rounds
    for _ in range(_RP):
        state = _add_rc_circuit(state, _ROUND_CONSTANTS[rc_offset:rc_offset + _T])
        rc_offset += _T
        state[0] = _sbox_circuit(c, state[0])
        state = _mds_circuit(state, _MDS_MATRIX)

    # Last RF/2 = 4 full rounds
    for _ in range(_RF // 2):
        state = _add_rc_circuit(state, _ROUND_CONSTANTS[rc_offset:rc_offset + _T])
        rc_offset += _T
        state = [_sbox_circuit(c, s) for s in state]
        state = _mds_circuit(state, _MDS_MATRIX)

    return state


def poseidon_circuit(c: Circuit, inputs: list[Signal]) -> Signal:
    """Build Poseidon hash circuit for Signal inputs.

    Uses sponge construction matching `poseidon()` in common/hash.py.
    Returns the output signal (first rate element after squeeze).
    """
    # Initialize state: [capacity=0, rate elements=0]
    state = [c._constant(0)] * _T

    # Absorb phase
    for i in range(0, len(inputs), _RATE):
        chunk = inputs[i:i + _RATE]
        for j, val in enumerate(chunk):
            state[j + _CAP] = state[j + _CAP] + val
        state = _poseidon_permutation_circuit(c, state)

    return state[_CAP]
