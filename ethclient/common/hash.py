"""Poseidon hash — ZK-friendly sponge hash over BN128 scalar field.

Parameters: t=3, rate=2, capacity=1, alpha=5, RF=8, RP=57
~243 R1CS constraints vs ~150,000 for keccak256.

Reference: https://eprint.iacr.org/2019/458
"""

from __future__ import annotations

import hashlib

from py_ecc.bn128 import curve_order

# BN128 scalar field
POSEIDON_FIELD = curve_order

# Poseidon parameters (t=3)
_T = 3          # state width
_RATE = 2       # rate (absorb 2 elements per permutation)
_CAP = 1        # capacity
_ALPHA = 5      # S-box exponent
_RF = 8         # full rounds
_RP = 57        # partial rounds


def _generate_round_constants(t: int, rf: int, rp: int, field: int) -> list[int]:
    """Generate round constants via SHA256 counter mode (Grain LFSR-like).

    Produces (rf + rp) * t constants deterministically.
    """
    num_constants = (rf + rp) * t
    constants: list[int] = []
    counter = 0
    while len(constants) < num_constants:
        h = hashlib.sha256(f"poseidon_rc_{t}_{rf}_{rp}_{counter}".encode()).digest()
        val = int.from_bytes(h, "big") % field
        constants.append(val)
        counter += 1
    return constants


def _generate_mds_matrix(t: int, field: int) -> list[list[int]]:
    """Generate t x t MDS (Cauchy) matrix.

    M[i][j] = 1 / (x_i + y_j) where x_i = i, y_j = t + j (all distinct mod p).
    """
    xs = list(range(t))
    ys = list(range(t, 2 * t))
    matrix: list[list[int]] = []
    for i in range(t):
        row: list[int] = []
        for j in range(t):
            val = pow((xs[i] + ys[j]) % field, field - 2, field)
            row.append(val)
        matrix.append(row)
    return matrix


# Module-level constants (computed once at import time)
_ROUND_CONSTANTS = _generate_round_constants(_T, _RF, _RP, POSEIDON_FIELD)
_MDS_MATRIX = _generate_mds_matrix(_T, POSEIDON_FIELD)


def _poseidon_permutation(state: list[int]) -> list[int]:
    """Apply Poseidon permutation: 4 full + 57 partial + 4 full rounds."""
    assert len(state) == _T
    F = POSEIDON_FIELD
    state = [s % F for s in state]
    rc_offset = 0

    # First RF/2 = 4 full rounds
    for _ in range(_RF // 2):
        # AddRoundConstants
        for i in range(_T):
            state[i] = (state[i] + _ROUND_CONSTANTS[rc_offset + i]) % F
        rc_offset += _T
        # S-box on ALL elements (full round)
        state = [pow(s, _ALPHA, F) for s in state]
        # MDS mix
        state = _mds_multiply(state, F)

    # RP = 57 partial rounds
    for _ in range(_RP):
        # AddRoundConstants
        for i in range(_T):
            state[i] = (state[i] + _ROUND_CONSTANTS[rc_offset + i]) % F
        rc_offset += _T
        # S-box on first element only (partial round)
        state[0] = pow(state[0], _ALPHA, F)
        # MDS mix
        state = _mds_multiply(state, F)

    # Last RF/2 = 4 full rounds
    for _ in range(_RF // 2):
        # AddRoundConstants
        for i in range(_T):
            state[i] = (state[i] + _ROUND_CONSTANTS[rc_offset + i]) % F
        rc_offset += _T
        # S-box on ALL elements (full round)
        state = [pow(s, _ALPHA, F) for s in state]
        # MDS mix
        state = _mds_multiply(state, F)

    return state


def _mds_multiply(state: list[int], field: int) -> list[int]:
    """Matrix-vector multiply with MDS matrix."""
    result = [0] * _T
    for i in range(_T):
        for j in range(_T):
            result[i] = (result[i] + _MDS_MATRIX[i][j] * state[j]) % field
    return result


def poseidon(inputs: list[int]) -> int:
    """Poseidon hash for field element inputs.

    Uses sponge construction: absorb `rate` elements at a time, squeeze one output.
    """
    if not inputs:
        inputs = [0]

    F = POSEIDON_FIELD
    # Validate inputs
    for i, v in enumerate(inputs):
        if not (0 <= v < F):
            raise ValueError(f"Input {i} = {v} not in field [0, {F})")

    # Sponge: state = [capacity || rate]
    state = [0] * _T  # state[0] = capacity, state[1..] = rate

    # Absorb phase
    for i in range(0, len(inputs), _RATE):
        chunk = inputs[i:i + _RATE]
        for j, val in enumerate(chunk):
            state[j + _CAP] = (state[j + _CAP] + val) % F
        state = _poseidon_permutation(state)

    # Squeeze: return first rate element
    return state[_CAP]


def poseidon_bytes(data: bytes) -> bytes:
    """Poseidon hash for arbitrary bytes.

    Splits data into 31-byte chunks (each fits in BN128 field), hashes via sponge,
    returns 32-byte big-endian output.
    """
    # Split into 31-byte chunks (max safe size for BN128 scalar field)
    chunk_size = 31
    elements: list[int] = []
    for i in range(0, max(1, len(data)), chunk_size):
        chunk = data[i:i + chunk_size]
        elements.append(int.from_bytes(chunk, "big"))

    result = poseidon(elements)
    return result.to_bytes(32, "big")
