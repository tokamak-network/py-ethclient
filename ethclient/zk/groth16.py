"""Groth16 proving system over BN128.

Pure Python implementation using py_ecc for curve operations.
Suitable for education, prototyping, and small circuits (< 1000 constraints).

Usage:
    from ethclient.zk import Circuit, groth16

    c = Circuit()
    x, y = c.private("x"), c.private("y")
    z = c.public("z")
    c.constrain(x * y, z)

    pk, vk = groth16.setup(c)
    proof = groth16.prove(pk, private={"x": 3, "y": 5}, public={"z": 15})
    assert groth16.verify(vk, proof, [15])
"""

from __future__ import annotations

import secrets
from typing import Union

from py_ecc.bn128 import (
    G1,
    G2,
    Z1,
    Z2,
    FQ12,
    add,
    curve_order,
    multiply,
    neg,
    pairing,
)

from ethclient.zk.circuit import Circuit, R1CS, _dot, _field, _field_inv
from ethclient.zk.types import (
    DebugResult,
    G1Point,
    G2Point,
    Proof,
    ProvingKey,
    VerificationKey,
)

FIELD_MODULUS = curve_order


# ── Helpers ──────────────────────────────────────────────────────────


def _rand_scalar() -> int:
    """Generate a random non-zero scalar in the BN128 field."""
    while True:
        r = secrets.randbelow(FIELD_MODULUS)
        if r != 0:
            return r


def _g1_mul(point, scalar: int):
    """Multiply a G1 point by a scalar."""
    scalar = scalar % FIELD_MODULUS
    if scalar == 0:
        return Z1
    if point is None or point == Z1:
        return Z1
    return multiply(point, scalar)


def _g2_mul(point, scalar: int):
    """Multiply a G2 point by a scalar."""
    scalar = scalar % FIELD_MODULUS
    if scalar == 0:
        return Z2
    if point is None or point == Z2:
        return Z2
    return multiply(point, scalar)


def _g1_add(p1, p2):
    """Add two G1 points."""
    return add(p1, p2)


def _g2_add(p1, p2):
    """Add two G2 points."""
    return add(p1, p2)


def _g1_neg(point):
    """Negate a G1 point."""
    if point is None or point == Z1:
        return Z1
    return neg(point)


def _g1_lc(points: list, scalars: list[int]):
    """G1 multi-scalar multiplication (linear combination)."""
    result = Z1
    for p, s in zip(points, scalars):
        result = _g1_add(result, _g1_mul(p, s))
    return result


def _g2_lc(points: list, scalars: list[int]):
    """G2 multi-scalar multiplication."""
    result = Z2
    for p, s in zip(points, scalars):
        result = _g2_add(result, _g2_mul(p, s))
    return result


# ── QAP (Quadratic Arithmetic Program) ──────────────────────────────


def _r1cs_to_qap(r1cs: R1CS) -> tuple[list[list[int]], list[list[int]], list[list[int]], list[int]]:
    """Convert R1CS to QAP via Lagrange interpolation over the field.

    Returns (u, v, w, domain) where:
    - u[j], v[j], w[j] are polynomial evaluations for variable j
    - domain contains the evaluation points (roots of unity or arbitrary)

    For m constraints, we use evaluation points 1, 2, ..., m.
    The polynomials are defined by their values at these points.
    """
    m = r1cs.num_constraints
    n = r1cs.num_variables

    # Use evaluation points 1..m
    domain = list(range(1, m + 1))

    # u[j][i] = A[i][j], v[j][i] = B[i][j], w[j][i] = C[i][j]
    u = [[0] * m for _ in range(n)]
    v = [[0] * m for _ in range(n)]
    w = [[0] * m for _ in range(n)]

    for i in range(m):
        for j, coeff in r1cs.A[i].items():
            u[j][i] = coeff
        for j, coeff in r1cs.B[i].items():
            v[j][i] = coeff
        for j, coeff in r1cs.C[i].items():
            w[j][i] = coeff

    return u, v, w, domain


def _lagrange_basis(domain: list[int], i: int, x: int) -> int:
    """Evaluate the i-th Lagrange basis polynomial at x."""
    result = 1
    for j, xj in enumerate(domain):
        if j != i:
            result = _field(result * _field((x - xj) * _field_inv(_field(domain[i] - xj))))
    return result


def _eval_poly_at(evals: list[int], domain: list[int], x: int) -> int:
    """Evaluate a polynomial given by its values at domain points, at point x."""
    result = 0
    for i, val in enumerate(evals):
        if val == 0:
            continue
        result = _field(result + _field(val * _lagrange_basis(domain, i, x)))
    return result


def _vanishing_poly_at(domain: list[int], x: int) -> int:
    """Evaluate the vanishing polynomial t(x) = prod(x - d) for d in domain."""
    result = 1
    for d in domain:
        result = _field(result * _field(x - d))
    return result


def _compute_h_evals(
    r1cs: R1CS,
    witness: list[int],
    u: list[list[int]],
    v: list[list[int]],
    w: list[list[int]],
    domain: list[int],
    tau: int,
) -> int:
    """Compute h(tau) where h(x) = (A(x)*B(x) - C(x)) / t(x).

    Instead of polynomial division, evaluate A(tau)*B(tau) - C(tau) and divide
    by t(tau) in the field.
    """
    n = r1cs.num_variables

    # A(tau) = sum_j witness[j] * u_j(tau)
    a_tau = 0
    for j in range(n):
        uj_tau = _eval_poly_at(u[j], domain, tau)
        a_tau = _field(a_tau + _field(witness[j] * uj_tau))

    b_tau = 0
    for j in range(n):
        vj_tau = _eval_poly_at(v[j], domain, tau)
        b_tau = _field(b_tau + _field(witness[j] * vj_tau))

    c_tau = 0
    for j in range(n):
        wj_tau = _eval_poly_at(w[j], domain, tau)
        c_tau = _field(c_tau + _field(witness[j] * wj_tau))

    # h(tau) = (A(tau)*B(tau) - C(tau)) / t(tau)
    numerator = _field(a_tau * b_tau - c_tau)
    t_tau = _vanishing_poly_at(domain, tau)

    if t_tau == 0:
        raise ValueError("tau is in the evaluation domain — toxic waste collision")

    return _field(numerator * _field_inv(t_tau))


# ── Setup ────────────────────────────────────────────────────────────


def setup(circuit: Circuit) -> tuple[ProvingKey, VerificationKey]:
    """Groth16 trusted setup.

    Generates proving and verification keys from the circuit's R1CS.
    The toxic waste (tau, alpha, beta, gamma, delta) is generated randomly
    and discarded after setup.
    """
    r1cs = circuit.to_r1cs()
    m = r1cs.num_constraints
    n = r1cs.num_variables
    num_public = r1cs.num_public  # includes constant "1"

    # QAP
    u, v, w, domain = _r1cs_to_qap(r1cs)

    # Toxic waste
    tau = _rand_scalar()
    alpha = _rand_scalar()
    beta = _rand_scalar()
    gamma = _rand_scalar()
    delta = _rand_scalar()

    gamma_inv = _field_inv(gamma)
    delta_inv = _field_inv(delta)

    # Vanishing polynomial at tau
    t_tau = _vanishing_poly_at(domain, tau)

    # ── Verification key ──
    alpha_g1 = _g1_mul(G1, alpha)
    beta_g2 = _g2_mul(G2, beta)
    gamma_g2 = _g2_mul(G2, gamma)
    delta_g2 = _g2_mul(G2, delta)

    # IC points: for each public variable j (indices 0..num_public-1)
    # IC[j] = (beta * u_j(tau) + alpha * v_j(tau) + w_j(tau)) / gamma * G1
    ic = []
    for j in range(num_public):
        uj_tau = _eval_poly_at(u[j], domain, tau)
        vj_tau = _eval_poly_at(v[j], domain, tau)
        wj_tau = _eval_poly_at(w[j], domain, tau)

        val = _field(beta * uj_tau + alpha * vj_tau + wj_tau)
        val = _field(val * gamma_inv)
        ic.append(_g1_mul(G1, val))

    vk = VerificationKey(
        alpha=G1Point.from_py_ecc(alpha_g1),
        beta=G2Point.from_py_ecc(beta_g2),
        gamma=G2Point.from_py_ecc(gamma_g2),
        delta=G2Point.from_py_ecc(delta_g2),
        ic=[G1Point.from_py_ecc(p) for p in ic],
    )

    # ── Proving key ──

    # A query: for each variable j, a_j = u_j(tau) * G1
    a_query = []
    for j in range(n):
        uj_tau = _eval_poly_at(u[j], domain, tau)
        a_query.append(_g1_mul(G1, uj_tau))

    # B query in G1 and G2: b_j = v_j(tau) * G1/G2
    b_g1_query = []
    b_g2_query = []
    for j in range(n):
        vj_tau = _eval_poly_at(v[j], domain, tau)
        b_g1_query.append(_g1_mul(G1, vj_tau))
        b_g2_query.append(_g2_mul(G2, vj_tau))

    # C query: for each PRIVATE variable j (indices num_public..n-1)
    # c_j = (beta * u_j(tau) + alpha * v_j(tau) + w_j(tau)) / delta * G1
    c_query = []
    for j in range(num_public, n):
        uj_tau = _eval_poly_at(u[j], domain, tau)
        vj_tau = _eval_poly_at(v[j], domain, tau)
        wj_tau = _eval_poly_at(w[j], domain, tau)

        val = _field(beta * uj_tau + alpha * vj_tau + wj_tau)
        val = _field(val * delta_inv)
        c_query.append(_g1_mul(G1, val))

    # H query: h_i = tau^i * t(tau) / delta * G1 for i = 0..m-1
    h_query = []
    for i in range(m):
        val = _field(pow(tau, i, FIELD_MODULUS) * t_tau % FIELD_MODULUS)
        val = _field(val * delta_inv)
        h_query.append(_g1_mul(G1, val))

    pk = ProvingKey(
        alpha=G1Point.from_py_ecc(alpha_g1),
        beta_g1=G1Point.from_py_ecc(_g1_mul(G1, beta)),
        beta_g2=G2Point.from_py_ecc(beta_g2),
        delta_g1=G1Point.from_py_ecc(_g1_mul(G1, delta)),
        delta_g2=G2Point.from_py_ecc(delta_g2),
        a_query=a_query,
        b_g1_query=b_g1_query,
        b_g2_query=b_g2_query,
        c_query=c_query,
        h_query=h_query,
        ic=ic,
        num_variables=n,
        num_public=num_public,
        num_constraints=m,
    )

    return pk, vk


# ── Prove ────────────────────────────────────────────────────────────


def prove(
    pk: ProvingKey,
    private: dict[str, int],
    public: dict[str, int],
    circuit: Circuit | None = None,
) -> Proof:
    """Generate a Groth16 proof.

    Args:
        pk: Proving key from setup()
        private: Private input assignments {name: value}
        public: Public input assignments {name: value}
        circuit: The circuit (needed to compute witness). If None, uses the
                circuit from which pk was generated (must call setup() first).
    """
    if circuit is None:
        raise ValueError("Circuit required — pass the circuit used in setup()")

    witness = circuit.compute_witness(private=private, public=public)
    r1cs = circuit.to_r1cs()

    # Verify witness satisfies R1CS
    if not r1cs.check_witness(witness):
        raise ValueError("Witness does not satisfy R1CS constraints")

    n = pk.num_variables
    num_public = pk.num_public
    m = pk.num_constraints

    # Randomness for zero-knowledge
    r = _rand_scalar()
    s = _rand_scalar()

    # ── Compute A = alpha + sum(w_j * a_j) + r * delta  (in G1) ──
    proof_a = pk.a_query[0]  # will be replaced
    proof_a = _g1_mul(G1, 0)  # start from identity
    # Add alpha
    proof_a = _g1_add(proof_a, pk.alpha.to_py_ecc())
    # Add sum(w_j * a_query_j)
    for j in range(n):
        if witness[j] != 0:
            proof_a = _g1_add(proof_a, _g1_mul(pk.a_query[j], witness[j]))
    # Add r * delta
    proof_a = _g1_add(proof_a, _g1_mul(pk.delta_g1.to_py_ecc(), r))

    # ── Compute B = beta + sum(w_j * b_j) + s * delta  (in G2) ──
    proof_b = _g2_mul(G2, 0)
    proof_b = _g2_add(proof_b, pk.beta_g2.to_py_ecc())
    for j in range(n):
        if witness[j] != 0:
            proof_b = _g2_add(proof_b, _g2_mul(pk.b_g2_query[j], witness[j]))
    proof_b = _g2_add(proof_b, _g2_mul(pk.delta_g2.to_py_ecc(), s))

    # ── Compute B in G1 (needed for C) ──
    proof_b_g1 = _g1_mul(G1, 0)
    proof_b_g1 = _g1_add(proof_b_g1, pk.beta_g1.to_py_ecc())
    for j in range(n):
        if witness[j] != 0:
            proof_b_g1 = _g1_add(proof_b_g1, _g1_mul(pk.b_g1_query[j], witness[j]))
    proof_b_g1 = _g1_add(proof_b_g1, _g1_mul(pk.delta_g1.to_py_ecc(), s))

    # ── Compute h(x) = (A(x)*B(x) - C(x)) / t(x) ──
    u, v, w_poly, domain = _r1cs_to_qap(r1cs)
    h_coeffs = _compute_h_coefficients(r1cs, witness, u, v, w_poly, domain)

    h_commitment = Z1
    for i, coeff in enumerate(h_coeffs):
        if coeff != 0 and i < len(pk.h_query):
            h_commitment = _g1_add(h_commitment, _g1_mul(pk.h_query[i], coeff))

    # ── Compute C ──
    # C = sum(w_j * c_query_j) for private vars + h_commitment + s*A + r*B_g1 - r*s*delta
    proof_c = Z1

    # Private variable contributions
    for j_offset in range(n - num_public):
        j = j_offset + num_public
        if witness[j] != 0:
            proof_c = _g1_add(proof_c, _g1_mul(pk.c_query[j_offset], witness[j]))

    # H polynomial commitment
    proof_c = _g1_add(proof_c, h_commitment)

    # s * A
    proof_c = _g1_add(proof_c, _g1_mul(proof_a, s))

    # r * B_g1
    proof_c = _g1_add(proof_c, _g1_mul(proof_b_g1, r))

    # - r * s * delta
    rs_delta = _g1_mul(pk.delta_g1.to_py_ecc(), _field(r * s))
    proof_c = _g1_add(proof_c, _g1_neg(rs_delta))

    return Proof(
        a=G1Point.from_py_ecc(proof_a),
        b=G2Point.from_py_ecc(proof_b),
        c=G1Point.from_py_ecc(proof_c),
    )


def _compute_h_coefficients(
    r1cs: R1CS,
    witness: list[int],
    u: list[list[int]],
    v: list[list[int]],
    w: list[list[int]],
    domain: list[int],
) -> list[int]:
    """Compute the coefficients of h(x) = (A(x)*B(x) - C(x)) / t(x).

    Uses polynomial arithmetic in coefficient form:
    1. Interpolate A(x), B(x), C(x) from evaluations
    2. Compute A(x)*B(x) - C(x)
    3. Divide by t(x)
    """
    m = r1cs.num_constraints
    n = r1cs.num_variables

    # Compute A(x), B(x), C(x) evaluations at domain points
    a_evals = [0] * m
    b_evals = [0] * m
    c_evals = [0] * m

    for i in range(m):
        for j in range(n):
            if witness[j] == 0:
                continue
            if u[j][i] != 0:
                a_evals[i] = _field(a_evals[i] + witness[j] * u[j][i])
            if v[j][i] != 0:
                b_evals[i] = _field(b_evals[i] + witness[j] * v[j][i])
            if w[j][i] != 0:
                c_evals[i] = _field(c_evals[i] + witness[j] * w[j][i])

    # Interpolate to coefficient form
    a_poly = _interpolate(domain, a_evals)
    b_poly = _interpolate(domain, b_evals)
    c_poly = _interpolate(domain, c_evals)

    # Multiply A*B
    ab_poly = _poly_mul(a_poly, b_poly)

    # Subtract C
    ab_c = _poly_sub(ab_poly, c_poly)

    # Compute vanishing polynomial t(x) = (x-1)(x-2)...(x-m)
    t_poly = [1]
    for d in domain:
        t_poly = _poly_mul(t_poly, [_field(-d), 1])

    # Divide: h = (A*B - C) / t
    h, remainder = _poly_div(ab_c, t_poly)

    # Verify remainder is zero (sanity check)
    for r in remainder:
        if r % FIELD_MODULUS != 0:
            raise ValueError("Non-zero remainder in QAP division — witness is invalid")

    return h


def _interpolate(domain: list[int], values: list[int]) -> list[int]:
    """Lagrange interpolation: returns polynomial coefficients [a0, a1, ..., a_{n-1}]."""
    n = len(domain)
    # Start with zero polynomial
    result = [0] * n

    for i in range(n):
        if values[i] == 0:
            continue

        # Compute the i-th Lagrange basis polynomial
        basis = [1]
        for j in range(n):
            if j == i:
                continue
            # Multiply by (x - domain[j]) / (domain[i] - domain[j])
            denom = _field_inv(_field(domain[i] - domain[j]))
            # (x - domain[j]) * denom = denom * x + (-domain[j] * denom)
            term = [_field(-domain[j] * denom), _field(denom)]
            basis = _poly_mul(basis, term)

        # Scale by values[i]
        for k in range(len(basis)):
            if k < n:
                result[k] = _field(result[k] + values[i] * basis[k])

    return result


def _poly_mul(a: list[int], b: list[int]) -> list[int]:
    """Multiply two polynomials in coefficient form."""
    if not a or not b:
        return []
    result = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj == 0:
                continue
            result[i + j] = _field(result[i + j] + ai * bj)
    return result


def _poly_sub(a: list[int], b: list[int]) -> list[int]:
    """Subtract polynomial b from a."""
    n = max(len(a), len(b))
    result = [0] * n
    for i in range(len(a)):
        result[i] = a[i]
    for i in range(len(b)):
        result[i] = _field(result[i] - b[i])
    return result


def _poly_div(num: list[int], den: list[int]) -> tuple[list[int], list[int]]:
    """Polynomial long division. Returns (quotient, remainder)."""
    # Remove trailing zeros
    while num and num[-1] % FIELD_MODULUS == 0:
        num = num[:-1]
    while den and den[-1] % FIELD_MODULUS == 0:
        den = den[:-1]

    if not den:
        raise ValueError("Division by zero polynomial")

    if len(num) < len(den):
        return [], list(num)

    # Copy numerator
    rem = [_field(x) for x in num]
    deg_diff = len(num) - len(den)
    quotient = [0] * (deg_diff + 1)
    den_lead_inv = _field_inv(_field(den[-1]))

    for i in range(deg_diff, -1, -1):
        if len(rem) < len(den) + i:
            continue
        coeff = _field(rem[len(den) - 1 + i] * den_lead_inv)
        quotient[i] = coeff
        if coeff == 0:
            continue
        for j in range(len(den)):
            rem[i + j] = _field(rem[i + j] - coeff * den[j])

    # Trim remainder
    while rem and rem[-1] % FIELD_MODULUS == 0:
        rem = rem[:-1]

    return quotient, rem


# ── Verify ───────────────────────────────────────────────────────────


def verify(
    vk: VerificationKey,
    proof: Proof,
    public_inputs: Union[list[int], dict[str, int]],
) -> bool:
    """Verify a Groth16 proof.

    Pairing equation:
        e(A, B) == e(alpha, beta) * e(IC_acc, gamma) * e(C, delta)

    Where IC_acc = IC[0] + sum(input[i] * IC[i+1])
    """
    if isinstance(public_inputs, dict):
        public_inputs = list(public_inputs.values())

    if len(public_inputs) != vk.num_public_inputs:
        raise ValueError(
            f"Expected {vk.num_public_inputs} public inputs, got {len(public_inputs)}"
        )

    # Compute IC accumulator
    ic_acc = vk.ic[0].to_py_ecc()
    for i, inp in enumerate(public_inputs):
        ic_acc = _g1_add(ic_acc, _g1_mul(vk.ic[i + 1].to_py_ecc(), _field(inp)))

    # Convert proof points
    proof_a = proof.a.to_py_ecc()
    proof_b = proof.b.to_py_ecc()
    proof_c = proof.c.to_py_ecc()

    alpha_g1 = vk.alpha.to_py_ecc()
    beta_g2 = vk.beta.to_py_ecc()
    gamma_g2 = vk.gamma.to_py_ecc()
    delta_g2 = vk.delta.to_py_ecc()

    # Pairing check: e(-A, B) * e(alpha, beta) * e(IC_acc, gamma) * e(C, delta) == 1
    neg_a = _g1_neg(proof_a)

    # Compute product of pairings
    # p1 = e(-A, B)
    p1 = pairing(proof_b, neg_a) if (neg_a is not None and neg_a != Z1 and proof_b is not None and proof_b != Z2) else FQ12.one()
    # p2 = e(alpha, beta)
    p2 = pairing(beta_g2, alpha_g1)
    # p3 = e(IC_acc, gamma)
    p3 = pairing(gamma_g2, ic_acc) if (ic_acc is not None and ic_acc != Z1) else FQ12.one()
    # p4 = e(C, delta)
    p4 = pairing(delta_g2, proof_c) if (proof_c is not None and proof_c != Z1) else FQ12.one()

    result = p1 * p2 * p3 * p4
    return result == FQ12.one()


def debug_verify(
    vk: VerificationKey,
    proof: Proof,
    public_inputs: Union[list[int], dict[str, int]],
) -> DebugResult:
    """Verify a proof with detailed debug output."""
    if isinstance(public_inputs, dict):
        public_inputs = list(public_inputs.values())

    if len(public_inputs) != vk.num_public_inputs:
        raise ValueError(
            f"Expected {vk.num_public_inputs} public inputs, got {len(public_inputs)}"
        )

    ic_acc = vk.ic[0].to_py_ecc()
    for i, inp in enumerate(public_inputs):
        ic_acc = _g1_add(ic_acc, _g1_mul(vk.ic[i + 1].to_py_ecc(), _field(inp)))

    proof_a = proof.a.to_py_ecc()
    proof_b = proof.b.to_py_ecc()
    proof_c = proof.c.to_py_ecc()

    alpha_g1 = vk.alpha.to_py_ecc()
    beta_g2 = vk.beta.to_py_ecc()
    gamma_g2 = vk.gamma.to_py_ecc()
    delta_g2 = vk.delta.to_py_ecc()

    # Individual pairings for debugging
    e_ab = pairing(proof_b, proof_a)
    e_alpha_beta = pairing(beta_g2, alpha_g1)
    e_ic_gamma = pairing(gamma_g2, ic_acc) if (ic_acc is not None and ic_acc != Z1) else FQ12.one()
    e_c_delta = pairing(delta_g2, proof_c) if (proof_c is not None and proof_c != Z1) else FQ12.one()

    # Check: e(A,B) == e(alpha,beta) * e(IC_acc, gamma) * e(C, delta)
    expected = e_alpha_beta * e_ic_gamma * e_c_delta
    valid = e_ab == expected

    return DebugResult(
        valid=valid,
        pairing_result=e_ab,
        e_ab=e_ab,
        e_alpha_beta=e_alpha_beta,
        e_ic_gamma=e_ic_gamma,
        e_c_delta=e_c_delta,
    )
