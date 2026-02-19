"""
EVM precompiled contracts (addresses 0x01 - 0x0a).

Each precompile takes input bytes and returns (gas_cost, output_bytes).
Returns None on failure.
"""

from __future__ import annotations

import os
from typing import Optional

from py_ecc.bn128 import (
    FQ, FQ2, add, multiply, is_on_curve,
    curve_order, field_modulus, Z1, Z2, b, b2,
)

from ethclient.common.crypto import sha256, ripemd160


# ---------------------------------------------------------------------------
# BN128 helpers
# ---------------------------------------------------------------------------

# Sentinel for decode errors (since Z1/Z2 are None in py_ecc)
_INVALID = object()


def _decode_g1_point(data: bytes):
    """Decode 64 bytes into a py_ecc G1 point. Returns _INVALID on error."""
    x = int.from_bytes(data[0:32], "big")
    y = int.from_bytes(data[32:64], "big")
    if x == 0 and y == 0:
        return None  # point at infinity (Z1)
    if x >= field_modulus or y >= field_modulus:
        return _INVALID
    p = (FQ(x), FQ(y))
    if not is_on_curve(p, b):
        return _INVALID
    return p


def _encode_g1_point(p) -> bytes:
    """Encode a py_ecc G1 point to 64 bytes."""
    if p is None:  # Z1 = None
        return b"\x00" * 64
    return int(p[0]).to_bytes(32, "big") + int(p[1]).to_bytes(32, "big")


def _decode_g2_point(data: bytes):
    """Decode 128 bytes into a py_ecc G2 point. Returns _INVALID on error."""
    # Ethereum encoding: x_imag(32) + x_real(32) + y_imag(32) + y_real(32)
    x_imag = int.from_bytes(data[0:32], "big")
    x_real = int.from_bytes(data[32:64], "big")
    y_imag = int.from_bytes(data[64:96], "big")
    y_real = int.from_bytes(data[96:128], "big")
    if x_imag == 0 and x_real == 0 and y_imag == 0 and y_real == 0:
        return None  # point at infinity (Z2)
    if x_imag >= field_modulus or x_real >= field_modulus:
        return _INVALID
    if y_imag >= field_modulus or y_real >= field_modulus:
        return _INVALID
    p = (FQ2([x_real, x_imag]), FQ2([y_real, y_imag]))
    if not is_on_curve(p, b2):
        return _INVALID
    return p


# ---------------------------------------------------------------------------
# KZG trusted setup (lazy-loaded)
# ---------------------------------------------------------------------------

_kzg_trusted_setup = None

# EIP-7883: reject oversized MODEXP lengths.
MODEXP_MAX_INPUT_FIELD_BYTES = 1024


def _get_kzg_trusted_setup():
    """Load KZG trusted setup on first use."""
    global _kzg_trusted_setup
    if _kzg_trusted_setup is None:
        import ckzg
        setup_path = os.path.join(os.path.dirname(__file__), "trusted_setup.txt")
        _kzg_trusted_setup = ckzg.load_trusted_setup(setup_path, 0)
    return _kzg_trusted_setup


# ---------------------------------------------------------------------------
# 0x01: ecRecover
# ---------------------------------------------------------------------------

def precompile_ecrecover(data: bytes) -> Optional[tuple[int, bytes]]:
    """Recover public key from ECDSA signature."""
    GAS = 3000
    data = data.ljust(128, b"\x00")
    msg_hash = data[0:32]
    v = int.from_bytes(data[32:64], "big")
    r = int.from_bytes(data[64:96], "big")
    s = int.from_bytes(data[96:128], "big")

    if v not in (27, 28):
        return GAS, b""
    if r == 0 or s == 0:
        return GAS, b""

    try:
        from ethclient.common.crypto import ecdsa_recover, pubkey_to_address
        recovery_id = v - 27
        pubkey = ecdsa_recover(msg_hash, recovery_id, r, s)
        addr = pubkey_to_address(pubkey)
        return GAS, addr.rjust(32, b"\x00")
    except Exception:
        return GAS, b""


# ---------------------------------------------------------------------------
# 0x02: SHA256
# ---------------------------------------------------------------------------

def precompile_sha256(data: bytes) -> Optional[tuple[int, bytes]]:
    word_count = (len(data) + 31) // 32
    gas = 60 + 12 * word_count
    return gas, sha256(data)


# ---------------------------------------------------------------------------
# 0x03: RIPEMD160
# ---------------------------------------------------------------------------

def precompile_ripemd160(data: bytes) -> Optional[tuple[int, bytes]]:
    word_count = (len(data) + 31) // 32
    gas = 600 + 120 * word_count
    result = ripemd160(data)
    return gas, result.rjust(32, b"\x00")


# ---------------------------------------------------------------------------
# 0x04: Identity (data copy)
# ---------------------------------------------------------------------------

def precompile_identity(data: bytes) -> Optional[tuple[int, bytes]]:
    word_count = (len(data) + 31) // 32
    gas = 15 + 3 * word_count
    return gas, data


# ---------------------------------------------------------------------------
# 0x05: ModExp (EIP-198)
# ---------------------------------------------------------------------------

def precompile_modexp(data: bytes) -> Optional[tuple[int, bytes]]:
    data = data.ljust(96, b"\x00")
    b_size = int.from_bytes(data[0:32], "big")
    e_size = int.from_bytes(data[32:64], "big")
    m_size = int.from_bytes(data[64:96], "big")

    if (
        b_size > MODEXP_MAX_INPUT_FIELD_BYTES
        or e_size > MODEXP_MAX_INPUT_FIELD_BYTES
        or m_size > MODEXP_MAX_INPUT_FIELD_BYTES
    ):
        return None

    rest = data[96:]
    rest = rest.ljust(b_size + e_size + m_size, b"\x00")

    base = int.from_bytes(rest[:b_size], "big") if b_size > 0 else 0
    exp = int.from_bytes(rest[b_size:b_size + e_size], "big") if e_size > 0 else 0
    mod = int.from_bytes(rest[b_size + e_size:b_size + e_size + m_size], "big") if m_size > 0 else 0

    # Gas calculation (EIP-2565)
    def _mult_complexity(length: int) -> int:
        words = max((length + 7) // 8, 1)
        return words * words

    def _iteration_count() -> int:
        if e_size <= 32:
            if exp == 0:
                return 0
            return exp.bit_length() - 1
        else:
            # First 32 bytes of exponent
            first_32 = int.from_bytes(rest[b_size:b_size + min(32, e_size)], "big")
            if first_32 == 0:
                return 8 * (e_size - 32)
            return (first_32.bit_length() - 1) + 8 * (e_size - 32)

    max_len = max(b_size, m_size)
    complexity = _mult_complexity(max_len)
    iters = max(_iteration_count(), 1)
    gas = max(200, (complexity * iters) // 3)

    if mod == 0:
        result = b"\x00" * m_size
    else:
        result_int = pow(base, exp, mod)
        result = result_int.to_bytes(m_size, "big") if m_size > 0 else b""

    return gas, result


# ---------------------------------------------------------------------------
# 0x0100: P256VERIFY (Fusaka / EIP-7951)
# ---------------------------------------------------------------------------

def precompile_p256verify(data: bytes) -> Optional[tuple[int, bytes]]:
    """Verify ECDSA P-256 signature.

    Input layout (160 bytes):
      msg(32) || r(32) || s(32) || pubkey_x(32) || pubkey_y(32)
    Output:
      32-byte boolean word (1 for valid, 0 for invalid)
    """
    GAS = 3450
    if len(data) != 160:
        return None

    msg = data[0:32]
    r = int.from_bytes(data[32:64], "big")
    s = int.from_bytes(data[64:96], "big")
    qx = int.from_bytes(data[96:128], "big")
    qy = int.from_bytes(data[128:160], "big")

    # Reject zero/invalid signature scalars early.
    if r == 0 or s == 0:
        return GAS, b"\x00" * 32

    try:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import DSS
        from Crypto.Hash import SHA256
    except Exception:
        return None

    try:
        public_key = ECC.construct(curve="P-256", point_x=qx, point_y=qy)
        verifier = DSS.new(public_key, "fips-186-3")
        digest = SHA256.new(msg)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        verifier.verify(digest, signature)
        return GAS, (1).to_bytes(32, "big")
    except Exception:
        return GAS, b"\x00" * 32


# ---------------------------------------------------------------------------
# 0x06: ecAdd (BN256/alt_bn128)
# ---------------------------------------------------------------------------

def precompile_ecadd(data: bytes) -> Optional[tuple[int, bytes]]:
    GAS = 150  # EIP-1108
    data = data.ljust(128, b"\x00")
    p1 = _decode_g1_point(data[0:64])
    if p1 is _INVALID:
        return None
    p2 = _decode_g1_point(data[64:128])
    if p2 is _INVALID:
        return None
    result = add(p1, p2)
    return GAS, _encode_g1_point(result)


# ---------------------------------------------------------------------------
# 0x07: ecMul (BN256/alt_bn128)
# ---------------------------------------------------------------------------

def precompile_ecmul(data: bytes) -> Optional[tuple[int, bytes]]:
    GAS = 6000  # EIP-1108
    data = data.ljust(96, b"\x00")
    p = _decode_g1_point(data[0:64])
    if p is _INVALID:
        return None
    scalar = int.from_bytes(data[64:96], "big")
    result = multiply(p, scalar % curve_order)
    return GAS, _encode_g1_point(result)


# ---------------------------------------------------------------------------
# 0x08: ecPairing (BN256/alt_bn128)
# ---------------------------------------------------------------------------

def precompile_ecpairing(data: bytes) -> Optional[tuple[int, bytes]]:
    if len(data) % 192 != 0:
        return None
    k = len(data) // 192
    gas = 45000 + 34000 * k  # EIP-1108

    pairs = []
    for i in range(k):
        chunk = data[i * 192:(i + 1) * 192]
        g1 = _decode_g1_point(chunk[0:64])
        if g1 is _INVALID:
            return None
        g2 = _decode_g2_point(chunk[64:192])
        if g2 is _INVALID:
            return None
        pairs.append((g1, g2))

    # Empty input → pairing check trivially passes
    if k == 0:
        return gas, b"\x00" * 31 + b"\x01"

    # Compute product of pairings: ∏ e(G1_i, G2_i) == 1
    from py_ecc.bn128 import FQ12, pairing as bn128_pairing
    result = FQ12.one()
    for g1, g2 in pairs:
        if g1 == Z1 or g2 == Z2:
            continue  # e(O, Q) = e(P, O) = 1
        result = result * bn128_pairing(g2, g1)

    success = result == FQ12.one()
    return gas, b"\x00" * 31 + (b"\x01" if success else b"\x00")


# ---------------------------------------------------------------------------
# 0x09: BLAKE2f (EIP-152)
# ---------------------------------------------------------------------------

def precompile_blake2f(data: bytes) -> Optional[tuple[int, bytes]]:
    if len(data) != 213:
        return None

    rounds = int.from_bytes(data[0:4], "big")
    gas = rounds

    # Final flag
    f = data[212]
    if f not in (0, 1):
        return None

    # Full BLAKE2b F compression function
    h = [int.from_bytes(data[4 + i * 8:4 + (i + 1) * 8], "little") for i in range(8)]
    m = [int.from_bytes(data[68 + i * 8:68 + (i + 1) * 8], "little") for i in range(16)]
    t = [
        int.from_bytes(data[196:204], "little"),
        int.from_bytes(data[204:212], "little"),
    ]

    MASK64 = 0xFFFFFFFFFFFFFFFF
    IV = [
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    ]
    SIGMA = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    v = list(h) + list(IV)
    v[12] ^= t[0]
    v[13] ^= t[1]
    if f:
        v[14] ^= MASK64

    def rotr64(x, n):
        return ((x >> n) | (x << (64 - n))) & MASK64

    def G(a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & MASK64
        v[d] = rotr64(v[d] ^ v[a], 32)
        v[c] = (v[c] + v[d]) & MASK64
        v[b] = rotr64(v[b] ^ v[c], 24)
        v[a] = (v[a] + v[b] + y) & MASK64
        v[d] = rotr64(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & MASK64
        v[b] = rotr64(v[b] ^ v[c], 63)

    for i in range(rounds):
        s = SIGMA[i % 10]
        G(0, 4, 8, 12, m[s[0]], m[s[1]])
        G(1, 5, 9, 13, m[s[2]], m[s[3]])
        G(2, 6, 10, 14, m[s[4]], m[s[5]])
        G(3, 7, 11, 15, m[s[6]], m[s[7]])
        G(0, 5, 10, 15, m[s[8]], m[s[9]])
        G(1, 6, 11, 12, m[s[10]], m[s[11]])
        G(2, 7, 8, 13, m[s[12]], m[s[13]])
        G(3, 4, 9, 14, m[s[14]], m[s[15]])

    result = b""
    for i in range(8):
        result += ((h[i] ^ v[i] ^ v[i + 8]) & MASK64).to_bytes(8, "little")

    return gas, result


# ---------------------------------------------------------------------------
# 0x0a: KZG point evaluation (EIP-4844)
# ---------------------------------------------------------------------------

# BLS modulus (used in return value)
_BLS_MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

def precompile_kzg_point_eval(data: bytes) -> Optional[tuple[int, bytes]]:
    GAS = 50000
    if len(data) != 192:
        return None

    versioned_hash = data[0:32]
    z = data[32:64]
    y = data[64:96]
    commitment = data[96:144]   # 48 bytes
    proof = data[144:192]       # 48 bytes

    # Verify versioned_hash == 0x01 || SHA256(commitment)[1:]
    import hashlib
    commitment_hash = hashlib.sha256(commitment).digest()
    expected_hash = b"\x01" + commitment_hash[1:]
    if versioned_hash != expected_hash:
        return None

    # Verify KZG proof
    import ckzg
    try:
        ts = _get_kzg_trusted_setup()
        ok = ckzg.verify_kzg_proof(commitment, z, y, proof, ts)
    except Exception:
        return None

    if not ok:
        return None

    # Return FIELD_ELEMENTS_PER_BLOB (4096) and BLS_MODULUS as two 32-byte values
    return GAS, (4096).to_bytes(32, "big") + _BLS_MODULUS.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

PRECOMPILES: dict[bytes, callable] = {
    b"\x00" * 19 + b"\x01": precompile_ecrecover,
    b"\x00" * 19 + b"\x02": precompile_sha256,
    b"\x00" * 19 + b"\x03": precompile_ripemd160,
    b"\x00" * 19 + b"\x04": precompile_identity,
    b"\x00" * 19 + b"\x05": precompile_modexp,
    b"\x00" * 19 + b"\x06": precompile_ecadd,
    b"\x00" * 19 + b"\x07": precompile_ecmul,
    b"\x00" * 19 + b"\x08": precompile_ecpairing,
    b"\x00" * 19 + b"\x09": precompile_blake2f,
    b"\x00" * 19 + b"\x0a": precompile_kzg_point_eval,
    b"\x00" * 18 + b"\x01\x00": precompile_p256verify,
}


def is_precompile(address: bytes) -> bool:
    return address in PRECOMPILES


def run_precompile(address: bytes, data: bytes) -> Optional[tuple[int, bytes]]:
    """Run a precompile. Returns (gas_used, output) or None on failure."""
    func = PRECOMPILES.get(address)
    if func is None:
        return None
    return func(data)
