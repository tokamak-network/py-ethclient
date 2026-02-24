"""R1CS binary export for snarkjs / circom toolchain compatibility.

Exports Circuit → .r1cs binary format and witness → JSON for snarkjs/rapidsnark.
See: https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md
"""

from __future__ import annotations

import struct
from typing import Any

from ethclient.zk.circuit import Circuit, FIELD_MODULUS


def export_r1cs_binary(circuit: Circuit) -> bytes:
    """Export a Circuit to snarkjs .r1cs binary format.

    Format:
        Header: magic + version + sections
        Section 1 (Header): field_size, prime, num_wires, num_pub_out, num_pub_in,
                            num_private_in, num_labels, num_constraints
        Section 2 (Constraints): A, B, C sparse matrices
        Section 3 (Wire mapping): placeholder identity map
    """
    r1cs = circuit.to_r1cs()
    field_size = 32  # BN128 = 32 bytes

    # ── Header Section (type 1) ──
    prime_bytes = FIELD_MODULUS.to_bytes(field_size, "little")

    # snarkjs convention: num_pub_out=0, num_pub_in = public inputs (excl. constant),
    # num_private_in = private + intermediate
    num_pub_in = len(circuit._public_vars)
    num_private_in = len(circuit._private_vars) + len(circuit._intermediate_vars)

    header_data = bytearray()
    header_data += struct.pack("<I", field_size)
    header_data += prime_bytes
    header_data += struct.pack("<I", r1cs.num_variables)  # nWires
    header_data += struct.pack("<I", 0)  # nPubOut
    header_data += struct.pack("<I", num_pub_in)  # nPubIn
    header_data += struct.pack("<I", num_private_in)  # nPrvIn
    header_data += struct.pack("<Q", r1cs.num_variables)  # nLabels (= nWires)
    header_data += struct.pack("<I", r1cs.num_constraints)  # mConstraints

    # ── Constraints Section (type 2) ──
    constraints_data = bytearray()
    for i in range(r1cs.num_constraints):
        constraints_data += _encode_sparse_vector(r1cs.A[i], field_size)
        constraints_data += _encode_sparse_vector(r1cs.B[i], field_size)
        constraints_data += _encode_sparse_vector(r1cs.C[i], field_size)

    # ── Wire Mapping Section (type 3) ──
    wire_data = bytearray()
    for i in range(r1cs.num_variables):
        wire_data += struct.pack("<Q", i)

    # ── Assemble File ──
    out = bytearray()
    # Magic: "r1cs"
    out += b"r1cs"
    # Version: 1
    out += struct.pack("<I", 1)
    # Number of sections: 3
    out += struct.pack("<I", 3)

    # Section 1: Header
    out += struct.pack("<I", 1)  # section type
    out += struct.pack("<Q", len(header_data))  # section size
    out += header_data

    # Section 2: Constraints
    out += struct.pack("<I", 2)
    out += struct.pack("<Q", len(constraints_data))
    out += constraints_data

    # Section 3: Wire mapping
    out += struct.pack("<I", 3)
    out += struct.pack("<Q", len(wire_data))
    out += wire_data

    return bytes(out)


def _encode_sparse_vector(row: dict[int, int], field_size: int) -> bytes:
    """Encode a sparse R1CS row as [num_entries, (wire_id, coeff_le), ...]."""
    out = bytearray()
    entries = [(idx, coeff) for idx, coeff in row.items() if coeff % FIELD_MODULUS != 0]
    out += struct.pack("<I", len(entries))
    for idx, coeff in entries:
        out += struct.pack("<I", idx)
        out += (coeff % FIELD_MODULUS).to_bytes(field_size, "little")
    return bytes(out)


def export_witness_json(
    public: dict[str, int],
    private: dict[str, int],
    circuit: Circuit,
) -> dict[str, Any]:
    """Export witness values as snarkjs-compatible JSON.

    Returns:
        {"witness": ["1", val_1, ..., val_n]} — decimal strings in R1CS variable order.
        Index 0 is always "1" (constant wire).
    """
    witness = circuit.compute_witness(private=private, public=public)
    return {"witness": [str(v) for v in witness]}


def export_public_json(public: dict[str, int], circuit: Circuit) -> list[str]:
    """Export public inputs as snarkjs public.json format.

    Returns a list of decimal strings in declaration order.
    """
    result = []
    for idx in circuit._public_vars:
        name = circuit._var_names.get(idx, "")
        val = public.get(name, 0)
        result.append(str(val % FIELD_MODULUS))
    return result
