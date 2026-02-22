"""R1CS Circuit Builder — Python expressions to Rank-1 Constraint Systems.

Usage:
    c = Circuit()
    x, y = c.private("x"), c.private("y")
    z = c.public("z")
    c.constrain(x * y, z)       # R1CS: x * y = z

    r1cs = c.to_r1cs()
    witness = c.compute_witness(private={"x": 3, "y": 5}, public={"z": 15})
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union

from py_ecc.bn128 import curve_order

FIELD_MODULUS = curve_order


def _field(x: int) -> int:
    """Reduce to field element."""
    return x % FIELD_MODULUS


def _field_inv(x: int) -> int:
    """Modular inverse via Fermat's little theorem."""
    return pow(x, FIELD_MODULUS - 2, FIELD_MODULUS)


@dataclass
class R1CS:
    """Rank-1 Constraint System: A*w . B*w = C*w (element-wise product).

    Each row in A, B, C is a sparse vector: dict mapping variable_index -> coefficient.
    """

    A: list[dict[int, int]]
    B: list[dict[int, int]]
    C: list[dict[int, int]]
    num_variables: int
    num_public: int  # includes the constant "1" wire (index 0)
    num_constraints: int

    def check_witness(self, witness: list[int]) -> bool:
        """Verify that a witness satisfies all constraints."""
        assert len(witness) == self.num_variables
        for i in range(self.num_constraints):
            a_val = _dot(self.A[i], witness)
            b_val = _dot(self.B[i], witness)
            c_val = _dot(self.C[i], witness)
            if _field(a_val * b_val) != _field(c_val):
                return False
        return True


def _dot(sparse_row: dict[int, int], witness: list[int]) -> int:
    """Dot product of sparse row with witness vector."""
    total = 0
    for idx, coeff in sparse_row.items():
        total = _field(total + _field(coeff * witness[idx]))
    return total


class Signal:
    """A symbolic linear combination of circuit variables.

    Internally, a Signal is a dict: {variable_index: coefficient}.
    This allows __add__, __sub__, __mul__ to produce new Signals
    that the Circuit can decompose into R1CS constraints.
    """

    def __init__(self, circuit: Circuit, terms: Optional[dict[int, int]] = None):
        self._circuit = circuit
        self.terms: dict[int, int] = terms or {}

    def _is_constant(self) -> bool:
        """Check if this signal has only a constant term."""
        return all(idx == 0 for idx in self.terms)

    def _constant_value(self) -> Optional[int]:
        """Return the constant value if this is a pure constant, else None."""
        if self._is_constant():
            return self.terms.get(0, 0)
        return None

    def __add__(self, other: Union[Signal, int]) -> Signal:
        if isinstance(other, int):
            other = self._circuit._constant(other)
        result = dict(self.terms)
        for idx, coeff in other.terms.items():
            result[idx] = _field(result.get(idx, 0) + coeff)
        return Signal(self._circuit, result)

    def __radd__(self, other: int) -> Signal:
        return self.__add__(other)

    def __sub__(self, other: Union[Signal, int]) -> Signal:
        if isinstance(other, int):
            other = self._circuit._constant(other)
        result = dict(self.terms)
        for idx, coeff in other.terms.items():
            result[idx] = _field(result.get(idx, 0) - coeff)
        return Signal(self._circuit, result)

    def __rsub__(self, other: int) -> Signal:
        neg = Signal(self._circuit, {idx: _field(-coeff) for idx, coeff in self.terms.items()})
        return self._circuit._constant(other) + neg

    def __mul__(self, other: Union[Signal, int]) -> Signal:
        if isinstance(other, int):
            # Scalar multiplication — no new constraint needed
            return Signal(
                self._circuit,
                {idx: _field(coeff * other) for idx, coeff in self.terms.items()},
            )
        # Signal * Signal — need to introduce an intermediate variable
        # unless one side is a constant
        if other._is_constant():
            c = other._constant_value()
            return self * c
        if self._is_constant():
            c = self._constant_value()
            return other * c

        # General case: create intermediate = self * other, add constraint
        result = self._circuit._new_intermediate()
        self._circuit._add_constraint(self.terms, other.terms, result.terms)
        return result

    def __rmul__(self, other: int) -> Signal:
        return self.__mul__(other)

    def __neg__(self) -> Signal:
        return Signal(
            self._circuit,
            {idx: _field(-coeff) for idx, coeff in self.terms.items()},
        )

    def __repr__(self) -> str:
        parts = []
        for idx, coeff in sorted(self.terms.items()):
            if coeff == 0:
                continue
            name = self._circuit._var_names.get(idx, f"v{idx}")
            if coeff == 1:
                parts.append(name)
            else:
                parts.append(f"{coeff}*{name}")
        return " + ".join(parts) if parts else "0"


class Circuit:
    """Circuit builder that collects signals and constraints into R1CS."""

    def __init__(self):
        # Variable allocation:
        #   index 0 = constant "1"
        #   indices 1..num_public = public inputs (in declaration order)
        #   indices num_public+1.. = private inputs, then intermediates
        self._num_vars = 1  # start with constant "1"
        self._public_vars: list[int] = []  # indices of public inputs
        self._private_vars: list[int] = []  # indices of private inputs
        self._intermediate_vars: list[int] = []

        # Name mappings
        self._var_names: dict[int, str] = {0: "1"}
        self._name_to_idx: dict[str, int] = {"1": 0}

        # R1CS constraints: each is (A_row, B_row, C_row)
        self._constraints: list[tuple[dict[int, int], dict[int, int], dict[int, int]]] = []

    @property
    def num_constraints(self) -> int:
        return len(self._constraints)

    @property
    def num_public(self) -> int:
        return len(self._public_vars)

    @property
    def num_private(self) -> int:
        return len(self._private_vars)

    @property
    def num_variables(self) -> int:
        return self._num_vars

    def public(self, name: str) -> Signal:
        """Declare a public input signal."""
        if name in self._name_to_idx:
            raise ValueError(f"Signal '{name}' already declared")
        idx = self._num_vars
        self._num_vars += 1
        self._public_vars.append(idx)
        self._var_names[idx] = name
        self._name_to_idx[name] = idx
        return Signal(self, {idx: 1})

    def private(self, name: str) -> Signal:
        """Declare a private input signal."""
        if name in self._name_to_idx:
            raise ValueError(f"Signal '{name}' already declared")
        idx = self._num_vars
        self._num_vars += 1
        self._private_vars.append(idx)
        self._var_names[idx] = name
        self._name_to_idx[name] = idx
        return Signal(self, {idx: 1})

    def intermediate(self, name: str) -> Signal:
        """Declare an intermediate (helper) signal."""
        if name in self._name_to_idx:
            raise ValueError(f"Signal '{name}' already declared")
        idx = self._num_vars
        self._num_vars += 1
        self._intermediate_vars.append(idx)
        self._var_names[idx] = name
        self._name_to_idx[name] = idx
        return Signal(self, {idx: 1})

    def constrain(self, lhs: Union[Signal, int], rhs: Union[Signal, int]) -> None:
        """Add constraint: lhs == rhs.

        Handles three cases:
        1. lhs is a product result (already added as A*B=C constraint via __mul__)
           → rewrite C to match rhs
        2. lhs or rhs is linear → add constraint as A*1 = C (linear equality)
        3. Both are products → error (need intermediate)
        """
        if isinstance(lhs, int):
            lhs = self._constant(lhs)
        if isinstance(rhs, int):
            rhs = self._constant(rhs)

        # If lhs was a product (from __mul__), the constraint was already added
        # with lhs as the result. We need to replace that constraint's C with rhs.
        # Check: does lhs have exactly one term pointing to an intermediate?
        lhs_idx = self._get_single_intermediate(lhs)
        if lhs_idx is not None and self._constraints:
            # The last constraint's C should have been set to lhs
            last_a, last_b, last_c = self._constraints[-1]
            if last_c == lhs.terms:
                # Replace C with rhs and remove the intermediate variable
                self._constraints[-1] = (last_a, last_b, rhs.terms)
                # Remove the intermediate we don't need
                self._remove_intermediate(lhs_idx)
                return

        rhs_idx = self._get_single_intermediate(rhs)
        if rhs_idx is not None and self._constraints:
            last_a, last_b, last_c = self._constraints[-1]
            if last_c == rhs.terms:
                self._constraints[-1] = (last_a, last_b, lhs.terms)
                self._remove_intermediate(rhs_idx)
                return

        # Linear equality: lhs == rhs → (lhs - rhs) * 1 = 0
        # Rewrite as: (lhs - rhs) * 1 = 0
        diff = lhs - rhs
        a_row = diff.terms
        b_row = {0: 1}  # constant 1
        c_row = {}  # zero
        self._constraints.append((a_row, b_row, c_row))

    def _constant(self, value: int) -> Signal:
        """Create a constant signal."""
        return Signal(self, {0: _field(value)})

    def _new_intermediate(self) -> Signal:
        """Allocate a new intermediate variable."""
        idx = self._num_vars
        self._num_vars += 1
        self._intermediate_vars.append(idx)
        self._var_names[idx] = f"_tmp{idx}"
        return Signal(self, {idx: 1})

    def _add_constraint(
        self,
        a_terms: dict[int, int],
        b_terms: dict[int, int],
        c_terms: dict[int, int],
    ) -> None:
        """Add a raw A*B=C constraint."""
        self._constraints.append((a_terms, b_terms, c_terms))

    def _get_single_intermediate(self, signal: Signal) -> Optional[int]:
        """If signal is a single intermediate variable, return its index."""
        nonzero = {idx: c for idx, c in signal.terms.items() if c != 0}
        if len(nonzero) == 1:
            idx, coeff = next(iter(nonzero.items()))
            if coeff == 1 and idx in self._intermediate_vars:
                return idx
        return None

    def _remove_intermediate(self, idx: int) -> None:
        """Remove an intermediate variable that was optimized away.

        Note: We don't renumber to avoid breaking existing constraint references.
        The variable slot remains but won't appear in the witness.
        """
        if idx in self._intermediate_vars:
            self._intermediate_vars.remove(idx)
        name = self._var_names.pop(idx, None)
        if name:
            self._name_to_idx.pop(name, None)

    def to_r1cs(self) -> R1CS:
        """Export to R1CS format.

        Variable ordering in witness:
          [0] = 1 (constant)
          [1..num_public] = public inputs (in declaration order)
          [num_public+1..] = private inputs, then intermediates
        """
        # Build variable remapping: old_idx -> new_idx
        # Order: constant, public, private, intermediate
        remap = {0: 0}
        new_idx = 1
        for old_idx in self._public_vars:
            remap[old_idx] = new_idx
            new_idx += 1
        for old_idx in self._private_vars:
            remap[old_idx] = new_idx
            new_idx += 1
        for old_idx in self._intermediate_vars:
            remap[old_idx] = new_idx
            new_idx += 1

        num_variables = new_idx

        def remap_row(row: dict[int, int]) -> dict[int, int]:
            result = {}
            for old, coeff in row.items():
                if coeff % FIELD_MODULUS == 0:
                    continue
                new = remap.get(old)
                if new is not None:
                    result[new] = _field(coeff)
            return result

        A, B, C = [], [], []
        for a_row, b_row, c_row in self._constraints:
            A.append(remap_row(a_row))
            B.append(remap_row(b_row))
            C.append(remap_row(c_row))

        num_public = 1 + len(self._public_vars)  # +1 for constant wire

        return R1CS(
            A=A,
            B=B,
            C=C,
            num_variables=num_variables,
            num_public=num_public,
            num_constraints=len(self._constraints),
        )

    def compute_witness(
        self,
        private: dict[str, int],
        public: dict[str, int],
    ) -> list[int]:
        """Compute the full witness vector from input assignments.

        Returns witness in R1CS variable ordering:
          [0] = 1, [1..num_public] = public, [num_public+1..] = private, intermediates
        """
        # Build old_idx -> value mapping
        values: dict[int, int] = {0: 1}

        for name, val in public.items():
            idx = self._name_to_idx.get(name)
            if idx is None:
                raise ValueError(f"Unknown public input: {name}")
            values[idx] = _field(val)

        for name, val in private.items():
            idx = self._name_to_idx.get(name)
            if idx is None:
                raise ValueError(f"Unknown private input: {name}")
            values[idx] = _field(val)

        # Compute intermediate values by evaluating constraints
        # For each constraint A*B=C:
        #   If C has exactly one unknown intermediate, solve for it
        self._solve_intermediates(values)

        # Build remapped witness
        remap = {0: 0}
        new_idx = 1
        for old_idx in self._public_vars:
            remap[old_idx] = new_idx
            new_idx += 1
        for old_idx in self._private_vars:
            remap[old_idx] = new_idx
            new_idx += 1
        for old_idx in self._intermediate_vars:
            remap[old_idx] = new_idx
            new_idx += 1

        num_variables = new_idx
        witness = [0] * num_variables
        for old_idx, val in values.items():
            new = remap.get(old_idx)
            if new is not None:
                witness[new] = _field(val)

        return witness

    def _solve_intermediates(self, values: dict[int, int]) -> None:
        """Solve for intermediate variable values from constraints."""
        # Iterate constraints multiple times until all intermediates are resolved
        max_iter = len(self._constraints) + 1
        for _ in range(max_iter):
            progress = False
            for a_row, b_row, c_row in self._constraints:
                # Evaluate A*B
                a_val = self._eval_lc(a_row, values)
                b_val = self._eval_lc(b_row, values)

                if a_val is not None and b_val is not None:
                    product = _field(a_val * b_val)
                    # Try to solve for unknown in C
                    if self._try_solve_lc(c_row, values, product):
                        progress = True
                else:
                    # Try to solve in A or B if C is known
                    c_val = self._eval_lc(c_row, values)
                    if c_val is not None and a_val is not None and a_val != 0:
                        # c = a * b → b = c / a
                        target = _field(c_val * _field_inv(a_val))
                        if self._try_solve_lc(b_row, values, target):
                            progress = True
                    elif c_val is not None and b_val is not None and b_val != 0:
                        target = _field(c_val * _field_inv(b_val))
                        if self._try_solve_lc(a_row, values, target):
                            progress = True

            if not progress:
                break

    def _eval_lc(self, row: dict[int, int], values: dict[int, int]) -> Optional[int]:
        """Evaluate a linear combination. Returns None if any variable is unknown."""
        total = 0
        for idx, coeff in row.items():
            if idx not in values:
                return None
            total = _field(total + _field(coeff * values[idx]))
        return total

    def _try_solve_lc(
        self, row: dict[int, int], values: dict[int, int], target: int
    ) -> bool:
        """Try to solve a linear combination = target for a single unknown."""
        unknown_idx = None
        unknown_coeff = 0
        known_sum = 0

        for idx, coeff in row.items():
            if coeff % FIELD_MODULUS == 0:
                continue
            if idx in values:
                known_sum = _field(known_sum + _field(coeff * values[idx]))
            elif unknown_idx is None:
                unknown_idx = idx
                unknown_coeff = coeff
            else:
                return False  # Multiple unknowns

        if unknown_idx is None:
            return False  # No unknowns (constraint already satisfied or violated)

        # target = known_sum + unknown_coeff * x
        # x = (target - known_sum) / unknown_coeff
        diff = _field(target - known_sum)
        values[unknown_idx] = _field(diff * _field_inv(unknown_coeff))
        return True
