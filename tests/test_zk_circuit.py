"""Tests for ZK R1CS Circuit Builder."""

import pytest
from py_ecc.bn128 import curve_order

from ethclient.zk.circuit import Circuit, R1CS, Signal, _field, _field_inv, FIELD_MODULUS


class TestSignal:
    """Test Signal arithmetic operations."""

    def test_add_signals(self):
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = x + y
        # z should have terms for both x and y
        assert len(z.terms) == 2

    def test_add_constant(self):
        c = Circuit()
        x = c.private("x")
        z = x + 5
        assert 0 in z.terms  # constant term

    def test_sub_signals(self):
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = x - y
        assert len(z.terms) == 2

    def test_mul_by_constant(self):
        c = Circuit()
        x = c.private("x")
        z = x * 3
        # Should NOT create a new constraint (scalar mul is free)
        assert c.num_constraints == 0
        assert len(z.terms) == 1

    def test_mul_signals_creates_constraint(self):
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        _ = x * y
        # Multiplication of two signals creates a constraint
        assert c.num_constraints == 1

    def test_neg_signal(self):
        c = Circuit()
        x = c.private("x")
        neg_x = -x
        assert len(neg_x.terms) == 1

    def test_radd(self):
        c = Circuit()
        x = c.private("x")
        z = 5 + x
        assert 0 in z.terms

    def test_rmul(self):
        c = Circuit()
        x = c.private("x")
        z = 3 * x
        assert c.num_constraints == 0


class TestCircuit:
    """Test Circuit construction."""

    def test_simple_multiply(self):
        """x * y = z (1 constraint)."""
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = c.public("z")
        c.constrain(x * y, z)

        assert c.num_constraints == 1
        assert c.num_public == 1
        assert c.num_private == 2

    def test_duplicate_name_raises(self):
        c = Circuit()
        c.private("x")
        with pytest.raises(ValueError, match="already declared"):
            c.private("x")

    def test_public_and_private(self):
        c = Circuit()
        x = c.private("x")
        z = c.public("z")
        c.constrain(x * x, z)

        assert c.num_constraints == 1
        assert c.num_public == 1
        assert c.num_private == 1

    def test_intermediate_variable(self):
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = c.public("z")
        # x * y = intermediate, then intermediate = z
        c.constrain(x * y, z)

        assert c.num_constraints == 1

    def test_multiple_constraints(self):
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z1 = c.public("z1")
        z2 = c.public("z2")

        c.constrain(x * y, z1)
        c.constrain(x * x, z2)

        assert c.num_constraints == 2
        assert c.num_public == 2

    def test_linear_constraint(self):
        """Test x + y = z (linear, no multiplication)."""
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = c.public("z")
        c.constrain(x + y, z)

        assert c.num_constraints == 1


class TestR1CS:
    """Test R1CS generation and witness checking."""

    def test_simple_multiply_r1cs(self):
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = c.public("z")
        c.constrain(x * y, z)

        r1cs = c.to_r1cs()

        # Variable ordering: [1, z, x, y]
        assert r1cs.num_public == 2  # constant + z
        assert r1cs.num_constraints == 1

    def test_witness_satisfies_r1cs(self):
        """Test that a correct witness satisfies the R1CS."""
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = c.public("z")
        c.constrain(x * y, z)

        witness = c.compute_witness(
            private={"x": 3, "y": 5},
            public={"z": 15},
        )

        r1cs = c.to_r1cs()
        assert r1cs.check_witness(witness)

    def test_wrong_witness_fails(self):
        """Test that an incorrect witness fails."""
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = c.public("z")
        c.constrain(x * y, z)

        witness = c.compute_witness(
            private={"x": 3, "y": 5},
            public={"z": 16},  # wrong: 3*5 = 15, not 16
        )

        r1cs = c.to_r1cs()
        assert not r1cs.check_witness(witness)

    def test_witness_variable_count(self):
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = c.public("z")
        c.constrain(x * y, z)

        witness = c.compute_witness(
            private={"x": 3, "y": 5},
            public={"z": 15},
        )

        r1cs = c.to_r1cs()
        assert len(witness) == r1cs.num_variables

    def test_linear_constraint_witness(self):
        """Test witness for x + y = z."""
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = c.public("z")
        c.constrain(x + y, z)

        witness = c.compute_witness(
            private={"x": 10, "y": 20},
            public={"z": 30},
        )

        r1cs = c.to_r1cs()
        assert r1cs.check_witness(witness)

    def test_two_constraints(self):
        """Test circuit with two constraints: x*y = z1, x+y = z2."""
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z1 = c.public("z1")
        z2 = c.public("z2")

        c.constrain(x * y, z1)
        c.constrain(x + y, z2)

        witness = c.compute_witness(
            private={"x": 3, "y": 7},
            public={"z1": 21, "z2": 10},
        )

        r1cs = c.to_r1cs()
        assert r1cs.check_witness(witness)

    def test_unknown_signal_raises(self):
        c = Circuit()
        c.private("x")
        with pytest.raises(ValueError, match="Unknown"):
            c.compute_witness(private={"y": 1}, public={})

    def test_large_field_values(self):
        """Test with values close to field modulus."""
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = c.public("z")
        c.constrain(x * y, z)

        val_x = FIELD_MODULUS - 1
        val_y = 2
        val_z = _field(val_x * val_y)

        witness = c.compute_witness(
            private={"x": val_x, "y": val_y},
            public={"z": val_z},
        )

        r1cs = c.to_r1cs()
        assert r1cs.check_witness(witness)

    def test_intermediate_solving(self):
        """Test that intermediate variables are computed correctly."""
        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        z = c.public("z")

        # x * y = intermediate, stored in diff
        diff = c.intermediate("diff")
        c.constrain(x, y + diff)  # x = y + diff → diff = x - y
        c.constrain(x * y, z)

        witness = c.compute_witness(
            private={"x": 10, "y": 3},
            public={"z": 30},
        )

        r1cs = c.to_r1cs()
        assert r1cs.check_witness(witness)


class TestFieldArithmetic:
    """Test field arithmetic helpers."""

    def test_field_modulus(self):
        assert FIELD_MODULUS == curve_order

    def test_field_inverse(self):
        x = 42
        inv = _field_inv(x)
        assert _field(x * inv) == 1

    def test_field_wrap(self):
        assert _field(FIELD_MODULUS) == 0
        assert _field(FIELD_MODULUS + 1) == 1
        assert _field(-1) == FIELD_MODULUS - 1
