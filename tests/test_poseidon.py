"""Tests for Poseidon hash, circuit, trie integration, and L2 integration."""

import pytest
from py_ecc.bn128 import curve_order

from ethclient.common.hash import (
    POSEIDON_FIELD,
    _ROUND_CONSTANTS,
    _MDS_MATRIX,
    _generate_round_constants,
    _generate_mds_matrix,
    _poseidon_permutation,
    poseidon,
    poseidon_bytes,
    _T,
    _RF,
    _RP,
)


# ===========================================================================
# TestPoseidonHash — pure hash function tests
# ===========================================================================

class TestPoseidonHash:
    def test_field_is_bn128(self):
        assert POSEIDON_FIELD == curve_order

    def test_round_constants_count(self):
        expected = (_RF + _RP) * _T  # 65 * 3 = 195
        assert len(_ROUND_CONSTANTS) == expected

    def test_round_constants_in_field(self):
        for rc in _ROUND_CONSTANTS:
            assert 0 <= rc < POSEIDON_FIELD

    def test_mds_matrix_dimensions(self):
        assert len(_MDS_MATRIX) == _T
        for row in _MDS_MATRIX:
            assert len(row) == _T

    def test_mds_matrix_in_field(self):
        for row in _MDS_MATRIX:
            for val in row:
                assert 0 <= val < POSEIDON_FIELD

    def test_constants_deterministic(self):
        rc2 = _generate_round_constants(_T, _RF, _RP, POSEIDON_FIELD)
        assert rc2 == _ROUND_CONSTANTS

    def test_mds_deterministic(self):
        mds2 = _generate_mds_matrix(_T, POSEIDON_FIELD)
        assert mds2 == _MDS_MATRIX

    def test_single_input(self):
        result = poseidon([42])
        assert isinstance(result, int)
        assert 0 <= result < POSEIDON_FIELD

    def test_two_inputs(self):
        result = poseidon([1, 2])
        assert isinstance(result, int)
        assert 0 <= result < POSEIDON_FIELD

    def test_multiple_inputs(self):
        result = poseidon([10, 20, 30])
        assert isinstance(result, int)
        assert 0 <= result < POSEIDON_FIELD

    def test_deterministic(self):
        a = poseidon([1, 2, 3])
        b = poseidon([1, 2, 3])
        assert a == b

    def test_different_inputs_different_output(self):
        a = poseidon([1, 2])
        b = poseidon([2, 1])
        assert a != b

    def test_empty_input(self):
        result = poseidon([])
        assert isinstance(result, int)
        assert 0 <= result < POSEIDON_FIELD

    def test_zero_input(self):
        result = poseidon([0])
        assert isinstance(result, int)
        assert 0 <= result < POSEIDON_FIELD

    def test_large_field_element(self):
        val = POSEIDON_FIELD - 1
        result = poseidon([val])
        assert 0 <= result < POSEIDON_FIELD

    def test_out_of_field_raises(self):
        with pytest.raises(ValueError, match="not in field"):
            poseidon([POSEIDON_FIELD])

    def test_negative_raises(self):
        with pytest.raises(ValueError, match="not in field"):
            poseidon([-1])

    def test_poseidon_bytes_basic(self):
        result = poseidon_bytes(b"hello")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_poseidon_bytes_deterministic(self):
        a = poseidon_bytes(b"test data")
        b = poseidon_bytes(b"test data")
        assert a == b

    def test_poseidon_bytes_empty(self):
        result = poseidon_bytes(b"")
        assert len(result) == 32

    def test_poseidon_bytes_long_input(self):
        data = b"x" * 200
        result = poseidon_bytes(data)
        assert len(result) == 32

    def test_poseidon_bytes_different_data(self):
        a = poseidon_bytes(b"alice")
        b = poseidon_bytes(b"bob")
        assert a != b

    def test_permutation_changes_state(self):
        state = [1, 2, 3]
        result = _poseidon_permutation(state)
        assert result != [1, 2, 3]
        assert len(result) == _T


# ===========================================================================
# TestPoseidonCircuit — R1CS encoding tests
# ===========================================================================

class TestPoseidonCircuit:
    def test_constraint_count(self):
        from ethclient.zk.circuit import Circuit
        from ethclient.zk.poseidon_circuit import poseidon_circuit

        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        _ = poseidon_circuit(c, [x, y])

        # Full rounds: 8 × 3 sboxes × 3 constraints = 72, minus 3 for first
        # round capacity element (constant → 0 constraints). Partial: 57 × 3 = 171.
        # Total: 72 - 3 + 171 = 240
        assert c.num_constraints == 240

    def test_witness_satisfies_constraints(self):
        from ethclient.zk.circuit import Circuit
        from ethclient.zk.poseidon_circuit import poseidon_circuit

        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        out = c.public("out")

        h = poseidon_circuit(c, [x, y])
        c.constrain(h, out)

        expected = poseidon([10, 20])
        witness = c.compute_witness(
            private={"x": 10, "y": 20},
            public={"out": expected},
        )

        r1cs = c.to_r1cs()
        assert r1cs.check_witness(witness)

    def test_wrong_witness_fails(self):
        from ethclient.zk.circuit import Circuit
        from ethclient.zk.poseidon_circuit import poseidon_circuit

        c = Circuit()
        x = c.private("x")
        y = c.private("y")
        out = c.public("out")

        h = poseidon_circuit(c, [x, y])
        c.constrain(h, out)

        wrong_output = 12345
        witness = c.compute_witness(
            private={"x": 10, "y": 20},
            public={"out": wrong_output},
        )

        r1cs = c.to_r1cs()
        assert not r1cs.check_witness(witness)

    def test_single_input_circuit(self):
        from ethclient.zk.circuit import Circuit
        from ethclient.zk.poseidon_circuit import poseidon_circuit

        c = Circuit()
        x = c.private("x")
        out = c.public("out")

        h = poseidon_circuit(c, [x])
        c.constrain(h, out)

        expected = poseidon([42])
        witness = c.compute_witness(
            private={"x": 42},
            public={"out": expected},
        )

        r1cs = c.to_r1cs()
        assert r1cs.check_witness(witness)

    def test_circuit_export_via_init(self):
        from ethclient.zk import poseidon_circuit as pc, Circuit
        c = Circuit()
        x = c.private("x")
        _ = pc(c, [x])
        assert c.num_constraints > 0


# ===========================================================================
# TestTrieWithPoseidon — Trie with custom hash function
# ===========================================================================

class TestTrieWithPoseidon:
    def test_default_trie_unchanged(self):
        from ethclient.common.trie import Trie, EMPTY_ROOT
        trie = Trie()
        assert trie.root_hash == EMPTY_ROOT

    def test_default_trie_no_hash_fn(self):
        from ethclient.common.trie import Trie
        from ethclient.common.crypto import keccak256
        trie = Trie()
        trie.put(b"key", b"value")
        root1 = trie.root_hash

        trie2 = Trie(hash_fn=keccak256)
        trie2.put(b"key", b"value")
        root2 = trie2.root_hash

        assert root1 == root2

    def test_poseidon_trie_put_get(self):
        from ethclient.common.trie import Trie
        trie = Trie(hash_fn=poseidon_bytes)
        trie.put(b"alice", b"100")
        trie.put(b"bob", b"200")

        assert trie.get(b"alice") == b"100"
        assert trie.get(b"bob") == b"200"
        assert trie.get(b"charlie") is None

    def test_poseidon_trie_delete(self):
        from ethclient.common.trie import Trie
        trie = Trie(hash_fn=poseidon_bytes)
        trie.put(b"key1", b"val1")
        trie.put(b"key2", b"val2")
        trie.delete(b"key1")

        assert trie.get(b"key1") is None
        assert trie.get(b"key2") == b"val2"

    def test_poseidon_trie_empty_root(self):
        from ethclient.common.trie import Trie, EMPTY_ROOT
        trie = Trie(hash_fn=poseidon_bytes)
        poseidon_empty = trie.root_hash
        assert poseidon_empty != EMPTY_ROOT
        assert len(poseidon_empty) == 32

    def test_poseidon_trie_deterministic(self):
        from ethclient.common.trie import Trie
        trie1 = Trie(hash_fn=poseidon_bytes)
        trie1.put(b"a", b"1")
        trie1.put(b"b", b"2")

        trie2 = Trie(hash_fn=poseidon_bytes)
        trie2.put(b"a", b"1")
        trie2.put(b"b", b"2")

        assert trie1.root_hash == trie2.root_hash

    def test_poseidon_vs_keccak_different_roots(self):
        from ethclient.common.trie import Trie
        trie_k = Trie()
        trie_k.put(b"key", b"value")

        trie_p = Trie(hash_fn=poseidon_bytes)
        trie_p.put(b"key", b"value")

        assert trie_k.root_hash != trie_p.root_hash

    def test_poseidon_trie_update(self):
        from ethclient.common.trie import Trie
        trie = Trie(hash_fn=poseidon_bytes)
        trie.put(b"key", b"old_value")
        root1 = trie.root_hash

        trie.put(b"key", b"new_value")
        root2 = trie.root_hash

        assert root1 != root2
        assert trie.get(b"key") == b"new_value"


# ===========================================================================
# TestL2PoseidonIntegration — L2 config/state/rollup integration
# ===========================================================================

class TestL2PoseidonIntegration:
    def test_config_default_keccak(self):
        from ethclient.l2.config import L2Config
        config = L2Config()
        assert config.hash_function == "keccak256"

    def test_config_poseidon(self):
        from ethclient.l2.config import L2Config
        config = L2Config(hash_function="poseidon")
        assert config.hash_function == "poseidon"

    def test_resolve_keccak(self):
        from ethclient.l2.config import resolve_hash_function
        from ethclient.common.crypto import keccak256
        fn = resolve_hash_function("keccak256")
        assert fn(b"test") == keccak256(b"test")

    def test_resolve_poseidon(self):
        from ethclient.l2.config import resolve_hash_function
        fn = resolve_hash_function("poseidon")
        assert fn(b"test") == poseidon_bytes(b"test")

    def test_resolve_unknown_raises(self):
        from ethclient.l2.config import resolve_hash_function
        with pytest.raises(ValueError, match="Unknown hash function"):
            resolve_hash_function("sha256")

    def test_state_store_with_poseidon(self):
        from ethclient.l2.state import L2StateStore
        store = L2StateStore({"a": 1, "b": 2}, hash_fn=poseidon_bytes)
        root = store.compute_state_root()
        assert isinstance(root, bytes)
        assert len(root) == 32

    def test_state_store_poseidon_vs_keccak(self):
        from ethclient.l2.state import L2StateStore
        store_k = L2StateStore({"x": 10})
        store_p = L2StateStore({"x": 10}, hash_fn=poseidon_bytes)
        assert store_k.compute_state_root() != store_p.compute_state_root()

    def test_rollup_propagates_hash_function(self):
        from ethclient.l2.config import L2Config
        from ethclient.l2.rollup import Rollup
        from ethclient.l2.types import STFResult

        config = L2Config(hash_function="poseidon")
        rollup = Rollup(
            stf=lambda state, tx: STFResult(success=True),
            config=config,
        )

        root_p = rollup.state_root

        rollup_k = Rollup(
            stf=lambda state, tx: STFResult(success=True),
            config=L2Config(hash_function="keccak256"),
        )
        root_k = rollup_k.state_root

        assert root_p != root_k
