"""Tests for PythonRuntime: wrapping user functions as STF."""

import pytest
from ethclient.l2.types import L2Tx, L2State, STFResult
from ethclient.l2.runtime import PythonRuntime
from ethclient.l2.interfaces import StateTransitionFunction


class TestPythonRuntime:
    def test_basic_wrapping(self):
        def my_func(state, tx):
            state["counter"] = state.get("counter", 0) + 1
            return STFResult(success=True)

        rt = PythonRuntime(my_func)
        assert isinstance(rt, StateTransitionFunction)

        state = L2State()
        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={})
        result = rt.apply_tx(state, tx)
        assert result.success
        assert state["counter"] == 1

    def test_function_returning_none(self):
        def noop(state, tx):
            pass

        rt = PythonRuntime(noop)
        state = L2State()
        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={})
        result = rt.apply_tx(state, tx)
        assert result.success

    def test_function_raising_exception(self):
        def bad_func(state, tx):
            raise ValueError("boom")

        rt = PythonRuntime(bad_func)
        state = L2State()
        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={})
        result = rt.apply_tx(state, tx)
        assert not result.success
        assert "boom" in result.error

    def test_validate_tx(self):
        def validator(state, tx):
            if tx.value > 100:
                return "value too high"
            return None

        rt = PythonRuntime(lambda s, t: STFResult(success=True), validator=validator)
        state = L2State()

        tx_ok = L2Tx(sender=b"\x01" * 20, nonce=0, data={}, value=50)
        assert rt.validate_tx(state, tx_ok) is None

        tx_bad = L2Tx(sender=b"\x01" * 20, nonce=0, data={}, value=200)
        assert rt.validate_tx(state, tx_bad) == "value too high"

    def test_genesis_state_dict(self):
        rt = PythonRuntime(
            lambda s, t: STFResult(success=True),
            genesis={"balance": 1000},
        )
        genesis = rt.genesis_state()
        assert genesis == {"balance": 1000}

    def test_genesis_state_callable(self):
        rt = PythonRuntime(
            lambda s, t: STFResult(success=True),
            genesis=lambda: {"count": 0, "admin": "alice"},
        )
        genesis = rt.genesis_state()
        assert genesis == {"count": 0, "admin": "alice"}

    def test_genesis_state_default(self):
        rt = PythonRuntime(lambda s, t: STFResult(success=True))
        assert rt.genesis_state() == {}

    def test_stf_result_with_output(self):
        def func(state, tx):
            return STFResult(success=True, output={"msg": "done"})

        rt = PythonRuntime(func)
        result = rt.apply_tx(L2State(), L2Tx(sender=b"\x01" * 20, nonce=0, data={}))
        assert result.output == {"msg": "done"}

    def test_validator_exception(self):
        def bad_validator(state, tx):
            raise RuntimeError("validator error")

        rt = PythonRuntime(
            lambda s, t: STFResult(success=True),
            validator=bad_validator,
        )
        state = L2State()
        tx = L2Tx(sender=b"\x01" * 20, nonce=0, data={})
        error = rt.validate_tx(state, tx)
        assert "validator error" in error
