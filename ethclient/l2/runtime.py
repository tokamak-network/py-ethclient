"""PythonRuntime — wraps a user-defined Python function as a StateTransitionFunction."""

from __future__ import annotations

from typing import Any, Callable, Optional

from ethclient.l2.interfaces import StateTransitionFunction
from ethclient.l2.types import L2State, L2Tx, STFResult


class PythonRuntime(StateTransitionFunction):
    """Wraps a plain Python function as an STF.

    The function signature should be: func(state: dict, tx: L2Tx) -> STFResult
    If the function returns None, it is treated as success.
    If it raises an exception, it is treated as failure.
    """

    def __init__(
        self,
        func: Callable,
        validator: Optional[Callable] = None,
        genesis: Optional[Callable | dict] = None,
    ) -> None:
        self._func = func
        self._validator = validator
        self._genesis = genesis

    def apply_tx(self, state: L2State, tx: L2Tx) -> STFResult:
        try:
            result = self._func(state, tx)
            if result is None:
                return STFResult(success=True)
            if isinstance(result, STFResult):
                return result
            return STFResult(success=True, output=result if isinstance(result, dict) else {})
        except Exception as e:
            return STFResult(success=False, error=str(e))

    def validate_tx(self, state: L2State, tx: L2Tx) -> Optional[str]:
        if self._validator is not None:
            try:
                return self._validator(state, tx)
            except Exception as e:
                return str(e)
        return None

    def genesis_state(self) -> dict[str, Any]:
        if self._genesis is None:
            return {}
        if isinstance(self._genesis, dict):
            return dict(self._genesis)
        return self._genesis()
