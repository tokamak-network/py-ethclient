"""
EVM execution hook system.

Provides extension points for L2 customization without modifying EVM core.
L1 uses DefaultHook (all no-ops). L2 can subclass ExecutionHook.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ethclient.vm.call_frame import CallFrame


class ExecutionHook:
    """Base hook interface — override methods to customize EVM behavior."""

    def before_execution(self, tx_data: dict) -> None:
        """Called before transaction execution begins."""
        pass

    def after_execution(self, tx_data: dict, success: bool, gas_used: int) -> None:
        """Called after transaction execution completes."""
        pass

    def before_call(self, frame: CallFrame) -> None:
        """Called before entering a new call frame (CALL/CREATE)."""
        pass

    def after_call(self, frame: CallFrame, success: bool, return_data: bytes) -> None:
        """Called after returning from a call frame."""
        pass

    def on_state_change(self, address: bytes, key: int, old_value: int, new_value: int) -> None:
        """Called when a storage slot is modified."""
        pass

    def on_balance_change(self, address: bytes, old_balance: int, new_balance: int) -> None:
        """Called when an account balance changes."""
        pass


class DefaultHook(ExecutionHook):
    """Default L1 hook — all operations are no-ops."""
    pass
