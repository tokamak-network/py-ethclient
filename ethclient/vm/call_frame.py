"""
EVM Call Frame — represents a single execution context.

Each CALL/CREATE/DELEGATECALL/STATICCALL creates a new CallFrame.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ethclient.vm.memory import Stack, Memory


@dataclass
class CallFrame:
    """One frame in the EVM call stack."""

    # Execution context
    caller: bytes = field(default_factory=lambda: b"\x00" * 20)
    address: bytes = field(default_factory=lambda: b"\x00" * 20)  # code address
    code_address: bytes = field(default_factory=lambda: b"\x00" * 20)
    origin: bytes = field(default_factory=lambda: b"\x00" * 20)

    # Code being executed
    code: bytes = b""
    pc: int = 0

    # Gas
    gas: int = 0
    gas_used: int = 0

    # Value & calldata
    value: int = 0
    calldata: bytes = b""

    # Depth in call stack
    depth: int = 0

    # Static flag (STATICCALL)
    is_static: bool = False

    # Stack & memory (created fresh per frame)
    stack: Stack = field(default_factory=Stack)
    memory: Memory = field(default_factory=Memory)

    # Return data from the last sub-call
    return_data: bytes = b""

    # Valid JUMPDEST positions (lazily computed)
    _valid_jumpdests: Optional[set[int]] = field(default=None, repr=False)

    @property
    def valid_jumpdests(self) -> set[int]:
        if self._valid_jumpdests is None:
            self._valid_jumpdests = _compute_valid_jumpdests(self.code)
        return self._valid_jumpdests

    def consume_gas(self, amount: int) -> None:
        """Consume gas, raising OutOfGas if insufficient."""
        from ethclient.vm.memory import OutOfGas
        remaining = self.gas - self.gas_used
        if amount > remaining:
            raise OutOfGas(f"Out of gas: need {amount}, have {remaining}")
        self.gas_used += amount

    @property
    def remaining_gas(self) -> int:
        return self.gas - self.gas_used

MAX_CALL_DEPTH = 1024


def _compute_valid_jumpdests(code: bytes) -> set[int]:
    """Pre-compute the set of valid JUMPDEST positions in bytecode.

    PUSH instructions' immediate data bytes are not valid jump targets.
    """
    valid = set()
    i = 0
    while i < len(code):
        op = code[i]
        if op == 0x5B:  # JUMPDEST
            valid.add(i)
        # PUSH1..PUSH32: skip immediate bytes
        if 0x60 <= op <= 0x7F:
            i += op - 0x5F  # skip 1..32 data bytes
        i += 1
    return valid
