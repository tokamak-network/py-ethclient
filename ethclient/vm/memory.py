"""
EVM Stack and Memory implementations.

Stack: 1024-depth, 256-bit (uint256) values.
Memory: byte-addressable, auto-expanding in 32-byte words.
"""

from __future__ import annotations

# Max uint256
UINT256_MAX = (1 << 256) - 1
UINT256_CEIL = 1 << 256


class EvmError(Exception):
    """Base class for EVM execution errors."""
    pass


class StackOverflow(EvmError):
    pass


class StackUnderflow(EvmError):
    pass


class InvalidJumpDest(EvmError):
    pass


class OutOfGas(EvmError):
    pass


class WriteProtection(EvmError):
    pass


class InvalidOpcode(EvmError):
    pass


class ReturnData(EvmError):
    """Not really an error — signals normal RETURN."""
    def __init__(self, data: bytes = b""):
        self.data = data
        super().__init__()


class Revert(EvmError):
    """REVERT opcode."""
    def __init__(self, data: bytes = b""):
        self.data = data
        super().__init__()


class SelfDestruct(EvmError):
    """SELFDESTRUCT opcode."""
    def __init__(self, beneficiary: bytes = b""):
        self.beneficiary = beneficiary
        super().__init__()


class StopExecution(EvmError):
    """STOP opcode — normal halt."""
    pass


MAX_STACK_DEPTH = 1024


class Stack:
    """EVM stack: max 1024 items, each item is a 256-bit unsigned integer."""

    __slots__ = ("_data",)

    def __init__(self) -> None:
        self._data: list[int] = []

    def push(self, value: int) -> None:
        if len(self._data) >= MAX_STACK_DEPTH:
            raise StackOverflow("Stack overflow (max 1024)")
        self._data.append(value & UINT256_MAX)

    def pop(self) -> int:
        if not self._data:
            raise StackUnderflow("Stack underflow")
        return self._data.pop()

    def peek(self, depth: int = 0) -> int:
        if depth >= len(self._data):
            raise StackUnderflow(f"Stack underflow: peek({depth})")
        return self._data[-(depth + 1)]

    def swap(self, depth: int) -> None:
        """Swap top with item at depth (1-indexed: SWAP1 uses depth=1)."""
        if depth >= len(self._data):
            raise StackUnderflow(f"Stack underflow: swap({depth})")
        idx = -(depth + 1)
        self._data[-1], self._data[idx] = self._data[idx], self._data[-1]

    def dup(self, depth: int) -> None:
        """Duplicate item at depth (1-indexed: DUP1 uses depth=1)."""
        if depth > len(self._data):
            raise StackUnderflow(f"Stack underflow: dup({depth})")
        if len(self._data) >= MAX_STACK_DEPTH:
            raise StackOverflow("Stack overflow on DUP")
        self._data.append(self._data[-depth])

    @property
    def size(self) -> int:
        return len(self._data)

    def __len__(self) -> int:
        return len(self._data)


class Memory:
    """EVM memory: byte-addressable, expands in 32-byte word increments."""

    __slots__ = ("_data",)

    def __init__(self) -> None:
        self._data = bytearray()

    def _expand(self, offset: int, size: int) -> None:
        """Expand memory to cover [offset, offset+size)."""
        if size == 0:
            return
        end = offset + size
        if end > len(self._data):
            # Expand to next 32-byte boundary
            new_size = ((end + 31) // 32) * 32
            self._data.extend(b"\x00" * (new_size - len(self._data)))

    def load(self, offset: int, size: int) -> bytes:
        """Read `size` bytes from memory starting at `offset`."""
        if size == 0:
            return b""
        self._expand(offset, size)
        return bytes(self._data[offset : offset + size])

    def load_word(self, offset: int) -> int:
        """Load a 32-byte word as uint256."""
        data = self.load(offset, 32)
        return int.from_bytes(data, "big")

    def store(self, offset: int, data: bytes) -> None:
        """Write bytes to memory at offset."""
        if len(data) == 0:
            return
        self._expand(offset, len(data))
        self._data[offset : offset + len(data)] = data

    def store_word(self, offset: int, value: int) -> None:
        """Store a uint256 as 32 bytes at offset."""
        self.store(offset, (value & UINT256_MAX).to_bytes(32, "big"))

    def store_byte(self, offset: int, value: int) -> None:
        """Store a single byte at offset."""
        self._expand(offset, 1)
        self._data[offset] = value & 0xFF

    @property
    def size(self) -> int:
        return len(self._data)

    def copy(self, dst: int, src: int, length: int) -> None:
        """Copy `length` bytes within memory from src to dst."""
        if length == 0:
            return
        self._expand(src, length)
        self._expand(dst, length)
        data = bytes(self._data[src : src + length])
        self._data[dst : dst + length] = data
