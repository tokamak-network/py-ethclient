"""
EVM gas cost calculations.

Covers base opcode costs, memory expansion costs, and EIP-2929 warm/cold access costs.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Base gas costs (Berlin+)
# ---------------------------------------------------------------------------

G_BASE = 2
G_VERY_LOW = 3
G_LOW = 5
G_MID = 8
G_HIGH = 10
G_JUMPDEST = 1
G_WARM_ACCESS = 100         # EIP-2929
G_COLD_SLOAD = 2100         # EIP-2929
G_COLD_ACCOUNT_ACCESS = 2600  # EIP-2929
G_SSET = 20000
G_SRESET = 2900             # EIP-2929: 5000 - 2100
G_SELFDESTRUCT = 5000
G_CREATE = 32000
G_CODEDEPOSIT = 200
G_CALLVALUE = 9000
G_CALLSTIPEND = 2300
G_NEW_ACCOUNT = 25000
G_EXP = 10
G_EXP_BYTE = 50
G_MEMORY = 3
G_TX_CREATE = 32000
G_TX_DATA_ZERO = 4
G_TX_DATA_NONZERO = 16
G_TX = 21000
G_LOG = 375
G_LOG_DATA = 8
G_LOG_TOPIC = 375
G_KECCAK256 = 30
G_KECCAK256_WORD = 6
G_COPY = 3
G_BLOCKHASH = 20

# EIP-3529 (London): Reduced refunds
MAX_REFUND_QUOTIENT = 5  # max refund = gas_used // 5


# ---------------------------------------------------------------------------
# Memory expansion cost
# ---------------------------------------------------------------------------

def memory_expansion_cost(current_word_size: int, new_word_size: int) -> int:
    """Calculate the additional gas cost for expanding memory.

    Memory cost = G_MEMORY * word_size + word_size^2 / 512
    Returns the incremental cost (new total - old total).
    """
    if new_word_size <= current_word_size:
        return 0

    def _mem_cost(word_size: int) -> int:
        return G_MEMORY * word_size + (word_size * word_size) // 512

    return _mem_cost(new_word_size) - _mem_cost(current_word_size)


def memory_word_size(byte_size: int) -> int:
    """Convert byte size to word (32-byte) count, rounding up."""
    return (byte_size + 31) // 32


def calc_memory_cost(current_mem_size: int, offset: int, length: int) -> int:
    """Calculate gas cost for a memory access at [offset, offset+length).

    Returns the additional gas cost needed for expansion (0 if no expansion).
    """
    if length == 0:
        return 0
    new_end = offset + length
    current_words = memory_word_size(current_mem_size)
    new_words = memory_word_size(new_end)
    return memory_expansion_cost(current_words, new_words)


# ---------------------------------------------------------------------------
# EIP-2929 Access lists (warm/cold tracking)
# ---------------------------------------------------------------------------

class AccessSets:
    """Track warm/cold state for addresses and storage keys (EIP-2929)."""

    def __init__(self) -> None:
        self.warm_addresses: set[bytes] = set()
        self.warm_storage: set[tuple[bytes, int]] = set()

    def is_warm_address(self, address: bytes) -> bool:
        return address in self.warm_addresses

    def mark_warm_address(self, address: bytes) -> bool:
        """Mark address as warm. Returns True if it was already warm."""
        was_warm = address in self.warm_addresses
        self.warm_addresses.add(address)
        return was_warm

    def is_warm_storage(self, address: bytes, key: int) -> bool:
        return (address, key) in self.warm_storage

    def mark_warm_storage(self, address: bytes, key: int) -> bool:
        """Mark storage slot as warm. Returns True if it was already warm."""
        slot = (address, key)
        was_warm = slot in self.warm_storage
        self.warm_storage.add(slot)
        return was_warm

    def snapshot(self) -> tuple[frozenset[bytes], frozenset[tuple[bytes, int]]]:
        return frozenset(self.warm_addresses), frozenset(self.warm_storage)

    def restore(self, snap: tuple[frozenset[bytes], frozenset[tuple[bytes, int]]]) -> None:
        self.warm_addresses = set(snap[0])
        self.warm_storage = set(snap[1])


# ---------------------------------------------------------------------------
# SSTORE gas (EIP-2200 + EIP-3529)
# ---------------------------------------------------------------------------

def sstore_gas(
    current_value: int,
    new_value: int,
    original_value: int,
    is_warm: bool,
) -> tuple[int, int]:
    """Calculate SSTORE gas cost and refund (EIP-2200 / EIP-3529).

    Returns (gas_cost, refund_delta).
    """
    warm_cost = 0 if is_warm else G_COLD_SLOAD

    if current_value == new_value:
        return G_WARM_ACCESS + warm_cost, 0

    refund = 0

    if original_value == current_value:
        # Slot hasn't been changed yet in this tx
        if original_value == 0:
            return G_SSET + warm_cost, 0
        else:
            if new_value == 0:
                refund = 4800  # EIP-3529
            return G_SRESET + warm_cost, refund
    else:
        # Slot was already changed
        gas = G_WARM_ACCESS + warm_cost

        if original_value != 0:
            if current_value == 0:
                refund -= 4800
            elif new_value == 0:
                refund += 4800

        if original_value == new_value:
            if original_value == 0:
                refund += G_SSET - G_WARM_ACCESS
            else:
                refund += G_SRESET - G_WARM_ACCESS

        return gas, refund


# ---------------------------------------------------------------------------
# CALL gas calculation
# ---------------------------------------------------------------------------

def call_gas(
    gas_available: int,
    gas_requested: int,
    has_value: bool,
    is_new_account: bool,
) -> tuple[int, int]:
    """Calculate gas for CALL-type opcodes.

    Returns (total_gas_cost, gas_for_callee).
    """
    extra = 0
    if has_value:
        extra += G_CALLVALUE
    if is_new_account:
        extra += G_NEW_ACCOUNT

    # EIP-150: cap gas sent to callee at 63/64 of available
    gas_after_extra = gas_available - extra
    if gas_after_extra < 0:
        gas_after_extra = 0

    max_callee_gas = gas_after_extra - (gas_after_extra // 64)
    callee_gas = min(gas_requested, max_callee_gas)

    total_cost = extra + callee_gas
    if has_value:
        callee_gas += G_CALLSTIPEND  # free gas for value transfer

    return total_cost, callee_gas


# ---------------------------------------------------------------------------
# EXP gas
# ---------------------------------------------------------------------------

def exp_gas(exponent: int) -> int:
    """Gas cost for EXP opcode."""
    if exponent == 0:
        return G_EXP
    byte_len = (exponent.bit_length() + 7) // 8
    return G_EXP + G_EXP_BYTE * byte_len


# ---------------------------------------------------------------------------
# Intrinsic gas for a transaction
# ---------------------------------------------------------------------------

def intrinsic_gas(data: bytes, is_create: bool, access_list_len: int = 0) -> int:
    """Calculate the intrinsic gas for a transaction."""
    gas = G_TX
    if is_create:
        gas += G_TX_CREATE
    for byte in data:
        gas += G_TX_DATA_ZERO if byte == 0 else G_TX_DATA_NONZERO
    # EIP-2930: access list items
    gas += access_list_len * 2400
    return gas
