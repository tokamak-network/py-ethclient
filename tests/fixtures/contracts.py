"""Standard test contract bytecodes for Ethereum tests.

These are minimal contracts used for testing various scenarios.
"""

# Empty bytecode (simple transfer)
SIMPLE_TRANSFER_BYTECODE = b""

# Simple storage: store value 42 at slot 0, then return it
# This matches the bytecode from tests/conftest.py that works
SIMPLE_STORAGE_BYTECODE = bytes.fromhex("602a60005260206000f3")

# Simple counter - just return a stored value
# PUSH1 0x00 SLOAD PUSH1 0x20 MSTORE PUSH1 0x20 RETURN
COUNTER_BYTECODE = bytes.fromhex("6000546020526020f3")

# Payable contract: can receive ETH
# PUSH1 0x00 PUSH1 0x00 RETURN (empty contract)
PAYABLE_BYTECODE = bytes.fromhex("60006000f3")

# Reverting contract: always reverts
REVERT_BYTECODE = bytes.fromhex("600080fd")  # REVERT

# Self-destruct pattern
SELF_DESTRUCT_BYTECODE = bytes.fromhex(
    "6080604052600080fd"  # Placeholder
)

# Event-emitting contract placeholder
EVENT_BYTECODE = bytes.fromhex(
    "6080604052600080fd"  # Placeholder
)

# CREATE2 pattern placeholder
CREATE2_BYTECODE = bytes.fromhex(
    "6080604052600080fd"  # Placeholder
)

# Dict of all test contracts
TEST_CONTRACTS = {
    "simple_transfer": SIMPLE_TRANSFER_BYTECODE,
    "simple_storage": SIMPLE_STORAGE_BYTECODE,
    "counter": COUNTER_BYTECODE,
    "payable": PAYABLE_BYTECODE,
    "revert": REVERT_BYTECODE,
    "self_destruct": SELF_DESTRUCT_BYTECODE,
    "event": EVENT_BYTECODE,
    "create2": CREATE2_BYTECODE,
}


def get_contract(name: str) -> bytes:
    """Get contract bytecode by name.
    
    Args:
        name: Contract name from TEST_CONTRACTS
        
    Returns:
        Contract bytecode
        
    Raises:
        KeyError: If contract name not found
    """
    if name not in TEST_CONTRACTS:
        raise KeyError(f"Unknown contract: {name}. Available: {list(TEST_CONTRACTS.keys())}")
    return TEST_CONTRACTS[name]