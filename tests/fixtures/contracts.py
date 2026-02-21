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

# =============================================================================
# CREATE2 Factory Contracts (EIP-1014)
# =============================================================================

# Simple init code: stores 42 at slot 0
# This is the code that gets deployed by CREATE2
# Runtime: PUSH1 42 PUSH1 0 SSTORE
SIMPLE_INIT_CODE = bytes.fromhex("602a600055602a60005260206000f3")
# Explanation:
# 602a      PUSH1 42         - value to store
# 6000      PUSH1 0          - storage slot
# 55        SSTORE           - store 42 at slot 0
# 602a      PUSH1 42         - value to return
# 6000      PUSH1 0          - memory offset
# 52        MSTORE           - store in memory
# 6020      PUSH1 32         - length
# 6000      PUSH1 0          - offset
# f3        RETURN           - return runtime code

# CREATE2 Factory: Minimal factory that deploys with salt=0
# This factory uses CREATE2 to deploy SIMPLE_INIT_CODE with salt=0
# Returns the deployed contract address
# 
# Stack layout for CREATE2: value, offset, size, salt_offset
# CREATE2 pops: value, memory_start, memory_length, salt
# 
# Memory layout:
#   0x00-0x1F: salt (32 bytes of zeros)
#   0x20-...: init_code
#
# Simplified CREATE2 factory bytecode:
# 1. Store salt (32 zero bytes) at memory 0x00
# 2. Store init_code at memory 0x20
# 3. Call CREATE2 with salt at 0x00, code at 0x20
# 4. Return deployed address
CREATE2_FACTORY_BYTECODE = bytes.fromhex(
    # Store init_code in memory at 0x20
    "7f" + SIMPLE_INIT_CODE.hex().zfill(64) +  # PUSH32 init_code
    "6020" +  # PUSH1 0x20 (memory offset)
    "52" +    # MSTORE (store init_code at 0x20)

    # Store salt (32 zeros) at memory 0x00
    "5f" +    # PUSH0 (push 0)
    "5f" +    # PUSH0 (push 0)  
    "52" +    # MSTORE (store 32 zero bytes at 0x00)

    # CREATE2: pops value=0, offset=0x20, size=15, salt_offset=0x00
    # Stack: value=0, offset=0x20, size=15
    "6000" +  # PUSH1 0 (value = 0 ETH)
    "60" + format(len(SIMPLE_INIT_CODE), '02x') +  # PUSH1 init_code_length
    "6020" +  # PUSH1 0x20 (init_code offset)
    "5f" +    # PUSH0 (salt offset = 0)
    "f5" +    # CREATE2

    # Return the deployed address (20 bytes)
    "6000" +  # PUSH1 0 (memory offset for address)
    "52" +    # MSTORE (store address at 0x00)
    "6014" +  # PUSH1 20 (20 bytes = address length)
    "600c" +  # PUSH1 12 (offset in memory - addresses are last 20 of 32 bytes)
    "f3"      # RETURN
)

# Alternative CREATE2 factory with configurable salt
# This factory takes salt as constructor argument
# PUSH1 0x20 PUSH1 0x0D PUSH1 0x00 CODECOPY (copy constructor args)
# Then use salt from calldata
CREATE2_FACTORY_WITH_SALT = bytes.fromhex(
    # Copy constructor args (salt) to memory 0x00
    "6020" +  # PUSH1 32 (length)
    "600d" +  # PUSH1 13 (offset in code where constructor args start)
    "6000" +  # PUSH1 0 (dest offset)
    "39" +    # CODECOPY

    # Store init_code at memory 0x20
    "7f" + SIMPLE_INIT_CODE.hex().zfill(64) +
    "6020" +
    "52" +

    # CREATE2 with salt from memory 0x00
    "6000" +  # PUSH1 0 (value)
    "60" + format(len(SIMPLE_INIT_CODE), '02x') +  # PUSH1 size
    "6020" +  # PUSH1 offset (init_code at 0x20)
    "6000" +  # PUSH1 salt offset (salt at 0x00)
    "f5" +    # CREATE2

    # Return address
    "6000" +
    "52" +
    "6014" +
    "600c" +
    "f3"
)

# CREATE2 test vector bytecode (from EIP-1014)
# This is the simplest possible init_code: returns nothing
EMPTY_INIT_CODE = bytes.fromhex("")  # Empty init code

# Dict of all test contracts
TEST_CONTRACTS = {
    "simple_transfer": SIMPLE_TRANSFER_BYTECODE,
    "simple_storage": SIMPLE_STORAGE_BYTECODE,
    "counter": COUNTER_BYTECODE,
    "payable": PAYABLE_BYTECODE,
    "revert": REVERT_BYTECODE,
    "self_destruct": SELF_DESTRUCT_BYTECODE,
    "event": EVENT_BYTECODE,
    "create2_factory": CREATE2_FACTORY_BYTECODE,
    "create2_factory_with_salt": CREATE2_FACTORY_WITH_SALT,
    "simple_init_code": SIMPLE_INIT_CODE,
    "empty_init_code": EMPTY_INIT_CODE,
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