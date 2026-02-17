"""
EVM opcode definitions and handlers.

Each handler takes a CallFrame and an ExecutionEnvironment and modifies them.
Opcodes are registered in the OPCODE_TABLE dict.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ethclient.vm.memory import (
    UINT256_MAX,
    UINT256_CEIL,
    StackUnderflow,
    InvalidJumpDest,
    StopExecution,
    ReturnData,
    Revert,
    SelfDestruct,
    WriteProtection,
    InvalidOpcode,
)
from ethclient.vm.gas import (
    G_VERY_LOW,
    G_LOW,
    G_MID,
    G_HIGH,
    G_BASE,
    G_JUMPDEST,
    G_WARM_ACCESS,
    G_COLD_SLOAD,
    G_COLD_ACCOUNT_ACCESS,
    G_LOG,
    G_LOG_DATA,
    G_LOG_TOPIC,
    G_KECCAK256,
    G_KECCAK256_WORD,
    G_COPY,
    G_BLOCKHASH,
    G_CREATE,
    G_CALLVALUE,
    G_CALLSTIPEND,
    G_NEW_ACCOUNT,
    G_CODEDEPOSIT,
    G_SELFDESTRUCT,
    calc_memory_cost,
    memory_word_size,
    exp_gas,
    sstore_gas,
    call_gas,
)

if TYPE_CHECKING:
    from ethclient.vm.evm import ExecutionEnvironment


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_signed(value: int) -> int:
    """Convert uint256 to signed int256."""
    if value >= (1 << 255):
        return value - UINT256_CEIL
    return value


def _to_unsigned(value: int) -> int:
    """Convert signed int256 to uint256."""
    return value % UINT256_CEIL


# ---------------------------------------------------------------------------
# Opcode enum / names
# ---------------------------------------------------------------------------

# fmt: off
class Op:
    STOP            = 0x00
    ADD             = 0x01
    MUL             = 0x02
    SUB             = 0x03
    DIV             = 0x04
    SDIV            = 0x05
    MOD             = 0x06
    SMOD            = 0x07
    ADDMOD          = 0x08
    MULMOD          = 0x09
    EXP             = 0x0A
    SIGNEXTEND      = 0x0B
    LT              = 0x10
    GT              = 0x11
    SLT             = 0x12
    SGT             = 0x13
    EQ              = 0x14
    ISZERO          = 0x15
    AND             = 0x16
    OR              = 0x17
    XOR             = 0x18
    NOT             = 0x19
    BYTE            = 0x1A
    SHL             = 0x1B
    SHR             = 0x1C
    SAR             = 0x1D
    KECCAK256       = 0x20
    ADDRESS         = 0x30
    BALANCE         = 0x31
    ORIGIN          = 0x32
    CALLER          = 0x33
    CALLVALUE       = 0x34
    CALLDATALOAD    = 0x35
    CALLDATASIZE    = 0x36
    CALLDATACOPY    = 0x37
    CODESIZE        = 0x38
    CODECOPY        = 0x39
    GASPRICE        = 0x3A
    EXTCODESIZE     = 0x3B
    EXTCODECOPY     = 0x3C
    RETURNDATASIZE  = 0x3D
    RETURNDATACOPY  = 0x3E
    EXTCODEHASH     = 0x3F
    BLOCKHASH       = 0x40
    COINBASE        = 0x41
    TIMESTAMP       = 0x42
    NUMBER          = 0x43
    PREVRANDAO      = 0x44  # was DIFFICULTY pre-merge
    GASLIMIT        = 0x45
    CHAINID         = 0x46
    SELFBALANCE     = 0x47
    BASEFEE         = 0x48
    BLOBHASH        = 0x49
    BLOBBASEFEE     = 0x4A
    POP             = 0x50
    MLOAD           = 0x51
    MSTORE          = 0x52
    MSTORE8         = 0x53
    SLOAD           = 0x54
    SSTORE          = 0x55
    JUMP            = 0x56
    JUMPI           = 0x57
    PC              = 0x58
    MSIZE           = 0x59
    GAS             = 0x5A
    JUMPDEST        = 0x5B
    TLOAD           = 0x5C
    TSTORE          = 0x5D
    MCOPY           = 0x5E
    PUSH0           = 0x5F
    PUSH1           = 0x60
    PUSH32          = 0x7F
    DUP1            = 0x80
    DUP16           = 0x8F
    SWAP1           = 0x90
    SWAP16          = 0x9F
    LOG0            = 0xA0
    LOG4            = 0xA4
    CREATE          = 0xF0
    CALL            = 0xF1
    CALLCODE        = 0xF2
    RETURN          = 0xF3
    DELEGATECALL    = 0xF4
    CREATE2         = 0xF5
    STATICCALL      = 0xFA
    REVERT          = 0xFD
    INVALID         = 0xFE
    SELFDESTRUCT    = 0xFF
# fmt: on


# ---------------------------------------------------------------------------
# Opcode handlers — each returns the PC increment (0 = already set PC)
# ---------------------------------------------------------------------------

def op_stop(frame, env):
    raise StopExecution()


# -- Arithmetic --

def op_add(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push((a + b) % UINT256_CEIL)
    frame.pc += 1


def op_mul(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push((a * b) % UINT256_CEIL)
    frame.pc += 1


def op_sub(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push((a - b) % UINT256_CEIL)
    frame.pc += 1


def op_div(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push(a // b if b != 0 else 0)
    frame.pc += 1


def op_sdiv(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    if b == 0:
        frame.stack.push(0)
    else:
        sa, sb = _to_signed(a), _to_signed(b)
        if sa == -(1 << 255) and sb == -1:
            frame.stack.push(1 << 255)  # overflow case
        else:
            sign = -1 if (sa < 0) ^ (sb < 0) else 1
            frame.stack.push(_to_unsigned(sign * (abs(sa) // abs(sb))))
    frame.pc += 1


def op_mod(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push(a % b if b != 0 else 0)
    frame.pc += 1


def op_smod(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    if b == 0:
        frame.stack.push(0)
    else:
        sa, sb = _to_signed(a), _to_signed(b)
        sign = -1 if sa < 0 else 1
        frame.stack.push(_to_unsigned(sign * (abs(sa) % abs(sb))))
    frame.pc += 1


def op_addmod(frame, env):
    a, b, n = frame.stack.pop(), frame.stack.pop(), frame.stack.pop()
    frame.stack.push((a + b) % n if n != 0 else 0)
    frame.pc += 1


def op_mulmod(frame, env):
    a, b, n = frame.stack.pop(), frame.stack.pop(), frame.stack.pop()
    frame.stack.push((a * b) % n if n != 0 else 0)
    frame.pc += 1


def op_exp(frame, env):
    base, exponent = frame.stack.pop(), frame.stack.pop()
    frame.consume_gas(exp_gas(exponent) - G_LOW)  # base G_LOW already charged
    frame.stack.push(pow(base, exponent, UINT256_CEIL))
    frame.pc += 1


def op_signextend(frame, env):
    b, x = frame.stack.pop(), frame.stack.pop()
    if b < 31:
        bit = b * 8 + 7
        mask = (1 << bit) - 1
        if x & (1 << bit):
            frame.stack.push(x | (UINT256_MAX - mask))
        else:
            frame.stack.push(x & mask)
    else:
        frame.stack.push(x)
    frame.pc += 1


# -- Comparison & Bitwise --

def op_lt(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push(1 if a < b else 0)
    frame.pc += 1


def op_gt(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push(1 if a > b else 0)
    frame.pc += 1


def op_slt(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push(1 if _to_signed(a) < _to_signed(b) else 0)
    frame.pc += 1


def op_sgt(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push(1 if _to_signed(a) > _to_signed(b) else 0)
    frame.pc += 1


def op_eq(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push(1 if a == b else 0)
    frame.pc += 1


def op_iszero(frame, env):
    a = frame.stack.pop()
    frame.stack.push(1 if a == 0 else 0)
    frame.pc += 1


def op_and(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push(a & b)
    frame.pc += 1


def op_or(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push(a | b)
    frame.pc += 1


def op_xor(frame, env):
    a, b = frame.stack.pop(), frame.stack.pop()
    frame.stack.push(a ^ b)
    frame.pc += 1


def op_not(frame, env):
    a = frame.stack.pop()
    frame.stack.push(a ^ UINT256_MAX)
    frame.pc += 1


def op_byte(frame, env):
    i, x = frame.stack.pop(), frame.stack.pop()
    if i >= 32:
        frame.stack.push(0)
    else:
        frame.stack.push((x >> (248 - i * 8)) & 0xFF)
    frame.pc += 1


def op_shl(frame, env):
    shift, value = frame.stack.pop(), frame.stack.pop()
    if shift >= 256:
        frame.stack.push(0)
    else:
        frame.stack.push((value << shift) % UINT256_CEIL)
    frame.pc += 1


def op_shr(frame, env):
    shift, value = frame.stack.pop(), frame.stack.pop()
    if shift >= 256:
        frame.stack.push(0)
    else:
        frame.stack.push(value >> shift)
    frame.pc += 1


def op_sar(frame, env):
    shift, value = frame.stack.pop(), frame.stack.pop()
    signed = _to_signed(value)
    if shift >= 256:
        frame.stack.push(_to_unsigned(-1 if signed < 0 else 0))
    else:
        frame.stack.push(_to_unsigned(signed >> shift))
    frame.pc += 1


# -- Keccak256 --

def op_keccak256(frame, env):
    from ethclient.common.crypto import keccak256
    offset, size = frame.stack.pop(), frame.stack.pop()
    gas_cost = G_KECCAK256_WORD * memory_word_size(size)
    gas_cost += calc_memory_cost(frame.memory.size, offset, size)
    frame.consume_gas(gas_cost)
    data = frame.memory.load(offset, size)
    frame.stack.push(int.from_bytes(keccak256(data), "big"))
    frame.pc += 1


# -- Environment --

def op_address(frame, env):
    frame.stack.push(int.from_bytes(frame.address, "big"))
    frame.pc += 1


def op_balance(frame, env):
    addr_int = frame.stack.pop()
    addr = addr_int.to_bytes(20, "big")
    was_warm = env.access_sets.mark_warm_address(addr)
    if not was_warm:
        frame.consume_gas(G_COLD_ACCOUNT_ACCESS - G_WARM_ACCESS)
    balance = env.get_balance(addr)
    frame.stack.push(balance)
    frame.pc += 1


def op_origin(frame, env):
    frame.stack.push(int.from_bytes(frame.origin, "big"))
    frame.pc += 1


def op_caller(frame, env):
    frame.stack.push(int.from_bytes(frame.caller, "big"))
    frame.pc += 1


def op_callvalue(frame, env):
    frame.stack.push(frame.value)
    frame.pc += 1


def op_calldataload(frame, env):
    offset = frame.stack.pop()
    data = frame.calldata
    chunk = data[offset : offset + 32] if offset < len(data) else b""
    # Pad to 32 bytes
    chunk = chunk.ljust(32, b"\x00")
    frame.stack.push(int.from_bytes(chunk, "big"))
    frame.pc += 1


def op_calldatasize(frame, env):
    frame.stack.push(len(frame.calldata))
    frame.pc += 1


def op_calldatacopy(frame, env):
    dest_offset = frame.stack.pop()
    data_offset = frame.stack.pop()
    size = frame.stack.pop()
    gas_cost = G_COPY * memory_word_size(size)
    gas_cost += calc_memory_cost(frame.memory.size, dest_offset, size)
    frame.consume_gas(gas_cost)
    data = frame.calldata
    src = data[data_offset : data_offset + size] if data_offset < len(data) else b""
    src = src.ljust(size, b"\x00")
    frame.memory.store(dest_offset, src[:size])
    frame.pc += 1


def op_codesize(frame, env):
    frame.stack.push(len(frame.code))
    frame.pc += 1


def op_codecopy(frame, env):
    dest_offset = frame.stack.pop()
    code_offset = frame.stack.pop()
    size = frame.stack.pop()
    gas_cost = G_COPY * memory_word_size(size)
    gas_cost += calc_memory_cost(frame.memory.size, dest_offset, size)
    frame.consume_gas(gas_cost)
    code = frame.code
    src = code[code_offset : code_offset + size]
    src = src.ljust(size, b"\x00")
    frame.memory.store(dest_offset, src[:size])
    frame.pc += 1


def op_gasprice(frame, env):
    frame.stack.push(env.gas_price)
    frame.pc += 1


def op_extcodesize(frame, env):
    addr_int = frame.stack.pop()
    addr = addr_int.to_bytes(20, "big")
    was_warm = env.access_sets.mark_warm_address(addr)
    if not was_warm:
        frame.consume_gas(G_COLD_ACCOUNT_ACCESS - G_WARM_ACCESS)
    code = env.get_code(addr)
    frame.stack.push(len(code))
    frame.pc += 1


def op_extcodecopy(frame, env):
    addr_int = frame.stack.pop()
    dest_offset = frame.stack.pop()
    code_offset = frame.stack.pop()
    size = frame.stack.pop()
    addr = addr_int.to_bytes(20, "big")
    was_warm = env.access_sets.mark_warm_address(addr)
    if not was_warm:
        frame.consume_gas(G_COLD_ACCOUNT_ACCESS - G_WARM_ACCESS)
    gas_cost = G_COPY * memory_word_size(size)
    gas_cost += calc_memory_cost(frame.memory.size, dest_offset, size)
    frame.consume_gas(gas_cost)
    code = env.get_code(addr)
    src = code[code_offset : code_offset + size]
    src = src.ljust(size, b"\x00")
    frame.memory.store(dest_offset, src[:size])
    frame.pc += 1


def op_returndatasize(frame, env):
    frame.stack.push(len(frame.return_data))
    frame.pc += 1


def op_returndatacopy(frame, env):
    dest_offset = frame.stack.pop()
    data_offset = frame.stack.pop()
    size = frame.stack.pop()
    if data_offset + size > len(frame.return_data):
        from ethclient.vm.memory import EvmError
        raise EvmError("RETURNDATACOPY out of bounds")
    gas_cost = G_COPY * memory_word_size(size)
    gas_cost += calc_memory_cost(frame.memory.size, dest_offset, size)
    frame.consume_gas(gas_cost)
    src = frame.return_data[data_offset : data_offset + size]
    frame.memory.store(dest_offset, src)
    frame.pc += 1


def op_extcodehash(frame, env):
    from ethclient.common.crypto import keccak256
    addr_int = frame.stack.pop()
    addr = addr_int.to_bytes(20, "big")
    was_warm = env.access_sets.mark_warm_address(addr)
    if not was_warm:
        frame.consume_gas(G_COLD_ACCOUNT_ACCESS - G_WARM_ACCESS)
    if not env.account_exists(addr):
        frame.stack.push(0)
    else:
        code = env.get_code(addr)
        frame.stack.push(int.from_bytes(keccak256(code), "big"))
    frame.pc += 1


# -- Block info --

def op_blockhash(frame, env):
    block_num = frame.stack.pop()
    current = env.block_number
    if block_num >= current or current - block_num > 256:
        frame.stack.push(0)
    else:
        h = env.get_block_hash(block_num)
        frame.stack.push(int.from_bytes(h, "big"))
    frame.pc += 1


def op_coinbase(frame, env):
    frame.stack.push(int.from_bytes(env.coinbase, "big"))
    frame.pc += 1


def op_timestamp(frame, env):
    frame.stack.push(env.timestamp)
    frame.pc += 1


def op_number(frame, env):
    frame.stack.push(env.block_number)
    frame.pc += 1


def op_prevrandao(frame, env):
    frame.stack.push(env.prevrandao)
    frame.pc += 1


def op_gaslimit(frame, env):
    frame.stack.push(env.gas_limit)
    frame.pc += 1


def op_chainid(frame, env):
    frame.stack.push(env.chain_id)
    frame.pc += 1


def op_selfbalance(frame, env):
    balance = env.get_balance(frame.address)
    frame.stack.push(balance)
    frame.pc += 1


def op_basefee(frame, env):
    frame.stack.push(env.base_fee)
    frame.pc += 1


def op_blobhash(frame, env):
    idx = frame.stack.pop()
    if idx < len(env.blob_hashes):
        frame.stack.push(int.from_bytes(env.blob_hashes[idx], "big"))
    else:
        frame.stack.push(0)
    frame.pc += 1


def op_blobbasefee(frame, env):
    frame.stack.push(env.blob_base_fee)
    frame.pc += 1


# -- Stack, Memory, Storage, Flow --

def op_pop(frame, env):
    frame.stack.pop()
    frame.pc += 1


def op_mload(frame, env):
    offset = frame.stack.pop()
    gas_cost = calc_memory_cost(frame.memory.size, offset, 32)
    frame.consume_gas(gas_cost)
    frame.stack.push(frame.memory.load_word(offset))
    frame.pc += 1


def op_mstore(frame, env):
    offset = frame.stack.pop()
    value = frame.stack.pop()
    gas_cost = calc_memory_cost(frame.memory.size, offset, 32)
    frame.consume_gas(gas_cost)
    frame.memory.store_word(offset, value)
    frame.pc += 1


def op_mstore8(frame, env):
    offset = frame.stack.pop()
    value = frame.stack.pop()
    gas_cost = calc_memory_cost(frame.memory.size, offset, 1)
    frame.consume_gas(gas_cost)
    frame.memory.store_byte(offset, value & 0xFF)
    frame.pc += 1


def op_sload(frame, env):
    key = frame.stack.pop()
    was_warm = env.access_sets.mark_warm_storage(frame.address, key)
    if not was_warm:
        frame.consume_gas(G_COLD_SLOAD - G_WARM_ACCESS)
    value = env.get_storage(frame.address, key)
    frame.stack.push(value)
    frame.pc += 1


def op_sstore(frame, env):
    if frame.is_static:
        raise WriteProtection("SSTORE in static call")
    key = frame.stack.pop()
    new_value = frame.stack.pop()
    was_warm = env.access_sets.mark_warm_storage(frame.address, key)
    current = env.get_storage(frame.address, key)
    original = env.get_original_storage(frame.address, key)
    gas_cost, refund = sstore_gas(current, new_value, original, was_warm)
    frame.consume_gas(gas_cost - G_WARM_ACCESS)  # base already charged
    env.set_storage(frame.address, key, new_value)
    env.refund += refund
    frame.pc += 1


def op_jump(frame, env):
    dest = frame.stack.pop()
    if dest not in frame.valid_jumpdests:
        raise InvalidJumpDest(f"Invalid JUMP destination: {dest}")
    frame.pc = dest


def op_jumpi(frame, env):
    dest = frame.stack.pop()
    cond = frame.stack.pop()
    if cond != 0:
        if dest not in frame.valid_jumpdests:
            raise InvalidJumpDest(f"Invalid JUMPI destination: {dest}")
        frame.pc = dest
    else:
        frame.pc += 1


def op_pc(frame, env):
    frame.stack.push(frame.pc)
    frame.pc += 1


def op_msize(frame, env):
    frame.stack.push(frame.memory.size)
    frame.pc += 1


def op_gas(frame, env):
    frame.stack.push(frame.remaining_gas)
    frame.pc += 1


def op_jumpdest(frame, env):
    frame.pc += 1


def op_tload(frame, env):
    key = frame.stack.pop()
    value = env.get_transient(frame.address, key)
    frame.stack.push(value)
    frame.pc += 1


def op_tstore(frame, env):
    if frame.is_static:
        raise WriteProtection("TSTORE in static call")
    key = frame.stack.pop()
    value = frame.stack.pop()
    env.set_transient(frame.address, key, value)
    frame.pc += 1


def op_mcopy(frame, env):
    dest = frame.stack.pop()
    src = frame.stack.pop()
    size = frame.stack.pop()
    gas_cost = G_COPY * memory_word_size(size)
    gas_cost += calc_memory_cost(frame.memory.size, max(dest, src), size)
    frame.consume_gas(gas_cost)
    frame.memory.copy(dest, src, size)
    frame.pc += 1


# -- PUSH --

def op_push0(frame, env):
    frame.stack.push(0)
    frame.pc += 1


def _make_push(n: int):
    def op_push(frame, env):
        data = frame.code[frame.pc + 1 : frame.pc + 1 + n]
        value = int.from_bytes(data.ljust(n, b"\x00"), "big")
        frame.stack.push(value)
        frame.pc += 1 + n
    return op_push


# -- DUP --

def _make_dup(n: int):
    def op_dup(frame, env):
        frame.stack.dup(n)
        frame.pc += 1
    return op_dup


# -- SWAP --

def _make_swap(n: int):
    def op_swap(frame, env):
        frame.stack.swap(n)
        frame.pc += 1
    return op_swap


# -- LOG --

def _make_log(topic_count: int):
    def op_log(frame, env):
        if frame.is_static:
            raise WriteProtection(f"LOG{topic_count} in static call")
        offset = frame.stack.pop()
        size = frame.stack.pop()
        topics = [frame.stack.pop().to_bytes(32, "big") for _ in range(topic_count)]
        gas_cost = G_LOG + G_LOG_TOPIC * topic_count + G_LOG_DATA * size
        gas_cost += calc_memory_cost(frame.memory.size, offset, size)
        frame.consume_gas(gas_cost - G_LOG)  # base already in table
        data = frame.memory.load(offset, size)
        env.add_log(frame.address, topics, data)
        frame.pc += 1
    return op_log


# -- System --

def op_create(frame, env):
    if frame.is_static:
        raise WriteProtection("CREATE in static call")
    value = frame.stack.pop()
    offset = frame.stack.pop()
    size = frame.stack.pop()
    gas_cost = calc_memory_cost(frame.memory.size, offset, size)
    frame.consume_gas(gas_cost)
    init_code = frame.memory.load(offset, size)
    result = env.do_create(frame, value, init_code, None)
    frame.stack.push(result)
    frame.pc += 1


def op_create2(frame, env):
    if frame.is_static:
        raise WriteProtection("CREATE2 in static call")
    value = frame.stack.pop()
    offset = frame.stack.pop()
    size = frame.stack.pop()
    salt = frame.stack.pop()
    gas_cost = calc_memory_cost(frame.memory.size, offset, size)
    gas_cost += G_KECCAK256_WORD * memory_word_size(size)
    frame.consume_gas(gas_cost)
    init_code = frame.memory.load(offset, size)
    result = env.do_create(frame, value, init_code, salt)
    frame.stack.push(result)
    frame.pc += 1


def op_call(frame, env):
    gas_req = frame.stack.pop()
    addr_int = frame.stack.pop()
    value = frame.stack.pop()
    args_offset = frame.stack.pop()
    args_size = frame.stack.pop()
    ret_offset = frame.stack.pop()
    ret_size = frame.stack.pop()

    addr = addr_int.to_bytes(20, "big")
    was_warm = env.access_sets.mark_warm_address(addr)
    if not was_warm:
        frame.consume_gas(G_COLD_ACCOUNT_ACCESS - G_WARM_ACCESS)

    if frame.is_static and value > 0:
        raise WriteProtection("CALL with value in static context")

    mem_cost = calc_memory_cost(frame.memory.size, args_offset, args_size)
    mem_cost += calc_memory_cost(frame.memory.size, ret_offset, ret_size)
    frame.consume_gas(mem_cost)

    calldata = frame.memory.load(args_offset, args_size)

    has_value = value > 0
    is_new = has_value and not env.account_exists(addr)
    total_cost, callee_gas = call_gas(
        frame.remaining_gas, gas_req, has_value, is_new
    )
    frame.consume_gas(total_cost)

    success, return_data = env.do_call(
        frame, addr, addr, value, calldata, callee_gas, frame.is_static
    )
    frame.return_data = return_data
    ret = return_data[:ret_size]
    frame.memory.store(ret_offset, ret.ljust(ret_size, b"\x00")[:ret_size] if ret else b"\x00" * ret_size if ret_size > 0 else b"")

    frame.stack.push(1 if success else 0)
    frame.pc += 1


def op_callcode(frame, env):
    gas_req = frame.stack.pop()
    addr_int = frame.stack.pop()
    value = frame.stack.pop()
    args_offset = frame.stack.pop()
    args_size = frame.stack.pop()
    ret_offset = frame.stack.pop()
    ret_size = frame.stack.pop()

    addr = addr_int.to_bytes(20, "big")
    was_warm = env.access_sets.mark_warm_address(addr)
    if not was_warm:
        frame.consume_gas(G_COLD_ACCOUNT_ACCESS - G_WARM_ACCESS)

    mem_cost = calc_memory_cost(frame.memory.size, args_offset, args_size)
    mem_cost += calc_memory_cost(frame.memory.size, ret_offset, ret_size)
    frame.consume_gas(mem_cost)

    calldata = frame.memory.load(args_offset, args_size)
    has_value = value > 0
    total_cost, callee_gas = call_gas(
        frame.remaining_gas, gas_req, has_value, False
    )
    frame.consume_gas(total_cost)

    # CALLCODE: runs addr's code in current context
    success, return_data = env.do_call(
        frame, frame.address, addr, value, calldata, callee_gas, frame.is_static
    )
    frame.return_data = return_data
    if ret_size > 0:
        ret = return_data[:ret_size].ljust(ret_size, b"\x00")
        frame.memory.store(ret_offset, ret)

    frame.stack.push(1 if success else 0)
    frame.pc += 1


def op_delegatecall(frame, env):
    gas_req = frame.stack.pop()
    addr_int = frame.stack.pop()
    args_offset = frame.stack.pop()
    args_size = frame.stack.pop()
    ret_offset = frame.stack.pop()
    ret_size = frame.stack.pop()

    addr = addr_int.to_bytes(20, "big")
    was_warm = env.access_sets.mark_warm_address(addr)
    if not was_warm:
        frame.consume_gas(G_COLD_ACCOUNT_ACCESS - G_WARM_ACCESS)

    mem_cost = calc_memory_cost(frame.memory.size, args_offset, args_size)
    mem_cost += calc_memory_cost(frame.memory.size, ret_offset, ret_size)
    frame.consume_gas(mem_cost)

    calldata = frame.memory.load(args_offset, args_size)
    total_cost, callee_gas = call_gas(
        frame.remaining_gas, gas_req, False, False
    )
    frame.consume_gas(total_cost)

    success, return_data = env.do_delegatecall(
        frame, addr, calldata, callee_gas
    )
    frame.return_data = return_data
    if ret_size > 0:
        ret = return_data[:ret_size].ljust(ret_size, b"\x00")
        frame.memory.store(ret_offset, ret)

    frame.stack.push(1 if success else 0)
    frame.pc += 1


def op_staticcall(frame, env):
    gas_req = frame.stack.pop()
    addr_int = frame.stack.pop()
    args_offset = frame.stack.pop()
    args_size = frame.stack.pop()
    ret_offset = frame.stack.pop()
    ret_size = frame.stack.pop()

    addr = addr_int.to_bytes(20, "big")
    was_warm = env.access_sets.mark_warm_address(addr)
    if not was_warm:
        frame.consume_gas(G_COLD_ACCOUNT_ACCESS - G_WARM_ACCESS)

    mem_cost = calc_memory_cost(frame.memory.size, args_offset, args_size)
    mem_cost += calc_memory_cost(frame.memory.size, ret_offset, ret_size)
    frame.consume_gas(mem_cost)

    calldata = frame.memory.load(args_offset, args_size)
    total_cost, callee_gas = call_gas(
        frame.remaining_gas, gas_req, False, False
    )
    frame.consume_gas(total_cost)

    success, return_data = env.do_call(
        frame, addr, addr, 0, calldata, callee_gas, True
    )
    frame.return_data = return_data
    if ret_size > 0:
        ret = return_data[:ret_size].ljust(ret_size, b"\x00")
        frame.memory.store(ret_offset, ret)

    frame.stack.push(1 if success else 0)
    frame.pc += 1


def op_return(frame, env):
    offset = frame.stack.pop()
    size = frame.stack.pop()
    gas_cost = calc_memory_cost(frame.memory.size, offset, size)
    frame.consume_gas(gas_cost)
    data = frame.memory.load(offset, size)
    raise ReturnData(data)


def op_revert(frame, env):
    offset = frame.stack.pop()
    size = frame.stack.pop()
    gas_cost = calc_memory_cost(frame.memory.size, offset, size)
    frame.consume_gas(gas_cost)
    data = frame.memory.load(offset, size)
    raise Revert(data)


def op_invalid(frame, env):
    raise InvalidOpcode("INVALID opcode (0xFE)")


def op_selfdestruct(frame, env):
    if frame.is_static:
        raise WriteProtection("SELFDESTRUCT in static call")
    addr_int = frame.stack.pop()
    addr = addr_int.to_bytes(20, "big")
    raise SelfDestruct(addr)


# ---------------------------------------------------------------------------
# Opcode table: opcode -> (handler, base_gas_cost)
# ---------------------------------------------------------------------------

OPCODE_TABLE: dict[int, tuple[callable, int]] = {}


def _register():
    t = OPCODE_TABLE

    t[Op.STOP] = (op_stop, G_VERY_LOW)
    t[Op.ADD] = (op_add, G_VERY_LOW)
    t[Op.MUL] = (op_mul, G_LOW)
    t[Op.SUB] = (op_sub, G_VERY_LOW)
    t[Op.DIV] = (op_div, G_LOW)
    t[Op.SDIV] = (op_sdiv, G_LOW)
    t[Op.MOD] = (op_mod, G_LOW)
    t[Op.SMOD] = (op_smod, G_LOW)
    t[Op.ADDMOD] = (op_addmod, G_MID)
    t[Op.MULMOD] = (op_mulmod, G_MID)
    t[Op.EXP] = (op_exp, G_LOW)
    t[Op.SIGNEXTEND] = (op_signextend, G_LOW)

    t[Op.LT] = (op_lt, G_VERY_LOW)
    t[Op.GT] = (op_gt, G_VERY_LOW)
    t[Op.SLT] = (op_slt, G_VERY_LOW)
    t[Op.SGT] = (op_sgt, G_VERY_LOW)
    t[Op.EQ] = (op_eq, G_VERY_LOW)
    t[Op.ISZERO] = (op_iszero, G_VERY_LOW)
    t[Op.AND] = (op_and, G_VERY_LOW)
    t[Op.OR] = (op_or, G_VERY_LOW)
    t[Op.XOR] = (op_xor, G_VERY_LOW)
    t[Op.NOT] = (op_not, G_VERY_LOW)
    t[Op.BYTE] = (op_byte, G_VERY_LOW)
    t[Op.SHL] = (op_shl, G_VERY_LOW)
    t[Op.SHR] = (op_shr, G_VERY_LOW)
    t[Op.SAR] = (op_sar, G_VERY_LOW)

    t[Op.KECCAK256] = (op_keccak256, G_KECCAK256)

    t[Op.ADDRESS] = (op_address, G_BASE)
    t[Op.BALANCE] = (op_balance, G_WARM_ACCESS)
    t[Op.ORIGIN] = (op_origin, G_BASE)
    t[Op.CALLER] = (op_caller, G_BASE)
    t[Op.CALLVALUE] = (op_callvalue, G_BASE)
    t[Op.CALLDATALOAD] = (op_calldataload, G_VERY_LOW)
    t[Op.CALLDATASIZE] = (op_calldatasize, G_BASE)
    t[Op.CALLDATACOPY] = (op_calldatacopy, G_VERY_LOW)
    t[Op.CODESIZE] = (op_codesize, G_BASE)
    t[Op.CODECOPY] = (op_codecopy, G_VERY_LOW)
    t[Op.GASPRICE] = (op_gasprice, G_BASE)
    t[Op.EXTCODESIZE] = (op_extcodesize, G_WARM_ACCESS)
    t[Op.EXTCODECOPY] = (op_extcodecopy, G_WARM_ACCESS)
    t[Op.RETURNDATASIZE] = (op_returndatasize, G_BASE)
    t[Op.RETURNDATACOPY] = (op_returndatacopy, G_VERY_LOW)
    t[Op.EXTCODEHASH] = (op_extcodehash, G_WARM_ACCESS)

    t[Op.BLOCKHASH] = (op_blockhash, G_BLOCKHASH)
    t[Op.COINBASE] = (op_coinbase, G_BASE)
    t[Op.TIMESTAMP] = (op_timestamp, G_BASE)
    t[Op.NUMBER] = (op_number, G_BASE)
    t[Op.PREVRANDAO] = (op_prevrandao, G_BASE)
    t[Op.GASLIMIT] = (op_gaslimit, G_BASE)
    t[Op.CHAINID] = (op_chainid, G_BASE)
    t[Op.SELFBALANCE] = (op_selfbalance, G_LOW)
    t[Op.BASEFEE] = (op_basefee, G_BASE)
    t[Op.BLOBHASH] = (op_blobhash, G_VERY_LOW)
    t[Op.BLOBBASEFEE] = (op_blobbasefee, G_BASE)

    t[Op.POP] = (op_pop, G_BASE)
    t[Op.MLOAD] = (op_mload, G_VERY_LOW)
    t[Op.MSTORE] = (op_mstore, G_VERY_LOW)
    t[Op.MSTORE8] = (op_mstore8, G_VERY_LOW)
    t[Op.SLOAD] = (op_sload, G_WARM_ACCESS)
    t[Op.SSTORE] = (op_sstore, G_WARM_ACCESS)
    t[Op.JUMP] = (op_jump, G_MID)
    t[Op.JUMPI] = (op_jumpi, G_HIGH)
    t[Op.PC] = (op_pc, G_BASE)
    t[Op.MSIZE] = (op_msize, G_BASE)
    t[Op.GAS] = (op_gas, G_BASE)
    t[Op.JUMPDEST] = (op_jumpdest, G_JUMPDEST)
    t[Op.TLOAD] = (op_tload, G_WARM_ACCESS)
    t[Op.TSTORE] = (op_tstore, G_WARM_ACCESS)
    t[Op.MCOPY] = (op_mcopy, G_VERY_LOW)

    t[Op.PUSH0] = (op_push0, G_BASE)
    for i in range(1, 33):
        t[Op.PUSH1 + i - 1] = (_make_push(i), G_VERY_LOW)

    for i in range(1, 17):
        t[Op.DUP1 + i - 1] = (_make_dup(i), G_VERY_LOW)

    for i in range(1, 17):
        t[Op.SWAP1 + i - 1] = (_make_swap(i), G_VERY_LOW)

    for i in range(5):
        t[Op.LOG0 + i] = (_make_log(i), G_LOG)

    t[Op.CREATE] = (op_create, G_CREATE)
    t[Op.CALL] = (op_call, G_WARM_ACCESS)
    t[Op.CALLCODE] = (op_callcode, G_WARM_ACCESS)
    t[Op.RETURN] = (op_return, 0)
    t[Op.DELEGATECALL] = (op_delegatecall, G_WARM_ACCESS)
    t[Op.CREATE2] = (op_create2, G_CREATE)
    t[Op.STATICCALL] = (op_staticcall, G_WARM_ACCESS)
    t[Op.REVERT] = (op_revert, 0)
    t[Op.INVALID] = (op_invalid, 0)
    t[Op.SELFDESTRUCT] = (op_selfdestruct, G_SELFDESTRUCT)


_register()
