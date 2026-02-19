"""Tests for EVM execution."""

import pytest
from ethclient.vm.memory import Stack, Memory, StackOverflow, StackUnderflow
from ethclient.vm.call_frame import CallFrame, _compute_valid_jumpdests
from ethclient.vm.evm import ExecutionEnvironment, run_bytecode, execute_tx, TxResult
from ethclient.vm.opcodes import Op
from ethclient.vm.gas import (
    memory_expansion_cost,
    memory_word_size,
    calc_memory_cost,
    intrinsic_gas,
    AccessSets,
)


# ---------------------------------------------------------------------------
# Helper: build bytecode from opcodes
# ---------------------------------------------------------------------------

def bytecode(*ops) -> bytes:
    """Build bytecode from a mix of ints (opcodes) and bytes."""
    result = bytearray()
    for op in ops:
        if isinstance(op, int):
            result.append(op)
        elif isinstance(op, bytes):
            result.extend(op)
        elif isinstance(op, bytearray):
            result.extend(op)
    return bytes(result)


def push(value: int, n: int = 0) -> bytes:
    """Create PUSH instruction. Auto-selects PUSH width if n=0."""
    if value == 0 and n == 0:
        return bytes([Op.PUSH0])
    if n == 0:
        n = max(1, (value.bit_length() + 7) // 8)
    return bytes([Op.PUSH1 + n - 1]) + value.to_bytes(n, "big")


# ---------------------------------------------------------------------------
# Stack tests
# ---------------------------------------------------------------------------

class TestStack:
    def test_push_pop(self):
        s = Stack()
        s.push(42)
        assert s.pop() == 42

    def test_overflow(self):
        s = Stack()
        for i in range(1024):
            s.push(i)
        with pytest.raises(StackOverflow):
            s.push(1024)

    def test_underflow(self):
        s = Stack()
        with pytest.raises(StackUnderflow):
            s.pop()

    def test_peek(self):
        s = Stack()
        s.push(10)
        s.push(20)
        assert s.peek(0) == 20
        assert s.peek(1) == 10

    def test_swap(self):
        s = Stack()
        s.push(1)
        s.push(2)
        s.swap(1)
        assert s.pop() == 1
        assert s.pop() == 2

    def test_dup(self):
        s = Stack()
        s.push(42)
        s.dup(1)
        assert s.pop() == 42
        assert s.pop() == 42

    def test_uint256_overflow_wraps(self):
        s = Stack()
        s.push(2**256)  # should wrap to 0
        assert s.pop() == 0

    def test_uint256_max(self):
        s = Stack()
        s.push(2**256 - 1)
        assert s.pop() == 2**256 - 1


# ---------------------------------------------------------------------------
# Memory tests
# ---------------------------------------------------------------------------

class TestMemory:
    def test_store_load(self):
        m = Memory()
        m.store(0, b"hello")
        assert m.load(0, 5) == b"hello"

    def test_expansion(self):
        m = Memory()
        m.store(100, b"\x01")
        assert m.size == 128  # rounds to 32-byte boundary

    def test_word(self):
        m = Memory()
        m.store_word(0, 0xFF)
        assert m.load_word(0) == 0xFF

    def test_byte(self):
        m = Memory()
        m.store_byte(0, 0xAB)
        assert m.load(0, 1) == b"\xab"

    def test_copy(self):
        m = Memory()
        m.store(0, b"hello world")
        m.copy(32, 0, 11)
        assert m.load(32, 11) == b"hello world"


# ---------------------------------------------------------------------------
# Gas calculation tests
# ---------------------------------------------------------------------------

class TestGasCalc:
    def test_memory_word_size(self):
        assert memory_word_size(0) == 0
        assert memory_word_size(1) == 1
        assert memory_word_size(32) == 1
        assert memory_word_size(33) == 2

    def test_memory_expansion_cost(self):
        # First 32 bytes: cost = 3 * 1 + 0 = 3
        assert memory_expansion_cost(0, 1) == 3

    def test_intrinsic_gas(self):
        assert intrinsic_gas(b"", False) == 21000
        assert intrinsic_gas(b"", True) == 21000 + 32000
        assert intrinsic_gas(b"\x00", False) == 21000 + 4
        assert intrinsic_gas(b"\x01", False) == 21000 + 16


class TestAccessSets:
    def test_warm_address(self):
        a = AccessSets()
        addr = b"\x01" * 20
        assert not a.is_warm_address(addr)
        was = a.mark_warm_address(addr)
        assert not was
        assert a.is_warm_address(addr)
        was = a.mark_warm_address(addr)
        assert was

    def test_warm_storage(self):
        a = AccessSets()
        addr = b"\x01" * 20
        assert not a.is_warm_storage(addr, 42)
        a.mark_warm_storage(addr, 42)
        assert a.is_warm_storage(addr, 42)


# ---------------------------------------------------------------------------
# Valid jumpdest tests
# ---------------------------------------------------------------------------

class TestJumpdest:
    def test_simple(self):
        code = bytecode(Op.JUMPDEST, Op.STOP)
        assert _compute_valid_jumpdests(code) == {0}

    def test_push_skips_jumpdest(self):
        # PUSH1 followed by 0x5B (JUMPDEST byte) — should NOT be valid
        code = bytecode(Op.PUSH1, Op.JUMPDEST, Op.STOP)
        assert _compute_valid_jumpdests(code) == set()

    def test_multiple_jumpdests(self):
        code = bytecode(Op.JUMPDEST, Op.STOP, Op.JUMPDEST, Op.STOP)
        assert _compute_valid_jumpdests(code) == {0, 2}


# ---------------------------------------------------------------------------
# Bytecode execution tests
# ---------------------------------------------------------------------------

class TestArithmetic:
    def _run(self, code: bytes, gas: int = 100000) -> CallFrame:
        frame = CallFrame(code=code, gas=gas)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        return frame

    def test_add(self):
        code = bytecode(push(10), push(20), Op.ADD, Op.STOP)
        frame = self._run(code)
        assert frame.stack.pop() == 30

    def test_sub(self):
        code = bytecode(push(10), push(30), Op.SUB)
        frame = self._run(code)
        # 30 - 10 = 20 (note: second push is on top)
        assert frame.stack.pop() == 20

    def test_mul(self):
        code = bytecode(push(6), push(7), Op.MUL)
        frame = self._run(code)
        assert frame.stack.pop() == 42

    def test_div(self):
        code = bytecode(push(2), push(10), Op.DIV)
        frame = self._run(code)
        assert frame.stack.pop() == 5

    def test_div_by_zero(self):
        code = bytecode(push(0), push(10), Op.DIV)
        frame = self._run(code)
        assert frame.stack.pop() == 0

    def test_mod(self):
        code = bytecode(push(3), push(10), Op.MOD)
        frame = self._run(code)
        assert frame.stack.pop() == 1

    def test_addmod(self):
        code = bytecode(push(8), push(10), push(10), Op.ADDMOD)
        frame = self._run(code)
        assert frame.stack.pop() == 4  # (10+10) % 8 = 4

    def test_mulmod(self):
        code = bytecode(push(8), push(10), push(10), Op.MULMOD)
        frame = self._run(code)
        assert frame.stack.pop() == 4  # (10*10) % 8 = 4

    def test_exp(self):
        code = bytecode(push(3), push(2), Op.EXP)
        frame = self._run(code)
        assert frame.stack.pop() == 8

    def test_signextend(self):
        # signextend(0, 0xFF) = -1 in uint256 (all 1s)
        code = bytecode(push(0xFF), push(0), Op.SIGNEXTEND)
        frame = self._run(code)
        assert frame.stack.pop() == (2**256 - 1)

    def test_overflow_wraps(self):
        code = bytecode(push(1), push(2**256 - 1, 32), Op.ADD)
        frame = self._run(code)
        assert frame.stack.pop() == 0  # overflow wraps


class TestComparison:
    def _run(self, code: bytes) -> CallFrame:
        frame = CallFrame(code=code, gas=100000)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        return frame

    def test_lt(self):
        code = bytecode(push(20), push(10), Op.LT)
        assert self._run(code).stack.pop() == 1
        code = bytecode(push(10), push(20), Op.LT)
        assert self._run(code).stack.pop() == 0

    def test_gt(self):
        code = bytecode(push(10), push(20), Op.GT)
        assert self._run(code).stack.pop() == 1

    def test_eq(self):
        code = bytecode(push(10), push(10), Op.EQ)
        assert self._run(code).stack.pop() == 1
        code = bytecode(push(10), push(20), Op.EQ)
        assert self._run(code).stack.pop() == 0

    def test_iszero(self):
        code = bytecode(push(0), Op.ISZERO)
        assert self._run(code).stack.pop() == 1
        code = bytecode(push(1), Op.ISZERO)
        assert self._run(code).stack.pop() == 0


class TestBitwise:
    def _run(self, code: bytes) -> CallFrame:
        frame = CallFrame(code=code, gas=100000)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        return frame

    def test_and(self):
        code = bytecode(push(0x0F), push(0xFF), Op.AND)
        assert self._run(code).stack.pop() == 0x0F

    def test_or(self):
        code = bytecode(push(0xF0), push(0x0F), Op.OR)
        assert self._run(code).stack.pop() == 0xFF

    def test_xor(self):
        code = bytecode(push(0xFF), push(0x0F), Op.XOR)
        assert self._run(code).stack.pop() == 0xF0

    def test_not(self):
        code = bytecode(push(0), Op.NOT)
        assert self._run(code).stack.pop() == 2**256 - 1

    def test_byte(self):
        code = bytecode(push(0xFF00, 2), push(30), Op.BYTE)
        assert self._run(code).stack.pop() == 0xFF

    def test_shl(self):
        code = bytecode(push(1), push(4), Op.SHL)
        assert self._run(code).stack.pop() == 16

    def test_shr(self):
        code = bytecode(push(16), push(4), Op.SHR)
        assert self._run(code).stack.pop() == 1

    def test_clz(self):
        code = bytecode(push(0x0F), Op.CLZ)
        assert self._run(code).stack.pop() == 252

    def test_clz_zero(self):
        code = bytecode(push(0), Op.CLZ)
        assert self._run(code).stack.pop() == 256


class TestMemoryOps:
    def _run(self, code: bytes) -> tuple[CallFrame, ExecutionEnvironment]:
        frame = CallFrame(code=code, gas=100000)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        return frame, env

    def test_mstore_mload(self):
        code = bytecode(
            push(0x42), push(0), Op.MSTORE,
            push(0), Op.MLOAD,
        )
        frame, _ = self._run(code)
        assert frame.stack.pop() == 0x42

    def test_mstore8(self):
        code = bytecode(
            push(0xFF), push(31), Op.MSTORE8,
            push(0), Op.MLOAD,
        )
        frame, _ = self._run(code)
        assert frame.stack.pop() == 0xFF

    def test_msize(self):
        code = bytecode(
            push(1), push(0), Op.MSTORE,
            Op.MSIZE,
        )
        frame, _ = self._run(code)
        assert frame.stack.pop() == 32


class TestControlFlow:
    def _run(self, code: bytes) -> CallFrame:
        frame = CallFrame(code=code, gas=100000)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        return frame

    def test_jump(self):
        code = bytecode(
            push(4), Op.JUMP,  # jump to offset 4
            Op.INVALID,        # should be skipped
            Op.JUMPDEST,       # offset 4
            push(42),          # push 42
        )
        frame = self._run(code)
        assert frame.stack.pop() == 42

    def test_jumpi_taken(self):
        # PUSH1 1 (2 bytes) PUSH1 X (2 bytes) JUMPI (1 byte) INVALID (1 byte) JUMPDEST
        # offsets: 0:PUSH1, 2:PUSH1, 4:JUMPI, 5:INVALID, 6:JUMPDEST
        code = bytecode(
            push(1), push(6), Op.JUMPI,  # condition=1, jump to 6
            Op.INVALID,
            Op.JUMPDEST,                  # offset 6
            push(99),
        )
        frame = self._run(code)
        assert frame.stack.pop() == 99

    def test_jumpi_not_taken(self):
        code = bytecode(
            push(0), push(5), Op.JUMPI,  # condition=0, don't jump
            push(11),                      # should execute
        )
        frame = self._run(code)
        assert frame.stack.pop() == 11


class TestPushDupSwap:
    def _run(self, code: bytes) -> CallFrame:
        frame = CallFrame(code=code, gas=100000)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        return frame

    def test_push0(self):
        code = bytecode(Op.PUSH0)
        frame = self._run(code)
        assert frame.stack.pop() == 0

    def test_push1_through_push32(self):
        for n in range(1, 33):
            val = (1 << (n * 8)) - 1  # max value for n bytes
            code = bytecode(push(val, n))
            frame = self._run(code)
            assert frame.stack.pop() == val

    def test_dup1(self):
        code = bytecode(push(42), Op.DUP1)
        frame = self._run(code)
        assert frame.stack.pop() == 42
        assert frame.stack.pop() == 42

    def test_swap1(self):
        code = bytecode(push(1), push(2), Op.SWAP1)
        frame = self._run(code)
        assert frame.stack.pop() == 1
        assert frame.stack.pop() == 2


class TestEnvironmentOps:
    def test_caller(self):
        caller = b"\xAB" * 20
        code = bytecode(Op.CALLER)
        frame = CallFrame(code=code, gas=100000, caller=caller)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        result = frame.stack.pop()
        assert result == int.from_bytes(caller, "big")

    def test_callvalue(self):
        code = bytecode(Op.CALLVALUE)
        frame = CallFrame(code=code, gas=100000, value=1000)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        assert frame.stack.pop() == 1000

    def test_calldataload(self):
        data = b"\x00" * 31 + b"\x42"  # 0x42 at position 31
        code = bytecode(push(0), Op.CALLDATALOAD)
        frame = CallFrame(code=code, gas=100000, calldata=data)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        assert frame.stack.pop() == 0x42

    def test_calldatasize(self):
        code = bytecode(Op.CALLDATASIZE)
        frame = CallFrame(code=code, gas=100000, calldata=b"\x01\x02\x03")
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        assert frame.stack.pop() == 3

    def test_address(self):
        addr = b"\x01" * 20
        code = bytecode(Op.ADDRESS)
        frame = CallFrame(code=code, gas=100000, address=addr)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        assert frame.stack.pop() == int.from_bytes(addr, "big")

    def test_chainid(self):
        code = bytecode(Op.CHAINID)
        frame = CallFrame(code=code, gas=100000)
        env = ExecutionEnvironment()
        env.chain_id = 1337
        run_bytecode(frame, env)
        assert frame.stack.pop() == 1337


class TestStorageOps:
    def test_sstore_sload(self):
        addr = b"\x01" * 20
        code = bytecode(
            push(0xFF), push(0), Op.SSTORE,  # store 0xFF at slot 0
            push(0), Op.SLOAD,                # load slot 0
        )
        frame = CallFrame(code=code, gas=1_000_000, address=addr)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        assert frame.stack.pop() == 0xFF

    def test_sstore_update(self):
        addr = b"\x01" * 20
        code = bytecode(
            push(1), push(0), Op.SSTORE,
            push(2), push(0), Op.SSTORE,
            push(0), Op.SLOAD,
        )
        frame = CallFrame(code=code, gas=1_000_000, address=addr)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        assert frame.stack.pop() == 2


class TestReturnRevert:
    def test_return(self):
        code = bytecode(
            push(0x42), push(0), Op.MSTORE,
            push(32), push(0), Op.RETURN,
        )
        frame = CallFrame(code=code, gas=100000)
        env = ExecutionEnvironment()
        success, data = run_bytecode(frame, env)
        assert success is True
        assert int.from_bytes(data, "big") == 0x42

    def test_revert(self):
        code = bytecode(
            push(0), push(0), Op.REVERT,
        )
        frame = CallFrame(code=code, gas=100000)
        env = ExecutionEnvironment()
        success, data = run_bytecode(frame, env)
        assert success is False

    def test_stop(self):
        code = bytecode(Op.STOP)
        frame = CallFrame(code=code, gas=100000)
        env = ExecutionEnvironment()
        success, data = run_bytecode(frame, env)
        assert success is True
        assert data == b""

    def test_empty_code(self):
        frame = CallFrame(code=b"", gas=100000)
        env = ExecutionEnvironment()
        success, data = run_bytecode(frame, env)
        assert success is True


class TestKeccak256:
    def test_keccak256_empty(self):
        from ethclient.common.crypto import keccak256
        code = bytecode(
            push(0), push(0), Op.KECCAK256,
        )
        frame = CallFrame(code=code, gas=100000)
        env = ExecutionEnvironment()
        run_bytecode(frame, env)
        expected = int.from_bytes(keccak256(b""), "big")
        assert frame.stack.pop() == expected


class TestTransactionExecution:
    def test_simple_transfer(self):
        env = ExecutionEnvironment()
        sender = b"\x01" * 20
        receiver = b"\x02" * 20
        env.set_balance(sender, 10**18)

        result = execute_tx(
            env, sender, receiver,
            value=1000, data=b"",
            gas_limit=21000,
        )
        assert result.success is True
        assert env.get_balance(receiver) == 1000

    def test_contract_creation(self):
        env = ExecutionEnvironment()
        sender = b"\x01" * 20
        env.set_balance(sender, 10**18)

        # Simple contract: PUSH1 0x42 PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
        init_code = bytecode(
            push(0x42), push(0), Op.MSTORE,
            push(32), push(0), Op.RETURN,
        )

        result = execute_tx(
            env, sender, None,
            value=0, data=init_code,
            gas_limit=1_000_000,
        )
        assert result.success is True

    def test_insufficient_balance(self):
        env = ExecutionEnvironment()
        sender = b"\x01" * 20
        receiver = b"\x02" * 20
        env.set_balance(sender, 100)

        result = execute_tx(
            env, sender, receiver,
            value=1000, data=b"",
            gas_limit=21000,
        )
        assert result.success is False


class TestPrecompiles:
    def test_ecrecover(self):
        from ethclient.common.crypto import keccak256, ecdsa_sign, private_key_to_address
        pk = b"\x01" * 32
        msg_hash = keccak256(b"test")
        v, r, s = ecdsa_sign(msg_hash, pk)

        # Pack input: hash(32) + v(32) + r(32) + s(32)
        input_data = msg_hash
        input_data += (v + 27).to_bytes(32, "big")
        input_data += r.to_bytes(32, "big")
        input_data += s.to_bytes(32, "big")

        from ethclient.vm.precompiles import run_precompile
        result = run_precompile(b"\x00" * 19 + b"\x01", input_data)
        assert result is not None
        gas, output = result
        recovered_addr = output[12:]
        expected = private_key_to_address(pk)
        assert recovered_addr == expected

    def test_sha256_precompile(self):
        from ethclient.vm.precompiles import run_precompile
        result = run_precompile(b"\x00" * 19 + b"\x02", b"hello")
        assert result is not None
        gas, output = result
        from ethclient.common.crypto import sha256
        assert output == sha256(b"hello")

    def test_identity(self):
        from ethclient.vm.precompiles import run_precompile
        data = b"test data"
        result = run_precompile(b"\x00" * 19 + b"\x04", data)
        assert result is not None
        _, output = result
        assert output == data

    def test_modexp(self):
        from ethclient.vm.precompiles import run_precompile
        # 2^3 mod 5 = 3
        b_size = (1).to_bytes(32, "big")
        e_size = (1).to_bytes(32, "big")
        m_size = (1).to_bytes(32, "big")
        base = b"\x02"
        exp = b"\x03"
        mod = b"\x05"
        data = b_size + e_size + m_size + base + exp + mod
        result = run_precompile(b"\x00" * 19 + b"\x05", data)
        assert result is not None
        _, output = result
        assert int.from_bytes(output, "big") == 3

    def test_modexp_input_bound(self):
        from ethclient.vm.precompiles import run_precompile
        huge = (2**20).to_bytes(32, "big")
        # Only lengths are needed to trigger bound check.
        data = huge + huge + huge
        result = run_precompile(b"\x00" * 19 + b"\x05", data)
        assert result is None

    def test_p256verify_invalid_signature(self):
        from ethclient.vm.precompiles import run_precompile
        result = run_precompile(b"\x00" * 18 + b"\x01\x00", b"\x00" * 160)
        assert result is not None
        _, output = result
        assert int.from_bytes(output, "big") == 0

    # --- BN128 ecAdd (0x06) ---

    def test_ecadd_basic(self):
        """G1 + G1 should equal 2*G1."""
        from ethclient.vm.precompiles import run_precompile
        g1_x = (1).to_bytes(32, "big")
        g1_y = (2).to_bytes(32, "big")
        # G1 + G1
        data = g1_x + g1_y + g1_x + g1_y
        result = run_precompile(b"\x00" * 19 + b"\x06", data)
        assert result is not None
        gas, output = result
        assert gas == 150
        # Compare with ecMul(G1, 2)
        scalar = (2).to_bytes(32, "big")
        mul_result = run_precompile(b"\x00" * 19 + b"\x07", g1_x + g1_y + scalar)
        assert output == mul_result[1]

    def test_ecadd_zero(self):
        """P + 0 = P (identity element)."""
        from ethclient.vm.precompiles import run_precompile
        g1_x = (1).to_bytes(32, "big")
        g1_y = (2).to_bytes(32, "big")
        data = g1_x + g1_y + b"\x00" * 64
        result = run_precompile(b"\x00" * 19 + b"\x06", data)
        assert result is not None
        assert result[1] == g1_x + g1_y

    def test_ecadd_invalid(self):
        """Point not on curve should fail."""
        from ethclient.vm.precompiles import run_precompile
        # (1, 3) is not on BN128 curve
        bad_x = (1).to_bytes(32, "big")
        bad_y = (3).to_bytes(32, "big")
        data = bad_x + bad_y + b"\x00" * 64
        result = run_precompile(b"\x00" * 19 + b"\x06", data)
        assert result is None

    # --- BN128 ecMul (0x07) ---

    def test_ecmul_basic(self):
        """3 * G1 should be a valid point."""
        from ethclient.vm.precompiles import run_precompile
        g1_x = (1).to_bytes(32, "big")
        g1_y = (2).to_bytes(32, "big")
        scalar = (3).to_bytes(32, "big")
        result = run_precompile(b"\x00" * 19 + b"\x07", g1_x + g1_y + scalar)
        assert result is not None
        assert result[0] == 6000
        assert len(result[1]) == 64
        # Result should not be zero point
        assert result[1] != b"\x00" * 64

    def test_ecmul_zero_scalar(self):
        """0 * G1 = point at infinity."""
        from ethclient.vm.precompiles import run_precompile
        g1_x = (1).to_bytes(32, "big")
        g1_y = (2).to_bytes(32, "big")
        result = run_precompile(b"\x00" * 19 + b"\x07", g1_x + g1_y + b"\x00" * 32)
        assert result is not None
        assert result[1] == b"\x00" * 64

    def test_ecmul_curve_order(self):
        """curve_order * G1 = point at infinity."""
        from ethclient.vm.precompiles import run_precompile
        from py_ecc.bn128 import curve_order
        g1_x = (1).to_bytes(32, "big")
        g1_y = (2).to_bytes(32, "big")
        scalar = curve_order.to_bytes(32, "big")
        result = run_precompile(b"\x00" * 19 + b"\x07", g1_x + g1_y + scalar)
        assert result is not None
        assert result[1] == b"\x00" * 64

    # --- BN128 ecPairing (0x08) ---

    def test_ecpairing_empty(self):
        """Empty input → pairing check passes (true)."""
        from ethclient.vm.precompiles import run_precompile
        result = run_precompile(b"\x00" * 19 + b"\x08", b"")
        assert result is not None
        assert result[0] == 45000  # base gas, k=0
        assert result[1] == b"\x00" * 31 + b"\x01"

    def test_ecpairing_invalid_length(self):
        """Input not divisible by 192 → fail."""
        from ethclient.vm.precompiles import run_precompile
        result = run_precompile(b"\x00" * 19 + b"\x08", b"\x00" * 100)
        assert result is None

    def test_ecpairing_simple(self):
        """e(P, Q) * e(-P, Q) == 1 → true."""
        from ethclient.vm.precompiles import run_precompile
        from py_ecc.bn128 import G1, G2, neg

        # Encode G1
        g1_enc = int(G1[0]).to_bytes(32, "big") + int(G1[1]).to_bytes(32, "big")
        # Encode -G1
        neg_g1 = neg(G1)
        neg_g1_enc = int(neg_g1[0]).to_bytes(32, "big") + int(neg_g1[1]).to_bytes(32, "big")
        # Encode G2
        g2_enc = (
            int(G2[0].coeffs[1]).to_bytes(32, "big") +
            int(G2[0].coeffs[0]).to_bytes(32, "big") +
            int(G2[1].coeffs[1]).to_bytes(32, "big") +
            int(G2[1].coeffs[0]).to_bytes(32, "big")
        )
        # Pair: (G1, G2) + (-G1, G2) should equal 1
        data = g1_enc + g2_enc + neg_g1_enc + g2_enc
        result = run_precompile(b"\x00" * 19 + b"\x08", data)
        assert result is not None
        assert result[1] == b"\x00" * 31 + b"\x01"

    # --- KZG point evaluation (0x0a) ---

    def test_kzg_basic(self):
        """Valid KZG proof verification."""
        import hashlib
        import ckzg
        from ethclient.vm.precompiles import run_precompile, _get_kzg_trusted_setup

        ts = _get_kzg_trusted_setup()
        blob = b"\x00" * 131072
        commitment = ckzg.blob_to_kzg_commitment(blob, ts)
        z = b"\x00" * 32
        proof, y = ckzg.compute_kzg_proof(blob, z, ts)

        versioned_hash = b"\x01" + hashlib.sha256(commitment).digest()[1:]
        data = versioned_hash + z + y + commitment + proof
        result = run_precompile(b"\x00" * 19 + b"\x0a", data)
        assert result is not None
        assert result[0] == 50000
        assert int.from_bytes(result[1][0:32], "big") == 4096

    def test_kzg_invalid_hash(self):
        """Wrong versioned_hash → fail."""
        import hashlib
        import ckzg
        from ethclient.vm.precompiles import run_precompile, _get_kzg_trusted_setup

        ts = _get_kzg_trusted_setup()
        blob = b"\x00" * 131072
        commitment = ckzg.blob_to_kzg_commitment(blob, ts)
        z = b"\x00" * 32
        proof, y = ckzg.compute_kzg_proof(blob, z, ts)

        # Wrong hash
        versioned_hash = b"\x01" + b"\xff" * 31
        data = versioned_hash + z + y + commitment + proof
        result = run_precompile(b"\x00" * 19 + b"\x0a", data)
        assert result is None
