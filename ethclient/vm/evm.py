"""
EVM main execution loop.

ExecutionEnvironment provides the world state interface.
run_bytecode() is the fetch-decode-execute loop.
execute_tx() handles full transaction execution including gas accounting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ethclient.common.crypto import keccak256
from ethclient.common import rlp
from ethclient.vm.call_frame import CallFrame, MAX_CALL_DEPTH
from ethclient.vm.memory import (
    EvmError,
    OutOfGas,
    StopExecution,
    ReturnData,
    Revert,
    SelfDestruct,
    InvalidOpcode,
)
from ethclient.vm.gas import AccessSets, G_CODEDEPOSIT
from ethclient.vm.opcodes import OPCODE_TABLE
from ethclient.vm.precompiles import is_precompile, run_precompile
from ethclient.vm.hooks import ExecutionHook, DefaultHook
from ethclient.common.types import Log


# ---------------------------------------------------------------------------
# Execution environment — world state interface for the EVM
# ---------------------------------------------------------------------------

class ExecutionEnvironment:
    """Interface between EVM and world state.

    Subclass or replace to connect to actual storage backends.
    Default implementation uses in-memory dicts for testing.
    """

    def __init__(self) -> None:
        # Block context
        self.block_number: int = 0
        self.timestamp: int = 0
        self.coinbase: bytes = b"\x00" * 20
        self.prevrandao: int = 0
        self.gas_limit: int = 30_000_000
        self.chain_id: int = 1
        self.base_fee: int = 0
        self.blob_base_fee: int = 0
        self.blob_hashes: list[bytes] = []
        self.gas_price: int = 0

        # EIP-2929 access tracking
        self.access_sets: AccessSets = AccessSets()

        # Transient storage (EIP-1153)
        self._transient: dict[tuple[bytes, int], int] = {}

        # Gas refund counter
        self.refund: int = 0

        # Logs
        self.logs: list[Log] = []

        # Self-destructs
        self.selfdestructs: set[bytes] = set()

        # State (in-memory for testing)
        self._balances: dict[bytes, int] = {}
        self._nonces: dict[bytes, int] = {}
        self._code: dict[bytes, bytes] = {}
        self._storage: dict[tuple[bytes, int], int] = {}
        self._original_storage: dict[tuple[bytes, int], int] = {}

        # Hook
        self.hook: ExecutionHook = DefaultHook()

        # Snapshots for rollback
        self._snapshots: list[dict] = []

    # -- State accessors --

    def get_balance(self, address: bytes) -> int:
        return self._balances.get(address, 0)

    def set_balance(self, address: bytes, balance: int) -> None:
        old = self._balances.get(address, 0)
        self._balances[address] = balance
        self.hook.on_balance_change(address, old, balance)

    def add_balance(self, address: bytes, amount: int) -> None:
        self.set_balance(address, self.get_balance(address) + amount)

    def sub_balance(self, address: bytes, amount: int) -> None:
        self.set_balance(address, self.get_balance(address) - amount)

    def get_nonce(self, address: bytes) -> int:
        return self._nonces.get(address, 0)

    def set_nonce(self, address: bytes, nonce: int) -> None:
        self._nonces[address] = nonce

    def increment_nonce(self, address: bytes) -> None:
        self._nonces[address] = self.get_nonce(address) + 1

    def get_code(self, address: bytes) -> bytes:
        return self._code.get(address, b"")

    def set_code(self, address: bytes, code: bytes) -> None:
        self._code[address] = code

    def get_storage(self, address: bytes, key: int) -> int:
        return self._storage.get((address, key), 0)

    def set_storage(self, address: bytes, key: int, value: int) -> None:
        old = self.get_storage(address, key)
        self._storage[(address, key)] = value
        self.hook.on_state_change(address, key, old, value)

    def get_original_storage(self, address: bytes, key: int) -> int:
        return self._original_storage.get((address, key), 0)

    def account_exists(self, address: bytes) -> bool:
        return (
            address in self._balances
            or address in self._nonces
            or address in self._code
        )

    def get_block_hash(self, block_number: int) -> bytes:
        # Override in real implementation
        return b"\x00" * 32

    def get_transient(self, address: bytes, key: int) -> int:
        return self._transient.get((address, key), 0)

    def set_transient(self, address: bytes, key: int, value: int) -> None:
        self._transient[(address, key)] = value

    def add_log(self, address: bytes, topics: list[bytes], data: bytes) -> None:
        self.logs.append(Log(address=address, topics=topics, data=data))

    # -- Snapshots for call-level rollback --

    def snapshot(self) -> int:
        snap = {
            "balances": dict(self._balances),
            "nonces": dict(self._nonces),
            "code": dict(self._code),
            "storage": dict(self._storage),
            "logs_count": len(self.logs),
            "selfdestructs": set(self.selfdestructs),
            "refund": self.refund,
            "access_sets": self.access_sets.snapshot(),
        }
        self._snapshots.append(snap)
        return len(self._snapshots) - 1

    def rollback(self, snap_id: int) -> None:
        snap = self._snapshots[snap_id]
        self._balances = snap["balances"]
        self._nonces = snap["nonces"]
        self._code = snap["code"]
        self._storage = snap["storage"]
        self.logs = self.logs[: snap["logs_count"]]
        self.selfdestructs = snap["selfdestructs"]
        self.refund = snap["refund"]
        self.access_sets.restore(snap["access_sets"])
        self._snapshots = self._snapshots[:snap_id]

    def commit(self, snap_id: int) -> None:
        self._snapshots = self._snapshots[:snap_id]

    # -- CREATE --

    def do_create(
        self,
        frame: CallFrame,
        value: int,
        init_code: bytes,
        salt: Optional[int],
    ) -> int:
        """Execute CREATE or CREATE2. Returns new address as uint256 or 0 on failure."""
        sender = frame.address
        nonce = self.get_nonce(sender)

        if salt is None:
            # CREATE: address = keccak256(rlp([sender, nonce]))[12:]
            addr = keccak256(rlp.encode([sender, nonce]))[12:]
        else:
            # CREATE2: address = keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12:]
            addr = keccak256(
                b"\xff" + sender + salt.to_bytes(32, "big") + keccak256(init_code)
            )[12:]

        self.increment_nonce(sender)

        if frame.depth >= MAX_CALL_DEPTH:
            return 0

        snap = self.snapshot()

        # Transfer value
        if value > 0:
            if self.get_balance(sender) < value:
                self.rollback(snap)
                return 0
            self.sub_balance(sender, value)
            self.add_balance(addr, value)

        self.set_nonce(addr, 1)
        self.access_sets.mark_warm_address(addr)

        # Execute init code
        new_frame = CallFrame(
            caller=sender,
            address=addr,
            code_address=addr,
            origin=frame.origin,
            code=init_code,
            gas=frame.remaining_gas - (frame.remaining_gas // 64),
            value=value,
            depth=frame.depth + 1,
        )

        self.hook.before_call(new_frame)
        success, return_data = run_bytecode(new_frame, self)
        self.hook.after_call(new_frame, success, return_data)

        if success:
            # Code deposit
            code_cost = G_CODEDEPOSIT * len(return_data)
            if len(return_data) > 24576:  # EIP-170: max code size
                self.rollback(snap)
                return 0
            if return_data and return_data[0] == 0xEF:  # EIP-3541
                self.rollback(snap)
                return 0
            frame.gas_used += new_frame.gas_used + code_cost
            self.set_code(addr, return_data)
            self.commit(snap)
            frame.return_data = b""
            return int.from_bytes(addr, "big")
        else:
            frame.gas_used += new_frame.gas_used
            self.rollback(snap)
            frame.return_data = return_data
            return 0

    # -- CALL --

    def do_call(
        self,
        parent: CallFrame,
        to: bytes,
        code_addr: bytes,
        value: int,
        calldata: bytes,
        gas: int,
        is_static: bool,
    ) -> tuple[bool, bytes]:
        """Execute CALL/CALLCODE/STATICCALL."""
        if parent.depth >= MAX_CALL_DEPTH:
            return False, b""

        # Check precompiles
        if is_precompile(code_addr):
            result = run_precompile(code_addr, calldata)
            if result is None:
                return False, b""
            pc_gas, output = result
            if pc_gas > gas:
                return False, b""
            parent.gas_used += pc_gas
            return True, output

        snap = self.snapshot()

        # Transfer value
        if value > 0:
            if self.get_balance(parent.address) < value:
                self.rollback(snap)
                return False, b""
            self.sub_balance(parent.address, value)
            self.add_balance(to, value)

        code = self.get_code(code_addr)
        if not code:
            self.commit(snap)
            return True, b""

        new_frame = CallFrame(
            caller=parent.address,
            address=to,
            code_address=code_addr,
            origin=parent.origin,
            code=code,
            gas=gas,
            value=value,
            calldata=calldata,
            depth=parent.depth + 1,
            is_static=is_static,
        )

        self.hook.before_call(new_frame)
        success, return_data = run_bytecode(new_frame, self)
        self.hook.after_call(new_frame, success, return_data)

        parent.gas_used += new_frame.gas_used

        if success:
            self.commit(snap)
        else:
            self.rollback(snap)

        return success, return_data

    def do_delegatecall(
        self,
        parent: CallFrame,
        code_addr: bytes,
        calldata: bytes,
        gas: int,
    ) -> tuple[bool, bytes]:
        """Execute DELEGATECALL — runs code_addr's code in parent's context."""
        if parent.depth >= MAX_CALL_DEPTH:
            return False, b""

        if is_precompile(code_addr):
            result = run_precompile(code_addr, calldata)
            if result is None:
                return False, b""
            pc_gas, output = result
            if pc_gas > gas:
                return False, b""
            parent.gas_used += pc_gas
            return True, output

        snap = self.snapshot()
        code = self.get_code(code_addr)
        if not code:
            self.commit(snap)
            return True, b""

        new_frame = CallFrame(
            caller=parent.caller,
            address=parent.address,
            code_address=code_addr,
            origin=parent.origin,
            code=code,
            gas=gas,
            value=parent.value,
            calldata=calldata,
            depth=parent.depth + 1,
            is_static=parent.is_static,
        )

        self.hook.before_call(new_frame)
        success, return_data = run_bytecode(new_frame, self)
        self.hook.after_call(new_frame, success, return_data)

        parent.gas_used += new_frame.gas_used

        if success:
            self.commit(snap)
        else:
            self.rollback(snap)

        return success, return_data


# ---------------------------------------------------------------------------
# Main execution loop
# ---------------------------------------------------------------------------

def run_bytecode(frame: CallFrame, env: ExecutionEnvironment) -> tuple[bool, bytes]:
    """Execute bytecode in the given call frame.

    Returns (success, return_data).
    """
    try:
        while frame.pc < len(frame.code):
            opcode = frame.code[frame.pc]
            entry = OPCODE_TABLE.get(opcode)
            if entry is None:
                raise InvalidOpcode(f"Unknown opcode: 0x{opcode:02x}")

            handler, base_gas = entry

            # Charge base gas
            frame.consume_gas(base_gas)

            # Execute handler
            handler(frame, env)

        # Fell off the end of code — implicit STOP
        return True, b""

    except StopExecution:
        return True, b""

    except ReturnData as ret:
        return True, ret.data

    except Revert as rev:
        return False, rev.data

    except SelfDestruct as sd:
        env.selfdestructs.add(frame.address)
        balance = env.get_balance(frame.address)
        if balance > 0:
            env.add_balance(sd.beneficiary, balance)
            env.set_balance(frame.address, 0)
        return True, b""

    except (OutOfGas, EvmError, InvalidOpcode):
        # Consume all remaining gas on error
        frame.gas_used = frame.gas
        return False, b""


# ---------------------------------------------------------------------------
# Transaction execution
# ---------------------------------------------------------------------------

@dataclass
class TxResult:
    success: bool = True
    gas_used: int = 0
    return_data: bytes = b""
    logs: list[Log] = field(default_factory=list)
    error: Optional[str] = None


def execute_tx(
    env: ExecutionEnvironment,
    sender: bytes,
    to: Optional[bytes],
    value: int,
    data: bytes,
    gas_limit: int,
    hook: Optional[ExecutionHook] = None,
) -> TxResult:
    """Execute a transaction and return the result.

    Args:
        env: execution environment with world state
        sender: sender address (20 bytes)
        to: recipient address (None for contract creation)
        value: wei to transfer
        data: calldata or init code
        gas_limit: gas limit for this tx
        hook: optional execution hook
    """
    if hook:
        env.hook = hook

    env.hook.before_execution({
        "sender": sender, "to": to, "value": value,
        "data": data, "gas_limit": gas_limit,
    })

    # Reset per-tx state
    env.logs = []
    env.refund = 0
    env._transient = {}
    env.selfdestructs = set()

    # Mark sender warm
    env.access_sets.mark_warm_address(sender)
    if to:
        env.access_sets.mark_warm_address(to)

    # Snapshot for tx-level rollback
    snap = env.snapshot()

    # Transfer value
    if value > 0:
        if env.get_balance(sender) < value:
            env.rollback(snap)
            return TxResult(success=False, gas_used=gas_limit, error="Insufficient balance")
        env.sub_balance(sender, value)
        if to:
            env.add_balance(to, value)

    if to is None:
        # Contract creation
        nonce = env.get_nonce(sender)
        contract_addr = keccak256(rlp.encode([sender, nonce]))[12:]
        env.increment_nonce(sender)
        env.set_nonce(contract_addr, 1)
        env.add_balance(contract_addr, value)

        frame = CallFrame(
            caller=sender,
            address=contract_addr,
            code_address=contract_addr,
            origin=sender,
            code=data,
            gas=gas_limit,
            value=value,
            depth=0,
        )

        env.hook.before_call(frame)
        success, return_data = run_bytecode(frame, env)
        env.hook.after_call(frame, success, return_data)

        if success and return_data:
            if len(return_data) <= 24576:
                code_cost = G_CODEDEPOSIT * len(return_data)
                frame.gas_used += code_cost
                env.set_code(contract_addr, return_data)

    else:
        # Message call
        code = env.get_code(to)
        frame = CallFrame(
            caller=sender,
            address=to,
            code_address=to,
            origin=sender,
            code=code,
            gas=gas_limit,
            value=value,
            calldata=data,
            depth=0,
        )

        if is_precompile(to):
            result = run_precompile(to, data)
            if result is not None:
                pc_gas, output = result
                frame.gas_used = pc_gas
                success = True
                return_data = output
            else:
                success = False
                return_data = b""
                frame.gas_used = gas_limit
        elif code:
            env.hook.before_call(frame)
            success, return_data = run_bytecode(frame, env)
            env.hook.after_call(frame, success, return_data)
        else:
            success = True
            return_data = b""

    gas_used = frame.gas_used

    if success:
        # Apply refund (capped at gas_used // MAX_REFUND_QUOTIENT)
        from ethclient.vm.gas import MAX_REFUND_QUOTIENT
        max_refund = gas_used // MAX_REFUND_QUOTIENT
        actual_refund = min(env.refund, max_refund)
        gas_used -= actual_refund
        env.commit(snap)
    else:
        env.rollback(snap)

    env.hook.after_execution(
        {"sender": sender, "to": to, "value": value},
        success, gas_used,
    )

    return TxResult(
        success=success,
        gas_used=gas_used,
        return_data=return_data,
        logs=list(env.logs) if success else [],
    )
