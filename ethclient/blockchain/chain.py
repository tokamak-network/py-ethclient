"""
Blockchain engine — block validation and execution.

Validates block headers, executes transactions via EVM, and commits state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ethclient.common.types import (
    Block,
    BlockHeader,
    Transaction,
    Receipt,
    Log,
    TxType,
    EMPTY_TRIE_ROOT,
    ZERO_HASH,
    BLOOM_BYTE_SIZE,
    logs_bloom,
)
from ethclient.common.trie import ordered_trie_root
from ethclient.common.crypto import keccak256
from ethclient.common import rlp
from ethclient.common.config import ChainConfig
from ethclient.storage.store import Store
from ethclient.vm.evm import ExecutionEnvironment, run_bytecode, CallFrame
from ethclient.vm.gas import (
    intrinsic_gas,
    G_CODEDEPOSIT,
    MAX_REFUND_QUOTIENT,
    AccessSets,
)
from ethclient.vm.precompiles import is_precompile, run_precompile, PRECOMPILES
from ethclient.vm.hooks import ExecutionHook, DefaultHook


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class BlockValidationError(Exception):
    pass


class TransactionError(Exception):
    pass


# ---------------------------------------------------------------------------
# Simulated call (eth_call / eth_estimateGas)
# ---------------------------------------------------------------------------

@dataclass
class CallResult:
    """Result of a simulated call (eth_call / eth_estimateGas)."""
    success: bool = True
    return_data: bytes = b""
    gas_used: int = 0
    error: Optional[str] = None


def simulate_call(
    sender: bytes,
    to: Optional[bytes],
    data: bytes,
    value: int,
    gas_limit: int,
    header: BlockHeader,
    store: Store,
    config: ChainConfig,
) -> CallResult:
    """Execute a call against current state without modifying it.

    Used by eth_call and eth_estimateGas. Unlike execute_transaction(),
    this skips signature verification, nonce checks, balance deduction,
    coinbase payment, and always rolls back state changes.
    """
    # Snapshot store so we can roll back all changes
    store_snap = store.snapshot()

    try:
        is_create = to is None
        base_gas = intrinsic_gas(data, is_create)
        if base_gas > gas_limit:
            return CallResult(success=False, gas_used=gas_limit,
                              error="intrinsic gas exceeds gas limit")

        base_fee = header.base_fee_per_gas or 0

        # Set up EVM execution environment
        env = ExecutionEnvironment()
        env.block_number = header.number
        env.timestamp = header.timestamp
        env.coinbase = header.coinbase
        env.gas_limit = header.gas_limit
        env.chain_id = config.chain_id
        env.base_fee = base_fee
        env.gas_price = base_fee  # effective gas price = base_fee for calls
        env.prevrandao = int.from_bytes(header.mix_hash, "big")
        env.hook = DefaultHook()

        _bind_env_to_store(env, store)

        # Pre-warm access lists (EIP-2929)
        env.access_sets.mark_warm_address(sender)
        if to is not None:
            env.access_sets.mark_warm_address(to)
        env.access_sets.mark_warm_address(header.coinbase)
        for precompile_addr in PRECOMPILES:
            env.access_sets.mark_warm_address(precompile_addr)

        gas_available = gas_limit - base_gas
        snap = env.snapshot()

        if to is None:
            # Contract creation
            nonce = store.get_nonce(sender)
            contract_addr = keccak256(rlp.encode([sender, nonce]))[12:]
            env.set_nonce(contract_addr, 1)
            if value > 0:
                env.add_balance(contract_addr, value)
                env.sub_balance(sender, value)

            frame = CallFrame(
                caller=sender, address=contract_addr,
                code_address=contract_addr, origin=sender,
                code=data, gas=gas_available, value=value, depth=0,
            )
            success, return_data = run_bytecode(frame, env)

            if success and return_data:
                if len(return_data) <= 24576:
                    code_cost = G_CODEDEPOSIT * len(return_data)
                    if frame.gas_used + code_cost <= gas_available:
                        frame.gas_used += code_cost
                    else:
                        success = False
                        frame.gas_used = gas_available
                else:
                    success = False
                    frame.gas_used = gas_available
        else:
            # Message call
            if value > 0:
                env.sub_balance(sender, value)
                env.add_balance(to, value)

            if is_precompile(to):
                result = run_precompile(to, data)
                if result is not None:
                    pc_gas, output = result
                    frame = CallFrame(gas=gas_available)
                    frame.gas_used = pc_gas
                    success = True
                    return_data = output
                else:
                    frame = CallFrame(gas=gas_available)
                    frame.gas_used = gas_available
                    success = False
                    return_data = b""
            else:
                code = env.get_code(to)
                frame = CallFrame(
                    caller=sender, address=to, code_address=to,
                    origin=sender, code=code, gas=gas_available,
                    value=value, calldata=data, depth=0,
                )
                if code:
                    success, return_data = run_bytecode(frame, env)
                else:
                    success = True
                    return_data = b""

        evm_gas_used = frame.gas_used
        total_gas_used = base_gas + evm_gas_used

        if success:
            max_refund = total_gas_used // MAX_REFUND_QUOTIENT
            actual_refund = min(env.refund, max_refund)
            total_gas_used -= actual_refund

        error_msg = None
        if not success:
            error_msg = "execution reverted"

        return CallResult(
            success=success,
            return_data=return_data,
            gas_used=total_gas_used,
            error=error_msg,
        )
    finally:
        # Always roll back store state
        store.rollback(store_snap)


# ---------------------------------------------------------------------------
# Header validation
# ---------------------------------------------------------------------------

def validate_header(
    header: BlockHeader,
    parent: BlockHeader,
    config: ChainConfig,
) -> None:
    """Validate a block header against its parent."""

    # Block number must be parent + 1
    if header.number != parent.number + 1:
        raise BlockValidationError(
            f"Invalid block number: expected {parent.number + 1}, got {header.number}"
        )

    # Parent hash
    if header.parent_hash != parent.block_hash():
        raise BlockValidationError("Parent hash mismatch")

    # Timestamp must be greater than parent
    if header.timestamp <= parent.timestamp:
        raise BlockValidationError(
            f"Timestamp {header.timestamp} <= parent {parent.timestamp}"
        )

    # Gas limit bounds (EIP-1559: ±1/1024 of parent)
    parent_gas_limit = parent.gas_limit
    max_delta = parent_gas_limit // 1024
    if header.gas_limit > parent_gas_limit + max_delta:
        raise BlockValidationError("Gas limit too high")
    if header.gas_limit < parent_gas_limit - max_delta:
        raise BlockValidationError("Gas limit too low")
    if header.gas_limit < 5000:
        raise BlockValidationError("Gas limit below minimum (5000)")

    # Gas used cannot exceed gas limit
    if header.gas_used > header.gas_limit:
        raise BlockValidationError(
            f"Gas used {header.gas_used} > gas limit {header.gas_limit}"
        )

    # Extra data max size
    if len(header.extra_data) > 32:
        raise BlockValidationError("Extra data too long (max 32 bytes)")

    # Base fee validation (post-London)
    if config.is_london(header.number):
        expected_base_fee = calc_base_fee(parent, config)
        if header.base_fee_per_gas != expected_base_fee:
            raise BlockValidationError(
                f"Base fee mismatch: expected {expected_base_fee}, "
                f"got {header.base_fee_per_gas}"
            )


def calc_base_fee(parent: BlockHeader, config: ChainConfig) -> int:
    """Calculate the expected base fee for the next block (EIP-1559)."""
    if not config.is_london(parent.number + 1):
        return 0

    # First London block
    if parent.base_fee_per_gas is None:
        return 1_000_000_000  # 1 Gwei initial base fee

    parent_base_fee = parent.base_fee_per_gas
    parent_gas_target = parent.gas_limit // 2  # elasticity multiplier = 2

    if parent.gas_used == parent_gas_target:
        return parent_base_fee
    elif parent.gas_used > parent_gas_target:
        gas_used_delta = parent.gas_used - parent_gas_target
        base_fee_delta = max(
            parent_base_fee * gas_used_delta // parent_gas_target // 8,
            1,
        )
        return parent_base_fee + base_fee_delta
    else:
        gas_used_delta = parent_gas_target - parent.gas_used
        base_fee_delta = parent_base_fee * gas_used_delta // parent_gas_target // 8
        return max(parent_base_fee - base_fee_delta, 0)


# ---------------------------------------------------------------------------
# Transaction execution (single tx)
# ---------------------------------------------------------------------------

@dataclass
class TxExecutionResult:
    success: bool = True
    gas_used: int = 0
    receipt: Optional[Receipt] = None
    return_data: bytes = b""
    error: Optional[str] = None
    logs: list[Log] = field(default_factory=list)


def execute_transaction(
    tx: Transaction,
    header: BlockHeader,
    store: Store,
    config: ChainConfig,
    cumulative_gas: int,
    tx_index: int,
    hook: ExecutionHook = DefaultHook(),
) -> TxExecutionResult:
    """Execute a single transaction against the current state."""

    # Recover sender
    try:
        sender = tx.sender()
    except Exception as e:
        return TxExecutionResult(success=False, error=f"Invalid signature: {e}")

    # Validate nonce
    expected_nonce = store.get_nonce(sender)
    if tx.nonce != expected_nonce:
        return TxExecutionResult(
            success=False,
            error=f"Nonce mismatch: expected {expected_nonce}, got {tx.nonce}",
        )

    # Calculate intrinsic gas
    is_create = tx.to is None
    al_count = sum(1 + len(e.storage_keys) for e in tx.access_list)
    base_gas = intrinsic_gas(tx.data, is_create, al_count)
    if base_gas > tx.gas_limit:
        return TxExecutionResult(
            success=False, gas_used=tx.gas_limit,
            error="Intrinsic gas exceeds gas limit",
        )

    # Effective gas price
    base_fee = header.base_fee_per_gas or 0
    effective_gas_price = tx.effective_gas_price(base_fee)

    # Check balance: sender must afford gas + value
    max_cost = tx.gas_limit * effective_gas_price + tx.value
    if tx.tx_type == TxType.BLOB:
        blob_fee = (header.excess_blob_gas or 0)  # simplified
        max_cost += len(tx.blob_versioned_hashes) * tx.max_fee_per_blob_gas
    sender_balance = store.get_balance(sender)
    if sender_balance < max_cost:
        return TxExecutionResult(
            success=False, gas_used=tx.gas_limit,
            error="Insufficient balance for gas + value",
        )

    # Deduct gas upfront
    store.set_balance(sender, sender_balance - tx.gas_limit * effective_gas_price)
    store.increment_nonce(sender)

    # Set up EVM execution environment
    env = ExecutionEnvironment()
    env.block_number = header.number
    env.timestamp = header.timestamp
    env.coinbase = header.coinbase
    env.gas_limit = header.gas_limit
    env.chain_id = config.chain_id
    env.base_fee = base_fee
    env.gas_price = effective_gas_price
    env.prevrandao = int.from_bytes(header.mix_hash, "big")
    env.blob_hashes = tx.blob_versioned_hashes
    env.hook = hook

    # Connect env to store
    _bind_env_to_store(env, store)

    # Pre-warm access lists (EIP-2929)
    env.access_sets.mark_warm_address(sender)
    if tx.to:
        env.access_sets.mark_warm_address(tx.to)
    env.access_sets.mark_warm_address(header.coinbase)
    for precompile_addr in PRECOMPILES:
        env.access_sets.mark_warm_address(precompile_addr)
    for entry in tx.access_list:
        env.access_sets.mark_warm_address(entry.address)
        for key in entry.storage_keys:
            env.access_sets.mark_warm_storage(entry.address, int.from_bytes(key, "big"))

    # Execute
    gas_available = tx.gas_limit - base_gas
    to_bytes = tx.to if tx.to is not None else None

    snap = env.snapshot()

    if to_bytes is None:
        # Contract creation
        nonce = store.get_nonce(sender) - 1  # already incremented
        contract_addr = keccak256(rlp.encode([sender, nonce]))[12:]
        env.set_nonce(contract_addr, 1)
        if tx.value > 0:
            env.add_balance(contract_addr, tx.value)
            env.sub_balance(sender, tx.value)

        frame = CallFrame(
            caller=sender,
            address=contract_addr,
            code_address=contract_addr,
            origin=sender,
            code=tx.data,
            gas=gas_available,
            value=tx.value,
            depth=0,
        )
        hook.before_call(frame)
        success, return_data = run_bytecode(frame, env)
        hook.after_call(frame, success, return_data)

        if success and return_data:
            if len(return_data) <= 24576:
                code_cost = G_CODEDEPOSIT * len(return_data)
                if frame.gas_used + code_cost <= gas_available:
                    frame.gas_used += code_cost
                    env.set_code(contract_addr, return_data)
                    store.set_account_code(contract_addr, return_data)
                else:
                    success = False
                    frame.gas_used = gas_available
            else:
                success = False
                frame.gas_used = gas_available
    else:
        # Message call
        if tx.value > 0:
            env.sub_balance(sender, tx.value)
            env.add_balance(to_bytes, tx.value)

        if is_precompile(to_bytes):
            result = run_precompile(to_bytes, tx.data)
            if result is not None:
                pc_gas, output = result
                frame = CallFrame(gas=gas_available)
                frame.gas_used = pc_gas
                success = True
                return_data = output
            else:
                frame = CallFrame(gas=gas_available)
                frame.gas_used = gas_available
                success = False
                return_data = b""
        else:
            code = env.get_code(to_bytes)
            frame = CallFrame(
                caller=sender,
                address=to_bytes,
                code_address=to_bytes,
                origin=sender,
                code=code,
                gas=gas_available,
                value=tx.value,
                calldata=tx.data,
                depth=0,
            )
            if code:
                hook.before_call(frame)
                success, return_data = run_bytecode(frame, env)
                hook.after_call(frame, success, return_data)
            else:
                success = True
                return_data = b""

    evm_gas_used = frame.gas_used
    total_gas_used = base_gas + evm_gas_used

    if success:
        # Apply refund
        max_refund = total_gas_used // MAX_REFUND_QUOTIENT
        actual_refund = min(env.refund, max_refund)
        total_gas_used -= actual_refund
        env.commit(snap)

        # Sync env state changes back to store
        _sync_env_to_store(env, store)
    else:
        env.rollback(snap)

    # Refund unused gas to sender
    gas_refund = (tx.gas_limit - total_gas_used) * effective_gas_price
    store.set_balance(sender, store.get_balance(sender) + gas_refund)

    # Pay coinbase (priority fee)
    priority_fee = effective_gas_price - base_fee
    coinbase_reward = total_gas_used * priority_fee
    if coinbase_reward > 0:
        store.set_balance(
            header.coinbase,
            store.get_balance(header.coinbase) + coinbase_reward,
        )

    # Build receipt
    cumulative = cumulative_gas + total_gas_used
    tx_logs = env.logs if success else []
    bloom = logs_bloom(tx_logs)
    receipt = Receipt(
        succeeded=success,
        cumulative_gas_used=cumulative,
        logs_bloom=bloom,
        logs=tx_logs,
        tx_type=tx.tx_type,
    )

    return TxExecutionResult(
        success=success,
        gas_used=total_gas_used,
        receipt=receipt,
        return_data=return_data,
        logs=tx_logs,
    )


def _bind_env_to_store(env: ExecutionEnvironment, store: Store) -> None:
    """Connect ExecutionEnvironment state accessors to Store."""
    env._balances = {}
    env._nonces = {}
    env._code = {}
    env._storage = {}
    env._original_storage = {}

    # Copy current state into env
    for addr, acc in store.iter_accounts():
        env._balances[addr] = acc.balance
        env._nonces[addr] = acc.nonce
        code = store.get_account_code(addr)
        if code:
            env._code[addr] = code
    for (addr, key), val in store.iter_storage():
        env._storage[(addr, key)] = val
    for (addr, key), val in store.iter_original_storage():
        env._original_storage[(addr, key)] = val


def _sync_env_to_store(env: ExecutionEnvironment, store: Store) -> None:
    """Sync state changes from ExecutionEnvironment back to Store."""
    from ethclient.common.types import Account, EMPTY_CODE_HASH

    # Update balances and nonces
    all_addrs = set(env._balances.keys()) | set(env._nonces.keys())
    for addr in all_addrs:
        acc = store.get_account(addr)
        if acc is None:
            acc = Account()
            store.put_account(addr, acc)
        if addr in env._balances:
            acc.balance = env._balances[addr]
        if addr in env._nonces:
            acc.nonce = env._nonces[addr]

    # Update storage
    for (addr, key), val in env._storage.items():
        store.put_storage(addr, key, val)

    # Handle self-destructs
    for addr in env.selfdestructs:
        store.delete_account(addr)


# ---------------------------------------------------------------------------
# Block execution
# ---------------------------------------------------------------------------

@dataclass
class BlockExecutionResult:
    receipts: list[Receipt] = field(default_factory=list)
    total_gas_used: int = 0
    state_root: bytes = field(default_factory=lambda: ZERO_HASH)
    receipts_root: bytes = field(default_factory=lambda: EMPTY_TRIE_ROOT)
    logs_bloom: bytes = field(default_factory=lambda: b"\x00" * BLOOM_BYTE_SIZE)


def execute_block(
    block: Block,
    store: Store,
    config: ChainConfig,
    hook: ExecutionHook = DefaultHook(),
) -> BlockExecutionResult:
    """Execute all transactions in a block and return the result."""

    receipts: list[Receipt] = []
    cumulative_gas = 0
    block_bloom = bytearray(BLOOM_BYTE_SIZE)

    # Snapshot original storage for SSTORE gas calculations
    store.commit_original_storage()

    for i, tx in enumerate(block.transactions):
        result = execute_transaction(
            tx, block.header, store, config, cumulative_gas, i, hook,
        )
        if result.receipt is None:
            raise BlockValidationError(
                f"Transaction {i} execution failed: {result.error}"
            )
        receipts.append(result.receipt)
        cumulative_gas += result.gas_used

        # Merge bloom
        for j in range(BLOOM_BYTE_SIZE):
            block_bloom[j] |= result.receipt.logs_bloom[j]

    # Block reward (PoW blocks only — pre-merge)
    if block.header.difficulty > 0:
        _apply_block_reward(block, store, config)

    # Process withdrawals (post-Shanghai)
    if block.withdrawals is not None:
        for w in block.withdrawals:
            # Withdrawal amount is in Gwei, convert to Wei
            amount_wei = w.amount * 10**9
            store.set_balance(
                w.address,
                store.get_balance(w.address) + amount_wei,
            )

    # Compute state root
    state_root = store.compute_state_root()

    # Compute receipts root
    receipt_rlps = [r.encode_rlp() for r in receipts]
    receipts_root = ordered_trie_root(receipt_rlps)

    return BlockExecutionResult(
        receipts=receipts,
        total_gas_used=cumulative_gas,
        state_root=state_root,
        receipts_root=receipts_root,
        logs_bloom=bytes(block_bloom),
    )


def _apply_block_reward(
    block: Block,
    store: Store,
    config: ChainConfig,
) -> None:
    """Apply PoW block reward to miner and uncle miners.

    Reward schedule:
      - Frontier/Homestead: 5 ETH
      - Byzantium:          3 ETH
      - Constantinople+:    2 ETH
      - Post-merge:         0 ETH (difficulty == 0)
    """
    WEI = 10**18

    if config.is_constantinople(block.header.number):
        base_reward = 2 * WEI
    elif config.is_byzantium(block.header.number):
        base_reward = 3 * WEI
    else:
        base_reward = 5 * WEI

    # Miner reward = base + (base / 32) * num_uncles
    num_ommers = len(block.ommers)
    miner_reward = base_reward + (base_reward // 32) * num_ommers
    store.set_balance(
        block.header.coinbase,
        store.get_balance(block.header.coinbase) + miner_reward,
    )

    # Uncle rewards: ((uncle_number + 8 - block_number) / 8) * base_reward
    for ommer in block.ommers:
        uncle_reward = ((ommer.number + 8 - block.header.number) * base_reward) // 8
        if uncle_reward > 0:
            store.set_balance(
                ommer.coinbase,
                store.get_balance(ommer.coinbase) + uncle_reward,
            )


def validate_and_execute_block(
    block: Block,
    parent: BlockHeader,
    store: Store,
    config: ChainConfig,
    hook: ExecutionHook = DefaultHook(),
) -> BlockExecutionResult:
    """Validate block header, execute transactions, and verify post-state."""

    # 1. Validate header
    validate_header(block.header, parent, config)

    # 2. Validate transactions root
    tx_rlps = [tx.encode_rlp() for tx in block.transactions]
    expected_tx_root = ordered_trie_root(tx_rlps)
    if block.header.transactions_root != expected_tx_root:
        raise BlockValidationError(
            f"Transactions root mismatch: "
            f"expected {expected_tx_root.hex()}, "
            f"got {block.header.transactions_root.hex()}"
        )

    # 3. Execute block
    result = execute_block(block, store, config, hook)

    # 4. Verify gas used
    if result.total_gas_used != block.header.gas_used:
        raise BlockValidationError(
            f"Gas used mismatch: expected {block.header.gas_used}, "
            f"got {result.total_gas_used}"
        )

    # 5. Verify state root
    if result.state_root != block.header.state_root:
        raise BlockValidationError(
            f"State root mismatch: "
            f"expected {block.header.state_root.hex()}, "
            f"got {result.state_root.hex()}"
        )

    # 6. Verify receipts root
    if result.receipts_root != block.header.receipts_root:
        raise BlockValidationError(
            f"Receipts root mismatch: "
            f"expected {block.header.receipts_root.hex()}, "
            f"got {result.receipts_root.hex()}"
        )

    return result
