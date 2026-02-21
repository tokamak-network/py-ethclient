"""Sequencer chain management."""

import threading
import time
from typing import Any

from eth_utils import to_wei
from eth_keys import keys

from sequencer.core.constants import (
    DEFAULT_CHAIN_ID,
    DEFAULT_GAS_LIMIT,
    ELASTICITY_MULTIPLIER,
    BASE_FEE_MAX_CHANGE_DENOMINATOR,
    INITIAL_BASE_FEE,
)
from sequencer.core.types import Block, BlockHeader, Receipt
from sequencer.core.crypto import keccak256, private_key_to_address
from sequencer.core.create2 import compute_create_address
from sequencer.evm.adapter import EVMAdapter, ChainConfig, ExecutionResult
from sequencer.storage.store import InMemoryStore
from sequencer.storage.sqlite_store import SQLiteStore
from sequencer.sequencer.mempool import Mempool


EMPTY_OMMERS_HASH = keccak256(b"\xc0")
DEFAULT_BLOCK_TIME = 10


def calc_base_fee(parent_gas_used: int, parent_gas_limit: int, parent_base_fee: int) -> int:
    gas_target = parent_gas_limit // ELASTICITY_MULTIPLIER
    if parent_gas_used == gas_target:
        return parent_base_fee
    elif parent_gas_used > gas_target:
        gas_delta = parent_gas_used - gas_target
        fee_delta = max(parent_base_fee * gas_delta // gas_target // BASE_FEE_MAX_CHANGE_DENOMINATOR, 1)
        return parent_base_fee + fee_delta
    else:
        gas_delta = gas_target - parent_gas_used
        fee_delta = parent_base_fee * gas_delta // gas_target // BASE_FEE_MAX_CHANGE_DENOMINATOR
        return max(parent_base_fee - fee_delta, 1)


class Chain:
    def __init__(
        self,
        chain_id: int = DEFAULT_CHAIN_ID,
        gas_limit: int = DEFAULT_GAS_LIMIT,
        coinbase: bytes = b"\x00" * 20,
        genesis_state: dict | None = None,
        block_time: int = DEFAULT_BLOCK_TIME,
        store_type: str = "memory",
        store_path: str = "sequencer.db",
    ):
        self.chain_id = chain_id
        self.gas_limit = gas_limit
        self.coinbase = coinbase
        self.block_time = block_time
        self._store_path = store_path  # Keep for state persistence
        
        # Initialize storage backend
        if store_type == "sqlite":
            self.store = SQLiteStore(store_path)
        else:
            self.store = InMemoryStore()
        
        self.mempool = Mempool()
        self._last_block_time: int = 0
        self._lock = threading.RLock()  # Thread safety for concurrent access
        
        # Track touched addresses for state persistence
        self._touched_addresses: set[bytes] = set()
        
        config = ChainConfig(
            chain_id=chain_id,
            gas_limit=gas_limit,
            coinbase=coinbase,
            genesis_state=genesis_state,
        )
        self.evm = EVMAdapter(config)
        
        # Track genesis addresses
        if genesis_state:
            for address in genesis_state.keys():
                addr = address if isinstance(address, bytes) else bytes.fromhex(address)
                self._touched_addresses.add(addr)

    def _restore_evm_state(self):
        """Restore EVM state from SQLite storage."""
        if not isinstance(self.store, SQLiteStore):
            return
        
        # Load state from SQLite
        state = self.store.load_evm_state()
        
        if not state:
            return
        
        # Import state into EVM
        self.evm.import_state(state)
        
        # Track addresses
        for address in state.keys():
            self._touched_addresses.add(address)
        
        print(f"✅ Restored state for {len(state)} accounts from {self._store_path}")

    def _save_evm_state(self):
        """Save EVM state to SQLite storage."""
        if not isinstance(self.store, SQLiteStore):
            return
        
        # Export state for all touched addresses
        state = {}
        for address in self._touched_addresses:
            try:
                nonce = self.evm.get_nonce(address)
                balance = self.evm.get_balance(address)
                code = self.evm.get_code(address)
                
                # Get storage from SQLite if it exists
                storage = self.store.get_all_storage(address)
                
                state[address] = {
                    "nonce": nonce,
                    "balance": balance,
                    "code": code,
                    "storage": storage,
                }
            except Exception:
                pass
        
        # Save to SQLite
        self.store.save_evm_state(state)
        
        print(f"✅ Saved state for {len(state)} accounts to {self._store_path}")

    @classmethod
    def from_genesis(
        cls,
        genesis_state: dict,
        chain_id: int = DEFAULT_CHAIN_ID,
        gas_limit: int = DEFAULT_GAS_LIMIT,
        coinbase: bytes = b"\x00" * 20,
        timestamp: int | None = None,
        block_time: int = DEFAULT_BLOCK_TIME,
        store_type: str = "memory",
        store_path: str = "sequencer.db",
    ) -> "Chain":
        # Check if we have existing blocks and state in SQLite
        merged_state = genesis_state.copy() if genesis_state else {}
        has_existing_blocks = False
        existing_genesis = None
        
        if store_type == "sqlite":
            from sequencer.storage.sqlite_store import SQLiteStore
            temp_store = SQLiteStore(store_path)
            
            # Check if there's existing state
            existing_state = temp_store.load_evm_state()
            if existing_state:
                print(f"✅ Loaded existing state for {len(existing_state)} accounts from {store_path}")
                # Merge existing state with genesis state (existing state takes precedence)
                for address, account_data in existing_state.items():
                    merged_state[address] = account_data
            
            # Check if there's an existing genesis block
            existing_genesis = temp_store.get_block(0)
            temp_store.close()
            
            # If genesis block exists, don't create a new one
            has_existing_blocks = existing_genesis is not None
        
        chain = cls(
            chain_id=chain_id,
            gas_limit=gas_limit,
            coinbase=coinbase,
            genesis_state=merged_state,
            block_time=block_time,
            store_type=store_type,
            store_path=store_path,
        )
        
        # Only create genesis block if this is a new chain
        if not has_existing_blocks:
            genesis_block = chain._create_genesis_block(timestamp or int(time.time()))
            chain.store.save_block(genesis_block, [], [])
            chain._last_block_time = genesis_block.header.timestamp
        else:
            # Use existing genesis block's timestamp
            chain._last_block_time = existing_genesis.header.timestamp
        
        return chain
    
    def _create_genesis_block(self, timestamp: int) -> Block:
        # Don't reinitialize state if we already have state loaded
        # State should already be set via from_genesis or import_state
        header = BlockHeader(
            parent_hash=b"\x00" * 32,
            ommers_hash=EMPTY_OMMERS_HASH,
            coinbase=self.coinbase,
            state_root=self.evm.state_root,
            transactions_root=keccak256(b"\x80"),
            receipts_root=keccak256(b"\x80"),
            logs_bloom=b"\x00" * 256,
            difficulty=0,
            number=0,
            gas_limit=self.gas_limit,
            gas_used=0,
            timestamp=timestamp,
            base_fee_per_gas=1_000_000_000,
        )
        return Block(header=header, transactions=[])

    def get_nonce(self, address: bytes) -> int:
        return self.evm.get_nonce(address)

    def get_balance(self, address: bytes) -> int:
        return self.evm.get_balance(address)

    def get_code(self, address: bytes) -> bytes:
        return self.evm.get_code(address)

    def get_storage_at(self, address: bytes, slot: int) -> int:
        return self.evm.get_storage(address, slot)

    def get_block_by_number(self, number: int) -> Block | None:
        return self.store.get_block(number)

    def get_block_by_hash(self, block_hash: bytes) -> Block | None:
        return self.store.get_block_by_hash(block_hash)

    def get_latest_block(self) -> Block | None:
        return self.store.get_latest_block()

    def get_latest_block_number(self) -> int:
        return self.store.get_latest_number()

    def get_transaction_receipt(self, tx_hash: bytes):
        return self.store.get_transaction_receipt(tx_hash)

    def get_transaction_by_hash(self, tx_hash: bytes):
        """Get transaction by hash. Returns (block, tx) or None."""
        result = self.store.get_transaction_by_hash(tx_hash)
        if not result:
            return None
        
        block, tx_index = result
        return (block, block.transactions[tx_index])

    def add_transaction_to_pool(self, tx) -> bool:
        with self._lock:
            sender = tx.sender
            current_nonce = self.get_nonce(sender)
            return self.mempool.add(tx, current_nonce)

    def create_transaction(
        self,
        from_private_key: bytes,
        to: bytes | None,
        value: int = 0,
        data: bytes = b"",
        gas: int = 100_000,
        gas_price: int | None = None,
        nonce: int | None = None,
    ) -> Any:
        sender = private_key_to_address(from_private_key)
        
        if nonce is None:
            nonce = self.get_nonce(sender)
        
        if gas_price is None:
            gas_price = 1_000_000_000
        
        to_address = b"" if to is None else to
        
        unsigned_tx = self.evm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=to_address,
            value=value,
            data=data,
        )
        
        pk = keys.PrivateKey(from_private_key)
        return unsigned_tx.as_signed_transaction(pk)

    def create_eip1559_transaction(
        self,
        from_private_key: bytes,
        to: bytes | None,
        value: int = 0,
        data: bytes = b"",
        gas: int = 100_000,
        max_priority_fee_per_gas: int | None = None,
        max_fee_per_gas: int | None = None,
        nonce: int | None = None,
        access_list: list[tuple[bytes, Sequence[int]]] | None = None,
    ) -> Any:
        """
        Create a signed EIP-1559 transaction (Type 0x02).
        
        EIP-1559 transactions introduce a base fee mechanism and can optionally
        include an access list (EIP-2930) for gas optimization.
        
        Args:
            from_private_key: Private key of the sender
            to: Recipient address (None for contract creation)
            value: Value to transfer in wei
            data: Transaction data
            gas: Gas limit
            max_priority_fee_per_gas: Priority fee per gas (tip to miner)
            max_fee_per_gas: Maximum total fee per gas
            nonce: Sender's nonce (auto-filled if None)
            access_list: Optional list of (address, [storage_keys]) tuples.
                        Can be in tuple format [(addr_bytes, [slot_int, ...])]
                        or RPC format [{"address": "0x...", "storageKeys": ["0x..."]}]
        
        Returns:
            Signed DynamicFeeTransaction
        
        Example:
            >>> # Simple transfer
            >>> tx = chain.create_eip1559_transaction(
            ...     from_private_key=private_key,
            ...     to=recipient,
            ...     value=1_000_000,
            ...     gas=21_000,
            ... )
            >>> 
            >>> # With access list for gas optimization (tuple format)
            >>> access_list = [(contract_address, [0, 1])]
            >>> tx = chain.create_eip1559_transaction(
            ...     from_private_key=private_key,
            ...     to=contract_address,
            ...     data=calldata,
            ...     gas=200_000,
            ...     access_list=access_list,
            ... )
        """
        sender = private_key_to_address(from_private_key)
        
        if nonce is None:
            nonce = self.get_nonce(sender)
        
        latest_block = self.get_latest_block()
        base_fee = latest_block.header.base_fee_per_gas if latest_block and latest_block.header.base_fee_per_gas else INITIAL_BASE_FEE
        
        if max_fee_per_gas is None:
            max_fee_per_gas = base_fee * 2
        
        if max_priority_fee_per_gas is None:
            max_priority_fee_per_gas = base_fee // 10
        
        to_address = b"" if to is None else to
        
        # Parse access_list if provided (support both tuple and dict formats)
        formatted_access_list: Sequence[tuple[bytes, Sequence[int]]] = ()
        if access_list is not None:
            formatted_access_list = []
            for item in access_list:
                if isinstance(item, dict):
                    # RPC format: {"address": "0x...", "storageKeys": [...]}
                    addr_str = item["address"]
                    addr = bytes.fromhex(addr_str[2:] if addr_str.startswith("0x") else addr_str)
                    storage_keys = [int(k, 16) if isinstance(k, str) and k.startswith("0x") else int(k) for k in item.get("storageKeys", [])]
                    formatted_access_list.append((addr, storage_keys))
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    # Tuple format: (address_bytes, [slot_int, ...])
                    addr, storage_keys = item
                    if isinstance(addr, str):
                        addr = bytes.fromhex(addr.replace("0x", ""))
                    parsed_keys = [int(k, 16) if isinstance(k, str) and k.startswith("0x") else int(k) for k in storage_keys]
                    formatted_access_list.append((addr, parsed_keys))
                else:
                    formatted_access_list.append(item)
        
        unsigned_tx = self.evm.create_unsigned_eip1559_transaction(
            nonce=nonce,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            max_fee_per_gas=max_fee_per_gas,
            gas=gas,
            to=to_address,
            value=value,
            data=data,
            chain_id=self.chain_id,
            access_list=formatted_access_list,
        )
        
        pk = keys.PrivateKey(from_private_key)
        return unsigned_tx.as_signed_transaction(pk)

    def create_access_list_transaction(
        self,
        from_private_key: bytes,
        to: bytes | None,
        access_list: list[tuple[bytes, Sequence[int]]],
        value: int = 0,
        data: bytes = b"",
        gas: int = 100_000,
        gas_price: int | None = None,
        nonce: int | None = None,
    ) -> Any:
        """
        Create a signed EIP-2930 access list transaction (Type 0x01).
        
        Access list transactions allow pre-declaring addresses and storage slots
        that will be accessed during execution, providing:
        - Lower gas costs for cold accesses (pre-warming)
        - More predictable gas estimation
        - Better compatibility with L2 protocols
        
        Args:
            from_private_key: Private key of the sender
            to: Recipient address (None for contract creation)
            access_list: List of (address, [storage_keys]) tuples
            value: Value to transfer in wei
            data: Transaction data
            gas: Gas limit
            gas_price: Gas price in wei (auto-filled if None)
            nonce: Sender's nonce (auto-filled if None)
        
        Returns:
            Signed AccessListTransaction
        
        Example:
            >>> # Pre-declare addresses and storage slots to access
            >>> access_list = [
            ...     (token_address, [0, 1]),  # Token contract: slots 0, 1
            ...     (router_address, []),      # Router contract: no slots
            ... ]
            >>> tx = chain.create_access_list_transaction(
            ...     from_private_key=private_key,
            ...     to=router_address,
            ...     access_list=access_list,
            ...     data=swap_calldata,
            ...     gas=500_000,
            ... )
        """
        from typing import Sequence as TypingSequence
        
        sender = private_key_to_address(from_private_key)
        
        if nonce is None:
            nonce = self.get_nonce(sender)
        
        if gas_price is None:
            latest_block = self.get_latest_block()
            base_fee = latest_block.header.base_fee_per_gas if latest_block and latest_block.header.base_fee_per_gas else INITIAL_BASE_FEE
            gas_price = base_fee
        
        to_address = b"" if to is None else to
        
        # Parse access_list (support both tuple and dict formats)
        formatted_access_list: Sequence[tuple[bytes, Sequence[int]]] = []
        for item in access_list:
            if isinstance(item, dict):
                # RPC format: {"address": "0x...", "storageKeys": [...]}
                addr_str = item["address"]
                addr = bytes.fromhex(addr_str[2:] if addr_str.startswith("0x") else addr_str)
                storage_keys = [int(k, 16) if isinstance(k, str) and k.startswith("0x") else int(k) for k in item.get("storageKeys", [])]
                formatted_access_list.append((addr, storage_keys))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                # Tuple format: (address_bytes, [slot_int, ...])
                addr, storage_keys = item
                if isinstance(addr, str):
                    addr = bytes.fromhex(addr.replace("0x", ""))
                parsed_keys = [int(k, 16) if isinstance(k, str) and k.startswith("0x") else int(k) for k in storage_keys]
                formatted_access_list.append((addr, parsed_keys))
            else:
                formatted_access_list.append(item)
        
        unsigned_tx = self.evm.create_unsigned_access_list_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=to_address,
            value=value,
            data=data,
            access_list=formatted_access_list,
            chain_id=self.chain_id,
        )
        
        pk = keys.PrivateKey(from_private_key)
        return unsigned_tx.as_signed_transaction(pk)

    def create_setcode_transaction(
        self,
        from_private_key: bytes,
        to: bytes,
        value: int = 0,
        data: bytes = b"",
        gas: int = 100_000,
        max_priority_fee_per_gas: int | None = None,
        max_fee_per_gas: int | None = None,
        nonce: int | None = None,
        authorization_list: list | None = None,
    ) -> Any:
        """
        Create a signed EIP-7702 SetCode transaction (Type 0x04).
        
        This allows an EOA to temporarily set its code to a contract's code.
        
        Args:
            from_private_key: Private key of the sender
            to: Recipient address (required for SetCode transactions)
            value: Value to transfer
            data: Transaction data
            gas: Gas limit
            max_priority_fee_per_gas: Priority fee per gas
            max_fee_per_gas: Maximum fee per gas
            nonce: Sender's nonce (auto-filled if None)
            authorization_list: List of Authorization objects
        
        Returns:
            Signed SetCodeTransaction
        """
        sender = private_key_to_address(from_private_key)
        
        if nonce is None:
            nonce = self.get_nonce(sender)
        
        latest_block = self.get_latest_block()
        base_fee = latest_block.header.base_fee_per_gas if latest_block and latest_block.header.base_fee_per_gas else INITIAL_BASE_FEE
        
        if max_fee_per_gas is None:
            max_fee_per_gas = base_fee * 2
        
        if max_priority_fee_per_gas is None:
            max_priority_fee_per_gas = base_fee // 10
        
        if authorization_list is None:
            authorization_list = []
        
        unsigned_tx = self.evm.create_unsigned_setcode_transaction(
            nonce=nonce,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            max_fee_per_gas=max_fee_per_gas,
            gas=gas,
            to=to,
            value=value,
            data=data,
            authorization_list=authorization_list,
            chain_id=self.chain_id,
        )
        
        pk = keys.PrivateKey(from_private_key)
        return unsigned_tx.as_signed_transaction(pk)

    def create_authorization(
        self,
        chain_id: int,
        address: bytes,
        nonce: int,
        private_key: bytes,
    ):
        """
        Create a signed EIP-7702 authorization.
        
        Args:
            chain_id: Chain ID (0 = all chains, or specific chain ID)
            address: Contract address to delegate to
            nonce: Account nonce after authorization
            private_key: Private key to sign the authorization
        
        Returns:
            Signed Authorization object
        """
        return self.evm.create_authorization(
            chain_id=chain_id,
            address=address,
            nonce=nonce,
            private_key=private_key,
        )

    def send_transaction(self, signed_tx) -> bytes:
        with self._lock:
            # Validate balance before adding to mempool
            sender = signed_tx.sender
            balance = self.get_balance(sender)
            
            # Calculate required amount: value + gas * gas_price
            value = signed_tx.value
            
            # Get gas price (handle both legacy and EIP-1559 transactions)
            if hasattr(signed_tx, 'max_fee_per_gas'):
                # EIP-1559 transaction
                gas_price = signed_tx.max_fee_per_gas
            else:
                # Legacy transaction
                gas_price = signed_tx.gas_price
            
            gas = signed_tx.gas
            required = value + (gas * gas_price)
            
            # Account for pending transactions from the same sender
            pending_cost = 0
            if sender in self.mempool.by_sender:
                for tx_hash in self.mempool.by_sender[sender].values():
                    pending_tx = self.mempool.txs.get(tx_hash)
                    if pending_tx:
                        pending_cost += pending_tx.value
                        # Add gas cost for pending transaction
                        if hasattr(pending_tx, 'max_fee_per_gas'):
                            pending_cost += pending_tx.gas * pending_tx.max_fee_per_gas
                        else:
                            pending_cost += pending_tx.gas * pending_tx.gas_price
            
            available_balance = balance - pending_cost
            
            if available_balance < required:
                from sequencer.sequencer.mempool import InsufficientFunds
                raise InsufficientFunds(
                    f"insufficient funds for gas * price + value: "
                    f"address {sender.hex()} have {balance} want {required}"
                    f" (pending: {pending_cost})"
                )
            
            tx_hash = keccak256(signed_tx.encode())
            self.add_transaction_to_pool(signed_tx)
            return tx_hash
    
    def should_build_block(self) -> bool:
        with self._lock:
            if len(self.mempool) == 0:
                return False
            
            current_time = int(time.time())
            time_elapsed = current_time - self._last_block_time
            
            return time_elapsed >= self.block_time

    def call(
        self,
        from_address: bytes,
        to: bytes,
        value: int = 0,
        data: bytes = b"",
        gas: int = 30_000_000,
    ) -> bytes:
        """
        Execute a call without modifying state (eth_call).
        
        Returns the output data from the execution.
        """
        vm = self.evm.get_vm()
        
        # Get the code at the target address
        code = vm.state.get_code(to)
        
        # Execute the bytecode
        computation = vm.execute_bytecode(
            origin=from_address,
            gas_price=0,
            gas=gas,
            to=to,
            sender=from_address,
            value=value,
            data=data,
            code=code,
        )
        
        # Return the output (even if there was an error, return output for debugging)
        return computation.output

    def estimate_gas(
        self,
        from_address: bytes,
        to: bytes | None,
        value: int = 0,
        data: bytes = b"",
        gas_limit: int | None = None,
    ) -> int:
        """
        Estimate gas for a transaction using binary search.
        
        Returns the minimum gas required for the transaction to succeed.
        """
        if gas_limit is None:
            gas_limit = self.gas_limit
        
        # Minimum gas for a transaction is 21,000
        low = 21_000
        high = gas_limit
        
        # Quick check: try with full gas limit first
        success, _ = self._try_execution(from_address, to, value, data, high)
        if not success:
            # Transaction will fail even with max gas
            # Return high value anyway (let caller handle the error)
            return high
        
        # Binary search for minimum gas
        result = high
        
        # Optimization: if it's a simple transfer (no data), return 21,000
        if not data or len(data) == 0:
            return 21_000
        
        # Binary search
        while low < high:
            mid = (low + high) // 2
            success, gas_used = self._try_execution(from_address, to, value, data, mid)
            
            if success:
                result = mid
                high = mid
            else:
                low = mid + 1
        
        # Add a small buffer (10%) to account for potential variations
        return int(result * 1.1)

    def _try_execution(
        self,
        from_address: bytes,
        to: bytes | None,
        value: int,
        data: bytes,
        gas: int,
    ) -> tuple[bool, int]:
        """
        Try executing a transaction with the given gas limit.
        
        Returns (success, gas_used).
        """
        vm = self.evm.get_vm()
        
        # Use execute_bytecode for stateless execution
        try:
            if to is None:
                # Contract creation
                computation = vm.execute_bytecode(
                    origin=from_address,
                    gas_price=0,
                    gas=gas,
                    to=b"",
                    sender=from_address,
                    value=value,
                    data=data,
                    code=data,
                )
            else:
                # Contract call or transfer
                computation = vm.execute_bytecode(
                    origin=from_address,
                    gas_price=0,
                    gas=gas,
                    to=to,
                    sender=from_address,
                    value=value,
                    data=data,
                    code=b"",
                )
            
            if computation.is_error:
                return (False, 0)
            
            # Return the gas used
            gas_used = computation.get_gas_used()
            return (True, gas_used)
            
        except Exception as e:
            return (False, 0)

    def build_block(self, timestamp: int | None = None) -> Block:
        with self._lock:
            return self._build_block_unsafe(timestamp)
    
    def _extract_created_contracts(self, computation, tx) -> dict[bytes, dict]:
        """
        Extract all contract addresses created during transaction execution.
        
        This detects both CREATE (nonce-based) and CREATE2 (salt-based) deployments
        by examining the computation's children.
        
        Args:
            computation: The EVM computation result
            tx: The transaction that was executed
        
        Returns:
            Dict mapping address -> {"type": "create"|"create2", "salt": bytes|None}
        """
        created = {}
        
        # Method 1: Check for direct contract creation (CREATE)
        if tx.to is None or tx.to == b"":
            # CREATE contract: address based on sender + nonce
            address = compute_create_address(tx.sender, tx.nonce)
            created[address] = {"type": "create", "salt": None}
        
        # Method 2: Extract CREATE2 deployments from computation children
        # CREATE2 happens during contract execution, not at the top level
        if hasattr(computation, 'children'):
            for child in computation.children:
                # Check if this is a CREATE/CREATE2 execution
                if hasattr(child, 'msg'):
                    msg = child.msg
                    if hasattr(msg, 'create_address') and msg.create_address:
                        # Determine if it's CREATE or CREATE2
                        is_create2 = hasattr(msg, 'salt') and msg.salt is not None
                        if is_create2:
                            created[msg.create_address] = {
                                "type": "create2",
                                "salt": msg.salt if hasattr(msg, 'salt') else None,
                                "deployer": tx.sender,
                                "init_code_hash": keccak256(msg.data) if hasattr(msg, 'data') else None,
                            }
                        elif msg.create_address not in created:
                            # Nested CREATE (can happen in factory patterns)
                            created[msg.create_address] = {"type": "create", "salt": None}
        
        return created

    def _build_block_unsafe(self, timestamp: int | None = None) -> Block:
        """Internal build_block without lock (callers must hold _lock)."""
        import time as time_module
        from eth_utils.exceptions import ValidationError
        
        current_time = int(time_module.time())
        
        current_nonces = {}
        for sender in self.mempool.by_sender.keys():
            current_nonces[sender] = self.get_nonce(sender)
        
        pending = self.mempool.get_pending(100, current_nonces)
        
        receipts = []
        cumulative_gas = 0
        
        # Track addresses that are touched during this block
        touched_this_block: set[bytes] = set()
        
        # Track CREATE2 contracts for persistence
        create2_contracts: list[tuple[bytes, dict]] = []
        
        # Track which transactions are actually included (gas limit may cut some off)
        included_txs = []
        included_tx_hashes = []
        
        # Track failed transactions to remove from mempool
        failed_tx_hashes = []
        
        for tx in pending:
            # Check gas limit BEFORE execution using declared gas
            tx_gas_limit = tx.gas
            if cumulative_gas + tx_gas_limit > self.gas_limit:
                break  # Block full, stop adding transactions
            
            tx_hash = keccak256(tx.encode())
            
            # Try to execute the transaction
            try:
                block, evm_receipt, computation = self.evm.apply_transaction(tx)
            except ValidationError as e:
                # Transaction failed validation (e.g., insufficient balance)
                # Skip this transaction and continue with others
                print(f"Warning: Transaction {tx_hash.hex()} failed validation: {e}")
                failed_tx_hashes.append(tx_hash)
                continue
            
            # Track this transaction as included
            included_txs.append(tx)
            included_tx_hashes.append(tx_hash)
            
            # Track sender
            touched_this_block.add(tx.sender)
            
            # Track recipient (if not contract creation)
            if tx.to and tx.to != b"":
                touched_this_block.add(tx.to)
            
            # IMPORTANT: receipt.gas_used is cumulative (Ethereum spec)
            # So we use it directly rather than adding
            if computation.is_error:
                # On error, add the full gas
                cumulative_gas += tx.gas
            else:
                # Use receipt's cumulative gas used
                cumulative_gas = evm_receipt.gas_used if hasattr(evm_receipt, 'gas_used') else cumulative_gas + tx.gas
            
            # Extract all contracts created during this transaction (CREATE and CREATE2)
            created_contracts = self._extract_created_contracts(computation, tx)
            
            # Track all created contract addresses
            for contract_address, contract_info in created_contracts.items():
                touched_this_block.add(contract_address)
                
                # Track CREATE2 contracts for persistence
                if contract_info["type"] == "create2" and isinstance(self.store, SQLiteStore):
                    create2_contracts.append((
                        contract_address,
                        {
                            "deployer": contract_info.get("deployer", tx.sender),
                            "salt": contract_info.get("salt", b"\x00" * 32),
                            "init_code_hash": contract_info.get("init_code_hash", b"\x00" * 32),
                        }
                    ))
            
            # Primary contract address for receipt (first created contract, or None)
            # For CREATE transactions, this is the single contract created
            # For CREATE2, we track all contracts but receipt shows the primary one
            contract_address = None
            if tx.to is None or tx.to == b"":
                # Use CREATE address calculation for primary receipt field
                contract_address = compute_create_address(tx.sender, tx.nonce)
            
            receipt = Receipt(
                status=0 if computation.is_error else 1,
                cumulative_gas_used=cumulative_gas,
                logs=computation.get_log_entries() if hasattr(computation, "get_log_entries") else [],
                contract_address=contract_address,
            )
            receipts.append(receipt)
            
            # Save individual account state changes to SQLite
            if isinstance(self.store, SQLiteStore):
                for contract_address in created_contracts:
                    # Save contract code immediately after creation
                    code = self.evm.get_code(contract_address)
                    if code:
                        self.store.save_account(
                            contract_address,
                            nonce=self.evm.get_nonce(contract_address),
                            balance=self.evm.get_balance(contract_address),
                            code=code,
                        )
        
        parent = self.get_latest_block()
        parent_timestamp = parent.header.timestamp if parent else current_time - 1
        block_timestamp = max(current_time, parent_timestamp + 1)
        
        mined_block = self.evm.mine_block(timestamp=block_timestamp)
        
        parent_hash = parent.hash if parent else b"\x00" * 32
        number = (parent.number + 1) if parent else 1
        
        if parent and parent.header.base_fee_per_gas:
            new_base_fee = calc_base_fee(
                parent.header.gas_used,
                parent.header.gas_limit,
                parent.header.base_fee_per_gas,
            )
        else:
            new_base_fee = INITIAL_BASE_FEE
        
        header = BlockHeader(
            parent_hash=parent_hash,
            ommers_hash=EMPTY_OMMERS_HASH,
            coinbase=self.coinbase,
            state_root=mined_block.header.state_root,
            transactions_root=self._compute_transactions_root(included_txs),
            receipts_root=self._compute_receipts_root(receipts),
            logs_bloom=b"\x00" * 256,
            difficulty=0,
            number=number,
            gas_limit=self.gas_limit,
            gas_used=cumulative_gas,
            timestamp=block_timestamp,
            base_fee_per_gas=new_base_fee,
        )
        
        block = Block(header=header, transactions=included_txs)
        self.store.save_block(block, receipts, included_tx_hashes)
        
        # Remove included transactions from mempool
        for tx_hash in included_tx_hashes:
            self.mempool.remove(tx_hash)
        
        # Remove failed transactions from mempool
        for tx_hash in failed_tx_hashes:
            self.mempool.remove(tx_hash)
        
        self._last_block_time = block_timestamp
        
        # Update touched addresses and save EVM state
        self._touched_addresses.update(touched_this_block)
        
        # Save state changes to SQLite
        if isinstance(self.store, SQLiteStore):
            self._save_evm_state_incremental(touched_this_block)
            
            # Save CREATE2 contract metadata
            for contract_address, contract_info in create2_contracts:
                self.store.save_create2_contract(
                    address=contract_address,
                    deployer=contract_info["deployer"],
                    salt=contract_info["salt"],
                    init_code_hash=contract_info["init_code_hash"],
                    block_number=number,
                    tx_hash=included_tx_hashes[-1] if included_tx_hashes else b"",
                )
        
        return block
    
    def _save_evm_state_incremental(self, addresses: set[bytes]):
        """Save EVM state for specific addresses (incremental update).
        
        Known Limitation: This uses a heuristic to discover storage slots by checking
        slots 0-99 and any previously stored slots. Contracts using slots >= 100 for
        the first time may lose state on restart. For proper storage tracking, the EVM
        state journal would need to be hooked.
        """
        if not isinstance(self.store, SQLiteStore):
            return
        
        for address in addresses:
            try:
                nonce = self.evm.get_nonce(address)
                balance = self.evm.get_balance(address)
                code = self.evm.get_code(address)
                
                # Save account
                self.store.save_account(address, nonce=nonce, balance=balance, code=code)
                
                # Get and save storage for contracts
                if code:
                    # Get previously stored slots
                    stored_storage = self.store.get_all_storage(address)
                    
                    # Heuristic: Check slots 0-99 (covers most simple contracts) plus
                    # any slots that were previously stored. This is NOT comprehensive -
                    # contracts using high slot numbers (>99) may lose state on restart.
                    # 
                    # Proper fix: Hook into EVM's state journal to capture all writes.
                    # See: https://github.com/ethereum/py-evm/issues/172
                    slots_to_check = set(range(100)) | set(stored_storage.keys())
                    
                    for slot in slots_to_check:
                        value = self.evm.get_storage(address, slot)
                        if value != 0:
                            self.store.save_storage(address, slot, value)
                        elif slot in stored_storage and stored_storage[slot] != 0:
                            # Storage was cleared
                            self.store.save_storage(address, slot, 0)
            except Exception as e:
                # Log but continue
                print(f"Warning: Failed to save state for {address.hex()}: {e}")

    def _compute_transactions_root(self, transactions: list) -> bytes:
        from trie import HexaryTrie
        from rlp import encode
        
        trie = HexaryTrie({})
        for i, tx in enumerate(transactions):
            trie[encode(i)] = encode(tx.encode() if hasattr(tx, "encode") else tx)
        return trie.root_hash

    def _compute_receipts_root(self, receipts: list[Receipt]) -> bytes:
        from trie import HexaryTrie
        from rlp import encode
        
        trie = HexaryTrie({})
        for i, receipt in enumerate(receipts):
            trie[encode(i)] = receipt.to_rlp()
        return trie.root_hash

    # ==================== CREATE2 Methods ====================
    
    def compute_create2_address(
        self,
        sender: bytes,
        salt: bytes,
        init_code: bytes,
    ) -> bytes:
        """
        Compute the CREATE2 contract address before deployment.
        
        This allows predicting the address of a contract that will be deployed
        via CREATE2, even before the deployment transaction is sent.
        
        Args:
            sender: 20-byte deployer address
            salt: 32-byte salt value (any 32 bytes)
            init_code: Contract initialization code (constructor bytecode)
        
        Returns:
            20-byte predicted contract address
        
        Example:
            >>> sender = bytes.fromhex("deadbeef" * 5)
            >>> salt = bytes(32)  # 32 zero bytes
            >>> init_code = bytes.fromhex("602a60005260206000f3")
            >>> address = chain.compute_create2_address(sender, salt, init_code)
        """
        from sequencer.core.create2 import compute_create2_address
        return compute_create2_address(sender, salt, init_code)
    
    def is_create2_contract(self, address: bytes) -> bool:
        """
        Check if a contract was deployed via CREATE2.
        
        Args:
            address: Contract address (20 bytes)
        
        Returns:
            True if deployed via CREATE2, False otherwise
        """
        if isinstance(self.store, SQLiteStore):
            return self.store.is_create2_contract(address)
        return False
    
    def get_create2_contract_info(self, address: bytes) -> dict | None:
        """
        Get CREATE2 deployment information for a contract.
        
        Args:
            address: Contract address (20 bytes)
        
        Returns:
            Dict with deployer, salt, init_code_hash, block_number, tx_hash
            or None if not a CREATE2 contract
        """
        if isinstance(self.store, SQLiteStore):
            return self.store.get_create2_contract(address)
        return None
    
    def get_create2_contracts_by_deployer(self, deployer: bytes) -> list[dict]:
        """
        Get all CREATE2 contracts deployed by a specific address.
        
        Args:
            deployer: Deployer address (20 bytes)
        
        Returns:
            List of dicts with contract deployment info
        """
        if isinstance(self.store, SQLiteStore):
            return self.store.get_create2_contracts_by_deployer(deployer)
        return []
    
    def find_create2_contract(
        self,
        deployer: bytes,
        salt: bytes,
        init_code_hash: bytes,
    ) -> bytes | None:
        """
        Find a CREATE2 contract by its deployment parameters.
        
        This allows verifying if a specific CREATE2 deployment has occurred.
        
        Args:
            deployer: Deployer address (20 bytes)
            salt: Salt used (32 bytes)
            init_code_hash: Hash of init code (32 bytes)
        
        Returns:
            Contract address if found, None otherwise
        """
        if isinstance(self.store, SQLiteStore):
            return self.store.find_create2_contract(deployer, salt, init_code_hash)
        return None