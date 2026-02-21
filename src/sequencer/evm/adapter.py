"""py-evm adapter for transaction execution."""

from dataclasses import dataclass
from typing import Any, Sequence

from eth import constants
from eth.chains.base import MiningChain
from eth.consensus.noproof import NoProofConsensus
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB
from eth.vm.forks.prague import PragueVM
from eth.vm.forks.prague.transactions import (
    Authorization,
    SetCodeTransaction,
    UnsignedSetCodeTransaction,
    SET_CODE_TRANSACTION_TYPE,
)
from eth_keys import keys
from eth_utils import to_wei

from sequencer.core.constants import DEFAULT_CHAIN_ID, DEFAULT_GAS_LIMIT


@dataclass
class ExecutionResult:
    success: bool
    output: bytes
    gas_used: int
    logs: list[tuple[bytes, list[int], bytes]]
    contract_address: bytes | None = None


@dataclass
class ChainConfig:
    chain_id: int = DEFAULT_CHAIN_ID
    gas_limit: int = DEFAULT_GAS_LIMIT
    timestamp: int = 0
    coinbase: bytes = b"\x00" * 20
    genesis_state: dict | None = None


class EVMAdapter:
    def __init__(self, chain_config: ChainConfig | None = None):
        self.config = chain_config or ChainConfig()
        self._setup_chain()

    def _setup_chain(self):
        """Initialize the blockchain with PragueVM (supports EIP-7702)."""
        PragueNoProof = PragueVM.configure(consensus_class=NoProofConsensus)
        
        chain_class = MiningChain.configure(
            __name__="SequencerChain",
            vm_configuration=((constants.GENESIS_BLOCK_NUMBER, PragueNoProof),),
            chain_id=self.config.chain_id,
        )
        
        genesis_params = {
            "difficulty": 0,
            "gas_limit": self.config.gas_limit,
            "timestamp": self.config.timestamp,
            "coinbase": self.config.coinbase,
        }
        
        formatted_state = {}
        if self.config.genesis_state:
            for address, account_state in self.config.genesis_state.items():
                addr = address if isinstance(address, bytes) else bytes.fromhex(address)
                formatted_state[addr] = {
                    "balance": account_state.get("balance", 0),
                    "nonce": account_state.get("nonce", 0),
                    "code": account_state.get("code", b""),
                    "storage": account_state.get("storage", {}),
                }
        
        self.base_db = AtomicDB(MemoryDB())
        self.chain = chain_class.from_genesis(self.base_db, genesis_params, formatted_state)

    def get_vm(self):
        return self.chain.get_vm()

    def get_nonce(self, address: bytes) -> int:
        vm = self.get_vm()
        return vm.state.get_nonce(address)

    def get_balance(self, address: bytes) -> int:
        vm = self.get_vm()
        return vm.state.get_balance(address)

    def get_code(self, address: bytes) -> bytes:
        vm = self.get_vm()
        return vm.state.get_code(address)

    def get_storage(self, address: bytes, slot: int) -> int:
        vm = self.get_vm()
        return vm.state.get_storage(address, slot)

    def set_nonce(self, address: bytes, nonce: int):
        """Set account nonce."""
        vm = self.get_vm()
        vm.state.set_nonce(address, nonce)

    def set_balance(self, address: bytes, balance: int):
        """Set account balance."""
        vm = self.get_vm()
        vm.state.set_balance(address, balance)

    def set_code(self, address: bytes, code: bytes):
        """Set account code."""
        vm = self.get_vm()
        vm.state.set_code(address, code)

    def set_storage(self, address: bytes, slot: int, value: int):
        """Set storage slot value."""
        vm = self.get_vm()
        vm.state.set_storage(address, slot, value)

    def get_all_accounts(self) -> list[bytes]:
        """Get all addresses that have been modified in the current state."""
        vm = self.get_vm()
        # Use the state's internal methods to get all accounts
        # This iterates through all accounts in the state trie
        accounts = []
        
        # Access the underlying state database
        state_db = vm.state._db
        
        # Iterate through all accounts in the state
        try:
            from eth.db.account import AccountDB
            from eth.db.backends.base import BaseAtomicDB
            
            # Get the account trie
            for address in state_db._trie.get_all():
                if address:
                    accounts.append(address)
        except Exception:
            # Fallback: we'll need to track accounts manually
            pass
        
        return accounts

    def export_state(self, addresses: list[bytes] | None = None) -> dict[bytes, dict]:
        """
        Export EVM state for given addresses.
        
        Args:
            addresses: List of addresses to export. If None, exports all known accounts.
        
        Returns:
            Dict mapping address -> {nonce, balance, code, storage}
        """
        vm = self.get_vm()
        state = {}
        
        if addresses is None:
            # If no addresses provided, we need to track them
            # This is a limitation - we can only export addresses we know about
            addresses = []
        
        for address in addresses:
            try:
                nonce = vm.state.get_nonce(address)
                balance = vm.state.get_balance(address)
                code = vm.state.get_code(address)
                
                # Only include accounts that have been touched
                if nonce > 0 or balance > 0 or len(code) > 0:
                    storage = {}
                    # Export non-zero storage slots
                    # We need to iterate through storage - this is expensive
                    # For now, we'll track storage separately
                    
                    state[address] = {
                        "nonce": nonce,
                        "balance": balance,
                        "code": code,
                        "storage": storage,
                    }
            except Exception:
                # Account doesn't exist, skip
                pass
        
        return state

    def import_state(self, state: dict[bytes, dict]):
        """
        Import EVM state.
        
        Args:
            state: Dict mapping address -> {nonce, balance, code, storage}
        """
        vm = self.get_vm()
        
        for address, account_data in state.items():
            try:
                # Always set balance (even if 0)
                balance = account_data.get("balance", 0)
                vm.state.set_balance(address, balance)
                
                # Always set nonce (even if 0)
                nonce = account_data.get("nonce", 0)
                vm.state.set_nonce(address, nonce)
                
                # Set code if exists
                code = account_data.get("code", b"")
                vm.state.set_code(address, code)
                
                # Set storage
                storage = account_data.get("storage", {})
                for slot, value in storage.items():
                    vm.state.set_storage(address, int(slot), int(value))
            except Exception as e:
                # Log but continue
                print(f"Warning: Failed to import state for {address.hex()}: {e}")
        
        # Persist the state changes
        vm.state.persist()

    def create_unsigned_transaction(
        self,
        nonce: int,
        gas_price: int,
        gas: int,
        to: bytes | None,
        value: int,
        data: bytes,
    ) -> Any:
        vm = self.get_vm()
        return vm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=to,
            value=value,
            data=data,
        )

    def create_unsigned_access_list_transaction(
        self,
        nonce: int,
        gas_price: int,
        gas: int,
        to: bytes | None,
        value: int,
        data: bytes,
        access_list: Sequence[tuple[bytes, Sequence[int]]],
        chain_id: int | None = None,
    ) -> Any:
        """
        Create an unsigned EIP-2930 access list transaction (Type 0x01).
        
        Access list transactions allow pre-declaring addresses and storage slots
        that will be accessed during execution, reducing gas costs for cold accesses.
        
        Args:
            nonce: Sender's nonce
            gas_price: Gas price in wei
            gas: Gas limit
            to: Recipient address (None for contract creation)
            value: Value to transfer in wei
            data: Transaction data (calldata or initcode)
            access_list: List of (address, [storage_keys]) tuples
            chain_id: Chain ID (defaults to configured chain_id)
        
        Returns:
            UnsignedAccessListTransaction
        
        Example:
            >>> access_list = [
            ...     (b'\\x12' * 20, [0, 1]),  # Address with slots 0 and 1
            ...     (b'\\xab' * 20, []),        # Address only, no storage keys
            ... ]
            >>> tx = adapter.create_unsigned_access_list_transaction(
            ...     nonce=0,
            ...     gas_price=30_000_000_000,
            ...     gas=200_000,
            ...     to=b'\\x12' * 20,
            ...     value=0,
            ...     data=b'\\x00',
            ...     access_list=access_list,
            ... )
        """
        from eth.vm.forks.berlin.transactions import BerlinTransactionBuilder
        
        tx_chain_id = chain_id if chain_id is not None else self.config.chain_id
        to_address = to if to else b""
        
        return BerlinTransactionBuilder.new_unsigned_access_list_transaction(
            chain_id=tx_chain_id,
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=to_address,
            value=value,
            data=data,
            access_list=access_list,
        )

    def create_unsigned_eip1559_transaction(
        self,
        nonce: int,
        max_priority_fee_per_gas: int,
        max_fee_per_gas: int,
        gas: int,
        to: bytes | None,
        value: int,
        data: bytes,
        chain_id: int | None = None,
        access_list: Sequence[tuple[bytes, Sequence[int]]] | None = None,
    ) -> Any:
        """
        Create an unsigned EIP-1559 dynamic fee transaction (Type 0x02).
        
        Note: EIP-1559 transactions can optionally include an access list.
        
        Args:
            nonce: Sender's nonce
            max_priority_fee_per_gas: Priority fee per gas (tip to miner)
            max_fee_per_gas: Maximum total fee per gas
            gas: Gas limit
            to: Recipient address (None for contract creation)
            value: Value to transfer in wei
            data: Transaction data
            chain_id: Chain ID (defaults to configured chain_id)
            access_list: Optional list of (address, [storage_keys]) tuples
        
        Returns:
            UnsignedDynamicFeeTransaction
        """
        from eth.vm.forks.london.transactions import LondonTransactionBuilder
        
        tx_chain_id = chain_id if chain_id is not None else self.config.chain_id
        to_address = to if to else b""
        tx_access_list = access_list if access_list is not None else ()
        
        return LondonTransactionBuilder.new_unsigned_dynamic_fee_transaction(
            chain_id=tx_chain_id,
            nonce=nonce,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            max_fee_per_gas=max_fee_per_gas,
            gas=gas,
            to=to_address,
            value=value,
            data=data,
            access_list=tx_access_list,
        )

    def create_unsigned_setcode_transaction(
        self,
        nonce: int,
        max_priority_fee_per_gas: int,
        max_fee_per_gas: int,
        gas: int,
        to: bytes | None,
        value: int,
        data: bytes,
        authorization_list: Sequence[Authorization],
        chain_id: int | None = None,
        access_list: Sequence[tuple[bytes, Sequence[int]]] | None = None,
    ) -> UnsignedSetCodeTransaction:
        """
        Create an unsigned EIP-7702 SetCode transaction (Type 0x04).
        
        Args:
            nonce: Sender's nonce
            max_priority_fee_per_gas: Priority fee per gas
            max_fee_per_gas: Maximum fee per gas
            gas: Gas limit
            to: Recipient address (cannot be None for SetCode transactions)
            value: Value to transfer
            data: Transaction data
            authorization_list: List of EIP-7702 authorizations
            chain_id: Chain ID (defaults to configured chain_id)
            access_list: Optional access list for EIP-2930
        
        Returns:
            UnsignedSetCodeTransaction
        """
        tx_chain_id = chain_id if chain_id is not None else self.config.chain_id
        to_address = to if to else b""
        tx_access_list = access_list if access_list else ()
        
        return UnsignedSetCodeTransaction(
            chain_id=tx_chain_id,
            nonce=nonce,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            max_fee_per_gas=max_fee_per_gas,
            gas=gas,
            to=to_address,
            value=value,
            data=data,
            access_list=tx_access_list,
            authorization_list=authorization_list,
        )

    @staticmethod
    def create_authorization(
        chain_id: int,
        address: bytes,
        nonce: int,
        private_key: bytes,
    ) -> Authorization:
        """
        Create a signed EIP-7702 authorization.
        
        An authorization allows an EOA to temporarily set its code to
        the code of the contract at `address`.
        
        Args:
            chain_id: Chain ID (0 = all chains, specific chain ID = that chain only)
            address: Address of the contract to delegate to
            nonce: The account nonce after authorization
            private_key: Private key to sign the authorization
        
        Returns:
            Signed Authorization object
        """
        from eth_keys import keys as eth_keys
        
        # Create unsigned authorization for signing
        # The signature is over: chain_id, address, nonce
        pk = eth_keys.PrivateKey(private_key)
        
        # Build the message for signing
        # Message format: 0x05 || rlp([chain_id, address, nonce])
        import rlp
        from eth_utils import to_bytes
        
        unsigned_auth_payload = rlp.encode([chain_id, address, nonce])
        type_byte = to_bytes(SET_CODE_TRANSACTION_TYPE)
        message = type_byte + unsigned_auth_payload
        
        # Sign the message
        signature = pk.sign_msg(message)
        y_parity, r, s = signature.vrs
        
        return Authorization(
            chain_id=chain_id,
            address=address,
            nonce=nonce,
            y_parity=y_parity,
            r=r,
            s=s,
        )

    def apply_transaction(self, signed_tx) -> tuple[Any, Any, Any]:
        block, receipt, computation = self.chain.apply_transaction(signed_tx)
        return block, receipt, computation

    def mine_block(self, timestamp: int | None = None) -> Any:
        if timestamp is not None:
            return self.chain.mine_block(timestamp=timestamp)
        return self.chain.mine_block()

    def get_canonical_head(self):
        return self.chain.get_canonical_head()

    def get_block_by_number(self, block_number: int):
        return self.chain.get_canonical_block_by_number(block_number)

    def get_latest_block(self):
        return self.get_block_by_number(self.chain.get_canonical_head().number)

    def set_state(self, genesis_state: dict):
        for address, account_state in genesis_state.items():
            addr = address if isinstance(address, bytes) else bytes.fromhex(address)
            
            vm = self.get_vm()
            
            if "balance" in account_state:
                vm.state.set_balance(addr, account_state["balance"])
            
            if "code" in account_state:
                vm.state.set_code(addr, account_state["code"])
            
            if "nonce" in account_state:
                vm.state.set_nonce(addr, account_state["nonce"])
            
            if "storage" in account_state:
                for slot, value in account_state["storage"].items():
                    vm.state.set_storage(addr, slot, value)

    @property
    def state_root(self) -> bytes:
        return self.chain.get_canonical_head().state_root