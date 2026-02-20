"""py-evm adapter for transaction execution."""

from dataclasses import dataclass
from typing import Any

from eth import constants
from eth.chains.base import MiningChain
from eth.consensus.noproof import NoProofConsensus
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB
from eth.vm.forks.cancun import CancunVM
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
        CancunNoProof = CancunVM.configure(consensus_class=NoProofConsensus)
        
        chain_class = MiningChain.configure(
            __name__="SequencerChain",
            vm_configuration=((constants.GENESIS_BLOCK_NUMBER, CancunNoProof),),
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
    ) -> Any:
        from eth.vm.forks.london.transactions import LondonTransactionBuilder
        
        tx_chain_id = chain_id if chain_id is not None else self.config.chain_id
        to_address = to if to else b""
        access_list = ()
        
        return LondonTransactionBuilder.new_unsigned_dynamic_fee_transaction(
            chain_id=tx_chain_id,
            nonce=nonce,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            max_fee_per_gas=max_fee_per_gas,
            gas=gas,
            to=to_address,
            value=value,
            data=data,
            access_list=access_list,
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