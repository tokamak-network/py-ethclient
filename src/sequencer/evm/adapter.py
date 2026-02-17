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