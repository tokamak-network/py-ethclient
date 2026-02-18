"""Sequencer chain management."""

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
from sequencer.evm.adapter import EVMAdapter, ChainConfig, ExecutionResult
from sequencer.storage.store import InMemoryStore


EMPTY_OMMERS_HASH = keccak256(b"\xc0")


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
    ):
        self.chain_id = chain_id
        self.gas_limit = gas_limit
        self.coinbase = coinbase
        self.store = InMemoryStore()
        
        config = ChainConfig(
            chain_id=chain_id,
            gas_limit=gas_limit,
            coinbase=coinbase,
            genesis_state=genesis_state,
        )
        self.evm = EVMAdapter(config)
        self._pending_transactions: list = []

    @classmethod
    def from_genesis(
        cls,
        genesis_state: dict,
        chain_id: int = DEFAULT_CHAIN_ID,
        gas_limit: int = DEFAULT_GAS_LIMIT,
        coinbase: bytes = b"\x00" * 20,
        timestamp: int | None = None,
    ) -> "Chain":
        chain = cls(
            chain_id=chain_id, 
            gas_limit=gas_limit, 
            coinbase=coinbase,
            genesis_state=genesis_state,
        )
        
        genesis_block = chain._create_genesis_block(timestamp or int(time.time()))
        chain.store.save_block(genesis_block, [], [])
        
        return chain

    def _create_genesis_block(self, timestamp: int) -> Block:
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

    def add_transaction_to_pool(self, tx) -> None:
        self._pending_transactions.append(tx)

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
    ) -> Any:
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
        
        unsigned_tx = self.evm.create_unsigned_eip1559_transaction(
            nonce=nonce,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            max_fee_per_gas=max_fee_per_gas,
            gas=gas,
            to=to_address,
            value=value,
            data=data,
            chain_id=self.chain_id,
        )
        
        pk = keys.PrivateKey(from_private_key)
        return unsigned_tx.as_signed_transaction(pk)

    def send_transaction(self, signed_tx) -> bytes:
        tx_hash = keccak256(signed_tx.encode())
        self._pending_transactions.append(signed_tx)
        self.build_block()  # Auto-mine block for single sequencer
        return tx_hash

    def call(
        self,
        from_address: bytes,
        to: bytes,
        value: int = 0,
        data: bytes = b"",
        gas: int = 30_000_000,
    ) -> bytes:
        vm = self.evm.get_vm()
        return vm.state.get_code(to)

    def build_block(self, timestamp: int | None = None) -> Block:
        import time as time_module
        current_time = int(time_module.time())
        
        pending = self._pending_transactions.copy()
        self._pending_transactions = []
        
        receipts = []
        gas_used = 0
        
        for tx in pending:
            block, evm_receipt, computation = self.evm.apply_transaction(tx)
            
            if computation.is_error:
                gas_used += tx.gas
            else:
                gas_used = computation.get_gas_used()
            
            receipt = Receipt(
                status=0 if computation.is_error else 1,
                cumulative_gas_used=gas_used,
                logs=computation.get_log_entries() if hasattr(computation, "get_log_entries") else [],
                contract_address=None,
            )
            receipts.append(receipt)
        
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
        
        tx_hashes = [keccak256(tx.encode()) for tx in pending]
        
        header = BlockHeader(
            parent_hash=parent_hash,
            ommers_hash=EMPTY_OMMERS_HASH,
            coinbase=self.coinbase,
            state_root=mined_block.header.state_root,
            transactions_root=self._compute_transactions_root(pending),
            receipts_root=self._compute_receipts_root(receipts),
            logs_bloom=b"\x00" * 256,
            difficulty=0,
            number=number,
            gas_limit=self.gas_limit,
            gas_used=gas_used,
            timestamp=block_timestamp,
            base_fee_per_gas=new_base_fee,
        )
        
        block = Block(header=header, transactions=pending)
        self.store.save_block(block, receipts, tx_hashes)
        
        return block

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