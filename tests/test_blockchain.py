"""Tests for blockchain engine: validation, execution, mempool, fork choice."""

import pytest
from ethclient.common.types import (
    Block,
    BlockHeader,
    Transaction,
    TxType,
    Receipt,
    Withdrawal,
    EMPTY_TRIE_ROOT,
    ZERO_HASH,
    ZERO_ADDRESS,
    BLOOM_BYTE_SIZE,
)
from ethclient.common.trie import ordered_trie_root, EMPTY_ROOT
from ethclient.common.crypto import keccak256, ecdsa_sign, private_key_to_address
from ethclient.common import rlp
from ethclient.common.config import ChainConfig, Genesis, GenesisAlloc
from ethclient.storage.memory_backend import MemoryBackend
from ethclient.blockchain.chain import (
    validate_header,
    calc_base_fee,
    execute_block,
    execute_transaction,
    BlockValidationError,
)
from ethclient.blockchain.mempool import Mempool
from ethclient.blockchain.fork_choice import ForkChoice


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

# Test private keys (DO NOT use in production)
PK1 = b"\x01" * 32
PK2 = b"\x02" * 32
ADDR1 = private_key_to_address(PK1)
ADDR2 = private_key_to_address(PK2)
COINBASE = b"\xCC" * 20

ALL_FORKS_CONFIG = ChainConfig(
    chain_id=1337,
    homestead_block=0,
    eip150_block=0,
    eip155_block=0,
    eip158_block=0,
    byzantium_block=0,
    constantinople_block=0,
    petersburg_block=0,
    istanbul_block=0,
    berlin_block=0,
    london_block=0,
    shanghai_time=0,
)


def make_signed_tx(
    pk: bytes,
    nonce: int = 0,
    to: bytes = ADDR2,
    value: int = 0,
    data: bytes = b"",
    gas_limit: int = 21000,
    gas_price: int = 10_000_000_000,
    chain_id: int = 1337,
) -> Transaction:
    """Create and sign a legacy transaction."""
    tx = Transaction(
        tx_type=TxType.LEGACY,
        nonce=nonce,
        gas_price=gas_price,
        gas_limit=gas_limit,
        to=to,
        value=value,
        data=data,
    )
    msg_hash = tx.signing_hash(chain_id)
    v, r, s = ecdsa_sign(msg_hash, pk)
    tx.v = v + 35 + 2 * chain_id  # EIP-155
    tx.r = r
    tx.s = s
    return tx


def make_parent_header(
    number: int = 0,
    gas_limit: int = 30_000_000,
    gas_used: int = 0,
    timestamp: int = 1000,
    base_fee: int = 1_000_000_000,
) -> BlockHeader:
    return BlockHeader(
        number=number,
        gas_limit=gas_limit,
        gas_used=gas_used,
        timestamp=timestamp,
        base_fee_per_gas=base_fee,
        coinbase=COINBASE,
    )


# ---------------------------------------------------------------------------
# Header validation tests
# ---------------------------------------------------------------------------

class TestHeaderValidation:
    def test_valid_header(self):
        parent = make_parent_header()
        child = BlockHeader(
            number=1,
            parent_hash=parent.block_hash(),
            timestamp=1001,
            gas_limit=30_000_000,
            base_fee_per_gas=calc_base_fee(parent, ALL_FORKS_CONFIG),
            coinbase=COINBASE,
        )
        validate_header(child, parent, ALL_FORKS_CONFIG)  # should not raise

    def test_invalid_block_number(self):
        parent = make_parent_header()
        child = BlockHeader(
            number=5,  # should be 1
            parent_hash=parent.block_hash(),
            timestamp=1001,
            gas_limit=30_000_000,
        )
        with pytest.raises(BlockValidationError, match="block number"):
            validate_header(child, parent, ALL_FORKS_CONFIG)

    def test_invalid_parent_hash(self):
        parent = make_parent_header()
        child = BlockHeader(
            number=1,
            parent_hash=ZERO_HASH,  # wrong
            timestamp=1001,
            gas_limit=30_000_000,
        )
        with pytest.raises(BlockValidationError, match="Parent hash"):
            validate_header(child, parent, ALL_FORKS_CONFIG)

    def test_timestamp_not_increasing(self):
        parent = make_parent_header(timestamp=1000)
        child = BlockHeader(
            number=1,
            parent_hash=parent.block_hash(),
            timestamp=999,  # before parent
            gas_limit=30_000_000,
        )
        with pytest.raises(BlockValidationError, match="Timestamp"):
            validate_header(child, parent, ALL_FORKS_CONFIG)

    def test_gas_limit_too_high(self):
        parent = make_parent_header(gas_limit=30_000_000)
        child = BlockHeader(
            number=1,
            parent_hash=parent.block_hash(),
            timestamp=1001,
            gas_limit=31_000_000,  # >1/1024 increase
        )
        with pytest.raises(BlockValidationError, match="Gas limit"):
            validate_header(child, parent, ALL_FORKS_CONFIG)

    def test_gas_used_exceeds_limit(self):
        parent = make_parent_header()
        child = BlockHeader(
            number=1,
            parent_hash=parent.block_hash(),
            timestamp=1001,
            gas_limit=30_000_000,
            gas_used=31_000_000,
            base_fee_per_gas=calc_base_fee(parent, ALL_FORKS_CONFIG),
        )
        with pytest.raises(BlockValidationError, match="Gas used"):
            validate_header(child, parent, ALL_FORKS_CONFIG)

    def test_extra_data_too_long(self):
        parent = make_parent_header()
        child = BlockHeader(
            number=1,
            parent_hash=parent.block_hash(),
            timestamp=1001,
            gas_limit=30_000_000,
            extra_data=b"\x00" * 33,
            base_fee_per_gas=calc_base_fee(parent, ALL_FORKS_CONFIG),
        )
        with pytest.raises(BlockValidationError, match="Extra data"):
            validate_header(child, parent, ALL_FORKS_CONFIG)


# ---------------------------------------------------------------------------
# Base fee calculation tests
# ---------------------------------------------------------------------------

class TestBaseFee:
    def test_stable_base_fee(self):
        """When gas_used == target, base fee stays the same."""
        parent = make_parent_header(gas_limit=30_000_000, gas_used=15_000_000, base_fee=1_000_000_000)
        assert calc_base_fee(parent, ALL_FORKS_CONFIG) == 1_000_000_000

    def test_increase_when_over_target(self):
        parent = make_parent_header(gas_limit=30_000_000, gas_used=20_000_000, base_fee=1_000_000_000)
        new_fee = calc_base_fee(parent, ALL_FORKS_CONFIG)
        assert new_fee > 1_000_000_000

    def test_decrease_when_under_target(self):
        parent = make_parent_header(gas_limit=30_000_000, gas_used=10_000_000, base_fee=1_000_000_000)
        new_fee = calc_base_fee(parent, ALL_FORKS_CONFIG)
        assert new_fee < 1_000_000_000

    def test_base_fee_floor_zero(self):
        parent = make_parent_header(gas_limit=30_000_000, gas_used=0, base_fee=1)
        new_fee = calc_base_fee(parent, ALL_FORKS_CONFIG)
        assert new_fee >= 0


# ---------------------------------------------------------------------------
# Transaction execution tests
# ---------------------------------------------------------------------------

class TestTransactionExecution:
    def _setup(self) -> tuple[MemoryBackend, BlockHeader]:
        store = MemoryBackend()
        store.put_account(ADDR1, __import__("ethclient.common.types", fromlist=["Account"]).Account(
            balance=10 * 10**18, nonce=0,
        ))
        header = BlockHeader(
            number=1,
            timestamp=2000,
            gas_limit=30_000_000,
            coinbase=COINBASE,
            base_fee_per_gas=1_000_000_000,
        )
        return store, header

    def test_simple_transfer(self):
        store, header = self._setup()
        tx = make_signed_tx(PK1, nonce=0, to=ADDR2, value=10**18, gas_price=10_000_000_000)

        result = execute_transaction(tx, header, store, ALL_FORKS_CONFIG, 0, 0)
        assert result.success is True
        assert result.gas_used == 21000
        assert result.receipt is not None
        assert result.receipt.succeeded is True

        # ADDR2 should have received value
        assert store.get_balance(ADDR2) == 10**18

    def test_nonce_mismatch(self):
        store, header = self._setup()
        tx = make_signed_tx(PK1, nonce=5, to=ADDR2, value=0)

        result = execute_transaction(tx, header, store, ALL_FORKS_CONFIG, 0, 0)
        assert result.success is False
        assert "Nonce" in result.error

    def test_insufficient_balance(self):
        store, header = self._setup()
        tx = make_signed_tx(PK1, nonce=0, to=ADDR2, value=100 * 10**18)

        result = execute_transaction(tx, header, store, ALL_FORKS_CONFIG, 0, 0)
        assert result.success is False
        assert "balance" in result.error.lower()


# ---------------------------------------------------------------------------
# Block execution tests
# ---------------------------------------------------------------------------

class TestBlockExecution:
    def test_empty_block(self):
        store = MemoryBackend()
        store.put_account(ADDR1, __import__("ethclient.common.types", fromlist=["Account"]).Account(
            balance=10 * 10**18,
        ))

        header = BlockHeader(
            number=1,
            timestamp=2000,
            gas_limit=30_000_000,
            coinbase=COINBASE,
            base_fee_per_gas=1_000_000_000,
        )
        block = Block(header=header, transactions=[])

        result = execute_block(block, store, ALL_FORKS_CONFIG)
        assert result.total_gas_used == 0
        assert len(result.receipts) == 0
        assert result.state_root != ZERO_HASH

    def test_block_with_transfer(self):
        store = MemoryBackend()
        from ethclient.common.types import Account
        store.put_account(ADDR1, Account(balance=10 * 10**18, nonce=0))

        tx = make_signed_tx(PK1, nonce=0, to=ADDR2, value=10**18, gas_price=10_000_000_000)

        header = BlockHeader(
            number=1,
            timestamp=2000,
            gas_limit=30_000_000,
            coinbase=COINBASE,
            base_fee_per_gas=1_000_000_000,
        )
        block = Block(header=header, transactions=[tx])

        result = execute_block(block, store, ALL_FORKS_CONFIG)
        assert result.total_gas_used == 21000
        assert len(result.receipts) == 1
        assert result.receipts[0].succeeded is True
        assert store.get_balance(ADDR2) == 10**18

    def test_block_with_withdrawals(self):
        store = MemoryBackend()

        withdrawal = Withdrawal(
            index=0,
            validator_index=100,
            address=ADDR2,
            amount=1_000_000,  # 1M Gwei = 0.001 ETH
        )

        header = BlockHeader(
            number=1,
            timestamp=2000,
            gas_limit=30_000_000,
            coinbase=COINBASE,
            base_fee_per_gas=1_000_000_000,
        )
        block = Block(header=header, transactions=[], withdrawals=[withdrawal])

        result = execute_block(block, store, ALL_FORKS_CONFIG)
        assert store.get_balance(ADDR2) == 1_000_000 * 10**9


# ---------------------------------------------------------------------------
# Mempool tests
# ---------------------------------------------------------------------------

class TestMempool:
    def test_add_and_get(self):
        pool = Mempool()
        tx = make_signed_tx(PK1, nonce=0, to=ADDR2, value=1000)
        ok, err = pool.add(tx, ADDR1, current_nonce=0, sender_balance=10**18)
        assert ok is True
        assert err is None
        assert pool.size == 1

    def test_duplicate_rejected(self):
        pool = Mempool()
        tx = make_signed_tx(PK1, nonce=0, to=ADDR2)
        pool.add(tx, ADDR1, current_nonce=0, sender_balance=10**18)
        ok, err = pool.add(tx, ADDR1, current_nonce=0, sender_balance=10**18)
        assert ok is False
        assert "Already known" in err

    def test_nonce_too_low(self):
        pool = Mempool()
        tx = make_signed_tx(PK1, nonce=0, to=ADDR2)
        ok, err = pool.add(tx, ADDR1, current_nonce=5, sender_balance=10**18)
        assert ok is False
        assert "Nonce too low" in err

    def test_insufficient_balance(self):
        pool = Mempool()
        tx = make_signed_tx(PK1, nonce=0, to=ADDR2, value=10**18, gas_price=10**10)
        ok, err = pool.add(tx, ADDR1, current_nonce=0, sender_balance=100)
        assert ok is False
        assert "balance" in err.lower()

    def test_get_pending_ordered(self):
        pool = Mempool()
        tx0 = make_signed_tx(PK1, nonce=0, to=ADDR2, gas_price=10**10)
        tx1 = make_signed_tx(PK1, nonce=1, to=ADDR2, gas_price=10**10)
        pool.add(tx0, ADDR1, current_nonce=0, sender_balance=10**18)
        pool.add(tx1, ADDR1, current_nonce=0, sender_balance=10**18)

        pending = pool.get_pending(current_nonces={ADDR1: 0})
        assert len(pending) == 2
        assert pending[0].nonce == 0
        assert pending[1].nonce == 1

    def test_get_pending_with_gap(self):
        pool = Mempool()
        # Add nonce 0 and 2 (skipping 1) — only nonce 0 should be pending
        tx0 = make_signed_tx(PK1, nonce=0, to=ADDR2, gas_price=10**10)
        tx2 = make_signed_tx(PK1, nonce=2, to=ADDR2, gas_price=10**10)
        pool.add(tx0, ADDR1, current_nonce=0, sender_balance=10**18)
        pool.add(tx2, ADDR1, current_nonce=0, sender_balance=10**18)

        pending = pool.get_pending(current_nonces={ADDR1: 0})
        assert len(pending) == 1
        assert pending[0].nonce == 0

    def test_remove_committed(self):
        pool = Mempool()
        tx0 = make_signed_tx(PK1, nonce=0, to=ADDR2, gas_price=10**10)
        tx1 = make_signed_tx(PK1, nonce=1, to=ADDR2, gas_price=10**10)
        pool.add(tx0, ADDR1, current_nonce=0, sender_balance=10**18)
        pool.add(tx1, ADDR1, current_nonce=0, sender_balance=10**18)

        removed = pool.remove_committed(ADDR1, committed_nonce=1)
        assert removed == 1
        assert pool.size == 1

    def test_replacement(self):
        pool = Mempool()
        tx1 = make_signed_tx(PK1, nonce=0, to=ADDR2, gas_price=10**10)
        pool.add(tx1, ADDR1, current_nonce=0, sender_balance=10**18)

        # Replace with higher gas price (>10% increase)
        tx2 = make_signed_tx(PK1, nonce=0, to=ADDR2, gas_price=12 * 10**9)
        ok, _ = pool.add(tx2, ADDR1, current_nonce=0, sender_balance=10**18)
        assert ok is True
        assert pool.size == 1  # replaced, not added

    def test_replacement_too_low(self):
        pool = Mempool()
        tx1 = make_signed_tx(PK1, nonce=0, to=ADDR2, gas_price=10**10)
        pool.add(tx1, ADDR1, current_nonce=0, sender_balance=10**18)

        # Try replace with only 5% increase — should fail
        tx2 = make_signed_tx(PK1, nonce=0, to=ADDR2, gas_price=int(10.5 * 10**9))
        ok, err = pool.add(tx2, ADDR1, current_nonce=0, sender_balance=10**18)
        assert ok is False
        assert "Replacement" in err


# ---------------------------------------------------------------------------
# Fork choice tests
# ---------------------------------------------------------------------------

class TestForkChoice:
    def _setup(self) -> tuple[MemoryBackend, ForkChoice]:
        store = MemoryBackend()
        fc = ForkChoice(store)
        return store, fc

    def test_set_head(self):
        store, fc = self._setup()
        header = BlockHeader(number=0, timestamp=1000, gas_limit=30_000_000)
        block = Block(header=header)
        store.put_block(block)

        fc.set_head(header.block_hash())
        assert fc.head_number == 0
        assert fc.head_hash == header.block_hash()

    def test_canonical_chain(self):
        store, fc = self._setup()

        headers = []
        for i in range(5):
            h = BlockHeader(
                number=i,
                timestamp=1000 + i,
                gas_limit=30_000_000,
                parent_hash=headers[-1].block_hash() if headers else ZERO_HASH,
            )
            headers.append(h)
            store.put_block(Block(header=h))

        fc.set_head(headers[-1].block_hash())

        for i, h in enumerate(headers):
            assert store.get_canonical_hash(i) == h.block_hash()
            assert fc.is_canonical(h.block_hash())

    def test_find_common_ancestor(self):
        store, fc = self._setup()

        # Build chain: 0 -> 1 -> 2a, 0 -> 1 -> 2b
        h0 = BlockHeader(number=0, timestamp=1000, gas_limit=30_000_000)
        h1 = BlockHeader(number=1, timestamp=1001, gas_limit=30_000_000, parent_hash=h0.block_hash())
        h2a = BlockHeader(number=2, timestamp=1002, gas_limit=30_000_000, parent_hash=h1.block_hash(), extra_data=b"a")
        h2b = BlockHeader(number=2, timestamp=1003, gas_limit=30_000_000, parent_hash=h1.block_hash(), extra_data=b"b")

        for h in [h0, h1, h2a, h2b]:
            store.put_block(Block(header=h))

        ancestor = fc.find_common_ancestor(h2a.block_hash(), h2b.block_hash())
        assert ancestor == h1.block_hash()

    def test_get_ancestor(self):
        store, fc = self._setup()

        h0 = BlockHeader(number=0, timestamp=1000, gas_limit=30_000_000)
        h1 = BlockHeader(number=1, timestamp=1001, gas_limit=30_000_000, parent_hash=h0.block_hash())
        h2 = BlockHeader(number=2, timestamp=1002, gas_limit=30_000_000, parent_hash=h1.block_hash())

        for h in [h0, h1, h2]:
            store.put_block(Block(header=h))

        assert fc.get_ancestor(h2.block_hash(), 0) == h0.block_hash()
        assert fc.get_ancestor(h2.block_hash(), 1) == h1.block_hash()

    def test_reorg_detection(self):
        store, fc = self._setup()

        h0 = BlockHeader(number=0, timestamp=1000, gas_limit=30_000_000)
        h1a = BlockHeader(number=1, timestamp=1001, gas_limit=30_000_000,
                          parent_hash=h0.block_hash(), extra_data=b"a")
        h1b = BlockHeader(number=1, timestamp=1002, gas_limit=30_000_000,
                          parent_hash=h0.block_hash(), extra_data=b"b")

        for h in [h0, h1a, h1b]:
            store.put_block(Block(header=h))

        fc.set_head(h1a.block_hash())
        assert not fc.set_head(h1a.block_hash())  # same head, no reorg

        is_reorg = fc.set_head(h1b.block_hash())
        assert is_reorg is True
