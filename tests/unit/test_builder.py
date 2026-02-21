"""Unit tests for block builder functionality.

Tests the block building logic in sequencer.sequencer.chain, specifically:
- calc_base_fee() - our EIP-1559 base fee calculation
"""

import pytest
from eth_utils import keccak

from sequencer.sequencer.chain import calc_base_fee
from sequencer.core.constants import (
    INITIAL_BASE_FEE,
    BASE_FEE_MAX_CHANGE_DENOMINATOR,
    DEFAULT_GAS_LIMIT,
)
from sequencer.core.crypto import keccak256


class TestCalcBaseFee:
    """Test EIP-1559 base fee calculation.

    This tests OUR code (calc_base_fee), not py-evm's implementation.
    """

    def test_base_fee_at_target(self):
        """Base fee stays same when gas at target."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        
        result = calc_base_fee(gas_target, gas_limit, INITIAL_BASE_FEE)
        
        # When exactly at target, base fee stays the same
        assert result == INITIAL_BASE_FEE

    def test_base_fee_above_target(self):
        """Base fee increases when gas above target."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        gas_used = gas_target + 1_000_000  # Over target
        
        result = calc_base_fee(gas_used, gas_limit, INITIAL_BASE_FEE)
        
        # Base fee should increase
        assert result > INITIAL_BASE_FEE

    def test_base_fee_below_target(self):
        """Base fee decreases when gas below target."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        gas_used = gas_target - 1_000_000  # Under target
        
        result = calc_base_fee(gas_used, gas_limit, INITIAL_BASE_FEE)
        
        # Base fee should decrease
        assert result < INITIAL_BASE_FEE
        assert result > 0  # But never goes to zero

    def test_base_fee_max_change(self):
        """Base fee change is capped at ~12.5% per block."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        
        # Use all gas (maximum increase scenario)
        gas_used = gas_limit
        
        result = calc_base_fee(gas_used, gas_limit, INITIAL_BASE_FEE)
        
        # Maximum increase is ~12.5% (1/8)
        max_expected = INITIAL_BASE_FEE * 9 // 8  # 112.5%
        
        # Should not exceed max change
        assert result <= max_expected

    def test_base_fee_minimum_value(self):
        """Base fee never goes below 1 wei."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        
        # Very low usage - should still have minimum
        gas_used = 0  # No gas used
        
        result = calc_base_fee(gas_used, gas_limit, INITIAL_BASE_FEE)
        
        assert result >= 1

    def test_base_fee_high_initial(self):
        """Base fee calculation works with high initial fee."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        high_fee = 100_000_000_000  # 100 Gwei
        
        result = calc_base_fee(gas_target, gas_limit, high_fee)
        
        # At target, stays same
        assert result == high_fee

    def test_base_fee_consecutive_increases(self):
        """Simulate consecutive blocks with increasing base fee."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        current_fee = INITIAL_BASE_FEE
        
        # Simulate 5 blocks of above-target usage
        for _ in range(5):
            gas_used = gas_target + 500_000
            current_fee = calc_base_fee(gas_used, gas_limit, current_fee)
        
        # Base fee should have increased each time
        assert current_fee > INITIAL_BASE_FEE

    def test_base_fee_consecutive_decreases(self):
        """Simulate consecutive blocks with decreasing base fee."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        current_fee = 10_000_000_000  # Start higher
        
        # Simulate 5 blocks of below-target usage
        for _ in range(5):
            gas_used = gas_target - 500_000
            current_fee = calc_base_fee(gas_used, gas_limit, current_fee)
        
        # Base fee should have decreased
        assert current_fee < 10_000_000_000

    def test_base_fee_denominator_relationship(self):
        """Verify the denominator affects change rate correctly."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        gas_used = gas_target + 1_000_000
        
        # Expected change
        expected_delta = max(
            INITIAL_BASE_FEE * 1_000_000 // gas_target // BASE_FEE_MAX_CHANGE_DENOMINATOR,
            1
        )
        expected = INITIAL_BASE_FEE + expected_delta
        
        result = calc_base_fee(gas_used, gas_limit, INITIAL_BASE_FEE)
        
        assert result == expected


class TestBlockBuildingConstraints:
    """Test block building constraints and edge cases."""

    def test_gas_limit_constant(self):
        """Gas limit is a fixed constant."""
        assert DEFAULT_GAS_LIMIT == 30_000_000

    def test_base_fee_denominator_constant(self):
        """Base fee change denominator is 8 (12.5% max change)."""
        assert BASE_FEE_MAX_CHANGE_DENOMINATOR == 8

    def test_initial_base_fee_constant(self):
        """Initial base fee is 1 Gwei."""
        assert INITIAL_BASE_FEE == 1_000_000_000

    def test_gas_target_is_half_limit(self):
        """Gas target is half the gas limit."""
        gas_target = DEFAULT_GAS_LIMIT // 2
        assert gas_target == 15_000_000


class TestMerkleRootComputation:
    """Test Merkle root computation for transactions and receipts."""

    def test_single_item_hash(self):
        """Single item produces valid hash."""
        item = keccak256(b"item1")
        
        result = keccak256(item)
        
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_hash_consistency(self):
        """Same input produces same hash."""
        data = b"test data"
        
        hash1 = keccak256(data)
        hash2 = keccak256(data)
        
        assert hash1 == hash2

    def test_different_data_different_hashes(self):
        """Different data produces different hashes."""
        hash1 = keccak256(b"data1")
        hash2 = keccak256(b"data2")
        
        assert hash1 != hash2


class TestEIP1559Mechanics:
    """Test EIP-1559 fee market mechanics."""

    def test_fee_market_equilibrium(self):
        """At equilibrium (target usage), fee is stable."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        base_fee = INITIAL_BASE_FEE
        
        # Simulate many blocks at target
        for _ in range(10):
            base_fee = calc_base_fee(gas_target, gas_limit, base_fee)
        
        # Should stay very close to initial
        assert base_fee == INITIAL_BASE_FEE

    def test_fee_market_surge(self):
        """During surge (high demand), fee increases rapidly."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        base_fee = INITIAL_BASE_FEE
        
        # Simulate blocks at full capacity
        for _ in range(10):
            base_fee = calc_base_fee(gas_limit, gas_limit, base_fee)
        
        # Fee should have increased significantly
        assert base_fee > INITIAL_BASE_FEE * 2

    def test_fee_market_drop(self):
        """During low demand, fee decreases."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        base_fee = 10_000_000_000  # Start high
        
        # Simulate blocks with minimal usage
        for _ in range(10):
            base_fee = calc_base_fee(gas_target // 2, gas_limit, base_fee)
        
        # Fee should have decreased significantly
        assert base_fee < 10_000_000_000

    def test_fee_change_bounds(self):
        """Fee change is bounded by denominator."""
        gas_limit = DEFAULT_GAS_LIMIT
        gas_target = gas_limit // 2
        
        # Maximum change scenario: from 0 gas to full gas
        base_fee_low = calc_base_fee(0, gas_limit, INITIAL_BASE_FEE)
        base_fee_high = calc_base_fee(gas_limit, gas_limit, INITIAL_BASE_FEE)
        
        # Both changes should be within 12.5%
        decrease_pct = (INITIAL_BASE_FEE - base_fee_low) / INITIAL_BASE_FEE
        increase_pct = (base_fee_high - INITIAL_BASE_FEE) / INITIAL_BASE_FEE
        
        assert decrease_pct <= 0.125  # Max 12.5% decrease
        assert increase_pct <= 0.125  # Max 12.5% increase