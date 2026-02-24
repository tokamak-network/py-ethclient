"""Tests for LocalDAProvider: store, retrieve, verify commitment."""

import pytest
from ethclient.l2.da import LocalDAProvider


class TestLocalDAProvider:
    def test_store_and_retrieve(self):
        da = LocalDAProvider()
        data = b"batch data here"
        commitment = da.store_batch(0, data)

        assert len(commitment) == 32
        assert da.retrieve_batch(0) == data

    def test_retrieve_nonexistent(self):
        da = LocalDAProvider()
        assert da.retrieve_batch(999) is None

    def test_verify_commitment_valid(self):
        da = LocalDAProvider()
        data = b"some batch"
        commitment = da.store_batch(1, data)
        assert da.verify_commitment(1, commitment)

    def test_verify_commitment_invalid(self):
        da = LocalDAProvider()
        da.store_batch(1, b"real data")
        assert not da.verify_commitment(1, b"\x00" * 32)

    def test_verify_nonexistent_batch(self):
        da = LocalDAProvider()
        assert not da.verify_commitment(999, b"\x00" * 32)

    def test_multiple_batches(self):
        da = LocalDAProvider()
        c0 = da.store_batch(0, b"batch0")
        c1 = da.store_batch(1, b"batch1")

        assert c0 != c1
        assert da.retrieve_batch(0) == b"batch0"
        assert da.retrieve_batch(1) == b"batch1"
        assert da.batch_count == 2

    def test_commitment_deterministic(self):
        da1 = LocalDAProvider()
        da2 = LocalDAProvider()
        c1 = da1.store_batch(0, b"same data")
        c2 = da2.store_batch(0, b"same data")
        assert c1 == c2

    def test_different_batch_numbers_different_commitments(self):
        da = LocalDAProvider()
        c0 = da.store_batch(0, b"data")
        c1 = da.store_batch(1, b"data")
        assert c0 != c1
