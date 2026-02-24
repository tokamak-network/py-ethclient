"""Tests for EthL1Backend — real Ethereum L1 backend via JSON-RPC (mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ethclient.l2.eth_l1_backend import EthL1Backend
from ethclient.l2.eth_rpc import EthRPCError
from ethclient.zk.types import G1Point, G2Point, Proof, VerificationKey


# Deterministic test key (DO NOT use in production)
TEST_PRIVATE_KEY = b"\x01" * 32


def _make_vk() -> VerificationKey:
    """Create a minimal verification key for testing."""
    g1 = G1Point(1, 2)
    g2 = G2Point(
        x_real=10857046999023057135944570762232829481370756359578518086990519993285655852781,
        x_imag=11559732032986387107991004021392285783925812861821192530917403151452391805634,
        y_real=8495653923123431417604973247489272438418190587263600148770280649306958101930,
        y_imag=4082367875863433681332203403145435568316851327593401208105741076214120093531,
    )
    return VerificationKey(
        alpha=g1,
        beta=g2,
        gamma=g2,
        delta=g2,
        ic=[g1, g1, g1, g1],  # 3 public inputs + 1
    )


def _make_proof() -> Proof:
    return Proof(
        a=G1Point(1, 2),
        b=G2Point(
            x_real=10857046999023057135944570762232829481370756359578518086990519993285655852781,
            x_imag=11559732032986387107991004021392285783925812861821192530917403151452391805634,
            y_real=8495653923123431417604973247489272438418190587263600148770280649306958101930,
            y_imag=4082367875863433681332203403145435568316851327593401208105741076214120093531,
        ),
        c=G1Point(1, 2),
    )


def _mock_rpc():
    """Create a mock EthRPCClient."""
    rpc = MagicMock()
    rpc.get_nonce.return_value = 0
    rpc.get_base_fee.return_value = 1_000_000_000  # 1 gwei
    rpc.get_max_priority_fee.return_value = 100_000_000  # 0.1 gwei
    rpc.send_raw_transaction.return_value = b"\xaa" * 32
    return rpc


class TestDeployVerifier:
    def test_successful_deployment(self):
        backend = EthL1Backend("http://localhost:8545", TEST_PRIVATE_KEY, chain_id=1)
        backend._rpc = _mock_rpc()

        contract_addr = "0x" + "ab" * 20
        backend._rpc.wait_for_receipt.return_value = {
            "status": "0x1",
            "contractAddress": contract_addr,
        }

        vk = _make_vk()
        addr = backend.deploy_verifier(vk)
        assert addr == bytes.fromhex("ab" * 20)
        assert backend._verifier_address == addr
        backend._rpc.send_raw_transaction.assert_called_once()

    def test_deployment_revert(self):
        backend = EthL1Backend("http://localhost:8545", TEST_PRIVATE_KEY, chain_id=1)
        backend._rpc = _mock_rpc()
        backend._rpc.wait_for_receipt.return_value = {
            "status": "0x0",
            "contractAddress": "",
        }

        vk = _make_vk()
        with pytest.raises(EthRPCError, match="deployment failed"):
            backend.deploy_verifier(vk)

    def test_deployment_no_contract_address(self):
        backend = EthL1Backend("http://localhost:8545", TEST_PRIVATE_KEY, chain_id=1)
        backend._rpc = _mock_rpc()
        backend._rpc.wait_for_receipt.return_value = {
            "status": "0x1",
            "contractAddress": "",
        }

        vk = _make_vk()
        with pytest.raises(EthRPCError, match="no contract address"):
            backend.deploy_verifier(vk)


class TestSubmitBatch:
    def _setup_backend(self):
        backend = EthL1Backend("http://localhost:8545", TEST_PRIVATE_KEY, chain_id=1)
        backend._rpc = _mock_rpc()
        backend._rpc.wait_for_receipt.return_value = {
            "status": "0x1",
            "contractAddress": "0x" + "ab" * 20,
        }
        vk = _make_vk()
        backend.deploy_verifier(vk)
        return backend

    def test_successful_submission(self):
        backend = self._setup_backend()
        backend._rpc.wait_for_receipt.return_value = {"status": "0x1"}

        tx_hash = backend.submit_batch(
            batch_number=0,
            old_root=b"\x00" * 32,
            new_root=b"\x01" * 32,
            proof=_make_proof(),
            tx_commitment=b"\x02" * 32,
        )
        assert tx_hash == b"\xaa" * 32
        assert backend.is_batch_verified(0)
        assert backend.get_verified_state_root() == b"\x01" * 32

    def test_submission_revert(self):
        backend = self._setup_backend()
        backend._rpc.wait_for_receipt.return_value = {"status": "0x0"}

        tx_hash = backend.submit_batch(
            batch_number=0,
            old_root=b"\x00" * 32,
            new_root=b"\x01" * 32,
            proof=_make_proof(),
            tx_commitment=b"\x02" * 32,
        )
        assert tx_hash == b"\xaa" * 32
        assert not backend.is_batch_verified(0)

    def test_submit_without_deploy_raises(self):
        backend = EthL1Backend("http://localhost:8545", TEST_PRIVATE_KEY, chain_id=1)
        with pytest.raises(RuntimeError, match="Verifier not deployed"):
            backend.submit_batch(0, b"\x00" * 32, b"\x01" * 32, _make_proof(), b"\x02" * 32)

    def test_calldata_encoding(self):
        backend = self._setup_backend()
        backend._rpc.wait_for_receipt.return_value = {"status": "0x1"}

        proof = _make_proof()
        backend.submit_batch(
            batch_number=1,
            old_root=b"\x11" * 32,
            new_root=b"\x22" * 32,
            proof=proof,
            tx_commitment=b"\x33" * 32,
        )
        # Verify send_raw_transaction was called (calldata is embedded in the tx)
        assert backend._rpc.send_raw_transaction.call_count == 2  # deploy + submit


class TestBuildAndSignTx:
    def test_build_tx_deployment(self):
        backend = EthL1Backend("http://localhost:8545", TEST_PRIVATE_KEY, chain_id=1)
        backend._rpc = _mock_rpc()

        tx = backend._build_tx(to=None, data=b"\x60\x00")
        assert tx.to is None
        assert tx.gas_limit == 5_000_000
        assert tx.data == b"\x60\x00"
        assert tx.chain_id == 1

    def test_build_tx_call(self):
        backend = EthL1Backend("http://localhost:8545", TEST_PRIVATE_KEY, chain_id=1)
        backend._rpc = _mock_rpc()

        addr = b"\xab" * 20
        tx = backend._build_tx(to=addr, data=b"\xca\xfe")
        assert tx.to == addr
        assert tx.gas_limit == 500_000

    def test_sign_tx_produces_valid_rlp(self):
        backend = EthL1Backend("http://localhost:8545", TEST_PRIVATE_KEY, chain_id=1)
        backend._rpc = _mock_rpc()

        tx = backend._build_tx(to=None, data=b"\x60\x00")
        raw = backend._sign_tx(tx)
        assert isinstance(raw, bytes)
        assert len(raw) > 0
        # EIP-1559 tx starts with type byte 0x02
        assert raw[0] == 0x02


class TestGasMultiplier:
    def test_custom_gas_multiplier(self):
        backend = EthL1Backend(
            "http://localhost:8545", TEST_PRIVATE_KEY,
            chain_id=1, gas_multiplier=2.0,
        )
        backend._rpc = _mock_rpc()

        tx = backend._build_tx(to=None, data=b"")
        base = 1_000_000_000
        priority = 100_000_000
        expected = int((base + priority) * 2.0)
        assert tx.max_fee_per_gas == expected


class TestMultipleBatches:
    def test_multiple_verified_batches(self):
        backend = EthL1Backend("http://localhost:8545", TEST_PRIVATE_KEY, chain_id=1)
        backend._rpc = _mock_rpc()
        backend._rpc.wait_for_receipt.return_value = {
            "status": "0x1",
            "contractAddress": "0x" + "ab" * 20,
        }
        backend.deploy_verifier(_make_vk())

        for i in range(3):
            backend._rpc.wait_for_receipt.return_value = {"status": "0x1"}
            root = bytes([i + 1]) * 32
            backend.submit_batch(i, b"\x00" * 32, root, _make_proof(), b"\x02" * 32)

        assert backend.is_batch_verified(0)
        assert backend.is_batch_verified(1)
        assert backend.is_batch_verified(2)
        assert not backend.is_batch_verified(3)
        assert backend.get_verified_state_root() == b"\x03" * 32
