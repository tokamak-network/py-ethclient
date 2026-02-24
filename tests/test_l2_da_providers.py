"""Tests for production DA providers: EthRPCClient, S3, Calldata, Blob.

All external services are mocked with unittest.mock.
"""

from __future__ import annotations

import json
import struct
import time
from io import BytesIO
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from ethclient.common.crypto import ecdsa_sign, keccak256, private_key_to_address


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PRIVATE_KEY = b"\x01" * 32
SENDER = private_key_to_address(PRIVATE_KEY)


def _make_rpc_response(result: Any) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "result": result, "id": 1}).encode()


def _make_rpc_error(msg: str, code: int = -32000) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "error": {"code": code, "message": msg},
        "id": 1,
    }).encode()


class FakeHTTPResponse:
    """Minimal context-manager wrapper around bytes for urllib mocking."""

    def __init__(self, data: bytes, status: int = 200):
        self._data = data
        self.status = status

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


# ===========================================================================
# TestEthRPCClient
# ===========================================================================

class TestEthRPCClient:

    def _make_client(self):
        from ethclient.l2.eth_rpc import EthRPCClient
        return EthRPCClient("http://localhost:8545", timeout=5)

    @patch("urllib.request.urlopen")
    def test_get_chain_id(self, mock_urlopen):
        mock_urlopen.return_value = FakeHTTPResponse(_make_rpc_response("0x1"))
        client = self._make_client()
        assert client.get_chain_id() == 1

    @patch("urllib.request.urlopen")
    def test_get_nonce(self, mock_urlopen):
        mock_urlopen.return_value = FakeHTTPResponse(_make_rpc_response("0xa"))
        client = self._make_client()
        assert client.get_nonce("0x" + "ab" * 20) == 10

    @patch("urllib.request.urlopen")
    def test_get_gas_price(self, mock_urlopen):
        mock_urlopen.return_value = FakeHTTPResponse(
            _make_rpc_response("0x3b9aca00")  # 1 Gwei
        )
        client = self._make_client()
        assert client.get_gas_price() == 1_000_000_000

    @patch("urllib.request.urlopen")
    def test_get_base_fee(self, mock_urlopen):
        block = {"baseFeePerGas": "0x3b9aca00"}
        mock_urlopen.return_value = FakeHTTPResponse(_make_rpc_response(block))
        client = self._make_client()
        assert client.get_base_fee() == 1_000_000_000

    @patch("urllib.request.urlopen")
    def test_send_raw_transaction(self, mock_urlopen):
        tx_hash = "0x" + "ab" * 32
        mock_urlopen.return_value = FakeHTTPResponse(_make_rpc_response(tx_hash))
        client = self._make_client()
        result = client.send_raw_transaction(b"\x02\x00")
        assert result == bytes.fromhex("ab" * 32)

    @patch("urllib.request.urlopen")
    def test_rpc_error_raises(self, mock_urlopen):
        from ethclient.l2.eth_rpc import EthRPCError
        mock_urlopen.return_value = FakeHTTPResponse(
            _make_rpc_error("nonce too low", -32000)
        )
        client = self._make_client()
        with pytest.raises(EthRPCError, match="nonce too low"):
            client.get_chain_id()

    @patch("urllib.request.urlopen")
    def test_transport_error(self, mock_urlopen):
        from ethclient.l2.eth_rpc import EthRPCError
        mock_urlopen.side_effect = OSError("connection refused")
        client = self._make_client()
        with pytest.raises(EthRPCError, match="transport error"):
            client.get_chain_id()

    @patch("urllib.request.urlopen")
    def test_wait_for_receipt_success(self, mock_urlopen):
        receipt = {"status": "0x1", "blockNumber": "0x10"}
        # First call returns None (not mined yet), second returns receipt
        mock_urlopen.side_effect = [
            FakeHTTPResponse(_make_rpc_response(None)),
            FakeHTTPResponse(_make_rpc_response(receipt)),
        ]
        client = self._make_client()
        result = client.wait_for_receipt(b"\xaa" * 32, timeout=5)
        assert result["status"] == "0x1"

    @patch("time.sleep")
    @patch("time.monotonic")
    @patch("urllib.request.urlopen")
    def test_wait_for_receipt_timeout(self, mock_urlopen, mock_monotonic, mock_sleep):
        mock_urlopen.return_value = FakeHTTPResponse(_make_rpc_response(None))
        # Simulate time passing beyond deadline
        mock_monotonic.side_effect = [0.0, 0.0, 200.0]
        client = self._make_client()
        with pytest.raises(TimeoutError):
            client.wait_for_receipt(b"\xaa" * 32, timeout=5)


# ===========================================================================
# TestS3DAProvider
# ===========================================================================

class TestS3DAProvider:

    def _make_provider(self, mock_boto3):
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        from ethclient.l2.da_s3 import S3DAProvider
        provider = S3DAProvider(bucket="test-bucket", prefix="batches/")
        return provider, mock_client

    @patch.dict("sys.modules", {"boto3": MagicMock()})
    def test_store_batch(self):
        import sys
        mock_boto3 = sys.modules["boto3"]
        provider, mock_client = self._make_provider(mock_boto3)

        data = b"test batch data"
        commitment = provider.store_batch(0, data)

        assert len(commitment) == 32
        expected = keccak256((0).to_bytes(8, "big") + data)
        assert commitment == expected
        mock_client.put_object.assert_called_once_with(
            Bucket="test-bucket", Key="batches/00000000", Body=data,
        )

    @patch.dict("sys.modules", {"boto3": MagicMock()})
    def test_retrieve_batch(self):
        import sys
        mock_boto3 = sys.modules["boto3"]
        provider, mock_client = self._make_provider(mock_boto3)

        body_mock = MagicMock()
        body_mock.read.return_value = b"batch data"
        mock_client.get_object.return_value = {"Body": body_mock}

        result = provider.retrieve_batch(5)
        assert result == b"batch data"
        mock_client.get_object.assert_called_once_with(
            Bucket="test-bucket", Key="batches/00000005",
        )

    @patch.dict("sys.modules", {"boto3": MagicMock()})
    def test_retrieve_nonexistent(self):
        import sys
        mock_boto3 = sys.modules["boto3"]
        provider, mock_client = self._make_provider(mock_boto3)
        mock_client.get_object.side_effect = Exception("NoSuchKey")
        assert provider.retrieve_batch(999) is None

    @patch.dict("sys.modules", {"boto3": MagicMock()})
    def test_verify_commitment_valid(self):
        import sys
        mock_boto3 = sys.modules["boto3"]
        provider, mock_client = self._make_provider(mock_boto3)

        data = b"verify me"
        body_mock = MagicMock()
        body_mock.read.return_value = data
        mock_client.get_object.return_value = {"Body": body_mock}

        commitment = keccak256((1).to_bytes(8, "big") + data)
        assert provider.verify_commitment(1, commitment)

    @patch.dict("sys.modules", {"boto3": MagicMock()})
    def test_verify_commitment_invalid(self):
        import sys
        mock_boto3 = sys.modules["boto3"]
        provider, mock_client = self._make_provider(mock_boto3)

        body_mock = MagicMock()
        body_mock.read.return_value = b"real data"
        mock_client.get_object.return_value = {"Body": body_mock}
        assert not provider.verify_commitment(1, b"\x00" * 32)

    @patch.dict("sys.modules", {"boto3": MagicMock()})
    def test_commitment_consistency_with_local(self):
        """S3 and Local DA should produce identical commitments."""
        import sys
        mock_boto3 = sys.modules["boto3"]
        provider, mock_client = self._make_provider(mock_boto3)

        from ethclient.l2.da import LocalDAProvider
        local = LocalDAProvider()

        data = b"consistency check"
        s3_commitment = provider.store_batch(0, data)
        local_commitment = local.store_batch(0, data)
        assert s3_commitment == local_commitment

    def test_import_error_without_boto3(self):
        with patch.dict("sys.modules", {"boto3": None}):
            from ethclient.l2 import da_s3
            # Reload to trigger the import check
            import importlib
            importlib.reload(da_s3)
            with pytest.raises(ImportError, match="boto3"):
                da_s3.S3DAProvider(bucket="test")


# ===========================================================================
# TestCalldataDAProvider
# ===========================================================================

class TestCalldataDAProvider:

    def _make_provider(self):
        from ethclient.l2.da_calldata import CalldataDAProvider
        provider = CalldataDAProvider(
            rpc_url="http://localhost:8545",
            private_key=PRIVATE_KEY,
            chain_id=1,
            receipt_timeout=5,
        )
        return provider

    def _mock_rpc(self, provider, nonce=0, base_fee=1000, priority_fee=100,
                  tx_hash=b"\xcc" * 32, receipt_status="0x1"):
        """Patch the provider's internal RPC client."""
        mock_rpc = MagicMock()
        mock_rpc.get_nonce.return_value = nonce
        mock_rpc.get_base_fee.return_value = base_fee
        mock_rpc.get_max_priority_fee.return_value = priority_fee
        mock_rpc.send_raw_transaction.return_value = tx_hash
        mock_rpc.wait_for_receipt.return_value = {"status": receipt_status, "blockNumber": "0x1"}
        mock_rpc.get_transaction.return_value = None
        provider._rpc = mock_rpc
        return mock_rpc

    def test_store_batch_builds_eip1559_tx(self):
        provider = self._make_provider()
        mock_rpc = self._mock_rpc(provider)

        data = b"calldata batch"
        commitment = provider.store_batch(0, data)

        assert len(commitment) == 32
        expected = keccak256((0).to_bytes(8, "big") + data)
        assert commitment == expected
        mock_rpc.send_raw_transaction.assert_called_once()
        raw_tx = mock_rpc.send_raw_transaction.call_args[0][0]
        # Type-2 tx starts with 0x02
        assert raw_tx[0] == 0x02

    def test_store_batch_records_tx_hash(self):
        provider = self._make_provider()
        tx_hash = b"\xdd" * 32
        self._mock_rpc(provider, tx_hash=tx_hash)

        provider.store_batch(5, b"data")
        assert provider._batch_to_tx[5] == tx_hash

    def test_store_batch_reverted_raises(self):
        provider = self._make_provider()
        self._mock_rpc(provider, receipt_status="0x0")

        with pytest.raises(RuntimeError, match="reverted"):
            provider.store_batch(0, b"data")

    def test_store_batch_timeout_raises(self):
        provider = self._make_provider()
        mock_rpc = self._mock_rpc(provider)
        mock_rpc.wait_for_receipt.side_effect = TimeoutError("timeout")

        with pytest.raises(TimeoutError):
            provider.store_batch(0, b"data")

    def test_retrieve_batch(self):
        provider = self._make_provider()
        mock_rpc = self._mock_rpc(provider)

        data = b"retrieve me"
        calldata_hex = "0x" + ((0).to_bytes(8, "big") + data).hex()
        mock_rpc.get_transaction.return_value = {"input": calldata_hex}
        provider._batch_to_tx[0] = b"\xcc" * 32

        result = provider.retrieve_batch(0)
        assert result == data

    def test_retrieve_nonexistent(self):
        provider = self._make_provider()
        self._mock_rpc(provider)
        assert provider.retrieve_batch(999) is None

    def test_verify_commitment(self):
        provider = self._make_provider()
        mock_rpc = self._mock_rpc(provider)

        data = b"verify calldata"
        calldata_hex = "0x" + ((1).to_bytes(8, "big") + data).hex()
        mock_rpc.get_transaction.return_value = {"input": calldata_hex}
        provider._batch_to_tx[1] = b"\xcc" * 32

        commitment = keccak256((1).to_bytes(8, "big") + data)
        assert provider.verify_commitment(1, commitment)
        assert not provider.verify_commitment(1, b"\x00" * 32)

    def test_gas_estimation(self):
        from ethclient.l2.da_calldata import _estimate_calldata_gas
        # All zeros: 21000 + 4*10 + 5000 = 26040
        assert _estimate_calldata_gas(b"\x00" * 10) == 21000 + 4 * 10 + 5000
        # All nonzero: 21000 + 16*5 + 5000 = 26080
        assert _estimate_calldata_gas(b"\xff" * 5) == 21000 + 16 * 5 + 5000
        # Mixed: 2 nonzero + 3 zero
        data = b"\x01\x02\x00\x00\x00"
        assert _estimate_calldata_gas(data) == 21000 + 16 * 2 + 4 * 3 + 5000


# ===========================================================================
# TestBlobEncoding
# ===========================================================================

class TestBlobEncoding:

    def test_encode_decode_roundtrip(self):
        from ethclient.l2.da_blob import encode_blob, decode_blob
        data = b"hello blob world" * 100
        blob = encode_blob(data)
        assert len(blob) == 131072
        recovered = decode_blob(blob)
        assert recovered == data

    def test_encode_decode_empty(self):
        from ethclient.l2.da_blob import encode_blob, decode_blob
        data = b""
        blob = encode_blob(data)
        assert decode_blob(blob) == data

    def test_encode_decode_max_size(self):
        from ethclient.l2.da_blob import encode_blob, decode_blob, MAX_DATA_PER_BLOB
        data = bytes(range(256)) * (MAX_DATA_PER_BLOB // 256)
        data = data[:MAX_DATA_PER_BLOB]
        blob = encode_blob(data)
        assert decode_blob(blob) == data

    def test_encode_too_large(self):
        from ethclient.l2.da_blob import encode_blob, MAX_DATA_PER_BLOB
        with pytest.raises(ValueError, match="too large"):
            encode_blob(b"\xff" * (MAX_DATA_PER_BLOB + 1))

    def test_blob_size(self):
        from ethclient.l2.da_blob import encode_blob
        blob = encode_blob(b"small")
        assert len(blob) == 131072

    def test_high_byte_always_zero(self):
        """Each 32-byte field element must have high byte = 0x00."""
        from ethclient.l2.da_blob import encode_blob
        data = b"\xff" * 1000
        blob = encode_blob(data)
        for i in range(4096):
            assert blob[i * 32] == 0x00, f"Field element {i} has non-zero high byte"

    def test_versioned_hash(self):
        from ethclient.l2.da_blob import versioned_hash
        from ethclient.common.crypto import sha256
        fake_commitment = b"\xab" * 48
        vh = versioned_hash(fake_commitment)
        assert len(vh) == 32
        assert vh[0] == 0x01
        assert vh[1:] == sha256(fake_commitment)[1:]


# ===========================================================================
# TestBlobDAProvider
# ===========================================================================

class TestBlobDAProvider:

    def _make_provider(self, mock_ckzg):
        mock_ckzg.load_trusted_setup = MagicMock()
        mock_ckzg.blob_to_kzg_commitment = MagicMock(return_value=b"\xaa" * 48)
        mock_ckzg.compute_blob_kzg_proof = MagicMock(return_value=b"\xbb" * 48)

        from ethclient.l2.da_blob import BlobDAProvider
        provider = BlobDAProvider(
            rpc_url="http://localhost:8545",
            private_key=PRIVATE_KEY,
            chain_id=1,
            beacon_url="http://localhost:5052",
            receipt_timeout=5,
        )
        return provider

    def _mock_rpc(self, provider, nonce=0, base_fee=1000, priority_fee=100,
                  blob_base_fee=1, tx_hash=b"\xee" * 32):
        mock_rpc = MagicMock()
        mock_rpc.get_nonce.return_value = nonce
        mock_rpc.get_base_fee.return_value = base_fee
        mock_rpc.get_max_priority_fee.return_value = priority_fee
        mock_rpc.get_blob_base_fee.return_value = blob_base_fee
        mock_rpc.send_raw_transaction.return_value = tx_hash
        mock_rpc.wait_for_receipt.return_value = {"status": "0x1", "blockNumber": "0x100"}
        mock_rpc.get_transaction.return_value = {"blockNumber": "0x100"}
        provider._rpc = mock_rpc
        return mock_rpc

    @patch.dict("sys.modules", {"ckzg": MagicMock()})
    def test_store_batch_builds_type3_tx(self):
        import sys
        provider = self._make_provider(sys.modules["ckzg"])
        self._mock_rpc(provider)

        data = b"blob batch data"
        commitment = provider.store_batch(0, data)

        assert len(commitment) == 32
        expected = keccak256((0).to_bytes(8, "big") + data)
        assert commitment == expected

        raw_tx = provider._rpc.send_raw_transaction.call_args[0][0]
        # Type-3 tx starts with 0x03
        assert raw_tx[0] == 0x03

    @patch.dict("sys.modules", {"ckzg": MagicMock()})
    def test_store_records_versioned_hash(self):
        import sys
        provider = self._make_provider(sys.modules["ckzg"])
        self._mock_rpc(provider)

        provider.store_batch(3, b"data")
        assert 3 in provider._batch_to_vhash
        assert provider._batch_to_vhash[3][0] == 0x01  # versioned hash prefix

    @patch.dict("sys.modules", {"ckzg": MagicMock()})
    def test_store_batch_reverted(self):
        import sys
        provider = self._make_provider(sys.modules["ckzg"])
        mock_rpc = self._mock_rpc(provider)
        mock_rpc.wait_for_receipt.return_value = {"status": "0x0"}

        with pytest.raises(RuntimeError, match="reverted"):
            provider.store_batch(0, b"data")

    @patch("urllib.request.urlopen")
    @patch.dict("sys.modules", {"ckzg": MagicMock()})
    def test_retrieve_batch_from_beacon(self, mock_urlopen):
        import sys
        from ethclient.l2.da_blob import encode_blob, versioned_hash
        provider = self._make_provider(sys.modules["ckzg"])
        self._mock_rpc(provider)

        data = b"retrieve blob"
        blob = encode_blob(data)
        fake_commit = b"\xaa" * 48
        v_hash = versioned_hash(fake_commit)

        provider._batch_to_tx[0] = b"\xee" * 32
        provider._batch_to_vhash[0] = v_hash

        beacon_response = {
            "data": [{
                "kzg_commitment": "0x" + fake_commit.hex(),
                "blob": "0x" + blob.hex(),
            }]
        }
        mock_urlopen.return_value = FakeHTTPResponse(
            json.dumps(beacon_response).encode()
        )

        result = provider.retrieve_batch(0)
        assert result == data

    @patch.dict("sys.modules", {"ckzg": MagicMock()})
    def test_retrieve_nonexistent(self):
        import sys
        provider = self._make_provider(sys.modules["ckzg"])
        self._mock_rpc(provider)
        assert provider.retrieve_batch(999) is None

    @patch("urllib.request.urlopen")
    @patch.dict("sys.modules", {"ckzg": MagicMock()})
    def test_verify_commitment_via_beacon(self, mock_urlopen):
        import sys
        from ethclient.l2.da_blob import encode_blob, versioned_hash
        provider = self._make_provider(sys.modules["ckzg"])
        self._mock_rpc(provider)

        data = b"verify blob"
        blob = encode_blob(data)
        fake_commit = b"\xaa" * 48
        v_hash = versioned_hash(fake_commit)

        provider._batch_to_tx[1] = b"\xee" * 32
        provider._batch_to_vhash[1] = v_hash

        beacon_response = {
            "data": [{
                "kzg_commitment": "0x" + fake_commit.hex(),
                "blob": "0x" + blob.hex(),
            }]
        }
        mock_urlopen.return_value = FakeHTTPResponse(
            json.dumps(beacon_response).encode()
        )

        commitment = keccak256((1).to_bytes(8, "big") + data)
        assert provider.verify_commitment(1, commitment)


# ===========================================================================
# TestDAProviderIntegration — with Sequencer
# ===========================================================================

class TestDAProviderIntegration:

    def test_local_da_with_sequencer(self):
        """Verify LocalDAProvider works end-to-end with Sequencer."""
        from ethclient.l2 import Sequencer, L2Config, L2Tx, L2TxType
        from ethclient.l2.da import LocalDAProvider
        from ethclient.l2.state import L2StateStore
        from ethclient.l2.runtime import PythonRuntime

        def noop_stf(state, tx):
            from ethclient.l2.types import STFResult
            return STFResult(success=True)

        config = L2Config(max_txs_per_batch=2)
        state_store = L2StateStore()
        stf = PythonRuntime(noop_stf)
        da = LocalDAProvider()
        seq = Sequencer(stf=stf, state_store=state_store, da=da, config=config)

        tx = L2Tx(sender=b"\x01" * 20, nonce=0, tx_type=L2TxType.CALL,
                   data={"action": "test"})
        seq.submit_tx(tx)
        batch = seq._seal_batch()

        import json as _json
        batch_data = _json.dumps({"txs": len(batch.transactions)}).encode()
        commitment = da.store_batch(batch.number, batch_data)

        assert len(commitment) == 32
        assert da.retrieve_batch(batch.number) == batch_data
        assert da.verify_commitment(batch.number, commitment)

    @patch.dict("sys.modules", {"boto3": MagicMock()})
    def test_s3_da_commitment_matches_local(self):
        """S3 DA produces same commitment as Local DA for same data."""
        import sys
        mock_boto3 = sys.modules["boto3"]
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        from ethclient.l2.da_s3 import S3DAProvider
        from ethclient.l2.da import LocalDAProvider

        s3 = S3DAProvider(bucket="test")
        local = LocalDAProvider()

        data = b"integration test batch data"
        c_s3 = s3.store_batch(0, data)
        c_local = local.store_batch(0, data)
        assert c_s3 == c_local

    def test_calldata_da_implements_interface(self):
        """CalldataDAProvider properly implements DAProvider ABC."""
        from ethclient.l2.da_calldata import CalldataDAProvider
        from ethclient.l2.interfaces import DAProvider
        assert issubclass(CalldataDAProvider, DAProvider)

        provider = CalldataDAProvider.__new__(CalldataDAProvider)
        assert hasattr(provider, "store_batch")
        assert hasattr(provider, "retrieve_batch")
        assert hasattr(provider, "verify_commitment")
