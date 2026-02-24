"""EIP-4844 Blob-based DA provider — stores batch data as blobs on L1."""

from __future__ import annotations

import json
import pathlib
import urllib.request
from typing import Optional

from ethclient.common import rlp
from ethclient.common.crypto import ecdsa_sign, keccak256, private_key_to_address, sha256
from ethclient.common.types import Transaction, TxType
from ethclient.l2.eth_rpc import EthRPCClient
from ethclient.l2.interfaces import DAProvider

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
FIELD_ELEMENTS_PER_BLOB = 4096
BYTES_PER_BLOB = 131072  # 4096 * 32
USABLE_BYTES_PER_ELEMENT = 31  # high byte must be 0x00 for BLS modulus safety
MAX_DATA_PER_BLOB = FIELD_ELEMENTS_PER_BLOB * USABLE_BYTES_PER_ELEMENT - 4  # 126,972

TRUSTED_SETUP_PATH = pathlib.Path(__file__).resolve().parent.parent / "vm" / "trusted_setup.txt"


# --------------------------------------------------------------------------
# Blob encoding / decoding
# --------------------------------------------------------------------------

def encode_blob(data: bytes) -> bytes:
    """Encode arbitrary data into a 131072-byte blob.

    Layout: 4-byte big-endian length header followed by data, packed into
    31-byte chunks. Each chunk is placed in the low 31 bytes of a 32-byte
    field element (high byte = 0x00 for BLS modulus safety).
    """
    if len(data) > MAX_DATA_PER_BLOB:
        raise ValueError(
            f"Data too large for single blob: {len(data)} > {MAX_DATA_PER_BLOB}"
        )
    payload = len(data).to_bytes(4, "big") + data
    blob = bytearray(BYTES_PER_BLOB)
    elem_idx = 0
    offset = 0
    while offset < len(payload):
        chunk = payload[offset : offset + USABLE_BYTES_PER_ELEMENT]
        start = elem_idx * 32
        # high byte stays 0x00
        blob[start + 1 : start + 1 + len(chunk)] = chunk
        offset += USABLE_BYTES_PER_ELEMENT
        elem_idx += 1
    return bytes(blob)


def decode_blob(blob: bytes) -> bytes:
    """Decode data from a 131072-byte blob (inverse of encode_blob)."""
    if len(blob) != BYTES_PER_BLOB:
        raise ValueError(f"Blob must be {BYTES_PER_BLOB} bytes, got {len(blob)}")
    # Read 4-byte length from first element
    length_bytes = blob[1:5]
    data_len = int.from_bytes(length_bytes, "big")
    if data_len > MAX_DATA_PER_BLOB:
        raise ValueError(f"Decoded length {data_len} exceeds maximum {MAX_DATA_PER_BLOB}")

    payload_needed = 4 + data_len
    result = bytearray()
    elem_idx = 0
    collected = 0
    while collected < payload_needed:
        start = elem_idx * 32
        chunk = blob[start + 1 : start + 1 + USABLE_BYTES_PER_ELEMENT]
        result.extend(chunk)
        collected += USABLE_BYTES_PER_ELEMENT
        elem_idx += 1
    # Strip the 4-byte length header
    return bytes(result[4 : 4 + data_len])


def versioned_hash(kzg_commitment: bytes) -> bytes:
    """Compute EIP-4844 versioned hash: 0x01 || SHA256(commitment)[1:]."""
    h = sha256(kzg_commitment)
    return b"\x01" + h[1:]


# --------------------------------------------------------------------------
# BlobDAProvider
# --------------------------------------------------------------------------

class BlobDAProvider(DAProvider):
    """Post batch data as EIP-4844 blobs on L1.

    Commitments are keccak256(batch_number_8bytes || data).
    """

    def __init__(
        self,
        rpc_url: str,
        private_key: bytes,
        chain_id: int,
        beacon_url: str = "http://localhost:5052",
        receipt_timeout: int = 120,
    ) -> None:
        import ckzg  # type: ignore[import-untyped]
        self._ckzg = ckzg
        ckzg.load_trusted_setup(str(TRUSTED_SETUP_PATH))

        self._rpc = EthRPCClient(rpc_url)
        self._private_key = private_key
        self._chain_id = chain_id
        self._sender = private_key_to_address(private_key)
        self._beacon_url = beacon_url.rstrip("/")
        self._receipt_timeout = receipt_timeout
        self._batch_to_tx: dict[int, bytes] = {}
        self._batch_to_vhash: dict[int, bytes] = {}

    def store_batch(self, batch_number: int, data: bytes) -> bytes:
        commitment = keccak256(batch_number.to_bytes(8, "big") + data)

        blob = encode_blob(data)
        kzg_commit = self._ckzg.blob_to_kzg_commitment(blob)
        kzg_proof = self._ckzg.compute_blob_kzg_proof(blob, kzg_commit)
        v_hash = versioned_hash(kzg_commit)

        sender_hex = "0x" + self._sender.hex()
        nonce = self._rpc.get_nonce(sender_hex)
        base_fee = self._rpc.get_base_fee()
        priority_fee = self._rpc.get_max_priority_fee()
        max_fee = base_fee * 2 + priority_fee
        blob_base_fee = self._rpc.get_blob_base_fee()
        max_blob_fee = max(blob_base_fee * 2, 1)

        tx = Transaction(
            tx_type=TxType.BLOB,
            chain_id=self._chain_id,
            nonce=nonce,
            max_priority_fee_per_gas=priority_fee,
            max_fee_per_gas=max_fee,
            gas_limit=21000 + 5000,
            to=self._sender,  # self-send
            value=0,
            data=b"",
            max_fee_per_blob_gas=max_blob_fee,
            blob_versioned_hashes=[v_hash],
        )

        msg_hash = tx.signing_hash()
        v, r, s = ecdsa_sign(msg_hash, self._private_key)
        tx.v, tx.r, tx.s = v, r, s

        # Network wrapper: 0x03 || RLP([tx_fields..., [blobs], [commitments], [proofs]])
        tx_list = tx.to_rlp_list()
        wrapper = tx_list + [[blob], [kzg_commit], [kzg_proof]]
        raw_tx = bytes([0x03]) + rlp.encode(wrapper)

        tx_hash = self._rpc.send_raw_transaction(raw_tx)
        receipt = self._rpc.wait_for_receipt(tx_hash, self._receipt_timeout)

        status = receipt.get("status", "0x1")
        if int(status, 16) == 0:
            raise RuntimeError(
                f"L1 blob transaction reverted: 0x{tx_hash.hex()}"
            )

        self._batch_to_tx[batch_number] = tx_hash
        self._batch_to_vhash[batch_number] = v_hash
        return commitment

    def retrieve_batch(self, batch_number: int) -> Optional[bytes]:
        v_hash = self._batch_to_vhash.get(batch_number)
        if v_hash is None:
            return None
        try:
            # Look up the tx to find the block
            tx_data = self._rpc.get_transaction(self._batch_to_tx[batch_number])
            if tx_data is None:
                return None
            block_num = int(tx_data["blockNumber"], 16)

            # Query beacon API for blob sidecars
            url = f"{self._beacon_url}/eth/v1/beacon/blob_sidecars/{block_num}"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())

            for sidecar in result.get("data", []):
                commit_hex = sidecar["kzg_commitment"]
                commit_bytes = bytes.fromhex(commit_hex[2:] if commit_hex.startswith("0x") else commit_hex)
                if versioned_hash(commit_bytes) == v_hash:
                    blob_hex = sidecar["blob"]
                    blob_bytes = bytes.fromhex(blob_hex[2:] if blob_hex.startswith("0x") else blob_hex)
                    return decode_blob(blob_bytes)
            return None
        except Exception:
            return None

    def verify_commitment(self, batch_number: int, commitment: bytes) -> bool:
        data = self.retrieve_batch(batch_number)
        if data is None:
            return False
        expected = keccak256(batch_number.to_bytes(8, "big") + data)
        return expected == commitment
