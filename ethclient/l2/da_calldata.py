"""Calldata-based DA provider — stores batch data in L1 transaction calldata."""

from __future__ import annotations

from typing import Optional

from ethclient.common.crypto import ecdsa_sign, keccak256, private_key_to_address
from ethclient.common.types import Transaction, TxType
from ethclient.l2.eth_rpc import EthRPCClient
from ethclient.l2.interfaces import DAProvider


class CalldataDAProvider(DAProvider):
    """Post batch data as calldata in EIP-1559 (type-2) L1 transactions.

    Commitments are keccak256(batch_number_8bytes || data).
    """

    def __init__(
        self,
        rpc_url: str,
        private_key: bytes,
        chain_id: int,
        to_address: Optional[bytes] = None,
        receipt_timeout: int = 120,
    ) -> None:
        self._rpc = EthRPCClient(rpc_url)
        self._private_key = private_key
        self._chain_id = chain_id
        self._sender = private_key_to_address(private_key)
        self._to = to_address or self._sender
        self._receipt_timeout = receipt_timeout
        self._batch_to_tx: dict[int, bytes] = {}

    def store_batch(self, batch_number: int, data: bytes) -> bytes:
        commitment = keccak256(batch_number.to_bytes(8, "big") + data)
        calldata = batch_number.to_bytes(8, "big") + data

        sender_hex = "0x" + self._sender.hex()
        nonce = self._rpc.get_nonce(sender_hex)
        base_fee = self._rpc.get_base_fee()
        priority_fee = self._rpc.get_max_priority_fee()
        max_fee = base_fee * 2 + priority_fee
        gas_limit = _estimate_calldata_gas(calldata)

        tx = Transaction(
            tx_type=TxType.FEE_MARKET,
            chain_id=self._chain_id,
            nonce=nonce,
            max_priority_fee_per_gas=priority_fee,
            max_fee_per_gas=max_fee,
            gas_limit=gas_limit,
            to=self._to,
            value=0,
            data=calldata,
        )

        msg_hash = tx.signing_hash()
        v, r, s = ecdsa_sign(msg_hash, self._private_key)
        tx.v, tx.r, tx.s = v, r, s
        raw_tx = tx.encode_rlp()

        tx_hash = self._rpc.send_raw_transaction(raw_tx)
        receipt = self._rpc.wait_for_receipt(tx_hash, self._receipt_timeout)

        status = receipt.get("status", "0x1")
        if int(status, 16) == 0:
            raise RuntimeError(
                f"L1 DA transaction reverted: 0x{tx_hash.hex()}"
            )

        self._batch_to_tx[batch_number] = tx_hash
        return commitment

    def retrieve_batch(self, batch_number: int) -> Optional[bytes]:
        tx_hash = self._batch_to_tx.get(batch_number)
        if tx_hash is None:
            return None
        try:
            tx_data = self._rpc.get_transaction(tx_hash)
            if tx_data is None:
                return None
            input_hex = tx_data.get("input", "0x")
            raw = bytes.fromhex(input_hex[2:])
            # Strip the 8-byte batch_number prefix
            if len(raw) < 8:
                return None
            return raw[8:]
        except Exception:
            return None

    def verify_commitment(self, batch_number: int, commitment: bytes) -> bool:
        data = self.retrieve_batch(batch_number)
        if data is None:
            return False
        expected = keccak256(batch_number.to_bytes(8, "big") + data)
        return expected == commitment


def _estimate_calldata_gas(data: bytes) -> int:
    """Estimate gas for calldata: 21000 base + 16/nonzero + 4/zero + 5000 overhead."""
    nonzero = sum(1 for b in data if b != 0)
    zero = len(data) - nonzero
    return 21000 + 16 * nonzero + 4 * zero + 5000
