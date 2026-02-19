"""Typed helpers for Engine API payload/forkchoice parsing and payload id generation."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.common.types import Withdrawal
from ethclient.rpc.server import RPCError

ENGINE_UNKNOWN_PAYLOAD = -38001
ENGINE_INVALID_FORKCHOICE_STATE = -38002
ENGINE_INVALID_PAYLOAD_ATTRIBUTES = -38003
ENGINE_UNSUPPORTED_FORK = -38005
ENGINE_INVALID_PARAMS = -32602

ZERO_HASH_HEX = "0x" + "00" * 32
ZERO_ADDRESS_HEX = "0x" + "00" * 20


class EngineValidationError(RPCError):
    """Engine API input validation error with explicit code."""



def _require_hex(value: Any, *, name: str, size: int) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} must be 0x-prefixed hex")
    body = value[2:]
    if len(body) != size * 2:
        raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} must be {size} bytes")
    try:
        return bytes.fromhex(body)
    except ValueError as exc:
        raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} is invalid hex") from exc



def _optional_hex(value: Any, *, name: str, size: int) -> Optional[bytes]:
    if value is None:
        return None
    return _require_hex(value, name=name, size=size)



def _hex_to_int(value: Any, *, name: str) -> int:
    if isinstance(value, int):
        if value < 0:
            raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} must be >= 0")
        return value
    if not isinstance(value, str) or not value.startswith("0x"):
        raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} must be hex quantity")
    try:
        result = int(value, 16)
    except ValueError as exc:
        raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} is invalid hex quantity") from exc
    if result < 0:
        raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} must be >= 0")
    return result



def _as_hex(value: bytes) -> str:
    return "0x" + value.hex()



def _as_quantity(value: int) -> str:
    return hex(value)


@dataclass(frozen=True)
class ForkchoiceState:
    head_block_hash: bytes
    safe_block_hash: bytes
    finalized_block_hash: bytes

    @classmethod
    def from_rpc(cls, raw: dict[str, Any]) -> ForkchoiceState:
        if not isinstance(raw, dict):
            raise EngineValidationError(ENGINE_INVALID_PARAMS, "forkchoice_state must be an object")
        return cls(
            head_block_hash=_require_hex(raw.get("headBlockHash", ZERO_HASH_HEX), name="headBlockHash", size=32),
            safe_block_hash=_require_hex(raw.get("safeBlockHash", ZERO_HASH_HEX), name="safeBlockHash", size=32),
            finalized_block_hash=_require_hex(raw.get("finalizedBlockHash", ZERO_HASH_HEX), name="finalizedBlockHash", size=32),
        )


@dataclass(frozen=True)
class ParsedPayloadAttributes:
    timestamp: int
    prev_randao: bytes
    suggested_fee_recipient: bytes
    withdrawals: Optional[list[Withdrawal]]
    parent_beacon_block_root: Optional[bytes]
    transactions: list[bytes] = field(default_factory=list)
    no_tx_pool: bool = False
    gas_limit: Optional[int] = None

    @classmethod
    def from_rpc(cls, raw: dict[str, Any]) -> ParsedPayloadAttributes:
        if not isinstance(raw, dict):
            raise EngineValidationError(ENGINE_INVALID_PARAMS, "payloadAttributes must be an object")

        txs_raw = raw.get("transactions", [])
        if txs_raw is None:
            txs_raw = []
        if not isinstance(txs_raw, list):
            raise EngineValidationError(ENGINE_INVALID_PARAMS, "transactions must be a list")

        txs: list[bytes] = []
        for i, tx_hex in enumerate(txs_raw):
            if not isinstance(tx_hex, str) or not tx_hex.startswith("0x"):
                raise EngineValidationError(ENGINE_INVALID_PARAMS, f"transactions[{i}] must be hex")
            try:
                txs.append(bytes.fromhex(tx_hex[2:]))
            except ValueError as exc:
                raise EngineValidationError(ENGINE_INVALID_PARAMS, f"transactions[{i}] is invalid hex") from exc

        withdrawals_raw = raw.get("withdrawals")
        withdrawals: Optional[list[Withdrawal]] = None
        if withdrawals_raw is not None:
            if not isinstance(withdrawals_raw, list):
                raise EngineValidationError(ENGINE_INVALID_PARAMS, "withdrawals must be a list")
            withdrawals = [_parse_withdrawal(w, f"withdrawals[{i}]") for i, w in enumerate(withdrawals_raw)]

        gas_limit_raw = raw.get("gasLimit")
        gas_limit = _hex_to_int(gas_limit_raw, name="gasLimit") if gas_limit_raw is not None else None

        no_tx_pool_raw = raw.get("noTxPool", False)
        if not isinstance(no_tx_pool_raw, bool):
            raise EngineValidationError(ENGINE_INVALID_PARAMS, "noTxPool must be a boolean")

        return cls(
            timestamp=_hex_to_int(raw.get("timestamp"), name="timestamp"),
            prev_randao=_require_hex(raw.get("prevRandao", ZERO_HASH_HEX), name="prevRandao", size=32),
            suggested_fee_recipient=_require_hex(
                raw.get("suggestedFeeRecipient", ZERO_ADDRESS_HEX), name="suggestedFeeRecipient", size=20
            ),
            withdrawals=withdrawals,
            parent_beacon_block_root=_optional_hex(
                raw.get("parentBeaconBlockRoot"), name="parentBeaconBlockRoot", size=32
            ),
            transactions=txs,
            no_tx_pool=no_tx_pool_raw,
            gas_limit=gas_limit,
        )



def _parse_withdrawal(raw: Any, name: str) -> Withdrawal:
    if not isinstance(raw, dict):
        raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} must be an object")
    return Withdrawal(
        index=_hex_to_int(raw.get("index", "0x0"), name=f"{name}.index"),
        validator_index=_hex_to_int(raw.get("validatorIndex", "0x0"), name=f"{name}.validatorIndex"),
        address=_require_hex(raw.get("address", ZERO_ADDRESS_HEX), name=f"{name}.address", size=20),
        amount=_hex_to_int(raw.get("amount", "0x0"), name=f"{name}.amount"),
    )



def payload_id_from_attributes(parent_hash: bytes, attrs: ParsedPayloadAttributes, version: int) -> str:
    """Deterministically compute payload id compatible with geth's build args hash inputs."""
    hasher = hashlib.sha256()
    hasher.update(parent_hash)
    hasher.update(struct.pack(">Q", attrs.timestamp))
    hasher.update(attrs.prev_randao)
    hasher.update(attrs.suggested_fee_recipient)
    hasher.update(
        rlp.encode([
            [w.index, w.validator_index, w.address, w.amount]
            for w in (attrs.withdrawals or [])
        ])
    )

    if attrs.parent_beacon_block_root is not None:
        hasher.update(attrs.parent_beacon_block_root)

    if attrs.no_tx_pool or attrs.transactions:
        hasher.update(b"\x01" if attrs.no_tx_pool else b"\x00")
        hasher.update(struct.pack(">Q", len(attrs.transactions)))
        for tx in attrs.transactions:
            hasher.update(keccak256(tx))

    if attrs.gas_limit is not None:
        hasher.update(struct.pack(">Q", attrs.gas_limit))

    payload_id = bytearray(hasher.digest()[:8])
    payload_id[0] = version & 0xFF
    return _as_hex(bytes(payload_id))



def serialize_withdrawals(withdrawals: Optional[list[Withdrawal]]) -> list[dict[str, str]]:
    if withdrawals is None:
        return []
    out: list[dict[str, str]] = []
    for w in withdrawals:
        out.append(
            {
                "index": _as_quantity(w.index),
                "validatorIndex": _as_quantity(w.validator_index),
                "address": _as_hex(w.address),
                "amount": _as_quantity(w.amount),
            }
        )
    return out



def quantity_hex(value: int) -> str:
    return _as_quantity(value)



def bytes_hex(value: bytes) -> str:
    return _as_hex(value)
