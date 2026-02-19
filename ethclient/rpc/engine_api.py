"""Engine API handlers for CL-EL communication (V1/V2/V3)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Any

logger = logging.getLogger(__name__)

from ethclient.blockchain.chain import (
    BlockValidationError,
    calc_base_fee,
    execute_block,
    validate_and_execute_block,
    validate_header,
)
from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.common.trie import ordered_trie_root
from ethclient.common.types import (
    Block,
    BlockHeader,
    Transaction,
    Withdrawal,
    EMPTY_TRIE_ROOT,
    ZERO_HASH,
)
from ethclient.rpc.engine_types import (
    ENGINE_INVALID_FORKCHOICE_STATE,
    ENGINE_INVALID_PARAMS,
    ENGINE_INVALID_PAYLOAD_ATTRIBUTES,
    ENGINE_UNSUPPORTED_FORK,
    ENGINE_UNKNOWN_PAYLOAD,
    EngineValidationError,
    ForkchoiceState,
    ParsedPayloadAttributes,
    bytes_hex,
    payload_id_from_attributes,
    quantity_hex,
    serialize_withdrawals,
)
from ethclient.rpc.server import RPCError, RPCServer

_MAX_TRACKED_PAYLOADS = 10
_MAX_TRACKED_HEADERS = 96
_EMPTY_OMMERS_HASH = keccak256(rlp.encode([]))


@dataclass
class BuiltPayload:
    payload_id: str
    version: int
    execution_payload: dict[str, Any]
    block_hash: bytes


class PayloadQueue:
    """Bounded in-memory payload cache with LRU-style eviction."""

    def __init__(self, max_items: int) -> None:
        self._max_items = max_items
        self._order: list[str] = []
        self._items: dict[str, BuiltPayload] = {}

    def put(self, payload: BuiltPayload) -> None:
        pid = payload.payload_id
        if pid in self._items:
            self._order = [x for x in self._order if x != pid]
        self._order.insert(0, pid)
        self._items[pid] = payload

        while len(self._order) > self._max_items:
            evicted = self._order.pop()
            self._items.pop(evicted, None)

    def get(self, payload_id: str) -> Optional[BuiltPayload]:
        payload = self._items.get(payload_id)
        if payload is None:
            return None
        self._order = [x for x in self._order if x != payload_id]
        self._order.insert(0, payload_id)
        return payload

    def has(self, payload_id: str) -> bool:
        return payload_id in self._items


class HeaderQueue:
    """Bounded in-memory remote header cache."""

    def __init__(self, max_items: int) -> None:
        self._max_items = max_items
        self._order: list[bytes] = []
        self._items: dict[bytes, BlockHeader] = {}

    def put(self, block_hash: bytes, header: BlockHeader) -> None:
        if block_hash in self._items:
            self._order = [x for x in self._order if x != block_hash]
        self._order.insert(0, block_hash)
        self._items[block_hash] = header

        while len(self._order) > self._max_items:
            evicted = self._order.pop()
            self._items.pop(evicted, None)

    def get(self, block_hash: bytes) -> Optional[BlockHeader]:
        return self._items.get(block_hash)



def register_engine_api(rpc: RPCServer, store=None, fork_choice=None, chain_config=None) -> None:
    """Register Engine API surface (V1/V2/V3)."""

    payloads = PayloadQueue(_MAX_TRACKED_PAYLOADS)
    remote_headers = HeaderQueue(_MAX_TRACKED_HEADERS)

    @rpc.method("engine_exchangeCapabilities")
    def engine_exchange_capabilities(_capabilities: Optional[list[str]] = None) -> list[str]:
        return [
            "engine_exchangeCapabilities",
            "engine_forkchoiceUpdatedV1",
            "engine_forkchoiceUpdatedV2",
            "engine_forkchoiceUpdatedV3",
            "engine_newPayloadV1",
            "engine_newPayloadV2",
            "engine_newPayloadV3",
            "engine_getPayloadV1",
            "engine_getPayloadV2",
            "engine_getPayloadV3",
            "engine_getClientVersionV1",
        ]

    @rpc.method("engine_getClientVersionV1")
    def engine_get_client_version(_client: Optional[dict] = None) -> list[dict]:
        return [{"code": "py-ethclient", "name": "py-ethclient", "version": "0.1.0", "commit": "local"}]

    def _payload_status(status: str, latest_valid_hash: Optional[bytes], validation_error: Optional[str]) -> dict:
        return {
            "status": status,
            "latestValidHash": None if latest_valid_hash is None else bytes_hex(latest_valid_hash),
            "validationError": validation_error,
        }

    def _is_zero_hash(value: bytes) -> bool:
        return value == ZERO_HASH

    def _canonical_contains(block_hash: bytes) -> bool:
        if store is None:
            return False
        header = store.get_block_header(block_hash)
        if header is None:
            return False
        return store.get_canonical_hash(header.number) == block_hash

    def _build_execution_payload(parent_hash: bytes, attrs: ParsedPayloadAttributes, version: int, payload_id: str) -> BuiltPayload:
        if store is None or chain_config is None:
            raise EngineValidationError(ENGINE_INVALID_PAYLOAD_ATTRIBUTES, "engine backend is not initialized")

        parent = store.get_block_header(parent_hash)
        if parent is None:
            raise EngineValidationError(ENGINE_INVALID_PAYLOAD_ATTRIBUTES, "unknown parent for payload build")

        txs: list[Transaction] = []
        for i, raw_tx in enumerate(attrs.transactions):
            try:
                txs.append(Transaction.decode_rlp(raw_tx))
            except Exception as exc:
                raise EngineValidationError(
                    ENGINE_INVALID_PAYLOAD_ATTRIBUTES,
                    f"transaction {i} is not valid: {exc}",
                ) from exc

        header = BlockHeader(
            parent_hash=parent_hash,
            ommers_hash=_EMPTY_OMMERS_HASH,
            coinbase=attrs.suggested_fee_recipient,
            number=parent.number + 1,
            gas_limit=attrs.gas_limit if attrs.gas_limit is not None else parent.gas_limit,
            gas_used=0,
            timestamp=attrs.timestamp,
            extra_data=b"",
            mix_hash=attrs.prev_randao,
            nonce=b"\x00" * 8,
            difficulty=0,
            base_fee_per_gas=calc_base_fee(parent, chain_config),
            transactions_root=ordered_trie_root([tx.encode_rlp() for tx in txs]),
            receipts_root=EMPTY_TRIE_ROOT,
            state_root=ZERO_HASH,
            logs_bloom=b"\x00" * 256,
        )

        if attrs.withdrawals is not None:
            withdrawal_rlps = [rlp.encode(w.to_rlp_list()) for w in attrs.withdrawals]
            header.withdrawals_root = ordered_trie_root(withdrawal_rlps)

        if chain_config.is_cancun(attrs.timestamp):
            header.blob_gas_used = 0
            header.excess_blob_gas = 0
            header.parent_beacon_block_root = attrs.parent_beacon_block_root or ZERO_HASH

        try:
            validate_header(header, parent, chain_config)
        except BlockValidationError as exc:
            raise EngineValidationError(ENGINE_INVALID_PAYLOAD_ATTRIBUTES, str(exc)) from exc

        block = Block(header=header, transactions=txs, withdrawals=attrs.withdrawals)

        snap = store.snapshot()
        try:
            result = execute_block(block, store, chain_config)
        except Exception as exc:
            store.rollback(snap)
            raise EngineValidationError(ENGINE_INVALID_PAYLOAD_ATTRIBUTES, f"payload build failed: {exc}") from exc

        header.gas_used = result.total_gas_used
        header.state_root = result.state_root
        header.receipts_root = result.receipts_root
        header.logs_bloom = result.logs_bloom
        block_hash = header.block_hash()

        # Debug: dump build-time header fields
        build_items = header.to_rlp_list()
        logger.info("buildPayload blockHash=%s number=%d rlp_fields=%d",
                     bytes_hex(block_hash), header.number, len(build_items))
        field_names = [
            "parentHash", "ommersHash", "coinbase", "stateRoot",
            "txRoot", "receiptsRoot", "logsBloom", "difficulty",
            "number", "gasLimit", "gasUsed", "timestamp",
            "extraData", "mixHash", "nonce", "baseFeePerGas",
            "withdrawalsRoot", "blobGasUsed", "excessBlobGas",
            "parentBeaconBlockRoot", "requestsHash",
        ]
        for i, item in enumerate(build_items):
            name = field_names[i] if i < len(field_names) else f"field{i}"
            if isinstance(item, bytes):
                logger.info("  BUILD [%d] %s = 0x%s", i, name, item.hex()[:64])
            else:
                logger.info("  BUILD [%d] %s = %s", i, name, item)

        store.rollback(snap)

        execution_payload = {
            "parentHash": bytes_hex(header.parent_hash),
            "feeRecipient": bytes_hex(header.coinbase),
            "stateRoot": bytes_hex(header.state_root),
            "receiptsRoot": bytes_hex(header.receipts_root),
            "logsBloom": bytes_hex(header.logs_bloom),
            "prevRandao": bytes_hex(header.mix_hash),
            "blockNumber": quantity_hex(header.number),
            "gasLimit": quantity_hex(header.gas_limit),
            "gasUsed": quantity_hex(header.gas_used),
            "timestamp": quantity_hex(header.timestamp),
            "extraData": bytes_hex(header.extra_data),
            "baseFeePerGas": quantity_hex(header.base_fee_per_gas or 0),
            "blockHash": bytes_hex(block_hash),
            "transactions": [bytes_hex(tx.encode_rlp()) for tx in txs],
        }

        if version >= 2:
            execution_payload["withdrawals"] = serialize_withdrawals(attrs.withdrawals)

        if version >= 3:
            execution_payload["blobGasUsed"] = quantity_hex(header.blob_gas_used or 0)
            execution_payload["excessBlobGas"] = quantity_hex(header.excess_blob_gas or 0)
            if header.parent_beacon_block_root is not None:
                execution_payload["parentBeaconBlockRoot"] = bytes_hex(header.parent_beacon_block_root)

        return BuiltPayload(payload_id=payload_id, version=version, execution_payload=execution_payload, block_hash=block_hash)

    def _normalize_v3_payload_attributes(attrs: ParsedPayloadAttributes) -> None:
        if attrs.withdrawals is None:
            raise EngineValidationError(ENGINE_INVALID_PARAMS, "missing withdrawals")
        if attrs.parent_beacon_block_root is None:
            raise EngineValidationError(ENGINE_INVALID_PARAMS, "missing parentBeaconBlockRoot")
        if chain_config is not None and not chain_config.is_cancun(attrs.timestamp):
            raise EngineValidationError(
                ENGINE_UNSUPPORTED_FORK,
                "forkchoiceUpdatedV3 must only be called for cancun payloads",
            )

    def _handle_forkchoice_update(forkchoice_state: dict, payload_attributes: Optional[dict], version: int) -> dict:
        state = ForkchoiceState.from_rpc(forkchoice_state)
        logger.info("forkchoiceUpdated V%d head=%s", version, bytes_hex(state.head_block_hash))

        if _is_zero_hash(state.head_block_hash):
            return {"payloadStatus": _payload_status("INVALID", None, None), "payloadId": None}

        status = "SYNCING"
        latest_valid_hash: Optional[bytes] = state.head_block_hash

        head_known = store is not None and store.get_block_header(state.head_block_hash) is not None
        if head_known:
            status = "VALID"
            if fork_choice is not None:
                fork_choice.set_head(state.head_block_hash)

                if not _is_zero_hash(state.safe_block_hash):
                    if not _canonical_contains(state.safe_block_hash):
                        raise RPCError(ENGINE_INVALID_FORKCHOICE_STATE, "safe block not in canonical chain")
                    fork_choice.set_safe(state.safe_block_hash)

                if not _is_zero_hash(state.finalized_block_hash):
                    if not _canonical_contains(state.finalized_block_hash):
                        raise RPCError(ENGINE_INVALID_FORKCHOICE_STATE, "finalized block not in canonical chain")
                    fork_choice.set_finalized(state.finalized_block_hash)
        else:
            if remote_headers.get(state.head_block_hash) is not None:
                status = "SYNCING"

        payload_id: Optional[str] = None
        if payload_attributes is not None and head_known:
            attrs = ParsedPayloadAttributes.from_rpc(payload_attributes)

            if version == 3:
                _normalize_v3_payload_attributes(attrs)
            elif version == 2 and attrs.parent_beacon_block_root is not None:
                raise EngineValidationError(ENGINE_INVALID_PARAMS, "unexpected parentBeaconBlockRoot for V2")
            elif version == 1:
                if attrs.withdrawals is not None:
                    raise EngineValidationError(ENGINE_INVALID_PARAMS, "withdrawals not supported in V1")
                if attrs.parent_beacon_block_root is not None:
                    raise EngineValidationError(ENGINE_INVALID_PARAMS, "parentBeaconBlockRoot not supported in V1")

            payload_id = payload_id_from_attributes(state.head_block_hash, attrs, version)
            if not payloads.has(payload_id):
                payloads.put(_build_execution_payload(state.head_block_hash, attrs, version, payload_id))

        return {
            "payloadStatus": _payload_status(status, latest_valid_hash, None),
            "payloadId": payload_id,
        }

    @rpc.method("engine_forkchoiceUpdatedV1")
    def engine_forkchoice_updated_v1(forkchoice_state: dict, payload_attributes: Optional[dict] = None) -> dict:
        return _handle_forkchoice_update(forkchoice_state, payload_attributes, version=1)

    @rpc.method("engine_forkchoiceUpdatedV2")
    def engine_forkchoice_updated_v2(forkchoice_state: dict, payload_attributes: Optional[dict] = None) -> dict:
        return _handle_forkchoice_update(forkchoice_state, payload_attributes, version=2)

    @rpc.method("engine_forkchoiceUpdatedV3")
    def engine_forkchoice_updated_v3(forkchoice_state: dict, payload_attributes: Optional[dict] = None) -> dict:
        return _handle_forkchoice_update(forkchoice_state, payload_attributes, version=3)

    def _get_payload(payload_id: str) -> BuiltPayload:
        payload = payloads.get(payload_id)
        if payload is None:
            raise RPCError(ENGINE_UNKNOWN_PAYLOAD, "Unknown payload")
        return payload

    @rpc.method("engine_getPayloadV1")
    def engine_get_payload_v1(payload_id: str) -> dict:
        payload = _get_payload(payload_id)
        return payload.execution_payload

    @rpc.method("engine_getPayloadV2")
    def engine_get_payload_v2(payload_id: str) -> dict:
        payload = _get_payload(payload_id)
        return {
            "executionPayload": payload.execution_payload,
            "blockValue": "0x0",
        }

    @rpc.method("engine_getPayloadV3")
    def engine_get_payload_v3(payload_id: str) -> dict:
        payload = _get_payload(payload_id)
        ep = payload.execution_payload
        # Per Engine API spec, parentBeaconBlockRoot is an envelope-level field,
        # NOT inside executionPayload. op-node reads it from envelope and passes
        # it as the 3rd param to newPayloadV3.
        parent_beacon = ep.get("parentBeaconBlockRoot", "0x" + "00" * 32)
        logger.info("getPayloadV3 id=%s blockHash=%s number=%s parentBeacon=%s",
                     payload_id, ep.get("blockHash", "?"),
                     ep.get("blockNumber", "?"), parent_beacon)
        return {
            "executionPayload": ep,
            "blockValue": "0x0",
            "blobsBundle": {"commitments": [], "proofs": [], "blobs": []},
            "shouldOverrideBuilder": False,
            "parentBeaconBlockRoot": parent_beacon,
        }

    def _parse_quantity(value: Any, name: str) -> int:
        if isinstance(value, int):
            return value
        if not isinstance(value, str) or not value.startswith("0x"):
            raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} must be hex quantity")
        try:
            return int(value, 16)
        except ValueError as exc:
            raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} is invalid hex quantity") from exc

    def _parse_bytes(value: Any, name: str, size: int) -> bytes:
        if not isinstance(value, str) or not value.startswith("0x"):
            raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} must be hex")
        raw = value[2:]
        if len(raw) != size * 2:
            raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} must be {size} bytes")
        try:
            return bytes.fromhex(raw)
        except ValueError as exc:
            raise EngineValidationError(ENGINE_INVALID_PARAMS, f"{name} invalid hex") from exc

    def _parse_withdrawals(raw: Any) -> Optional[list[Withdrawal]]:
        if raw is None:
            return None
        if not isinstance(raw, list):
            raise EngineValidationError(ENGINE_INVALID_PARAMS, "withdrawals must be a list")
        out: list[Withdrawal] = []
        for i, w in enumerate(raw):
            if not isinstance(w, dict):
                raise EngineValidationError(ENGINE_INVALID_PARAMS, f"withdrawals[{i}] must be object")
            out.append(
                Withdrawal(
                    index=_parse_quantity(w.get("index", "0x0"), f"withdrawals[{i}].index"),
                    validator_index=_parse_quantity(
                        w.get("validatorIndex", "0x0"), f"withdrawals[{i}].validatorIndex"
                    ),
                    address=_parse_bytes(w.get("address", "0x" + "00" * 20), f"withdrawals[{i}].address", 20),
                    amount=_parse_quantity(w.get("amount", "0x0"), f"withdrawals[{i}].amount"),
                )
            )
        return out

    def _collect_blob_hashes(transactions: list[Transaction]) -> list[bytes]:
        out: list[bytes] = []
        for tx in transactions:
            if tx.tx_type.value == 3:
                out.extend(tx.blob_versioned_hashes)
        return out

    def _execute_payload(
        payload: dict,
        *,
        version: int,
        expected_blob_versioned_hashes: Optional[list] = None,
        parent_beacon_block_root: Optional[str] = None,
    ) -> dict:
        logger.info("_execute_payload called V%d blockHash=%s blockNumber=%s",
                     version, payload.get("blockHash", "?"), payload.get("blockNumber", "?"))

        if store is None or chain_config is None:
            return _payload_status("SYNCING", None, None)

        block_hash = _parse_bytes(payload.get("blockHash", "0x" + "00" * 32), "blockHash", 32)

        # Fast-path: already imported block
        if store.get_block_header(block_hash) is not None:
            return _payload_status("VALID", block_hash, None)

        parent_hash = _parse_bytes(payload.get("parentHash", "0x" + "00" * 32), "parentHash", 32)
        parent = store.get_block_header(parent_hash)
        if parent is None:
            header = BlockHeader(parent_hash=parent_hash, number=_parse_quantity(payload.get("blockNumber", "0x0"), "blockNumber"))
            remote_headers.put(block_hash, header)
            return _payload_status("SYNCING", None, None)

        withdrawals = _parse_withdrawals(payload.get("withdrawals"))
        blob_gas_used_raw = payload.get("blobGasUsed")
        excess_blob_gas_raw = payload.get("excessBlobGas")
        parsed_parent_beacon = payload.get("parentBeaconBlockRoot")

        if version == 1 and withdrawals is not None:
            raise EngineValidationError(ENGINE_INVALID_PARAMS, "withdrawals not supported in V1")

        if version == 2:
            if chain_config.is_cancun(_parse_quantity(payload.get("timestamp", "0x0"), "timestamp")):
                raise EngineValidationError(ENGINE_INVALID_PARAMS, "can't use newPayloadV2 post-cancun")

        if version == 3:
            timestamp = _parse_quantity(payload.get("timestamp", "0x0"), "timestamp")
            if withdrawals is None:
                withdrawals = []  # OP Stack: default to empty withdrawals
            if blob_gas_used_raw is None:
                blob_gas_used_raw = "0x0"  # OP Stack L2: no blobs
            if excess_blob_gas_raw is None:
                excess_blob_gas_raw = "0x0"  # OP Stack L2: no blobs
            if expected_blob_versioned_hashes is None:
                expected_blob_versioned_hashes = []  # OP Stack L2: blobs disabled
            # Resolve parentBeaconBlockRoot: RPC param > payload body > ZERO_HASH
            if parent_beacon_block_root is not None:
                parsed_parent_beacon = parent_beacon_block_root
            if parsed_parent_beacon is None:
                parsed_parent_beacon = "0x" + "00" * 32  # Default to ZERO_HASH

        txs_raw = payload.get("transactions", [])
        if not isinstance(txs_raw, list):
            raise EngineValidationError(ENGINE_INVALID_PARAMS, "transactions must be a list")

        txs: list[Transaction] = []
        for i, raw in enumerate(txs_raw):
            if not isinstance(raw, str) or not raw.startswith("0x"):
                raise EngineValidationError(ENGINE_INVALID_PARAMS, f"transactions[{i}] must be hex")
            try:
                txs.append(Transaction.decode_rlp(bytes.fromhex(raw[2:])))
            except Exception as exc:
                return _payload_status("INVALID", None, f"Failed to decode transaction {i}: {exc}")

        if version == 3:
            expected_hashes: list[bytes] = []
            for i, h in enumerate(expected_blob_versioned_hashes or []):
                expected_hashes.append(_parse_bytes(h, f"expectedBlobVersionedHashes[{i}]", 32))
            if _collect_blob_hashes(txs) != expected_hashes:
                return _payload_status("INVALID", parent_hash, "blob versioned hashes mismatch")

        header = BlockHeader(
            parent_hash=parent_hash,
            ommers_hash=_EMPTY_OMMERS_HASH,
            coinbase=_parse_bytes(payload.get("feeRecipient", "0x" + "00" * 20), "feeRecipient", 20),
            state_root=_parse_bytes(payload.get("stateRoot", "0x" + "00" * 32), "stateRoot", 32),
            transactions_root=ordered_trie_root([tx.encode_rlp() for tx in txs]),
            receipts_root=_parse_bytes(payload.get("receiptsRoot", "0x" + "00" * 32), "receiptsRoot", 32),
            logs_bloom=_parse_bytes(payload.get("logsBloom", "0x" + "00" * 256), "logsBloom", 256),
            difficulty=0,
            number=_parse_quantity(payload.get("blockNumber", "0x0"), "blockNumber"),
            gas_limit=_parse_quantity(payload.get("gasLimit", "0x0"), "gasLimit"),
            gas_used=_parse_quantity(payload.get("gasUsed", "0x0"), "gasUsed"),
            timestamp=_parse_quantity(payload.get("timestamp", "0x0"), "timestamp"),
            extra_data=(
                bytes.fromhex(payload["extraData"][2:])
                if isinstance(payload.get("extraData"), str) and payload["extraData"].startswith("0x")
                else b""
            ),
            mix_hash=_parse_bytes(payload.get("prevRandao", "0x" + "00" * 32), "prevRandao", 32),
            nonce=b"\x00" * 8,
            base_fee_per_gas=_parse_quantity(payload.get("baseFeePerGas", "0x0"), "baseFeePerGas"),
        )

        if withdrawals is not None:
            withdrawal_rlps = [rlp.encode(w.to_rlp_list()) for w in withdrawals]
            header.withdrawals_root = ordered_trie_root(withdrawal_rlps)

        if blob_gas_used_raw is not None:
            header.blob_gas_used = _parse_quantity(blob_gas_used_raw, "blobGasUsed")
        if excess_blob_gas_raw is not None:
            header.excess_blob_gas = _parse_quantity(excess_blob_gas_raw, "excessBlobGas")
        if parsed_parent_beacon is not None:
            header.parent_beacon_block_root = _parse_bytes(parsed_parent_beacon, "parentBeaconBlockRoot", 32)

        computed_hash = header.block_hash()
        if block_hash != computed_hash:
            logger.error("block hash mismatch: expected=%s computed=%s number=%d",
                         bytes_hex(block_hash), bytes_hex(computed_hash), header.number)
            # Dump all header RLP fields for debugging
            rlp_items = header.to_rlp_list()
            field_names = [
                "parentHash", "ommersHash", "coinbase", "stateRoot",
                "txRoot", "receiptsRoot", "logsBloom", "difficulty",
                "number", "gasLimit", "gasUsed", "timestamp",
                "extraData", "mixHash", "nonce", "baseFeePerGas",
                "withdrawalsRoot", "blobGasUsed", "excessBlobGas",
                "parentBeaconBlockRoot", "requestsHash",
            ]
            for i, item in enumerate(rlp_items):
                name = field_names[i] if i < len(field_names) else f"field{i}"
                if isinstance(item, bytes):
                    logger.error("  [%d] %s = 0x%s", i, name, item.hex()[:64])
                else:
                    logger.error("  [%d] %s = %s", i, name, item)
            return _payload_status("INVALID", parent_hash, "block hash mismatch")

        block = Block(header=header, transactions=txs, withdrawals=withdrawals)

        logger.info("newPayload V%d block=%s number=%d txs=%d", version, bytes_hex(block_hash), header.number, len(txs))

        snap = store.snapshot()
        try:
            result = validate_and_execute_block(block, parent, store, chain_config)
            store.put_block(block)
            store.put_receipts(block_hash, result.receipts)
            store.commit(snap)
            logger.info("newPayload VALID block=%s", bytes_hex(block_hash))
            return _payload_status("VALID", block_hash, None)
        except BlockValidationError as exc:
            store.rollback(snap)
            logger.error("newPayload INVALID block=%s error=%s", bytes_hex(block_hash), exc)
            return _payload_status("INVALID", parent_hash, str(exc))
        except Exception as exc:
            store.rollback(snap)
            logger.error("newPayload ERROR block=%s error=%s", bytes_hex(block_hash), exc, exc_info=True)
            return _payload_status("INVALID", parent_hash, f"Execution error: {exc}")

    @rpc.method("engine_newPayloadV1")
    def engine_new_payload_v1(payload: dict) -> dict:
        return _execute_payload(payload, version=1)

    @rpc.method("engine_newPayloadV2")
    def engine_new_payload_v2(payload: dict) -> dict:
        return _execute_payload(payload, version=2)

    @rpc.method("engine_newPayloadV3")
    def engine_new_payload_v3(
        payload: dict,
        expected_blob_versioned_hashes: Optional[list] = None,
        parent_beacon_block_root: Optional[str] = None,
    ) -> dict:
        return _execute_payload(
            payload,
            version=3,
            expected_blob_versioned_hashes=expected_blob_versioned_hashes,
            parent_beacon_block_root=parent_beacon_block_root,
        )
