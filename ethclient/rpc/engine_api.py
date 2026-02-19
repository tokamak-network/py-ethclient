"""Engine API handlers used by op-node / CL-EL communication.

Supports Engine API V1/V2/V3 with OP Stack-specific PayloadAttributes:
- V1: Basic Shanghai support
- V2: L2-specific fields (transactions, noTxPool, gasLimit)
- V3: Prague support (parentBeaconBlockRoot)
"""

from __future__ import annotations

from typing import Optional

from ethclient.rpc.server import RPCError, RPCServer
from ethclient.common.types import BlockHeader, Block, Transaction, ZERO_HASH, EMPTY_TRIE_ROOT

ENGINE_UNKNOWN_PAYLOAD = -38001


def _zero_hash() -> str:
    return "0x" + "00" * 32


def _valid_hash_or_zero(value: Optional[str]) -> str:
    if isinstance(value, str) and value.startswith("0x") and len(value) == 66:
        return value
    return _zero_hash()


def register_engine_api(rpc: RPCServer, store=None, fork_choice=None, chain_config=None) -> None:
    """Register Engine API surface (V1/V2/V3).

    Args:
        rpc: RPCServer to register methods on
        store: Storage backend for state/blocks
        fork_choice: ForkChoice instance for canonical chain management
        chain_config: ChainConfig for validation rules
    """

    pending_payloads: dict[str, dict] = {}

    @rpc.method("engine_exchangeCapabilities")
    def engine_exchange_capabilities(capabilities: list[str]) -> list[str]:
        supported = [
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
        return [cap for cap in capabilities if cap in supported]

    @rpc.method("engine_getClientVersionV1")
    def engine_get_client_version(_client: Optional[str] = None) -> list[dict]:
        return [
            {
                "code": "py-ethclient",
                "name": "py-ethclient",
                "version": "0.1.0",
                "commit": "local",
            }
        ]

    def _handle_forkchoice_update(
        forkchoice_state: dict,
        payload_attributes: Optional[dict],
        version: int,
    ) -> dict:
        """Common forkchoice update logic for V1/V2/V3.

        Args:
            forkchoice_state: {headBlockHash, safeBlockHash, finalizedBlockHash}
            payload_attributes: Optional payload attributes (V2+ supports L2-specific fields)
            version: 1, 2, or 3
        """
        head_hash = _valid_hash_or_zero(forkchoice_state.get("headBlockHash"))
        safe_hash = _valid_hash_or_zero(forkchoice_state.get("safeBlockHash"))
        finalized_hash = _valid_hash_or_zero(forkchoice_state.get("finalizedBlockHash"))
        latest_valid_hash = head_hash
        status = "SYNCING"

        if store is not None and head_hash != _zero_hash():
            try:
                head_bytes = bytes.fromhex(head_hash[2:])
                if store.get_block_header(head_bytes) is not None:
                    status = "VALID"
                    # Update ForkChoice with new head/safe/finalized
                    if fork_choice is not None:
                        fork_choice.set_head(head_bytes)
                        if safe_hash != _zero_hash():
                            fork_choice.set_safe(bytes.fromhex(safe_hash[2:]))
                        if finalized_hash != _zero_hash():
                            fork_choice.set_finalized(bytes.fromhex(finalized_hash[2:]))
            except Exception:
                status = "SYNCING"

        payload_id = None
        if payload_attributes is not None:
            # Generate payload ID from head hash + attributes
            pid = hex(abs(hash((head_hash, str(payload_attributes)))) & ((1 << 64) - 1))
            payload_id = "0x" + pid.removeprefix("0x").zfill(16)
            pending_payloads[payload_id] = {
                "headBlockHash": head_hash,
                "payloadAttributes": payload_attributes,
                "version": version,
            }

        return {
            "payloadStatus": {
                "status": status,
                "latestValidHash": latest_valid_hash,
                "validationError": None,
            },
            "payloadId": payload_id,
        }

    @rpc.method("engine_forkchoiceUpdatedV1")
    def engine_forkchoice_updated_v1(forkchoice_state: dict, payload_attributes: Optional[dict] = None) -> dict:
        return _handle_forkchoice_update(forkchoice_state, payload_attributes, version=1)

    @rpc.method("engine_forkchoiceUpdatedV2")
    def engine_forkchoice_updated_v2(forkchoice_state: dict, payload_attributes: Optional[dict] = None) -> dict:
        # V2: L2-specific payload attributes (transactions, noTxPool, gasLimit)
        return _handle_forkchoice_update(forkchoice_state, payload_attributes, version=2)

    @rpc.method("engine_forkchoiceUpdatedV3")
    def engine_forkchoice_updated_v3(forkchoice_state: dict, payload_attributes: Optional[dict] = None) -> dict:
        # V3: Added parentBeaconBlockRoot
        return _handle_forkchoice_update(forkchoice_state, payload_attributes, version=3)

    def _execute_payload(payload: dict) -> dict:
        """Execute a payload (V1/V2/V3) and return PayloadStatus.

        OP Stack spec: execute transactions in order, return INVALID on error, VALID on success.
        """
        block_hash = _valid_hash_or_zero(payload.get("blockHash"))

        # If store or chain_config not available, fallback to SYNCING (stub mode)
        if store is None or chain_config is None:
            return {
                "status": "SYNCING",
                "latestValidHash": block_hash,
                "validationError": None,
            }

        try:
            # Decode parent header
            parent_hash_str = payload.get("parentHash", "0x" + "00" * 32)
            parent_hash = bytes.fromhex(parent_hash_str[2:])
            parent_header = store.get_block_header(parent_hash)
            if parent_header is None:
                # Parent unknown, still syncing
                return {
                    "status": "SYNCING",
                    "latestValidHash": None,
                    "validationError": None,
                }

            # Build BlockHeader from payload
            # Note: ommers_hash is always ZERO_HASH for post-merge blocks
            header = BlockHeader(
                parent_hash=parent_hash,
                ommers_hash=ZERO_HASH,  # Post-merge (PoS)
                coinbase=bytes.fromhex(payload.get("feeRecipient", "0x" + "00" * 20)[2:]),
                state_root=bytes.fromhex(payload.get("stateRoot", "0x" + "00" * 32)[2:]),
                transactions_root=EMPTY_TRIE_ROOT,  # Will be recalculated in validate_and_execute_block
                receipts_root=bytes.fromhex(payload.get("receiptsRoot", "0x" + "00" * 32)[2:]),
                logs_bloom=bytes.fromhex(payload.get("logsBloom", "0x" + "00" * 256)[2:]),
                difficulty=0,  # Post-merge
                number=int(payload.get("blockNumber", "0x0"), 0),
                gas_limit=int(payload.get("gasLimit", "0x0"), 0),
                gas_used=int(payload.get("gasUsed", "0x0"), 0),
                timestamp=int(payload.get("timestamp", "0x0"), 0),
                extra_data=bytes.fromhex(payload.get("extraData", "0x")[2:]) if payload.get("extraData") else b"",
                mix_hash=bytes.fromhex(payload.get("prevRandao", "0x" + "00" * 32)[2:]),
                nonce=b"\x00" * 8,  # Post-merge (PoS)
                base_fee_per_gas=int(payload.get("baseFeePerGas", "0x0"), 0),
                withdrawals_root=bytes.fromhex(payload.get("withdrawalsRoot", "0x" + "00" * 32)[2:])
                    if "withdrawalsRoot" in payload else None,
                blob_gas_used=int(payload.get("blobGasUsed", "0x0"), 0) if "blobGasUsed" in payload else None,
                excess_blob_gas=int(payload.get("excessBlobGas", "0x0"), 0) if "excessBlobGas" in payload else None,
                parent_beacon_block_root=bytes.fromhex(payload.get("parentBeaconBlockRoot", "0x" + "00" * 32)[2:])
                    if "parentBeaconBlockRoot" in payload else None,
            )

            # Decode transactions from payload
            raw_txs = payload.get("transactions", [])
            transactions = []
            for raw_tx in raw_txs:
                try:
                    tx_bytes = bytes.fromhex(raw_tx[2:]) if isinstance(raw_tx, str) else raw_tx
                    tx = Transaction.decode(tx_bytes)
                    transactions.append(tx)
                except Exception as e:
                    return {
                        "status": "INVALID",
                        "latestValidHash": None,
                        "validationError": f"Failed to decode transaction: {e}",
                    }

            # Decode withdrawals from payload
            withdrawals = []
            # TODO: implement withdrawals parsing if payload includes them

            # Create Block object
            block = Block(
                header=header,
                transactions=transactions,
                withdrawals=withdrawals or None,
            )

            # Execute block using chain's validate_and_execute_block
            from ethclient.blockchain.chain import (
                validate_and_execute_block,
                BlockValidationError,
            )

            try:
                validate_and_execute_block(block, parent_header, store, chain_config)
                # Success
                return {
                    "status": "VALID",
                    "latestValidHash": block_hash,
                    "validationError": None,
                }
            except BlockValidationError as e:
                return {
                    "status": "INVALID",
                    "latestValidHash": None,
                    "validationError": str(e),
                }

        except Exception as e:
            return {
                "status": "INVALID",
                "latestValidHash": None,
                "validationError": f"Execution error: {e}",
            }

    @rpc.method("engine_newPayloadV1")
    def engine_new_payload_v1(payload: dict) -> dict:
        return _execute_payload(payload)

    @rpc.method("engine_newPayloadV2")
    def engine_new_payload_v2(payload: dict) -> dict:
        return _execute_payload(payload)

    @rpc.method("engine_newPayloadV3")
    def engine_new_payload_v3(
        payload: dict,
        expected_blob_versioned_hashes: Optional[list] = None,
        parent_beacon_block_root: Optional[str] = None,
    ) -> dict:
        # L2 disables blob transactions - reject if expected_blob_versioned_hashes is non-empty
        if expected_blob_versioned_hashes and len(expected_blob_versioned_hashes) > 0:
            raise RPCError(-32602, "Blob transactions are not supported on L2")
        return _execute_payload(payload)

    def _build_base_payload(pending: dict) -> dict:
        """Build base ExecutionPayload from pending payload info."""
        head_hash = pending.get("headBlockHash", _zero_hash())
        attrs = pending.get("payloadAttributes", {})
        return {
            "parentHash": head_hash,
            "feeRecipient": attrs.get("suggestedFeeRecipient", "0x" + "00" * 20),
            "stateRoot": _zero_hash(),
            "receiptsRoot": _zero_hash(),
            "logsBloom": "0x" + "00" * 256,
            "prevRandao": attrs.get("prevRandao", _zero_hash()),
            "blockNumber": "0x0",
            "gasLimit": attrs.get("gasLimit", "0x0"),
            "gasUsed": "0x0",
            "timestamp": attrs.get("timestamp", "0x0"),
            "extraData": "0x",
            "baseFeePerGas": "0x0",
            "blockHash": _zero_hash(),
            "transactions": attrs.get("transactions", []),
        }

    @rpc.method("engine_getPayloadV1")
    def engine_get_payload_v1(payload_id: str) -> dict:
        payload = pending_payloads.get(payload_id)
        if payload is None:
            raise RPCError(ENGINE_UNKNOWN_PAYLOAD, "Unknown payload")
        return _build_base_payload(payload)

    @rpc.method("engine_getPayloadV2")
    def engine_get_payload_v2(payload_id: str) -> dict:
        payload = pending_payloads.get(payload_id)
        if payload is None:
            raise RPCError(ENGINE_UNKNOWN_PAYLOAD, "Unknown payload")
        base = _build_base_payload(payload)
        return {
            "executionPayload": {
                **base,
                "withdrawals": [],  # V2+ includes withdrawals
            },
            "blockValue": "0x0",
        }

    @rpc.method("engine_getPayloadV3")
    def engine_get_payload_v3(payload_id: str) -> dict:
        payload = pending_payloads.get(payload_id)
        if payload is None:
            raise RPCError(ENGINE_UNKNOWN_PAYLOAD, "Unknown payload")
        base = _build_base_payload(payload)
        return {
            "executionPayload": {
                **base,
                "withdrawals": [],
            },
            "blockValue": "0x0",
            "blobsBundle": {  # V3 includes blobsBundle (empty on L2 due to blob disabling)
                "commitments": [],
                "proofs": [],
                "blobs": [],
            },
            "shouldOverrideBuilder": False,
        }
