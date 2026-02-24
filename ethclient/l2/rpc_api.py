"""L2 JSON-RPC namespace (l2_*)."""

from __future__ import annotations

from typing import Optional

from ethclient.l2.rollup import Rollup
from ethclient.l2.types import L2Tx, L2TxType
from ethclient.rpc.server import RPCServer, bytes_to_hex, hex_to_bytes


def register_l2_api(rpc: RPCServer, rollup: Rollup) -> None:
    """Register l2_* RPC methods on the server."""

    def l2_sendTransaction(tx_data: dict) -> dict:
        try:
            sender = hex_to_bytes(tx_data.get("sender", "0x" + "00" * 20))
        except (ValueError, AttributeError) as e:
            return {"error": f"invalid sender: {e}"}

        try:
            nonce = int(tx_data.get("nonce", "0x0"), 16) if isinstance(tx_data.get("nonce"), str) else tx_data.get("nonce", 0)
            value = int(tx_data.get("value", "0x0"), 16) if isinstance(tx_data.get("value"), str) else tx_data.get("value", 0)
        except (ValueError, TypeError) as e:
            return {"error": f"invalid numeric field: {e}"}

        data = tx_data.get("data", {})
        if not isinstance(data, dict):
            return {"error": "data must be a dict"}

        try:
            tx_type = L2TxType(tx_data.get("txType", 0))
        except ValueError as e:
            return {"error": f"invalid txType: {e}"}

        tx = L2Tx(
            sender=sender,
            nonce=nonce,
            data=data,
            value=value,
            tx_type=tx_type,
        )
        error = rollup.submit_tx(tx)
        if error:
            return {"error": error}
        return {"txHash": bytes_to_hex(tx.tx_hash())}

    def l2_getState() -> dict:
        return dict(rollup.state)

    def l2_getStateRoot() -> str:
        return bytes_to_hex(rollup.state_root)

    def l2_getBatch(batch_number: int) -> Optional[dict]:
        batch = rollup.get_batch(batch_number)
        if batch is None:
            return None
        return {
            "number": batch.number,
            "txCount": len(batch.transactions),
            "oldStateRoot": bytes_to_hex(batch.old_state_root),
            "newStateRoot": bytes_to_hex(batch.new_state_root),
            "sealed": batch.sealed,
            "proven": batch.proven,
            "submitted": batch.submitted,
            "verified": batch.verified,
        }

    def l2_produceBatch() -> dict:
        try:
            batch = rollup.produce_batch()
        except RuntimeError as e:
            return {"error": str(e)}
        return {
            "number": batch.number,
            "txCount": len(batch.transactions),
            "oldStateRoot": bytes_to_hex(batch.old_state_root),
            "newStateRoot": bytes_to_hex(batch.new_state_root),
        }

    def l2_proveAndSubmit(batch_number: int) -> dict:
        batch = rollup.get_batch(batch_number)
        if batch is None:
            return {"error": f"Batch #{batch_number} not found"}
        try:
            receipt = rollup.prove_and_submit(batch)
        except (RuntimeError, ValueError) as e:
            return {"error": str(e)}
        return {
            "batchNumber": receipt.batch_number,
            "l1TxHash": bytes_to_hex(receipt.l1_tx_hash),
            "verified": receipt.verified,
            "stateRoot": bytes_to_hex(receipt.state_root),
        }

    def l2_chainInfo() -> dict:
        return rollup.chain_info()

    rpc.register("l2_sendTransaction", l2_sendTransaction)
    rpc.register("l2_getState", l2_getState)
    rpc.register("l2_getStateRoot", l2_getStateRoot)
    rpc.register("l2_getBatch", l2_getBatch)
    rpc.register("l2_produceBatch", l2_produceBatch)
    rpc.register("l2_proveAndSubmit", l2_proveAndSubmit)
    rpc.register("l2_chainInfo", l2_chainInfo)
