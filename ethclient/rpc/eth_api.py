"""
eth_ namespace JSON-RPC API handlers.

Implements the standard Ethereum JSON-RPC eth_ methods.
"""

from __future__ import annotations

import logging
from typing import Optional

from ethclient.common.types import Transaction, BlockHeader
from ethclient.common.config import ChainConfig
from ethclient.rpc.server import (
    RPCServer,
    RPCError,
    INVALID_PARAMS,
    hex_to_int,
    int_to_hex,
    bytes_to_hex,
    hex_to_bytes,
    parse_block_param,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _format_block_header(header: BlockHeader, full_txs: bool = False) -> dict:
    """Format a block header for JSON-RPC response."""
    result = {
        "number": int_to_hex(header.number),
        "hash": bytes_to_hex(header.block_hash()),
        "parentHash": bytes_to_hex(header.parent_hash),
        "nonce": bytes_to_hex(header.nonce),
        "sha3Uncles": bytes_to_hex(header.ommers_hash),
        "logsBloom": bytes_to_hex(header.logs_bloom),
        "transactionsRoot": bytes_to_hex(header.transactions_root),
        "stateRoot": bytes_to_hex(header.state_root),
        "receiptsRoot": bytes_to_hex(header.receipts_root),
        "miner": bytes_to_hex(header.coinbase),
        "difficulty": int_to_hex(header.difficulty),
        "extraData": bytes_to_hex(header.extra_data),
        "gasLimit": int_to_hex(header.gas_limit),
        "gasUsed": int_to_hex(header.gas_used),
        "timestamp": int_to_hex(header.timestamp),
        "mixHash": bytes_to_hex(header.mix_hash),
    }
    if header.base_fee_per_gas is not None:
        result["baseFeePerGas"] = int_to_hex(header.base_fee_per_gas)
    if header.withdrawals_root is not None:
        result["withdrawalsRoot"] = bytes_to_hex(header.withdrawals_root)
    if header.blob_gas_used is not None:
        result["blobGasUsed"] = int_to_hex(header.blob_gas_used)
    if header.excess_blob_gas is not None:
        result["excessBlobGas"] = int_to_hex(header.excess_blob_gas)
    return result


def _format_transaction(tx: Transaction, block_hash: bytes = b"",
                         block_number: int = 0, tx_index: int = 0) -> dict:
    """Format a transaction for JSON-RPC response."""
    result = {
        "hash": bytes_to_hex(tx.tx_hash()),
        "nonce": int_to_hex(tx.nonce),
        "blockHash": bytes_to_hex(block_hash) if block_hash else None,
        "blockNumber": int_to_hex(block_number) if block_hash else None,
        "transactionIndex": int_to_hex(tx_index),
        "from": bytes_to_hex(tx.sender()) if tx.v is not None else None,
        "to": bytes_to_hex(tx.to) if tx.to else None,
        "value": int_to_hex(tx.value),
        "gas": int_to_hex(tx.gas_limit),
        "input": bytes_to_hex(tx.data),
    }
    if tx.tx_type == 0:
        result["gasPrice"] = int_to_hex(tx.gas_price)
    else:
        result["maxFeePerGas"] = int_to_hex(tx.max_fee_per_gas)
        result["maxPriorityFeePerGas"] = int_to_hex(tx.max_priority_fee_per_gas)
    result["type"] = int_to_hex(tx.tx_type)
    return result


def _format_receipt(receipt, tx_hash: bytes, block_hash: bytes,
                    block_number: int, tx_index: int, gas_used: int = 0) -> dict:
    """Format a transaction receipt for JSON-RPC response."""
    logs = []
    for i, log in enumerate(receipt.logs):
        logs.append({
            "address": bytes_to_hex(log.address),
            "topics": [bytes_to_hex(t) for t in log.topics],
            "data": bytes_to_hex(log.data),
            "blockNumber": int_to_hex(block_number),
            "blockHash": bytes_to_hex(block_hash),
            "transactionHash": bytes_to_hex(tx_hash),
            "transactionIndex": int_to_hex(tx_index),
            "logIndex": int_to_hex(i),
            "removed": False,
        })

    return {
        "transactionHash": bytes_to_hex(tx_hash),
        "transactionIndex": int_to_hex(tx_index),
        "blockHash": bytes_to_hex(block_hash),
        "blockNumber": int_to_hex(block_number),
        "cumulativeGasUsed": int_to_hex(receipt.cumulative_gas_used),
        "gasUsed": int_to_hex(gas_used),
        "contractAddress": None,  # TODO: derive from CREATE
        "logs": logs,
        "logsBloom": bytes_to_hex(receipt.logs_bloom),
        "status": int_to_hex(1 if receipt.succeeded else 0),
        "type": int_to_hex(receipt.tx_type),
    }


def _format_log(log, block_hash: bytes, block_number: int,
                tx_hash: bytes, tx_index: int, log_index: int) -> dict:
    return {
        "address": bytes_to_hex(log.address),
        "topics": [bytes_to_hex(t) for t in log.topics],
        "data": bytes_to_hex(log.data),
        "blockNumber": int_to_hex(block_number),
        "blockHash": bytes_to_hex(block_hash),
        "transactionHash": bytes_to_hex(tx_hash),
        "transactionIndex": int_to_hex(tx_index),
        "logIndex": int_to_hex(log_index),
        "removed": False,
    }


# ---------------------------------------------------------------------------
# Register eth_ methods
# ---------------------------------------------------------------------------

def _parse_call_params(tx_obj: dict) -> tuple[bytes, Optional[bytes], bytes, int, int]:
    """Parse JSON-RPC transaction object into call parameters."""
    sender = hex_to_bytes(tx_obj["from"]) if tx_obj.get("from") else b"\x00" * 20
    to = hex_to_bytes(tx_obj["to"]) if tx_obj.get("to") else None
    data = hex_to_bytes(tx_obj.get("data") or tx_obj.get("input") or "0x")
    value = hex_to_int(tx_obj["value"]) if tx_obj.get("value") else 0
    gas_limit = hex_to_int(tx_obj["gas"]) if tx_obj.get("gas") else 30_000_000
    return sender, to, data, value, gas_limit


def register_eth_api(rpc: RPCServer, store=None, chain=None, mempool=None,
                     network_chain_id: int = 1, config: Optional[ChainConfig] = None) -> None:
    """Register all eth_ namespace methods on the RPC server."""

    def _resolve_block_number(block_param: str) -> Optional[int]:
        """Resolve a block parameter to a block number."""
        val = parse_block_param(block_param)
        if isinstance(val, int):
            return val
        if store is None:
            return 0
        latest = store.get_latest_block_number()
        if latest is None:
            return 0
        if val in ("latest", "safe", "finalized", "pending"):
            return latest
        if val == "earliest":
            return 0
        return latest

    # -- Account methods --

    @rpc.method("eth_getBalance")
    def get_balance(address: str, block: str = "latest") -> str:
        if store is None:
            return int_to_hex(0)
        addr = hex_to_bytes(address)
        account = store.get_account(addr)
        if account is None:
            return int_to_hex(0)
        return int_to_hex(account.balance)

    @rpc.method("eth_getTransactionCount")
    def get_transaction_count(address: str, block: str = "latest") -> str:
        if store is None:
            return int_to_hex(0)
        addr = hex_to_bytes(address)
        account = store.get_account(addr)
        if account is None:
            return int_to_hex(0)
        return int_to_hex(account.nonce)

    @rpc.method("eth_getCode")
    def get_code(address: str, block: str = "latest") -> str:
        if store is None:
            return "0x"
        addr = hex_to_bytes(address)
        code = store.get_account_code(addr)
        if code is None:
            return "0x"
        return bytes_to_hex(code)

    @rpc.method("eth_getStorageAt")
    def get_storage_at(address: str, position: str, block: str = "latest") -> str:
        if store is None:
            return bytes_to_hex(b"\x00" * 32)
        addr = hex_to_bytes(address)
        key = hex_to_int(position).to_bytes(32, "big")
        value = store.get_storage(addr, key)
        if value is None:
            return bytes_to_hex(b"\x00" * 32)
        return bytes_to_hex(value.to_bytes(32, "big") if isinstance(value, int) else value)

    # -- Block methods --

    @rpc.method("eth_blockNumber")
    def block_number() -> str:
        if store is None:
            return int_to_hex(0)
        latest = store.get_latest_block_number()
        return int_to_hex(latest if latest is not None else 0)

    @rpc.method("eth_getBlockByNumber")
    def get_block_by_number(block_param: str, full_txs: bool = False) -> Optional[dict]:
        if store is None:
            return None
        num = _resolve_block_number(block_param)
        if num is None:
            return None
        header = store.get_block_header_by_number(num)
        if header is None:
            return None
        block_hash = header.block_hash()
        result = _format_block_header(header, full_txs)
        body = store.get_block_body(block_hash)
        if body and full_txs:
            result["transactions"] = [
                _format_transaction(tx, block_hash, header.number, i)
                for i, tx in enumerate(body[0])
            ]
        elif body:
            result["transactions"] = [bytes_to_hex(tx.tx_hash()) for tx in body[0]]
        else:
            result["transactions"] = []
        result["uncles"] = []
        result["size"] = int_to_hex(0)
        return result

    @rpc.method("eth_getBlockByHash")
    def get_block_by_hash(block_hash_hex: str, full_txs: bool = False) -> Optional[dict]:
        if store is None:
            return None
        bh = hex_to_bytes(block_hash_hex)
        header = store.get_block_header(bh)
        if header is None:
            return None
        result = _format_block_header(header, full_txs)
        body = store.get_block_body(bh)
        if body and full_txs:
            result["transactions"] = [
                _format_transaction(tx, bh, header.number, i)
                for i, tx in enumerate(body[0])
            ]
        elif body:
            result["transactions"] = [bytes_to_hex(tx.tx_hash()) for tx in body[0]]
        else:
            result["transactions"] = []
        result["uncles"] = []
        result["size"] = int_to_hex(0)
        return result

    @rpc.method("eth_getBlockTransactionCountByNumber")
    def get_block_tx_count_by_number(block_param: str) -> Optional[str]:
        if store is None:
            return int_to_hex(0)
        num = _resolve_block_number(block_param)
        bh = store.get_canonical_hash(num)
        if bh is None:
            return None
        body = store.get_block_body(bh)
        return int_to_hex(len(body[0])) if body else int_to_hex(0)

    @rpc.method("eth_getBlockTransactionCountByHash")
    def get_block_tx_count_by_hash(block_hash_hex: str) -> Optional[str]:
        if store is None:
            return int_to_hex(0)
        body = store.get_block_body(hex_to_bytes(block_hash_hex))
        return int_to_hex(len(body[0])) if body else None

    # -- Transaction methods --

    @rpc.method("eth_getTransactionByHash")
    def get_transaction_by_hash(tx_hash_hex: str) -> Optional[dict]:
        if store is None:
            return None
        result = store.get_transaction_by_hash(hex_to_bytes(tx_hash_hex))
        if result is None:
            return None
        tx, block_hash, tx_index = result
        header = store.get_block_header(block_hash)
        block_number = header.number if header else 0
        return _format_transaction(tx, block_hash, block_number, tx_index)

    @rpc.method("eth_getTransactionReceipt")
    def get_transaction_receipt(tx_hash_hex: str) -> Optional[dict]:
        if store is None:
            return None
        tx_hash = hex_to_bytes(tx_hash_hex)
        result = store.get_transaction_receipt(tx_hash)
        if result is None:
            return None
        receipt, block_hash, tx_index = result
        header = store.get_block_header(block_hash)
        block_number = header.number if header else 0
        # gas_used = cumulative difference
        receipts = store.get_receipts(block_hash)
        prev = receipts[tx_index - 1].cumulative_gas_used if tx_index > 0 and receipts else 0
        gas_used = receipt.cumulative_gas_used - prev
        return _format_receipt(receipt, tx_hash, block_hash, block_number, tx_index, gas_used)

    @rpc.method("eth_sendRawTransaction")
    def send_raw_transaction(raw_tx: str) -> str:
        """Submit a raw signed transaction."""
        tx_bytes = hex_to_bytes(raw_tx)
        try:
            tx = Transaction.decode_raw(tx_bytes)
        except Exception as e:
            raise RPCError(INVALID_PARAMS, f"Failed to decode transaction: {e}")

        tx_hash = tx.tx_hash()

        if mempool is not None:
            mempool.add_transaction(tx)

        return bytes_to_hex(tx_hash)

    # -- Call/Estimate --

    def _get_block_header(block_param: str) -> BlockHeader:
        """Resolve block parameter to a BlockHeader."""
        block_num = _resolve_block_number(block_param)
        if store is not None:
            header = store.get_block_header_by_number(block_num)
            if header is not None:
                return header
        # Fallback header for pre-sync state
        header = BlockHeader()
        header.gas_limit = 30_000_000
        header.base_fee_per_gas = 0
        header.number = block_num or 0
        return header

    @rpc.method("eth_call")
    def eth_call(tx_obj: dict, block: str = "latest") -> str:
        """Execute a call without creating a transaction."""
        if store is None or config is None:
            return "0x"
        sender, to, data, value, gas_limit = _parse_call_params(tx_obj)
        header = _get_block_header(block)
        from ethclient.blockchain.chain import simulate_call
        result = simulate_call(sender, to, data, value, gas_limit, header, store, config)
        if not result.success:
            raise RPCError(3, f"execution reverted: {result.error or ''}",
                           bytes_to_hex(result.return_data))
        return bytes_to_hex(result.return_data)

    @rpc.method("eth_estimateGas")
    def estimate_gas(tx_obj: dict, block: str = "latest") -> str:
        """Estimate gas for a transaction."""
        if store is None or config is None:
            return int_to_hex(21000)
        sender, to, data, value, gas_limit = _parse_call_params(tx_obj)
        header = _get_block_header(block)
        from ethclient.blockchain.chain import simulate_call
        result = simulate_call(sender, to, data, value, gas_limit, header, store, config)
        if not result.success:
            raise RPCError(3, f"execution reverted: {result.error or ''}")
        return int_to_hex(result.gas_used)

    # -- Fee methods --

    @rpc.method("eth_gasPrice")
    def gas_price() -> str:
        return int_to_hex(1_000_000_000)  # 1 gwei default

    @rpc.method("eth_maxPriorityFeePerGas")
    def max_priority_fee() -> str:
        return int_to_hex(1_000_000_000)

    @rpc.method("eth_feeHistory")
    def fee_history(block_count: str, newest_block: str,
                    reward_percentiles: Optional[list] = None) -> dict:
        return {
            "baseFeePerGas": [int_to_hex(1_000_000_000)],
            "gasUsedRatio": [0.5],
            "oldestBlock": int_to_hex(0),
        }

    # -- Chain info --

    @rpc.method("eth_chainId")
    def get_chain_id() -> str:
        return int_to_hex(network_chain_id)

    @rpc.method("eth_syncing")
    def syncing() -> bool | dict:
        return False

    # -- Log methods --

    @rpc.method("eth_getLogs")
    def get_logs(filter_obj: dict) -> list:
        """Get logs matching a filter."""
        # TODO: implement log filtering
        return []

    @rpc.method("eth_getBlockReceipts")
    def get_block_receipts(block_param: str) -> Optional[list]:
        if store is None:
            return []
        num = _resolve_block_number(block_param)
        bh = store.get_canonical_hash(num)
        if bh is None:
            return []
        header = store.get_block_header(bh)
        receipts = store.get_receipts(bh)
        body = store.get_block_body(bh)
        if not receipts or not body:
            return []
        result = []
        for i, receipt in enumerate(receipts):
            tx_hash = body[0][i].tx_hash() if i < len(body[0]) else b""
            prev = receipts[i - 1].cumulative_gas_used if i > 0 else 0
            gas_used = receipt.cumulative_gas_used - prev
            result.append(_format_receipt(
                receipt, tx_hash, bh, header.number if header else 0, i, gas_used))
        return result

    # -- net_ methods --

    @rpc.method("net_version")
    def net_version() -> str:
        return "1"

    @rpc.method("net_peerCount")
    def net_peer_count() -> str:
        return int_to_hex(0)

    @rpc.method("net_listening")
    def net_listening() -> bool:
        return True

    # -- web3_ methods --

    @rpc.method("web3_clientVersion")
    def web3_client_version() -> str:
        return "py-ethclient/0.1.0"

    @rpc.method("web3_sha3")
    def web3_sha3(data: str) -> str:
        from ethclient.common.crypto import keccak256
        return bytes_to_hex(keccak256(hex_to_bytes(data)))
