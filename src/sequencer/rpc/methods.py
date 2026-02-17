"""JSON-RPC method implementations."""

from typing import Any, Callable
import json

from eth_utils import to_checksum_address

from sequencer.core.crypto import private_key_to_address, keccak256


def create_methods(chain) -> dict[str, Callable]:
    def eth_chainId(params: list) -> str:
        return hex(chain.chain_id)

    def eth_blockNumber(params: list) -> str:
        return hex(chain.get_latest_block_number())

    def eth_getBalance(params: list) -> str:
        address = _parse_address(params[0])
        block = params[1] if len(params) > 1 else "latest"
        balance = chain.get_balance(address)
        return hex(balance)

    def eth_getTransactionCount(params: list) -> str:
        address = _parse_address(params[0])
        block = params[1] if len(params) > 1 else "latest"
        nonce = chain.get_nonce(address)
        return hex(nonce)

    def eth_getCode(params: list) -> str:
        address = _parse_address(params[0])
        block = params[1] if len(params) > 1 else "latest"
        code = chain.get_code(address)
        return "0x" + code.hex()

    def eth_getStorageAt(params: list) -> str:
        address = _parse_address(params[0])
        slot = _parse_int(params[1])
        block = params[2] if len(params) > 2 else "latest"
        value = chain.get_storage_at(address, slot)
        return hex(value)

    def eth_getBlockByNumber(params: list) -> dict | None:
        block_number = _parse_block_number(params[0])
        include_txs = params[1] if len(params) > 1 else False
        
        block = chain.get_block_by_number(block_number)
        if not block:
            return None
        
        return _serialize_block(block, include_txs)

    def eth_getBlockByHash(params: list) -> dict | None:
        block_hash = _parse_bytes(params[0])
        include_txs = params[1] if len(params) > 1 else False
        
        block = chain.get_block_by_hash(block_hash)
        if not block:
            return None
        
        return _serialize_block(block, include_txs)

    def eth_call(params: list) -> str:
        tx_params = params[0]
        block = params[1] if len(params) > 1 else "latest"
        
        from_addr = _parse_address(tx_params.get("from", "0x0000000000000000000000000000000000000000"))
        to = _parse_address(tx_params["to"])
        data = _parse_bytes(tx_params.get("data", "0x"))
        value = _parse_int(tx_params.get("value", "0x0"))
        
        result = chain.call(from_addr, to, value, data)
        return "0x" + result.hex()

    def eth_sendTransaction(params: list) -> str:
        tx_params = params[0]
        
        if "from" not in tx_params:
            raise ValueError("Missing 'from' address")
        
        from_private_key = tx_params.get("_private_key")
        if not from_private_key:
            raise ValueError("Missing '_private_key' - required for signing")
        
        private_key = _parse_bytes(from_private_key)
        to = _parse_address(tx_params["to"]) if "to" in tx_params else None
        value = _parse_int(tx_params.get("value", "0x0"))
        data = _parse_bytes(tx_params.get("data", "0x"))
        gas = _parse_int(tx_params.get("gas", "0x5208"))
        gas_price = _parse_int(tx_params.get("gasPrice", "0x3b9aca00"))
        nonce = _parse_int(tx_params["nonce"]) if "nonce" in tx_params else None
        
        signed_tx = chain.create_transaction(
            from_private_key=private_key,
            to=to,
            value=value,
            data=data,
            gas=gas,
            gas_price=gas_price,
            nonce=nonce,
        )
        
        tx_hash = chain.send_transaction(signed_tx)
        return "0x" + tx_hash.hex()

    def eth_estimateGas(params: list) -> str:
        tx_params = params[0]
        block = params[1] if len(params) > 1 else "latest"
        return hex(30_000_000)

    def eth_gasPrice(params: list) -> str:
        return hex(1_000_000_000)

    def net_version(params: list) -> str:
        return str(chain.chain_id)

    def eth_accounts(params: list) -> list:
        return []

    def eth_coinbase(params: list) -> str:
        return to_checksum_address(chain.coinbase)

    return {
        "eth_chainId": eth_chainId,
        "eth_blockNumber": eth_blockNumber,
        "eth_getBalance": eth_getBalance,
        "eth_getTransactionCount": eth_getTransactionCount,
        "eth_getCode": eth_getCode,
        "eth_getStorageAt": eth_getStorageAt,
        "eth_getBlockByNumber": eth_getBlockByNumber,
        "eth_getBlockByHash": eth_getBlockByHash,
        "eth_call": eth_call,
        "eth_sendTransaction": eth_sendTransaction,
        "eth_estimateGas": eth_estimateGas,
        "eth_gasPrice": eth_gasPrice,
        "net_version": net_version,
        "eth_accounts": eth_accounts,
        "eth_coinbase": eth_coinbase,
    }


def _parse_address(value: str) -> bytes:
    if value.startswith("0x"):
        value = value[2:]
    return bytes.fromhex(value.zfill(40))[:20]


def _parse_bytes(value: str) -> bytes:
    if value.startswith("0x"):
        value = value[2:]
    if not value:
        return b""
    return bytes.fromhex(value)


def _parse_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    if value.startswith("0x"):
        return int(value, 16)
    return int(value)


def _parse_block_number(value: str) -> int:
    if value == "latest":
        return -1
    if value == "pending":
        return -1
    if value == "earliest":
        return 0
    return _parse_int(value)


def _serialize_block(block, include_txs: bool) -> dict:
    header = block.header
    
    result = {
        "number": hex(header.number),
        "hash": "0x" + block.hash.hex(),
        "parentHash": "0x" + header.parent_hash.hex(),
        "sha3Uncles": "0x" + header.ommers_hash.hex(),
        "miner": to_checksum_address(header.coinbase),
        "stateRoot": "0x" + header.state_root.hex(),
        "transactionsRoot": "0x" + header.transactions_root.hex(),
        "receiptsRoot": "0x" + header.receipts_root.hex(),
        "logsBloom": "0x" + header.logs_bloom.hex(),
        "difficulty": hex(header.difficulty),
        "gasLimit": hex(header.gas_limit),
        "gasUsed": hex(header.gas_used),
        "timestamp": hex(header.timestamp),
        "extraData": "0x" + header.extra_data.hex() if header.extra_data else "0x",
        "mixHash": "0x" + header.prev_randao.hex(),
        "nonce": "0x" + header.nonce.hex(),
        "baseFeePerGas": hex(header.base_fee_per_gas) if header.base_fee_per_gas else "0x0",
    }
    
    if include_txs:
        result["transactions"] = [_serialize_tx(tx, block) for tx in block.transactions]
    else:
        result["transactions"] = ["0x" + _tx_hash(tx).hex() for tx in block.transactions]
    
    return result


def _serialize_tx(tx, block) -> dict:
    tx_hash = _tx_hash(tx)
    
    return {
        "hash": "0x" + tx_hash.hex(),
        "blockNumber": hex(block.number),
        "blockHash": "0x" + block.hash.hex(),
        "from": to_checksum_address(tx.sender),
        "gas": hex(tx.gas),
        "gasPrice": hex(tx.gas_price),
        "input": "0x" + (tx.data.hex() if tx.data else ""),
        "nonce": hex(tx.nonce),
        "to": to_checksum_address(tx.to) if tx.to else None,
        "value": hex(tx.value),
        "v": hex(tx.v),
        "r": hex(tx.r),
        "s": hex(tx.s),
    }


def _tx_hash(tx) -> bytes:
    if hasattr(tx, "encode"):
        return keccak256(tx.encode())
    return keccak256(bytes(tx))