"""JSON-RPC method implementations."""

from typing import Any, Callable
import json

from eth_utils.address import to_checksum_address
from rlp import decode as rlp_decode

from sequencer.core.crypto import keccak256
from sequencer.core.constants import ELASTICITY_MULTIPLIER, BASE_FEE_MAX_CHANGE_DENOMINATOR


def _calc_next_base_fee(gas_used: int, gas_limit: int, base_fee: int) -> int:
    gas_target = gas_limit // ELASTICITY_MULTIPLIER
    if gas_used == gas_target:
        return base_fee
    elif gas_used > gas_target:
        gas_delta = gas_used - gas_target
        fee_delta = max(base_fee * gas_delta // gas_target // BASE_FEE_MAX_CHANGE_DENOMINATOR, 1)
        return base_fee + fee_delta
    else:
        gas_delta = gas_target - gas_used
        fee_delta = base_fee * gas_delta // gas_target // BASE_FEE_MAX_CHANGE_DENOMINATOR
        return max(base_fee - fee_delta, 1)


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
        nonce = _parse_int(tx_params["nonce"]) if "nonce" in tx_params else None
        
        max_fee_per_gas = tx_params.get("maxFeePerGas")
        max_priority_fee_per_gas = tx_params.get("maxPriorityFeePerGas")
        
        if max_fee_per_gas is not None or max_priority_fee_per_gas is not None:
            max_fee = _parse_int(max_fee_per_gas) if max_fee_per_gas else None
            max_priority = _parse_int(max_priority_fee_per_gas) if max_priority_fee_per_gas else None
            
            signed_tx = chain.create_eip1559_transaction(
                from_private_key=private_key,
                to=to,
                value=value,
                data=data,
                gas=gas,
                max_priority_fee_per_gas=max_priority,
                max_fee_per_gas=max_fee,
                nonce=nonce,
            )
        else:
            gas_price = _parse_int(tx_params.get("gasPrice", "0x3b9aca00"))
            signed_tx = chain.create_transaction(
                from_private_key=private_key,
                to=to,
                value=value,
                data=data,
                gas=gas,
                gas_price=gas_price,
                nonce=nonce,
            )
        
        try:
            tx_hash = chain.send_transaction(signed_tx)
            return "0x" + tx_hash.hex()
        except Exception as e:
            error_msg = str(e)
            if "nonce too low" in error_msg.lower():
                raise ValueError(f"nonce too low")
            raise

    def eth_sendRawTransaction(params: list) -> str:
        raw_tx = _parse_bytes(params[0])
        signed_tx = _decode_raw_transaction(raw_tx)
        try:
            tx_hash = chain.send_transaction(signed_tx)
            return "0x" + tx_hash.hex()
        except Exception as e:
            error_msg = str(e)
            if "nonce too low" in error_msg.lower():
                raise ValueError(f"nonce too low")
            raise

    def eth_estimateGas(params: list) -> str:
        tx_params = params[0]
        block = params[1] if len(params) > 1 else "latest"
        
        from_addr = _parse_address(tx_params.get("from", "0x0000000000000000000000000000000000000000"))
        to = _parse_address(tx_params["to"]) if "to" in tx_params else None
        value = _parse_int(tx_params.get("value", "0x0"))
        data = _parse_bytes(tx_params.get("data", "0x"))
        gas_limit = _parse_int(tx_params.get("gas", "0x1c9c380"))  # Default 30M
        
        gas_estimate = chain.estimate_gas(from_addr, to, value, data, gas_limit)
        return hex(gas_estimate)

    def eth_gasPrice(params: list) -> str:
        return hex(1_000_000_000)

    def eth_feeHistory(params: list) -> dict:
        block_count = _parse_int(params[0]) if params else 1
        newest_block = params[1] if len(params) > 1 else "latest"
        reward_percentiles = params[2] if len(params) > 2 else []
        
        newest_number = _parse_block_number(newest_block)
        if newest_number == -1:
            newest_number = chain.get_latest_block_number()
        
        oldest_number = max(0, newest_number - block_count + 1)
        
        base_fee_per_gas = []
        gas_used_ratio = []
        reward = []
        
        for block_number in range(oldest_number, newest_number + 1):
            block = chain.get_block_by_number(block_number)
            if block:
                base_fee = block.header.base_fee_per_gas or 1_000_000_000
                base_fee_per_gas.append(hex(base_fee))
                
                gas_used = block.header.gas_used
                gas_limit = block.header.gas_limit
                ratio = gas_used / gas_limit if gas_limit > 0 else 0.0
                gas_used_ratio.append(ratio)
            else:
                base_fee_per_gas.append(hex(1_000_000_000))
                gas_used_ratio.append(0.0)
        
        latest_block = chain.get_block_by_number(newest_number)
        if latest_block and latest_block.header.base_fee_per_gas:
            next_base_fee = _calc_next_base_fee(
                latest_block.header.gas_used,
                latest_block.header.gas_limit,
                latest_block.header.base_fee_per_gas,
            )
            base_fee_per_gas.append(hex(next_base_fee))
        else:
            base_fee_per_gas.append(hex(1_000_000_000))
        
        if reward_percentiles:
            for block_number in range(oldest_number, newest_number + 1):
                rewards = [hex(0) for _ in reward_percentiles]
                reward.append(rewards)
        
        result = {
            "oldestBlock": hex(oldest_number),
            "baseFeePerGas": base_fee_per_gas,
            "gasUsedRatio": gas_used_ratio,
        }
        
        if reward_percentiles:
            result["reward"] = reward
        
        return result

    def net_version(params: list) -> str:
        return str(chain.chain_id)

    def eth_accounts(params: list) -> list:
        return []

    def eth_coinbase(params: list) -> str:
        return to_checksum_address(chain.coinbase)

    def eth_getTransactionByHash(params: list) -> dict | None:
        tx_hash = _parse_bytes(params[0])
        result = chain.get_transaction_by_hash(tx_hash)
        if not result:
            return None
        
        block, tx = result
        return _serialize_tx(tx, block)

    def eth_getTransactionReceipt(params: list) -> dict | None:
        tx_hash = _parse_bytes(params[0])
        receipt = chain.get_transaction_receipt(tx_hash)
        if not receipt:
            return None
        return _serialize_receipt(receipt, chain)

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
        "eth_sendRawTransaction": eth_sendRawTransaction,
        "eth_getTransactionByHash": eth_getTransactionByHash,
        "eth_getTransactionReceipt": eth_getTransactionReceipt,
        "eth_estimateGas": eth_estimateGas,
        "eth_gasPrice": eth_gasPrice,
        "eth_feeHistory": eth_feeHistory,
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


def _get_tx_type(tx) -> int:
    tx_type = getattr(tx, 'type_id', None)
    if tx_type is not None:
        return tx_type
    if hasattr(tx, 'max_priority_fee_per_gas'):
        if tx.max_priority_fee_per_gas is not None and tx.max_priority_fee_per_gas != tx.gas_price:
            return 2
    return 0


def _serialize_tx(tx, block) -> dict:
    tx_hash = _tx_hash(tx)
    
    tx_type = _get_tx_type(tx)
    is_eip1559 = tx_type == 2
    
    if is_eip1559:
        y_parity = getattr(tx, 'y_parity', None)
        if y_parity is not None:
            v_hex = hex(y_parity)
        else:
            v_hex = hex(tx.v) if hasattr(tx, 'v') else "0x0"
    else:
        v_hex = hex(tx.v) if hasattr(tx, 'v') else "0x0"
    
    result = {
        "hash": "0x" + tx_hash.hex(),
        "blockNumber": hex(block.number),
        "blockHash": "0x" + block.hash.hex(),
        "from": to_checksum_address(tx.sender),
        "gas": hex(tx.gas),
        "input": "0x" + (tx.data.hex() if tx.data else ""),
        "nonce": hex(tx.nonce),
        "to": to_checksum_address(tx.to) if tx.to else None,
        "value": hex(tx.value),
        "v": v_hex,
        "r": hex(tx.r),
        "s": hex(tx.s),
    }
    
    if is_eip1559:
        result["type"] = "0x2"
        result["maxFeePerGas"] = hex(tx.max_fee_per_gas)
        result["maxPriorityFeePerGas"] = hex(tx.max_priority_fee_per_gas)
        result["gasPrice"] = hex(tx.max_fee_per_gas)
        chain_id = getattr(tx, 'chain_id', None)
        result["chainId"] = hex(chain_id) if chain_id is not None else "0x0"
    else:
        result["type"] = "0x0"
        result["gasPrice"] = hex(tx.gas_price)
    
    return result


def _tx_hash(tx) -> bytes:
    if hasattr(tx, "encode"):
        return keccak256(tx.encode())
    return keccak256(bytes(tx))


def _decode_raw_transaction(raw_tx: bytes):
    from eth.vm.forks.cancun import CancunVM
    return CancunVM.get_transaction_builder().decode(raw_tx)


def _serialize_receipt(receipt_data, chain) -> dict:
    block_number, tx_index, receipt = receipt_data
    block = chain.get_block_by_number(block_number)
    
    tx = block.transactions[tx_index]
    tx_hash = _tx_hash(tx)
    
    tx_type = _get_tx_type(tx)
    is_eip1559 = tx_type == 2
    tx_type_hex = "0x2" if is_eip1559 else "0x0"
    effective_gas_price = tx.max_fee_per_gas if is_eip1559 else tx.gas_price
    
    logs = []
    for i, log in enumerate(receipt.logs):
        if isinstance(log, tuple) and len(log) == 3:
            address, topics, data = log
            logs.append({
                "address": to_checksum_address(address),
                "topics": ["0x" + t.hex() for t in topics],
                "data": "0x" + data.hex() if data else "0x",
                "logIndex": hex(i),
                "blockNumber": hex(block_number),
                "blockHash": "0x" + block.hash.hex(),
                "transactionHash": "0x" + tx_hash.hex(),
                "transactionIndex": hex(tx_index),
            })
    
    return {
        "status": hex(receipt.status),
        "cumulativeGasUsed": hex(receipt.cumulative_gas_used),
        "logs": logs,
        "logsBloom": "0x" + "00" * 256,
        "transactionHash": "0x" + tx_hash.hex(),
        "transactionIndex": hex(tx_index),
        "blockHash": "0x" + block.hash.hex(),
        "blockNumber": hex(block_number),
        "from": to_checksum_address(tx.sender),
        "to": to_checksum_address(tx.to) if tx.to else None,
        "contractAddress": to_checksum_address(receipt.contract_address) if receipt.contract_address else None,
        "gasUsed": hex(receipt.cumulative_gas_used),
        "type": tx_type_hex,
        "effectiveGasPrice": hex(effective_gas_price),
    }