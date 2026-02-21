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
        gas_price = tx_params.get("gasPrice")
        authorization_list = tx_params.get("authorizationList")
        access_list = tx_params.get("accessList")
        
        # Parse access list if present
        parsed_access_list = None
        if access_list is not None:
            parsed_access_list = _parse_access_list(access_list)
        
        # EIP-7702 SetCode transaction (Type 0x04)
        if authorization_list is not None:
            if to is None:
                raise ValueError("SetCode transaction must have a 'to' address")
            
            # Parse authorization list
            from eth.vm.forks.prague.transactions import Authorization
            parsed_auth_list = []
            for auth in authorization_list:
                auth_chain_id = _parse_int(auth["chainId"]) if "chainId" in auth else 0
                auth_address = _parse_address(auth["address"])
                auth_nonce = _parse_int(auth["nonce"])
                auth_y_parity = _parse_int(auth["yParity"])
                auth_r = _parse_int(auth["r"])
                auth_s = _parse_int(auth["s"])
                
                parsed_auth_list.append(Authorization(
                    chain_id=auth_chain_id,
                    address=auth_address,
                    nonce=auth_nonce,
                    y_parity=auth_y_parity,
                    r=auth_r,
                    s=auth_s,
                ))
            
            max_fee = _parse_int(max_fee_per_gas) if max_fee_per_gas else None
            max_priority = _parse_int(max_priority_fee_per_gas) if max_priority_fee_per_gas else None
            
            signed_tx = chain.create_setcode_transaction(
                from_private_key=private_key,
                to=to,
                value=value,
                data=data,
                gas=gas,
                max_priority_fee_per_gas=max_priority,
                max_fee_per_gas=max_fee,
                nonce=nonce,
                authorization_list=parsed_auth_list,
            )
        # EIP-1559 transaction with access list (Type 0x02)
        elif (max_fee_per_gas is not None or max_priority_fee_per_gas is not None) and parsed_access_list is not None:
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
                access_list=parsed_access_list,
            )
        # EIP-1559 transaction without access list (Type 0x02)
        elif max_fee_per_gas is not None or max_priority_fee_per_gas is not None:
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
        # EIP-2930 Access List transaction (Type 0x01)
        elif parsed_access_list is not None:
            gas_price_val = _parse_int(gas_price) if gas_price else None
            
            signed_tx = chain.create_access_list_transaction(
                from_private_key=private_key,
                to=to,
                access_list=parsed_access_list,
                value=value,
                data=data,
                gas=gas,
                gas_price=gas_price_val,
                nonce=nonce,
            )
        # Legacy transaction (Type 0x00)
        else:
            gas_price_val = _parse_int(tx_params.get("gasPrice", "0x3b9aca00"))
            signed_tx = chain.create_transaction(
                from_private_key=private_key,
                to=to,
                value=value,
                data=data,
                gas=gas,
                gas_price=gas_price_val,
                nonce=nonce,
            )
        
        try:
            tx_hash = chain.send_transaction(signed_tx)
            return "0x" + tx_hash.hex()
        except Exception as e:
            error_msg = str(e)
            if "nonce too low" in error_msg.lower():
                raise ValueError(f"nonce too low")
            if "insufficient funds" in error_msg.lower():
                raise ValueError(error_msg)
            raise

    def eth_signAuthorization(params: list) -> dict:
        """
        Sign an EIP-7702 authorization.
        
        Parameters:
        - chainId: Chain ID (0 for all chains, or specific chain ID)
        - address: Contract address to set code from
        - nonce: Account nonce
        - _private_key: Private key to sign with
        
        Returns:
        - Authorization object with chainId, address, nonce, yParity, r, s
        """
        auth_params = params[0]
        
        chain_id = _parse_int(auth_params.get("chainId", "0x0"))
        address = _parse_address(auth_params["address"])
        nonce = _parse_int(auth_params.get("nonce", "0x0"))
        
        private_key = auth_params.get("_private_key")
        if not private_key:
            raise ValueError("Missing '_private_key' - required for signing")
        
        private_key_bytes = _parse_bytes(private_key)
        
        auth = chain.create_authorization(
            chain_id=chain_id,
            address=address,
            nonce=nonce,
            private_key=private_key_bytes,
        )
        
        return {
            "chainId": hex(auth.chain_id),
            "address": to_checksum_address(auth.address),
            "nonce": hex(auth.nonce),
            "yParity": hex(auth.y_parity),
            "r": hex(auth.r),
            "s": hex(auth.s),
        }

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
            if "insufficient funds" in error_msg.lower():
                raise ValueError(error_msg)
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

    def eth_getLogs(params: list) -> list:
        """
        Get logs matching the filter.
        
        Parameters:
        - filter: object with optional fields:
          - fromBlock: block number or "latest" (default: "latest")
          - toBlock: block number or "latest" (default: "latest")
          - address: contract address or list of addresses
          - topics: list of topic filters
        """
        filter_obj = params[0] if params else {}
        
        # Parse block range
        from_block = _parse_block_number(filter_obj.get("fromBlock", "latest"))
        to_block = _parse_block_number(filter_obj.get("toBlock", "latest"))
        
        # Handle "latest" as current block
        latest = chain.get_latest_block_number()
        if from_block == -1:
            from_block = latest
        if to_block == -1:
            to_block = latest
        
        # Parse address filter
        address = None
        if "address" in filter_obj:
            addr = filter_obj["address"]
            if isinstance(addr, list):
                address = [_parse_address(a) for a in addr]
            else:
                address = _parse_address(addr)
        
        # Parse topics filter
        topics = None
        if "topics" in filter_obj:
            topics = []
            for topic in filter_obj["topics"]:
                if topic is None:
                    topics.append(None)
                elif isinstance(topic, list):
                    topics.append([_parse_bytes(t) for t in topic])
                else:
                    topics.append(_parse_bytes(topic))
        
        # Get logs from chain
        logs = chain.store.get_logs(from_block, to_block, address, topics)
        
        # Serialize logs
        serialized = []
        for log in logs:
            serialized.append({
                "address": to_checksum_address(log["address"]),
                "topics": ["0x" + t.hex() for t in log["topics"]],
                "data": "0x" + log["data"].hex() if log["data"] else "0x",
                "blockNumber": hex(log["block_number"]),
                "blockHash": "0x" + log["block_hash"].hex(),
                "transactionHash": "0x" + log["tx_hash"].hex(),
                "transactionIndex": hex(log["tx_index"]),
                "logIndex": hex(log["log_index"]),
            })
        
        return serialized

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
        "eth_getLogs": eth_getLogs,
        "eth_estimateGas": eth_estimateGas,
        "eth_gasPrice": eth_gasPrice,
        "eth_feeHistory": eth_feeHistory,
        "eth_signAuthorization": eth_signAuthorization,
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


def _parse_access_list(access_list: list) -> list[tuple[bytes, list[int]]]:
    """
    Parse an access list from JSON-RPC format.
    
    Input format:
        [
            {"address": "0x...", "storageKeys": ["0x...", "0x..."]},
            ...
        ]
    
    Output format:
        [(address_bytes, [slot_int, ...]), ...]
    """
    parsed = []
    for entry in access_list:
        if isinstance(entry, dict):
            addr = _parse_address(entry["address"])
            storage_keys = []
            for key in entry.get("storageKeys", entry.get("storage_keys", [])):
                if isinstance(key, int):
                    storage_keys.append(key)
                elif isinstance(key, str):
                    storage_keys.append(_parse_int(key))
                else:
                    storage_keys.append(int(key))
            parsed.append((addr, storage_keys))
        elif isinstance(entry, (list, tuple)) and len(entry) == 2:
            addr, storage_keys = entry
            if isinstance(addr, str):
                addr = _parse_address(addr)
            storage_keys = [int(k) if not isinstance(k, int) else k for k in storage_keys]
            parsed.append((addr, storage_keys))
    return parsed


def _serialize_access_list(access_list) -> list[dict]:
    """
    Serialize an access list to JSON-RPC format.
    
    Input: [(address_bytes, [slot_int, ...]), ...]
    Output: [{"address": "0x...", "storageKeys": ["0x...", ...]}, ...]
    """
    serialized = []
    for addr, storage_keys in access_list:
        entry = {
            "address": to_checksum_address(addr),
            "storageKeys": [hex(slot) for slot in storage_keys],
        }
        serialized.append(entry)
    return serialized


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
    """Get transaction type: 0=Legacy, 1=AccessList, 2=EIP-1559, 4=SetCode"""
    tx_type = getattr(tx, 'type_id', None)
    if tx_type is not None:
        return tx_type
    # Check for EIP-7702 SetCodeTransaction by checking type_id first
    # Then check if authorization_list exists and is accessible
    try:
        auth_list = getattr(tx, 'authorization_list', None)
        if auth_list is not None:
            return 4
    except NotImplementedError:
        # authorization_list raises NotImplementedError for pre-Prague transactions
        pass
    # Check for EIP-1559
    if hasattr(tx, 'max_priority_fee_per_gas'):
        max_priority = getattr(tx, 'max_priority_fee_per_gas', None)
        if max_priority is not None:
            gas_price = getattr(tx, 'gas_price', None)
            if gas_price is None or max_priority != gas_price:
                return 2
    # Check for EIP-2930 AccessList
    access_list = getattr(tx, 'access_list', None)
    if access_list is not None and len(access_list) > 0:
        return 1
    return 0


def _serialize_tx(tx, block) -> dict:
    tx_hash = _tx_hash(tx)
    
    tx_type = _get_tx_type(tx)
    is_eip1559 = tx_type == 2
    is_setcode = tx_type == 4
    is_access_list = tx_type == 1
    
    # Find transaction index in block
    tx_index = None
    for i, block_tx in enumerate(block.transactions):
        if _tx_hash(block_tx) == tx_hash:
            tx_index = i
            break
    tx_index = tx_index if tx_index is not None else 0
    
    # Get y_parity for EIP-1559 and SetCode transactions
    if is_eip1559 or is_setcode:
        y_parity = getattr(tx, 'y_parity', None)
        if y_parity is not None:
            v_hex = hex(y_parity)
        else:
            v_hex = hex(tx.v) if hasattr(tx, 'v') else "0x0"
    else:
        v_hex = hex(tx.v) if hasattr(tx, 'v') else "0x0"
    
    result = {
        "hash": "0x" + tx_hash.hex(),
        "nonce": hex(tx.nonce),
        "blockHash": "0x" + block.hash.hex(),
        "blockNumber": hex(block.number),
        "transactionIndex": hex(tx_index),
        "from": to_checksum_address(tx.sender),
        "to": to_checksum_address(tx.to) if tx.to else None,
        "value": hex(tx.value),
        "gas": hex(tx.gas),
        "input": "0x" + (tx.data.hex() if tx.data else ""),
        "v": v_hex,
        "r": hex(tx.r),
        "s": hex(tx.s),
    }
    
    if is_setcode:
        result["type"] = "0x4"
        result["maxFeePerGas"] = hex(tx.max_fee_per_gas)
        result["maxPriorityFeePerGas"] = hex(tx.max_priority_fee_per_gas)
        result["gasPrice"] = hex(tx.max_fee_per_gas)
        result["chainId"] = hex(tx.chain_id)
        
        # Serialize access list
        access_list = []
        for addr, slots in getattr(tx, 'access_list', []):
            access_list.append({
                "address": to_checksum_address(addr),
                "storageKeys": [hex(slot) if isinstance(slot, int) else "0x" + slot.hex() for slot in slots]
            })
        result["accessList"] = access_list
        
        # Serialize authorization list
        auth_list = []
        for auth in getattr(tx, 'authorization_list', []):
            auth_list.append({
                "chainId": hex(auth.chain_id),
                "address": to_checksum_address(auth.address),
                "nonce": hex(auth.nonce),
                "yParity": hex(auth.y_parity),
                "r": hex(auth.r),
                "s": hex(auth.s),
            })
        result["authorizationList"] = auth_list
        
    elif is_eip1559:
        result["type"] = "0x2"
        result["maxFeePerGas"] = hex(tx.max_fee_per_gas)
        result["maxPriorityFeePerGas"] = hex(tx.max_priority_fee_per_gas)
        result["gasPrice"] = hex(tx.max_fee_per_gas)
        chain_id = getattr(tx, 'chain_id', None)
        result["chainId"] = hex(chain_id) if chain_id is not None else "0x0"
        
        # Serialize access list if present
        if hasattr(tx, 'access_list') and tx.access_list:
            access_list = []
            for addr, slots in tx.access_list:
                access_list.append({
                    "address": to_checksum_address(addr),
                    "storageKeys": [hex(slot) if isinstance(slot, int) else "0x" + slot.hex() for slot in slots]
                })
            result["accessList"] = access_list
        else:
            result["accessList"] = []
            
    elif is_access_list:
        result["type"] = "0x1"
        result["gasPrice"] = hex(tx.gas_price)
        result["chainId"] = hex(tx.chain_id) if hasattr(tx, 'chain_id') else "0x0"
        
        # Serialize access list
        access_list = []
        for addr, slots in getattr(tx, 'access_list', []):
            access_list.append({
                "address": to_checksum_address(addr),
                "storageKeys": [hex(slot) if isinstance(slot, int) else "0x" + slot.hex() for slot in slots]
            })
        result["accessList"] = access_list
        
    else:
        result["type"] = "0x0"
        result["gasPrice"] = hex(tx.gas_price)
    
    return result


def _tx_hash(tx) -> bytes:
    if hasattr(tx, "encode"):
        return keccak256(tx.encode())
    return keccak256(bytes(tx))


def _decode_raw_transaction(raw_tx: bytes):
    """Decode a raw transaction. Supports Legacy (0x0), AccessList (0x1), EIP-1559 (0x2), and SetCode (0x4)."""
    from eth.vm.forks.prague import PragueVM
    return PragueVM.get_transaction_builder().decode(raw_tx)


def _serialize_receipt(receipt_data, chain) -> dict:
    block_number, tx_index, receipt = receipt_data
    block = chain.get_block_by_number(block_number)
    
    tx = block.transactions[tx_index]
    tx_hash = _tx_hash(tx)
    
    tx_type = _get_tx_type(tx)
    is_eip1559 = tx_type == 2
    is_setcode = tx_type == 4
    is_access_list = tx_type == 1
    
    # Determine transaction type hex
    if is_setcode:
        tx_type_hex = "0x4"
    elif is_eip1559:
        tx_type_hex = "0x2"
    elif is_access_list:
        tx_type_hex = "0x1"
    else:
        tx_type_hex = "0x0"
    
    # Get effective gas price
    if is_eip1559 or is_setcode:
        effective_gas_price = tx.max_fee_per_gas
    else:
        effective_gas_price = tx.gas_price
    
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