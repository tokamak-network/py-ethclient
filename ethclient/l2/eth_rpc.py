"""Lightweight Ethereum JSON-RPC client using urllib (no external dependencies)."""

from __future__ import annotations

import json
import time
import urllib.request
import urllib.error
from typing import Any, Optional


class EthRPCError(Exception):
    """Raised on JSON-RPC errors or transport failures."""

    def __init__(self, message: str, code: int = 0):
        super().__init__(message)
        self.code = code


class EthRPCClient:
    """Minimal Ethereum JSON-RPC client over HTTP."""

    def __init__(self, rpc_url: str, timeout: int = 30) -> None:
        self._url = rpc_url
        self._timeout = timeout
        self._id = 0

    def _call(self, method: str, params: list | None = None) -> Any:
        self._id += 1
        body = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": self._id,
        }).encode()
        req = urllib.request.Request(
            self._url,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, OSError) as exc:
            raise EthRPCError(f"RPC transport error: {exc}") from exc

        if "error" in data:
            err = data["error"]
            raise EthRPCError(err.get("message", str(err)), err.get("code", 0))
        return data.get("result")

    def get_chain_id(self) -> int:
        return int(self._call("eth_chainId"), 16)

    def get_nonce(self, address: str) -> int:
        return int(self._call("eth_getTransactionCount", [address, "pending"]), 16)

    def get_gas_price(self) -> int:
        return int(self._call("eth_gasPrice"), 16)

    def get_max_priority_fee(self) -> int:
        return int(self._call("eth_maxPriorityFeePerGas"), 16)

    def get_base_fee(self) -> int:
        block = self._call("eth_getBlockByNumber", ["latest", False])
        return int(block["baseFeePerGas"], 16)

    def get_blob_base_fee(self) -> int:
        block = self._call("eth_getBlockByNumber", ["latest", False])
        excess = int(block.get("excessBlobGas", "0x0"), 16)
        # EIP-4844 fake_exponential(1, excess, 3338477)
        return _fake_exponential(1, excess, 3338477)

    def send_raw_transaction(self, raw_tx: bytes) -> bytes:
        tx_hex = "0x" + raw_tx.hex()
        result = self._call("eth_sendRawTransaction", [tx_hex])
        return bytes.fromhex(result[2:])

    def get_transaction(self, tx_hash: bytes) -> Optional[dict]:
        result = self._call("eth_getTransactionByHash", ["0x" + tx_hash.hex()])
        return result

    def get_receipt(self, tx_hash: bytes) -> Optional[dict]:
        result = self._call("eth_getTransactionReceipt", ["0x" + tx_hash.hex()])
        return result

    def wait_for_receipt(self, tx_hash: bytes, timeout: int = 120) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            receipt = self.get_receipt(tx_hash)
            if receipt is not None:
                return receipt
            time.sleep(1.0)
        raise TimeoutError(
            f"Transaction 0x{tx_hash.hex()} not mined within {timeout}s"
        )


def _fake_exponential(factor: int, numerator: int, denominator: int) -> int:
    """EIP-4844 fake_exponential for blob base fee calculation."""
    i = 1
    output = 0
    numerator_accum = factor * denominator
    while numerator_accum > 0:
        output += numerator_accum
        numerator_accum = (numerator_accum * numerator) // (denominator * i)
        i += 1
    return output // denominator
