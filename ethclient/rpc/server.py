"""
JSON-RPC 2.0 server built on FastAPI.

Handles request parsing, method dispatch, error formatting, and batch requests.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JSON-RPC error codes
# ---------------------------------------------------------------------------

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
EXECUTION_ERROR = 3      # EVM execution error


# ---------------------------------------------------------------------------
# JSON-RPC response helpers
# ---------------------------------------------------------------------------

def _success_response(id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _error_response(id: Any, code: int, message: str, data: Any = None) -> dict:
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": id, "error": error}


# ---------------------------------------------------------------------------
# RPC Server
# ---------------------------------------------------------------------------

class RPCServer:
    """JSON-RPC 2.0 server with method registration and dispatch."""

    def __init__(self) -> None:
        self.app = FastAPI(title="py-ethclient JSON-RPC", docs_url=None, redoc_url=None)
        self._methods: dict[str, Callable] = {}
        self._setup_routes()

    def _setup_routes(self) -> None:
        @self.app.post("/")
        async def handle_rpc(request: Request) -> JSONResponse:
            try:
                body = await request.json()
            except Exception:
                return JSONResponse(
                    _error_response(None, PARSE_ERROR, "Parse error"),
                )

            # Batch request
            if isinstance(body, list):
                if not body:
                    return JSONResponse(
                        _error_response(None, INVALID_REQUEST, "Empty batch"),
                    )
                results = []
                for item in body:
                    result = await self._handle_single(item)
                    if result is not None:  # notifications have no response
                        results.append(result)
                return JSONResponse(results if results else None)

            # Single request
            result = await self._handle_single(body)
            if result is None:
                return JSONResponse(content=None, status_code=204)
            return JSONResponse(result)

    async def _handle_single(self, request: Any) -> Optional[dict]:
        """Handle a single JSON-RPC request."""
        if not isinstance(request, dict):
            return _error_response(None, INVALID_REQUEST, "Invalid request")

        jsonrpc = request.get("jsonrpc")
        method = request.get("method")
        params = request.get("params", [])
        req_id = request.get("id")

        if jsonrpc != "2.0":
            return _error_response(req_id, INVALID_REQUEST, "Invalid JSON-RPC version")

        if not isinstance(method, str):
            return _error_response(req_id, INVALID_REQUEST, "Invalid method")

        # Notification (no id) — still process but don't return response
        is_notification = "id" not in request

        handler = self._methods.get(method)
        if handler is None:
            if is_notification:
                return None
            return _error_response(req_id, METHOD_NOT_FOUND, f"Method not found: {method}")

        try:
            if isinstance(params, list):
                result = await handler(*params) if _is_async(handler) else handler(*params)
            elif isinstance(params, dict):
                result = await handler(**params) if _is_async(handler) else handler(**params)
            else:
                return _error_response(req_id, INVALID_PARAMS, "Invalid params")
        except TypeError as e:
            return _error_response(req_id, INVALID_PARAMS, str(e))
        except RPCError as e:
            return _error_response(req_id, e.code, e.message, e.data)
        except Exception as e:
            logger.exception("RPC internal error in %s", method)
            return _error_response(req_id, INTERNAL_ERROR, str(e))

        if is_notification:
            return None
        return _success_response(req_id, result)

    def register(self, name: str, handler: Callable) -> None:
        """Register an RPC method handler."""
        self._methods[name] = handler

    def method(self, name: str) -> Callable:
        """Decorator to register an RPC method."""
        def decorator(func: Callable) -> Callable:
            self._methods[name] = func
            return func
        return decorator


# ---------------------------------------------------------------------------
# RPC Error
# ---------------------------------------------------------------------------

class RPCError(Exception):
    """Custom RPC error with code and optional data."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _is_async(func: Callable) -> bool:
    import asyncio
    return asyncio.iscoroutinefunction(func)


def hex_to_int(value: str) -> int:
    """Parse a hex string (with or without 0x prefix) to int."""
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    return int(value, 16)


def int_to_hex(value: int) -> str:
    """Convert int to 0x-prefixed hex string."""
    return hex(value)


def bytes_to_hex(value: bytes) -> str:
    """Convert bytes to 0x-prefixed hex string."""
    return "0x" + value.hex()


def hex_to_bytes(value: str) -> bytes:
    """Parse a 0x-prefixed hex string to bytes."""
    if value.startswith("0x") or value.startswith("0X"):
        value = value[2:]
    return bytes.fromhex(value)


def parse_block_param(value: str) -> int | str:
    """Parse a block number parameter.

    Returns int for numeric values, or special strings like "latest", "pending", "earliest".
    """
    if value in ("latest", "pending", "earliest", "safe", "finalized"):
        return value
    return hex_to_int(value)
