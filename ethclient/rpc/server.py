from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Callable, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

logger = logging.getLogger(__name__)


PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
EXECUTION_ERROR = 3


def _success_response(id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _error_response(id: Any, code: int, message: str, data: Any = None) -> dict:
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": id, "error": error}


class RPCServer:
    """JSON-RPC 2.0 server with method registration and dispatch."""

    def __init__(self) -> None:
        self.app = FastAPI(title="py-ethclient JSON-RPC", docs_url=None, redoc_url=None)
        self._methods: dict[str, Callable] = {}
        self._engine_jwt_secret: Optional[bytes] = None
        self._metrics_provider: Optional[Callable[[], dict[str, float | int]]] = None
        self._setup_routes()

    def set_engine_jwt_secret(self, secret: bytes) -> None:
        """Enable JWT auth for engine_* RPC methods."""
        self._engine_jwt_secret = secret

    def set_metrics_provider(self, provider: Callable[[], dict[str, float | int]]) -> None:
        """Set metrics provider for Prometheus text exposition."""
        self._metrics_provider = provider

    def _setup_routes(self) -> None:
        @self.app.get("/metrics")
        async def handle_metrics() -> PlainTextResponse:
            lines: list[str] = []
            if self._metrics_provider is not None:
                try:
                    metrics = self._metrics_provider()
                    for key, value in metrics.items():
                        lines.append(f"{key} {value}")
                except Exception as exc:
                    logger.debug("metrics provider error: %s", exc)
            return PlainTextResponse("\n".join(lines) + ("\n" if lines else ""))

        @self.app.post("/")
        async def handle_rpc(request: Request) -> JSONResponse:
            try:
                body = await request.json()
            except Exception:
                return JSONResponse(_error_response(None, PARSE_ERROR, "Parse error"))

            auth_header = request.headers.get("authorization")

            if isinstance(body, list):
                if not body:
                    return JSONResponse(_error_response(None, INVALID_REQUEST, "Empty batch"))
                results = []
                for item in body:
                    result = await self._handle_single(item, auth_header)
                    if result is not None:
                        results.append(result)
                return JSONResponse(results if results else None)

            result = await self._handle_single(body, auth_header)
            if result is None:
                return JSONResponse(content=None, status_code=204)
            return JSONResponse(result)

    async def _handle_single(self, request: Any, auth_header: Optional[str] = None) -> Optional[dict]:
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

        if method.startswith("engine_") and self._engine_jwt_secret is not None:
            token = _extract_bearer_token(auth_header)
            if token is None or not _verify_jwt_hs256(token, self._engine_jwt_secret):
                return _error_response(req_id, -32001, "Unauthorized")

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
            logger.warning("RPC TypeError in %s: %s", method, e)
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
        self._methods[name] = handler

    def method(self, name: str) -> Callable:
        def decorator(func: Callable) -> Callable:
            self._methods[name] = func
            return func

        return decorator


class RPCError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _is_async(func: Callable) -> bool:
    import asyncio

    return asyncio.iscoroutinefunction(func)


def _extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if auth_header is None:
        return None
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _verify_jwt_hs256(token: str, secret: bytes) -> bool:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        header_raw, payload_raw, sig_raw = parts
        signing_input = f"{header_raw}.{payload_raw}".encode()

        expected_sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        got_sig = _b64url_decode(sig_raw)
        if not hmac.compare_digest(expected_sig, got_sig):
            return False

        header = json.loads(_b64url_decode(header_raw).decode())
        if header.get("alg") != "HS256":
            return False

        payload = json.loads(_b64url_decode(payload_raw).decode())
        iat = payload.get("iat")
        if not isinstance(iat, int):
            return False

        now = int(time.time())
        # Engine API JWTs are short-lived; allow small skew.
        if abs(now - iat) > 120:
            return False

        return True
    except (json.JSONDecodeError, ValueError, TypeError, KeyError, UnicodeDecodeError):
        return False


def hex_to_int(value: str) -> int:
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    return int(value, 16)


def int_to_hex(value: int) -> str:
    return hex(value)


def bytes_to_hex(value: bytes) -> str:
    return "0x" + value.hex()


def hex_to_bytes(value: str) -> bytes:
    if value.startswith("0x") or value.startswith("0X"):
        value = value[2:]
    return bytes.fromhex(value)


def parse_block_param(value: str) -> int | str:
    if value in ("latest", "pending", "earliest", "safe", "finalized"):
        return value
    return hex_to_int(value)
