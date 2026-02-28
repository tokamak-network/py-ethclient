"""Production middleware for L2 RPC server.

Provides API key authentication, IP-based rate limiting, and request size limiting.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


# ── Token Bucket Rate Limiter ──

@dataclass
class TokenBucket:
    """Token bucket algorithm for rate limiting."""

    capacity: int
    rate: float  # tokens per second
    tokens: float = 0.0
    last_refill: float = 0.0

    def __post_init__(self):
        self.tokens = float(self.capacity)
        self.last_refill = time.monotonic()

    def consume(self) -> bool:
        """Try to consume one token. Returns True if allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


# ── API Key Middleware ──

class APIKeyMiddleware(BaseHTTPMiddleware):
    """Validate X-API-Key header or api_key query parameter.

    Skips authentication for /health and /ready endpoints.
    """

    def __init__(self, app, api_keys: set[str]):
        super().__init__(app)
        self._api_keys = api_keys

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path
        if path in ("/health", "/ready", "/metrics"):
            return await call_next(request)

        api_key = request.headers.get("x-api-key") or request.query_params.get("api_key")
        if not api_key or api_key not in self._api_keys:
            return JSONResponse(
                status_code=401,
                content={"error": "Invalid or missing API key"},
            )
        return await call_next(request)


# ── Rate Limit Middleware ──

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP token bucket rate limiting."""

    def __init__(self, app, rps: float = 10.0, burst: int = 50):
        super().__init__(app)
        self._rps = rps
        self._burst = burst
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    def _get_bucket(self, client_ip: str) -> TokenBucket:
        if client_ip not in self._buckets:
            self._buckets[client_ip] = TokenBucket(capacity=self._burst, rate=self._rps)
        return self._buckets[client_ip]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        async with self._lock:
            bucket = self._get_bucket(client_ip)
            allowed = bucket.consume()

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded"},
            )
        return await call_next(request)


# ── Request Size Limit Middleware ──

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests exceeding max_bytes."""

    def __init__(self, app, max_bytes: int = 1_048_576):
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self._max_bytes:
            return JSONResponse(
                status_code=413,
                content={"error": f"Request too large (max {self._max_bytes} bytes)"},
            )
        return await call_next(request)
