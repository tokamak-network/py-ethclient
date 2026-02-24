"""Tests for L2 middleware — APIKey, RateLimit, RequestSize."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient
from fastapi import FastAPI

from ethclient.l2.middleware import (
    APIKeyMiddleware,
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
    TokenBucket,
)


@pytest.fixture
def app():
    """Create a minimal FastAPI app for testing."""
    app = FastAPI()

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/rpc")
    async def rpc():
        return {"result": "ok"}

    return app


class TestTokenBucket:
    def test_initial_burst(self):
        bucket = TokenBucket(capacity=5, rate=1.0)
        for _ in range(5):
            assert bucket.consume() is True
        assert bucket.consume() is False

    def test_refill(self):
        import time
        bucket = TokenBucket(capacity=2, rate=100.0)  # Fast refill for testing
        bucket.consume()
        bucket.consume()
        assert bucket.consume() is False

        time.sleep(0.05)  # 50ms → should refill ~5 tokens at rate=100/s
        assert bucket.consume() is True


class TestAPIKeyMiddleware:
    def test_valid_api_key_header(self, app):
        app.add_middleware(APIKeyMiddleware, api_keys={"secret123"})
        client = TestClient(app)

        resp = client.post("/rpc", headers={"x-api-key": "secret123"})
        assert resp.status_code == 200

    def test_invalid_api_key(self, app):
        app.add_middleware(APIKeyMiddleware, api_keys={"secret123"})
        client = TestClient(app)

        resp = client.post("/rpc", headers={"x-api-key": "wrong"})
        assert resp.status_code == 401

    def test_missing_api_key(self, app):
        app.add_middleware(APIKeyMiddleware, api_keys={"secret123"})
        client = TestClient(app)

        resp = client.post("/rpc")
        assert resp.status_code == 401

    def test_api_key_query_param(self, app):
        app.add_middleware(APIKeyMiddleware, api_keys={"secret123"})
        client = TestClient(app)

        resp = client.post("/rpc?api_key=secret123")
        assert resp.status_code == 200

    def test_health_skips_auth(self, app):
        app.add_middleware(APIKeyMiddleware, api_keys={"secret123"})
        client = TestClient(app)

        resp = client.get("/health")
        assert resp.status_code == 200


class TestRateLimitMiddleware:
    def test_within_burst(self, app):
        app.add_middleware(RateLimitMiddleware, rps=10.0, burst=5)
        client = TestClient(app)

        for _ in range(5):
            resp = client.post("/rpc")
            assert resp.status_code == 200

    def test_exceeds_burst(self, app):
        app.add_middleware(RateLimitMiddleware, rps=10.0, burst=3)
        client = TestClient(app)

        results = []
        for _ in range(6):
            resp = client.post("/rpc")
            results.append(resp.status_code)

        assert 429 in results

    def test_per_ip_isolation(self, app):
        """Different IPs should have independent buckets."""
        middleware = RateLimitMiddleware(app, rps=10.0, burst=2)
        bucket1 = middleware._get_bucket("1.2.3.4")
        bucket2 = middleware._get_bucket("5.6.7.8")
        assert bucket1 is not bucket2


class TestRequestSizeLimitMiddleware:
    def test_small_request_passes(self, app):
        app.add_middleware(RequestSizeLimitMiddleware, max_bytes=1024)
        client = TestClient(app)

        resp = client.post("/rpc", content=b"small", headers={"content-length": "5"})
        assert resp.status_code == 200

    def test_large_request_rejected(self, app):
        app.add_middleware(RequestSizeLimitMiddleware, max_bytes=10)
        client = TestClient(app)

        resp = client.post(
            "/rpc",
            content=b"x" * 100,
            headers={"content-length": "100"},
        )
        assert resp.status_code == 413

    def test_no_content_length_passes(self, app):
        """Requests without content-length header should pass."""
        app.add_middleware(RequestSizeLimitMiddleware, max_bytes=10)
        client = TestClient(app)

        resp = client.get("/health")
        assert resp.status_code == 200
