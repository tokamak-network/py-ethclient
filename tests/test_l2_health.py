"""Tests for L2 health and readiness endpoints."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient
from fastapi import FastAPI

from ethclient.l2.health import register_health_endpoints
from ethclient.l2.rollup import Rollup
from ethclient.l2.types import STFResult


def _make_stf(state, tx):
    state["counter"] = state.get("counter", 0) + 1
    return STFResult(success=True)


class TestHealthEndpoint:
    def test_health_returns_ok(self):
        app = FastAPI()
        rollup = Rollup(stf=_make_stf)
        register_health_endpoints(app, rollup)

        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestReadyEndpoint:
    def test_not_ready_before_setup(self):
        app = FastAPI()
        rollup = Rollup(stf=_make_stf)
        register_health_endpoints(app, rollup)

        client = TestClient(app)
        resp = client.get("/ready")
        assert resp.status_code == 503
        assert resp.json()["status"] == "not_ready"

    def test_ready_after_setup(self):
        app = FastAPI()
        rollup = Rollup(stf=_make_stf)
        rollup.setup()
        register_health_endpoints(app, rollup)

        client = TestClient(app)
        resp = client.get("/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert "chain_id" in data
        assert "state_root" in data
        assert "pending_txs" in data
        assert "sealed_batches" in data
