"""Health and readiness endpoints for L2 RPC server."""

from __future__ import annotations

from fastapi import FastAPI
from starlette.responses import JSONResponse

from ethclient.l2.rollup import Rollup


def register_health_endpoints(app: FastAPI, rollup: Rollup) -> None:
    """Register /health and /ready endpoints on the FastAPI app."""

    @app.get("/health")
    async def health():
        return JSONResponse(content={"status": "ok"})

    @app.get("/ready")
    async def ready():
        is_ready = rollup.is_setup
        info = rollup.chain_info()
        status = "ready" if is_ready else "not_ready"
        return JSONResponse(
            content={
                "status": status,
                "chain_id": info.get("chain_id"),
                "state_root": info.get("state_root"),
                "pending_txs": info.get("pending_txs"),
                "sealed_batches": info.get("sealed_batches"),
            },
            status_code=200 if is_ready else 503,
        )
