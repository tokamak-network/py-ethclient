#!/usr/bin/env python3
"""L2 RPC Server — JSON-RPC + 미들웨어 + 헬스체크 데모

L2 RPC 서버를 구성하고 7개 l2_* 메서드, 미들웨어(API Key, Rate Limit, Request Size),
/health + /ready + /metrics 엔드포인트를 설정한 뒤 httpx로 호출합니다.

Run:
    python examples/infra/l2_rpc_server.py
"""

import threading
import time

import httpx
import uvicorn

from ethclient.l2 import (
    Rollup, L2Tx, STFResult, PythonRuntime, L2Config,
)
from ethclient.l2.rpc_api import register_l2_api
from ethclient.l2.health import register_health_endpoints
from ethclient.l2.metrics import L2MetricsCollector
from ethclient.l2.middleware import (
    APIKeyMiddleware,
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
)
from ethclient.rpc.server import RPCServer

# ── STF 정의 ────────────────────────────────────────────────────────

def counter_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    if op == "increment":
        state["count"] = state.get("count", 0) + 1
        return STFResult(success=True, output={"count": state["count"]})
    if op == "set":
        state["count"] = int(tx.data["value"])
        return STFResult(success=True, output={"count": state["count"]})
    return STFResult(success=False, error=f"unknown op: {op}")


GENESIS = {"count": 0}

# ── 서버 구성 ────────────────────────────────────────────────────────

API_KEY = "demo-secret-key-12345"
PORT = 19545  # 테스트용 포트

config = L2Config(
    name="rpc-demo",
    chain_id=42170,
    rpc_port=PORT,
    api_keys=[API_KEY],
    rate_limit_rps=100.0,
    rate_limit_burst=200,
    max_request_size=512 * 1024,
)

stf = PythonRuntime(counter_stf, genesis=GENESIS)
rollup = Rollup(stf=stf, config=config)
rollup.setup()

# ── RPC 서버 + 미들웨어 + 헬스/메트릭 ────────────────────────────
rpc = RPCServer()
register_l2_api(rpc, rollup)
register_health_endpoints(rpc.app, rollup)

# Metrics
metrics_collector = L2MetricsCollector(rollup)
rpc.set_metrics_provider(metrics_collector.collect)

# Middleware (순서: 바깥 → 안쪽)
rpc.app.add_middleware(RequestSizeLimitMiddleware, max_bytes=config.max_request_size)
rpc.app.add_middleware(RateLimitMiddleware, rps=config.rate_limit_rps, burst=config.rate_limit_burst)
rpc.app.add_middleware(APIKeyMiddleware, api_keys=set(config.api_keys))


# ── 서버 시작 (백그라운드 스레드) ────────────────────────────────
def run_server():
    uvicorn.run(rpc.app, host="127.0.0.1", port=PORT, log_level="error")


server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()
time.sleep(1.0)  # 서버 시작 대기

BASE = f"http://127.0.0.1:{PORT}"
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}


def rpc_call(method: str, params=None, headers=None):
    headers = headers or HEADERS
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
    resp = httpx.post(BASE, json=payload, headers=headers, timeout=60.0)
    return resp.status_code, resp.json()


# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 RPC Server — JSON-RPC + Middleware Demo")
print("=" * 60)

# 1. Health check (API key 불필요)
print("\n[1] Health check (no API key needed)")
resp = httpx.get(f"{BASE}/health", timeout=10.0)
print(f"  GET /health → {resp.status_code}: {resp.json()}")
assert resp.status_code == 200

# 2. Readiness check
print("\n[2] Readiness check")
resp = httpx.get(f"{BASE}/ready", timeout=10.0)
body = resp.json()
print(f"  GET /ready → {resp.status_code}: status={body['status']}")
assert body["status"] == "ready"

# 3. API key 인증 실패
print("\n[3] API key authentication — missing key")
status, body = rpc_call("l2_chainInfo", headers={"Content-Type": "application/json"})
print(f"  No API key → {status}: {body.get('error', 'N/A')}")
assert status == 401

# 4. Chain info
print("\n[4] l2_chainInfo")
status, body = rpc_call("l2_chainInfo")
result = body.get("result", body)
print(f"  name={result.get('name')} chain_id={result.get('chain_id')} "
      f"is_setup={result.get('is_setup')}")
assert result["name"] == "rpc-demo"

# 5. 트랜잭션 전송
print("\n[5] l2_sendTransaction")
SENDER = "0x" + "01" * 20
tx_data = {
    "sender": SENDER,
    "nonce": 0,
    "data": {"op": "increment"},
}
status, body = rpc_call("l2_sendTransaction", [tx_data])
result = body.get("result", body)
print(f"  txHash: {result.get('txHash', 'N/A')}")
assert "txHash" in result

# 추가 트랜잭션
for i in range(1, 4):
    rpc_call("l2_sendTransaction", [{
        "sender": SENDER, "nonce": i,
        "data": {"op": "increment"},
    }])
print(f"  Sent 3 more txs (total 4)")

# 6. 배치 생성
print("\n[6] l2_produceBatch")
status, body = rpc_call("l2_produceBatch")
result = body.get("result", body)
print(f"  Batch #{result.get('number')}: {result.get('txCount')} txs")
batch_num = result["number"]

# 7. 증명 + 제출
print("\n[7] l2_proveAndSubmit")
status, body = rpc_call("l2_proveAndSubmit", [batch_num])
result = body.get("result", body)
print(f"  verified={result.get('verified')} stateRoot={result.get('stateRoot', '')[:18]}...")
assert result["verified"]

# 8. 상태 조회
print("\n[8] l2_getState")
status, body = rpc_call("l2_getState")
result = body.get("result", body)
print(f"  count = {result.get('count')}")
assert result["count"] == 4

# 9. 배치 조회
print("\n[9] l2_getBatch")
status, body = rpc_call("l2_getBatch", [batch_num])
result = body.get("result", body)
print(f"  Batch #{result['number']}: txCount={result['txCount']} "
      f"proven={result['proven']} submitted={result['submitted']}")

# 10. Metrics
print("\n[10] Metrics endpoint")
resp = httpx.get(f"{BASE}/metrics", timeout=10.0)
print(f"  GET /metrics → {resp.status_code}")
for line in resp.text.strip().split("\n")[:5]:
    print(f"    {line}")

# ── 최종 검증 ───────────────────────────────────────────────────────

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  RPC server: 7 l2_* methods registered")
print(f"  Middleware: APIKey + RateLimit + RequestSize")
print(f"  Endpoints: /health, /ready, /metrics")
print(f"  Batch #{batch_num}: 4 txs → verified on L1")
print(f"{'=' * 60}")
