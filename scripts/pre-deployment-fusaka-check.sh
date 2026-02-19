#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${RPC_URL:-http://localhost:8545}"
ENGINE_URL="${ENGINE_URL:-http://localhost:8551}"

echo "=== Fusaka 배포 전 점검 ==="

echo "[1] 기본 RPC 점검"
curl -sS -X POST "${RPC_URL}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' >/dev/null

echo "[2] Engine API 점검"
curl -sS -X POST "${ENGINE_URL}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"engine_exchangeCapabilities","params":[["engine_forkchoiceUpdatedV1"]],"id":2}' >/dev/null

echo "[3] 코드베이스 Fusaka 키워드 점검"
if rg -n "eth/69|EIP-7642|EIP-7910|EIP-7939|EIP-7951" ethclient >/dev/null; then
  echo "Fusaka 관련 코드 흔적 확인"
else
  echo "Fusaka 관련 코드 흔적 없음 (추가 구현 필요)"
fi

echo "=== 점검 완료 ==="
