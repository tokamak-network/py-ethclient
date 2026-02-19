#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${RPC_URL:-http://localhost:8545}"

echo "[RK-005] Fusaka 네트워크 호환성 스모크 테스트"

CHAIN_ID=$(curl -sS -X POST "${RPC_URL}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' | jq -r '.result // empty')

if [[ -z "${CHAIN_ID}" ]]; then
  echo "[RK-005] chainId 조회 실패"
  exit 1
fi

echo "[RK-005] chainId=${CHAIN_ID}"

BLOCK=$(curl -sS -X POST "${RPC_URL}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}' | jq -r '.result // empty')

if [[ -z "${BLOCK}" ]]; then
  echo "[RK-005] blockNumber 조회 실패"
  exit 1
fi

echo "[RK-005] blockNumber=${BLOCK}"
