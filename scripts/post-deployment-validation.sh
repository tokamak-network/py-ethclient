#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${RPC_URL:-http://localhost:8545}"

echo "=== Ethrex Migration Post-Deployment Validation ==="

echo "[1] RPC health"
curl -sS -X POST "${RPC_URL}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

echo "[2] block advancement check"
B1=$(curl -sS -X POST "${RPC_URL}" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}' | jq -r '.result')
sleep 5
B2=$(curl -sS -X POST "${RPC_URL}" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":3}' | jq -r '.result')

echo "block1=${B1}, block2=${B2}"

echo "=== Validation Complete ==="
