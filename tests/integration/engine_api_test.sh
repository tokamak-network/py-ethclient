#!/usr/bin/env bash
set -euo pipefail

ENGINE_URL="${ENGINE_URL:-http://localhost:8551}"
AUTH_HEADER=()

if [[ -n "${ENGINE_JWT:-}" ]]; then
  AUTH_HEADER=(-H "Authorization: Bearer ${ENGINE_JWT}")
fi

echo "[RK-001] Engine API smoke test 시작"

RESP=$(curl -sS -X POST "${ENGINE_URL}" \
  -H "Content-Type: application/json" \
  "${AUTH_HEADER[@]}" \
  -d '{
    "jsonrpc":"2.0",
    "method":"engine_forkchoiceUpdatedV1",
    "params":[
      {
        "headBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "safeBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "finalizedBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000"
      },
      null
    ],
    "id":1
  }')

if echo "${RESP}" | grep -q '"error"'; then
  echo "[RK-001] 실패 응답: ${RESP}"
  exit 1
fi

echo "${RESP}" | grep -q 'payloadStatus'
echo "[RK-001] 성공: engine_forkchoiceUpdatedV1 응답 확인"
