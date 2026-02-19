#!/usr/bin/env bash
set -euo pipefail

SOURCE_CHAINDATA="${SOURCE_CHAINDATA:-/data/geth/chaindata}"
DEST_ROOT="${DEST_ROOT:-/data/ethclient}"
DEST_CHAINDATA="${DEST_ROOT}/chaindata"

echo "[RK-002] 데이터 디렉토리 마이그레이션 점검 시작"

if [[ ! -d "${SOURCE_CHAINDATA}" ]]; then
  echo "[RK-002] 기존 op-geth chaindata 없음: ${SOURCE_CHAINDATA}"
  mkdir -p "${DEST_CHAINDATA}"
  exit 0
fi

mkdir -p "${DEST_CHAINDATA}"
echo "[RK-002] 기존 데이터 감지: ${SOURCE_CHAINDATA}"

# 구조 호환성은 보장되지 않으므로, 운영 기본값은 안전한 재동기화다.
if [[ "${FORCE_RESYNC:-true}" == "true" ]]; then
  echo "[RK-002] FORCE_RESYNC=true 이므로 py-ethclient chaindata를 초기화합니다"
  rm -rf "${DEST_CHAINDATA}"
  mkdir -p "${DEST_CHAINDATA}"
else
  echo "[RK-002] FORCE_RESYNC=false 이므로 파일 복사를 시도합니다"
  cp -a "${SOURCE_CHAINDATA}"/. "${DEST_CHAINDATA}"/ || true
fi

echo "[RK-002] 완료: ${DEST_CHAINDATA}"
