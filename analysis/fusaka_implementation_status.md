# Fusaka Implementation Status

## Scope

This tracker follows RK-005 mitigation work for Fusaka compatibility in `py-ethclient`.

## Status

### Networking
- [x] EIP-7642 `eth/69` (기본 Status/메시지 코드/협상)
- [x] EIP-7910 ReceiptsV2 (메시지 타입/응답 포맷 분기)

### Validation
- [x] EIP-7934 `MAX_RLP_BLOCK_SIZE`
- [x] EIP-7825 `MAX_TX_GAS`

### EVM
- [x] EIP-7939 `CLZ`
- [x] EIP-7951 `P256VERIFY`
- [~] EIP-7823 SetCode transaction update (Prague gating + auth list 필수, 세부 규칙 추가 필요)

### Other
- [x] EIP-7883 MODEXP input bound
- [~] EIP-7892 blob fee schedule (BPO 스케줄/eth_config 반영, 실네트워크 벡터 검증 필요)
- [x] EIP-7918 blob base fee update fraction (Osaka 이후 최소값 가드)

## Notes

- Current mitigation includes pre-deployment checks and compatibility smoke tests.
- Full Fusaka support requires protocol, VM, and validation updates.
- Test execution blocker:
  - Current environment is Python 3.14 only.
  - `coincurve` build fails on this runtime, so full `pytest` execution is blocked.
  - Recommended: run tests on Python 3.12 environment (project baseline).
