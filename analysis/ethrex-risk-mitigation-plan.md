# Ethrex/py-ethclient Migration: Risk Mitigation Plan

## Overview

This document defines mitigation actions for the top five migration risks when replacing `op-geth` with `ethrex` (`py-ethclient`) in OP Stack environments.

## Risk Matrix

| Risk ID | Risk | Impact | Severity | Trigger Time |
|---|---|---|---|---|
| RK-001 | Engine API missing/incomplete | L2 block production halt | Critical | Immediately after cutover |
| RK-002 | Data directory incompatibility | Sync failure / invalid state bootstrap | Critical | Early rollout |
| RK-003 | No metrics endpoint/port | Monitoring blind spots | High | Immediately after rollout |
| RK-004 | Archive mode limitations | Historical query/explorer gaps | High | Mid-term operation |
| RK-005 | Fusaka incompatibility | Network partition / block validation failures | Critical | At Fusaka activation |

---

## RK-001: Engine API

### Goal
Provide an Engine API endpoint usable by `op-node` and prevent `Method not found` failures.

### Implemented Mitigations

#### Phase 1: Engine API V1 Support (Baseline)
- Added Engine API registration module:
  - `engine_exchangeCapabilities`
  - `engine_getClientVersionV1`
  - `engine_forkchoiceUpdatedV1`
  - `engine_newPayloadV1`
  - `engine_getPayloadV1`
  - File: `ethclient/rpc/engine_api.py`
- Added dedicated Engine RPC port option:
  - `--engine-port` (default: `8551`)
  - File: `ethclient/main.py`
- Added optional JWT authentication for `engine_*` methods:
  - `--jwt-secret` (raw secret or file path)
  - File: `ethclient/rpc/server.py`
- Added smoke test script:
  - `tests/integration/engine_api_test.sh`
- Added Docker configuration:
  - `EXPOSE 8551/tcp` (Engine API port)
  - File: `Dockerfile`

#### Phase 2: Engine API V2/V3 Support (Enhanced)
- **engine_newPayloadV2/V3** implementation:
  - Actual block execution with transaction processing
  - State root verification and validation
  - Withdrawals support (V2+) and requests support (V3+)
  - Returns detailed PayloadStatus with validation errors
  - File: `ethclient/rpc/engine_api.py`

- **engine_forkchoiceUpdatedV2/V3** implementation:
  - Block tree fork choice updates (head, safe, finalized)
  - Payload attribute handling for block building triggers
  - Parent beacon block root support (V3+)
  - Payload ID generation for subsequent `engine_getPayloadV3` calls
  - File: `ethclient/rpc/engine_api.py`

- **engine_getPayloadV3** implementation:
  - Retrieves constructed execution payload by payload ID
  - Blob bundle support for proto-danksharding
  - Block value reporting for MEV
  - Payload memory management with ~12 second TTL
  - File: `ethclient/rpc/engine_api.py`

- Integration with block building engine:
  - Execution layer state transition function
  - Transaction selection and ordering (MEV support)
  - Gas accounting and limit validation
  - File: `ethclient/execution/block_builder.py`

- Enhanced validation tests:
  - `tests/integration/engine_api_v2_v3_test.py` (V2/V3 specific tests)
  - Block execution correctness verification
  - State root matching validation

### Validation Command
```bash
bash tests/integration/engine_api_test.sh
```
### References
https://specs.optimism.io/protocol/exec-engine.html

---

## RK-002: Data Directory Compatibility

### Goal
Avoid startup ambiguity and provide deterministic migration behavior from geth-style data paths.

### Implemented Mitigations
- Added geth-compatible datadir inputs:
  - CLI alias: `--datadir` (alias of `--data-dir`)
  - Env fallback: `DATADIR`, `DATA_DIR`
  - File: `ethclient/main.py`
- Added migration helper script:
  - `scripts/migrate-chaindata.sh`
  - Supports safe default (`FORCE_RESYNC=true`) to avoid unsafe state reuse.
- Added integration checks:
  - `tests/integration/chaindata_test.py`

### Validation Command
```bash
python3 -m pytest -q tests/integration/chaindata_test.py
```

---

## RK-003: Metrics Availability

### Goal
Expose baseline Prometheus metrics and restore observability.

### Implemented Mitigations
- Added `/metrics` endpoint to RPC server.
- Added dedicated metrics service startup:
  - `--metrics-port` (default: `6060`)
  - File: `ethclient/main.py`
- Exposed core metrics:
  - `ethclient_up`
  - `eth_block_number`
  - `eth_peer_count`
  - `eth_syncing`
- Added dashboard template:
  - `monitoring/ethrex-dashboard.json`

### Validation Command
```bash
curl -s http://localhost:6060/metrics
```

---

## RK-004: Archive Mode Constraints

### Goal
Prevent silent incorrect historical-state responses when archive semantics are unavailable.

### Implemented Mitigations
- Added explicit archive semantics flag:
  - `--archive`
  - File: `ethclient/main.py`
- Added RPC guard for historical state reads when archive mode is disabled:
  - Affects `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`
  - Returns explicit RPC error instead of silently returning latest-state semantics
  - File: `ethclient/rpc/eth_api.py`
- Added integration tests:
  - `tests/integration/archive_mode_test.py`

### Validation Command
```bash
python3 -m pytest -q tests/integration/archive_mode_test.py
```

---

## RK-005: Fusaka Compatibility

### Goal
Track and preflight Fusaka readiness; fail early before production cutover.

### Implemented Mitigations
- Added Fusaka pre-deployment check script:
  - `scripts/pre-deployment-fusaka-check.sh`
- Added network smoke test:
  - `tests/integration/fusaka_network_test.sh`
- Added compliance tracking test scaffold:
  - `tests/integration/fusaka_compliance_test.py`
- Added implementation tracker document:
  - `analysis/fusaka_implementation_status.md`

### Current Status
- Full Fusaka support is **not complete**.
- Tracking and preflight automation are in place.
- Detailed execution plan remains in:
  - `analysis/fusaka_compat_plan_ko.md`

### Validation Commands
```bash
bash tests/integration/fusaka_network_test.sh
python3 -m pytest -q tests/integration/fusaka_compliance_test.py
bash scripts/pre-deployment-fusaka-check.sh
```

---

## Unified Validation

Pre-deployment:
```bash
bash scripts/pre-deployment-validation.sh
```

Post-deployment:
```bash
bash scripts/post-deployment-validation.sh
```

## Deliverables Added/Updated

### Phase 1 (V1 Support)
- Updated:
  - `analysis/ethrex-risk-mitigation-plan.md` (English)
  - `ethclient/main.py`
  - `ethclient/rpc/server.py`
  - `ethclient/rpc/eth_api.py`
  - `Dockerfile` (EXPOSE 8551/tcp)
- Added:
  - `ethclient/rpc/engine_api.py` (V1 methods)
  - `scripts/migrate-chaindata.sh`
  - `scripts/pre-deployment-fusaka-check.sh`
  - `scripts/pre-deployment-validation.sh`
  - `scripts/post-deployment-validation.sh`
  - `tests/integration/engine_api_test.sh`
  - `tests/integration/chaindata_test.py`
  - `tests/integration/archive_mode_test.py`
  - `tests/integration/fusaka_network_test.sh`
  - `tests/integration/fusaka_compliance_test.py`
  - `monitoring/ethrex-dashboard.json`
  - `analysis/fusaka_implementation_status.md`

### Phase 2 (V2/V3 Support) - **Completed**
- Updated:
  - `ethclient/rpc/engine_api.py` (V2/V3 methods with actual block execution)
  - `ethclient/main.py` (pass fork_choice and chain_config to engine_api)
  - `Dockerfile` (EXPOSE 8551/tcp, 6060/tcp)
- Implementation Details:
  - `_handle_forkchoice_update()`: Common V1/V2/V3 logic with ForkChoice integration
  - `_execute_payload()`: Real block execution using validate_and_execute_block()
  - `_build_base_payload()`: OP Stack-aware ExecutionPayload construction
  - L2-specific blob transaction validation (rejected with appropriate error)
  - Fallback to SYNCING when store/chain_config unavailable (backward compatible)