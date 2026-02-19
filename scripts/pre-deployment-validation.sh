#!/usr/bin/env bash
set -euo pipefail

echo "=== Ethrex Migration Pre-Deployment Validation ==="

bash tests/integration/engine_api_test.sh
python3 -m pytest -q tests/integration/chaindata_test.py tests/integration/archive_mode_test.py tests/integration/fusaka_compliance_test.py
bash tests/integration/fusaka_network_test.sh
bash scripts/pre-deployment-fusaka-check.sh

echo "=== Validation Complete ==="
