#!/usr/bin/env python3
"""L2Config Full-Stack — 설정 기반 전체 스택 구성 데모

L2Config를 사용하여 state_backend, prover_backend, l1_backend, da_provider를
조합하고 Rollup이 자동으로 와이어링하는 과정을 보여줍니다.
NativeProverBackend의 Python fallback, CLI 사용법도 안내합니다.

Run:
    python examples/infra/l2_config_fullstack.py
"""

import json
import tempfile
from pathlib import Path

from ethclient.l2 import (
    Rollup, L2Tx, STFResult, PythonRuntime, L2Config,
    NativeProverBackend,
)

# ── STF 정의 ────────────────────────────────────────────────────────

def kv_stf(state: dict, tx: L2Tx) -> STFResult:
    """Simple key-value store STF."""
    op = tx.data.get("op")
    if op == "set":
        key = tx.data["key"]
        value = tx.data["value"]
        state[key] = value
        return STFResult(success=True, output={"set": key})
    if op == "delete":
        key = tx.data["key"]
        if key in state:
            del state[key]
        return STFResult(success=True, output={"deleted": key})
    return STFResult(success=False, error=f"unknown op: {op}")


GENESIS = {"_version": "1.0"}
SENDER = b"\x01" * 20

# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2Config Full-Stack — Configuration-based wiring")
print("=" * 60)

# ━━━ 1. 기본 설정 (모두 in-memory) ━━━
print("\n━━━ 1. Default config (all in-memory) ━━━")

config_default = L2Config()
print(f"  name:            {config_default.name}")
print(f"  chain_id:        {config_default.chain_id}")
print(f"  state_backend:   {config_default.state_backend}")
print(f"  prover_backend:  {config_default.prover_backend}")
print(f"  l1_backend:      {config_default.l1_backend}")
print(f"  da_provider:     {config_default.da_provider}")
print(f"  max_txs/batch:   {config_default.max_txs_per_batch}")
print(f"  rpc_port:        {config_default.rpc_port}")

stf = PythonRuntime(kv_stf, genesis=GENESIS)
rollup = Rollup(stf=stf, config=config_default)
rollup.setup()

rollup.submit_tx(L2Tx(sender=SENDER, nonce=0, data={"op": "set", "key": "hello", "value": "world"}))
batch = rollup.produce_batch()
receipt = rollup.prove_and_submit(batch)
print(f"\n  Test: state['hello'] = '{rollup.state.get('hello')}'")
print(f"  Verified: {receipt.verified}")
assert receipt.verified

# ━━━ 2. 커스텀 설정 ━━━
print("\n━━━ 2. Custom config — tuned for production ━━━")

config_custom = L2Config(
    name="my-dapp-rollup",
    chain_id=31337,
    max_txs_per_batch=128,
    batch_timeout=30,
    rpc_port=9999,

    # In-memory backends (safe for demo)
    state_backend="memory",
    prover_backend="python",
    l1_backend="memory",
    da_provider="local",

    # Sequencer hardening
    mempool_max_size=50000,
    api_keys=["prod-key-001", "prod-key-002"],
    rate_limit_rps=50.0,
    rate_limit_burst=200,
    max_request_size=2 * 1024 * 1024,
    cors_origins=["https://mydapp.com"],
    enable_metrics=True,
)

print(f"  name:            {config_custom.name}")
print(f"  chain_id:        {config_custom.chain_id}")
print(f"  max_txs/batch:   {config_custom.max_txs_per_batch}")
print(f"  batch_timeout:   {config_custom.batch_timeout}s")
print(f"  mempool_max:     {config_custom.mempool_max_size:,}")
print(f"  rate_limit:      {config_custom.rate_limit_rps} rps, burst={config_custom.rate_limit_burst}")
print(f"  max_request:     {config_custom.max_request_size // 1024} KB")
print(f"  api_keys:        {len(config_custom.api_keys)} keys")
print(f"  cors_origins:    {config_custom.cors_origins}")

stf2 = PythonRuntime(kv_stf, genesis=GENESIS)
rollup2 = Rollup(stf=stf2, config=config_custom)
rollup2.setup()

for i in range(5):
    rollup2.submit_tx(L2Tx(sender=SENDER, nonce=i,
                            data={"op": "set", "key": f"k{i}", "value": f"v{i}"}))
batch2 = rollup2.produce_batch()
receipt2 = rollup2.prove_and_submit(batch2)
print(f"\n  5 txs batched and verified: {receipt2.verified}")
assert receipt2.verified

# ━━━ 3. NativeProverBackend fallback 동작 ━━━
print("\n━━━ 3. NativeProverBackend — Python fallback ━━━")

native_prover = NativeProverBackend(
    prover_binary="rapidsnark",      # 설치되어 있지 않아도 OK
    fallback_verify=True,
)
print(f"  prover_binary:   {native_prover._prover_binary}")
print(f"  fallback_verify: {native_prover._fallback_verify}")
print(f"  prove_timeout:   {native_prover._prove_timeout}s")

# native binary가 없으면 Python Groth16으로 자동 폴백
stf3 = PythonRuntime(kv_stf, genesis=GENESIS)
config_native = L2Config(prover_backend="native")
rollup3 = Rollup(stf=stf3, config=config_native)
rollup3.setup()

rollup3.submit_tx(L2Tx(sender=SENDER, nonce=0,
                        data={"op": "set", "key": "test", "value": "native"}))
batch3 = rollup3.produce_batch()
receipt3 = rollup3.prove_and_submit(batch3)
print(f"  Native prover test: verified={receipt3.verified}")
print(f"  (Falls back to Python Groth16 if rapidsnark not installed)")
assert receipt3.verified

# ━━━ 4. Backend 자동 선택 확인 ━━━
print("\n━━━ 4. Backend auto-selection by config ━━━")

configs = [
    ("memory/python/memory/local", L2Config(
        state_backend="memory", prover_backend="python",
        l1_backend="memory", da_provider="local",
    )),
    ("memory/native/memory/local", L2Config(
        state_backend="memory", prover_backend="native",
        l1_backend="memory", da_provider="local",
    )),
]

for label, cfg in configs:
    stf_x = PythonRuntime(kv_stf, genesis=GENESIS)
    r = Rollup(stf=stf_x, config=cfg)

    # Check what backends were created
    prover_type = type(r._prover).__name__
    l1_type = type(r._l1).__name__
    da_type = type(r._da).__name__
    state_type = type(r._state_store).__name__

    print(f"  [{label}]")
    print(f"    state_store={state_type} prover={prover_type} "
          f"l1={l1_type} da={da_type}")

# ━━━ 5. JSON 설정 파일 패턴 ━━━
print("\n━━━ 5. JSON config file pattern ━━━")

config_dict = {
    "name": "production-rollup",
    "chain_id": 42170,
    "max_txs_per_batch": 256,
    "batch_timeout": 60,
    "state_backend": "lmdb",
    "data_dir": "/data/l2",
    "prover_backend": "native",
    "prover_binary": "rapidsnark",
    "l1_backend": "eth_rpc",
    "l1_rpc_url": "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY",
    "l1_chain_id": 1,
    "l1_private_key": "YOUR_PRIVATE_KEY_HEX",
    "da_provider": "blob",
    "beacon_url": "http://localhost:5052",
    "rpc_port": 9545,
    "api_keys": ["key-1", "key-2"],
    "rate_limit_rps": 100.0,
    "rate_limit_burst": 500,
    "enable_metrics": True,
}

# Write to temp file
fd, tmp_name = tempfile.mkstemp(suffix=".json")
import os; os.close(fd)
tmp = Path(tmp_name)
tmp.write_text(json.dumps(config_dict, indent=2))
print(f"  Config file: {tmp}")
print(f"  Contents:")
for k, v in config_dict.items():
    v_str = str(v)
    if "KEY" in v_str:
        v_str = v_str[:20] + "..."
    print(f"    {k}: {v_str}")

# Load pattern
loaded = json.loads(tmp.read_text())
# L2Config only accepts known fields
known_fields = {f.name for f in L2Config.__dataclass_fields__.values()}
filtered = {k: v for k, v in loaded.items() if k in known_fields}
# Don't actually create with eth_rpc (no real L1)
# config_from_file = L2Config(**filtered)
print(f"\n  Loadable fields: {len(filtered)}/{len(loaded)}")
tmp.unlink()

# ━━━ 6. CLI 사용법 ━━━
print("\n━━━ 6. CLI Usage ━━━")
print("""
  ethclient l2 init --name my-rollup --dir ./l2data
    → l2.json 설정 파일 + stf.py 템플릿 생성

  ethclient l2 start --config l2.json --rpc-port 9545
    → L2 RPC 서버 시작 (미들웨어 자동 와이어링)

  ethclient l2 prove --config l2.json
    → 미증명 배치들 증명

  ethclient l2 submit --config l2.json
    → 증명된 배치를 L1에 제출
""")

# ── 최종 ──
print(f"{'=' * 60}")
print(f"  All checks passed!")
print(f"  1. Default config: verified")
print(f"  2. Custom config: 5 txs verified")
print(f"  3. NativeProver fallback: verified")
print(f"  4. Auto-selection: correct backend types")
print(f"  5. JSON config pattern demonstrated")
print(f"  6. CLI usage documented")
print(f"{'=' * 60}")
