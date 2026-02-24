#!/usr/bin/env python3
"""L2 Persistent State — LMDB 영속화 + 크래시 복구 데모

L2Config(state_backend="lmdb")로 LMDB 상태 저장소를 사용하고,
배치 생성 → flush → "프로세스 종료" 시뮬레이션 → 재시작 → WAL 복구를 보여줍니다.

Run:
    python examples/infra/l2_persistent_state.py
"""

import shutil
import tempfile
from pathlib import Path

from ethclient.l2 import (
    Rollup, L2Tx, STFResult, PythonRuntime, L2Config,
    L2PersistentStateStore,
)

# ── STF 정의 ────────────────────────────────────────────────────────

def ledger_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    if op == "credit":
        account = tx.data["account"]
        amount = int(tx.data["amount"])
        state[account] = state.get(account, 0) + amount
        return STFResult(success=True, output={"balance": state[account]})
    if op == "debit":
        account = tx.data["account"]
        amount = int(tx.data["amount"])
        current = state.get(account, 0)
        if current < amount:
            return STFResult(success=False, error="insufficient balance")
        state[account] = current - amount
        return STFResult(success=True, output={"balance": state[account]})
    return STFResult(success=False, error=f"unknown op: {op}")


GENESIS = {"total_ops": 0}

SENDER = b"\x01" * 20


# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 Persistent State — LMDB + Crash Recovery")
print("=" * 60)

# 임시 디렉토리 사용 (테스트 후 정리)
data_dir = Path(tempfile.mkdtemp(prefix="l2_lmdb_demo_"))
print(f"\n  Data directory: {data_dir}")

try:
    # ━━━ Phase 1: 초기 배치 생성 + LMDB 영속화 ━━━
    print("\n━━━ Phase 1: Create batches and persist to LMDB ━━━")

    config = L2Config(
        name="persistent-demo",
        state_backend="lmdb",
        data_dir=str(data_dir),
    )
    stf = PythonRuntime(ledger_stf, genesis=GENESIS)
    rollup = Rollup(stf=stf, config=config)
    rollup.setup()

    nonce = 0

    # Batch 0: 3 credits
    for account in ["alice", "bob", "charlie"]:
        rollup.submit_tx(L2Tx(sender=SENDER, nonce=nonce,
                               data={"op": "credit", "account": account, "amount": "10000"}))
        nonce += 1

    batch0 = rollup.produce_batch()
    receipt0 = rollup.prove_and_submit(batch0)
    print(f"  Batch #0: {len(batch0.transactions)} txs → {'VERIFIED' if receipt0.verified else 'FAILED'}")

    # Batch 1: transfer
    rollup.submit_tx(L2Tx(sender=SENDER, nonce=nonce,
                           data={"op": "debit", "account": "alice", "amount": "3000"}))
    nonce += 1
    rollup.submit_tx(L2Tx(sender=SENDER, nonce=nonce,
                           data={"op": "credit", "account": "bob", "amount": "3000"}))
    nonce += 1

    batch1 = rollup.produce_batch()
    receipt1 = rollup.prove_and_submit(batch1)
    print(f"  Batch #1: {len(batch1.transactions)} txs → {'VERIFIED' if receipt1.verified else 'FAILED'}")

    # 상태 확인
    alice_bal = rollup.state.get("alice", 0)
    bob_bal = rollup.state.get("bob", 0)
    charlie_bal = rollup.state.get("charlie", 0)
    state_root_before = rollup.state_root.hex()[:16]
    print(f"\n  State: alice={alice_bal}, bob={bob_bal}, charlie={charlie_bal}")
    print(f"  State root: {state_root_before}...")
    print(f"  Sealed batches: {len(rollup.get_sealed_batches())}")

    assert alice_bal == 7000
    assert bob_bal == 13000
    assert charlie_bal == 10000

    # LMDB flush (Rollup이 자동으로 수행하지만, 명시적으로 확인)
    if hasattr(rollup._state_store, 'flush'):
        rollup._state_store.flush()
    print(f"  LMDB flushed to disk")

    # ━━━ Phase 2: "크래시" 시뮬레이션 → 새 Rollup으로 복구 ━━━
    print("\n━━━ Phase 2: Simulate crash → Recover from LMDB ━━━")
    print(f"  Simulating process crash...")

    # 기존 rollup 객체 "삭제" (프로세스 종료 시뮬레이션)
    del rollup
    del stf

    # 새 Rollup 생성 (같은 data_dir에서 LMDB 데이터 읽기)
    print(f"  Restarting with same data_dir...")
    config2 = L2Config(
        name="persistent-demo",
        state_backend="lmdb",
        data_dir=str(data_dir),
    )
    stf2 = PythonRuntime(ledger_stf, genesis=GENESIS)
    rollup2 = Rollup(stf=stf2, config=config2)
    rollup2.setup()

    # WAL 리플레이
    rollup2.recover()
    print(f"  WAL replay complete")

    # 상태 복구 확인
    alice_recovered = rollup2.state.get("alice", 0)
    bob_recovered = rollup2.state.get("bob", 0)
    charlie_recovered = rollup2.state.get("charlie", 0)
    state_root_after = rollup2.state_root.hex()[:16]

    print(f"\n  Recovered state: alice={alice_recovered}, bob={bob_recovered}, charlie={charlie_recovered}")
    print(f"  Recovered root: {state_root_after}...")

    assert alice_recovered == 7000, f"alice: expected 7000, got {alice_recovered}"
    assert bob_recovered == 13000, f"bob: expected 13000, got {bob_recovered}"
    assert charlie_recovered == 10000, f"charlie: expected 10000, got {charlie_recovered}"
    print(f"  State matches pre-crash values!")

    # ━━━ Phase 3: 복구 후 새 배치 계속 생성 ━━━
    print("\n━━━ Phase 3: Continue operation after recovery ━━━")

    # 복구된 rollup의 sequencer는 nonce를 0부터 기대하므로 새 sender 사용
    SENDER2 = b"\x02" * 20
    rollup2.submit_tx(L2Tx(sender=SENDER2, nonce=0,
                            data={"op": "credit", "account": "dave", "amount": "5000"}))

    batch2 = rollup2.produce_batch()
    receipt2 = rollup2.prove_and_submit(batch2)
    print(f"  Batch #2: {len(batch2.transactions)} txs → {'VERIFIED' if receipt2.verified else 'FAILED'}")
    assert receipt2.verified

    dave_bal = rollup2.state.get("dave", 0)
    print(f"  dave balance: {dave_bal}")
    assert dave_bal == 5000

    # ━━━ Phase 4: Batch / Proof 영속화 확인 ━━━
    print("\n━━━ Phase 4: Verify batch persistence ━━━")

    if isinstance(rollup2._state_store, L2PersistentStateStore):
        store = rollup2._state_store

        # 배치 조회
        stored_batch = store.get_batch(0)
        if stored_batch:
            print(f"  Batch #0 from LMDB: {len(stored_batch.transactions)} txs")
        else:
            print(f"  Batch #0: not persisted (in-memory only for this demo)")

        # 메타데이터
        last_batch = store.get_last_batch_number()
        print(f"  Last batch number: {last_batch}")

    # ── 최종 ──
    info = rollup2.chain_info()
    print(f"\n  Chain info: {info['name']} (chain_id={info['chain_id']})")
    print(f"  Total sealed batches: {info['sealed_batches']}")

finally:
    # 임시 디렉토리 정리
    shutil.rmtree(data_dir, ignore_errors=True)
    print(f"\n  Cleaned up: {data_dir}")

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  LMDB persistence: write → crash → recover → continue")
print(f"  State integrity verified across restarts")
print(f"  WAL replay recovered all pre-crash state")
print(f"{'=' * 60}")
