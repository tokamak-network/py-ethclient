#!/usr/bin/env python3
"""L2 Multi-Batch Operations — 멀티배치 운영 루프 데모

10개 배치를 루프로 생성 → 증명 → 제출하며,
prove_batch / submit_batch 분리 패턴과 배치 체이닝을 보여줍니다.

Run:
    python examples/infra/l2_multi_batch_ops.py
"""

import time

from ethclient.l2 import Rollup, L2Tx, STFResult, PythonRuntime, L2Config

# ── STF 정의 ────────────────────────────────────────────────────────

def counter_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    if op == "increment":
        state["count"] = state.get("count", 0) + 1
        state["last_sender"] = tx.sender.hex()
        return STFResult(success=True, output={"count": state["count"]})
    if op == "add":
        amount = int(tx.data["amount"])
        state["count"] = state.get("count", 0) + amount
        return STFResult(success=True, output={"count": state["count"]})
    return STFResult(success=False, error=f"unknown op: {op}")


GENESIS = {"count": 0}

SENDER_A = b"\x01" * 20
SENDER_B = b"\x02" * 20

# ── Rollup 구성 ─────────────────────────────────────────────────────

config = L2Config(name="multi-batch-demo", max_txs_per_batch=5)
stf = PythonRuntime(counter_stf, genesis=GENESIS)
rollup = Rollup(stf=stf, config=config)
rollup.setup()

# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 Multi-Batch Operations — 10 batch loop")
print("=" * 60)

# ━━━ Phase 1: 10개 배치 루프 (produce → prove_and_submit) ━━━
print("\n━━━ Phase 1: Sequential 10-batch loop ━━━")

nonces = {SENDER_A: 0, SENDER_B: 0}
t_start = time.perf_counter()

for batch_idx in range(10):
    # 각 배치에 3개 트랜잭션
    for i in range(3):
        sender = SENDER_A if i % 2 == 0 else SENDER_B
        rollup.submit_tx(L2Tx(
            sender=sender,
            nonce=nonces[sender],
            data={"op": "increment"},
        ))
        nonces[sender] += 1

    batch = rollup.produce_batch()
    receipt = rollup.prove_and_submit(batch)

    status = "OK" if receipt.verified else "FAIL"
    print(f"  Batch #{batch.number:2d}: {len(batch.transactions)} txs → {status}  "
          f"root={batch.new_state_root.hex()[:12]}...")

t_phase1 = time.perf_counter() - t_start
print(f"\n  10 batches in {t_phase1:.2f}s ({t_phase1/10:.3f}s per batch)")

# 상태 검증
count = rollup.state["count"]
assert count == 30, f"Expected 30, got {count}"
print(f"  State count: {count} (30 increments)")

# ━━━ Phase 2: prove / submit 분리 패턴 ━━━
print("\n━━━ Phase 2: Separate prove → submit pipeline ━━━")

# 먼저 5개 배치를 한번에 생성 (prove 전)
unproven_batches = []
for batch_idx in range(5):
    for i in range(2):
        sender = SENDER_A if i % 2 == 0 else SENDER_B
        rollup.submit_tx(L2Tx(
            sender=sender,
            nonce=nonces[sender],
            data={"op": "add", "amount": "10"},
        ))
        nonces[sender] += 1

    batch = rollup.produce_batch()
    unproven_batches.append(batch)
    print(f"  Sealed batch #{batch.number} ({len(batch.transactions)} txs) — not yet proven")

# prove 단계 (batch 실행과 분리)
print(f"\n  --- Proving {len(unproven_batches)} batches ---")
t_prove_start = time.perf_counter()
proven_batches = []
for batch in unproven_batches:
    proven = rollup.prove_batch(batch)
    proven_batches.append(proven)
    print(f"  Proved batch #{proven.number}: proven={proven.proven}")
    assert proven.proven

t_prove = time.perf_counter() - t_prove_start
print(f"  Proving time: {t_prove:.2f}s")

# submit 단계
print(f"\n  --- Submitting {len(proven_batches)} proven batches ---")
t_submit_start = time.perf_counter()
for batch in proven_batches:
    receipt = rollup.submit_batch(batch)
    print(f"  Submitted batch #{receipt.batch_number}: verified={receipt.verified}")
    assert receipt.verified

t_submit = time.perf_counter() - t_submit_start
print(f"  Submission time: {t_submit:.2f}s")

# ━━━ Phase 3: 배치 체이닝 검증 ━━━
print("\n━━━ Phase 3: Batch chaining verification ━━━")

all_batches = rollup.get_sealed_batches()
print(f"  Total sealed batches: {len(all_batches)}")

# 배치 연결성 확인: batch[n].new_state_root == batch[n+1].old_state_root
chain_valid = True
for i in range(1, len(all_batches)):
    prev_new = all_batches[i - 1].new_state_root
    curr_old = all_batches[i].old_state_root
    if prev_new != curr_old:
        print(f"  BREAK at batch #{all_batches[i].number}: "
              f"prev.new={prev_new.hex()[:8]} != curr.old={curr_old.hex()[:8]}")
        chain_valid = False

print(f"  Chain continuity: {'VALID' if chain_valid else 'BROKEN'}")
assert chain_valid

# ━━━ Phase 4: 배치 조회 API ━━━
print("\n━━━ Phase 4: Batch query API ━━━")

# get_batch by number
batch_5 = rollup.get_batch(5)
assert batch_5 is not None
print(f"  get_batch(5): #{batch_5.number}, {len(batch_5.transactions)} txs, "
      f"sealed={batch_5.sealed}, proven={batch_5.proven}, submitted={batch_5.submitted}")

# chain_info
info = rollup.chain_info()
print(f"  chain_info: name={info['name']}, sealed_batches={info['sealed_batches']}")

# get_sealed_batches
sealed = rollup.get_sealed_batches()
proven_count = sum(1 for b in sealed if b.proven)
submitted_count = sum(1 for b in sealed if b.submitted)
verified_count = sum(1 for b in sealed if b.verified)
print(f"  Batch stats: sealed={len(sealed)} proven={proven_count} "
      f"submitted={submitted_count} verified={verified_count}")

# ── 최종 상태 ────────────────────────────────────────────────────────

final_count = rollup.state["count"]
expected = 30 + (5 * 2 * 10)  # 30 + 100
print(f"\n  Final count: {final_count} (expected {expected})")
assert final_count == expected

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  Phase 1: 10 sequential batches ({t_phase1:.2f}s)")
print(f"  Phase 2: prove/submit pipeline ({t_prove + t_submit:.2f}s)")
print(f"  Phase 3: Batch chain integrity verified")
print(f"  Phase 4: Query API working")
print(f"  Total: 15 batches, {final_count} state transitions")
print(f"{'=' * 60}")
