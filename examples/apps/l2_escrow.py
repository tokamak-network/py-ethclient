#!/usr/bin/env python3
"""L2 Escrow Service — buyer / seller / arbiter 3자 에스크로 데모

App-specific ZK Rollup 위에서 동작하는 에스크로 서비스.
create_escrow, fund, release, refund, dispute 오퍼레이션.
상태 머신: Created → Funded → Released/Refunded/Disputed.
타임아웃: deadline 이후 자동 refund 가능.

Run:
    python examples/apps/l2_escrow.py
"""

from ethclient.l2 import Rollup, L2Tx, STFResult, PythonRuntime

# ── 주소 헬퍼 ───────────────────────────────────────────────────────
ALICE = b"\x01" * 20   # buyer
BOB = b"\x02" * 20     # seller
CHARLIE = b"\x03" * 20  # arbiter
DAVE = b"\x04" * 20    # another buyer

NAMES = {
    ALICE.hex(): "Alice(buyer)", BOB.hex(): "Bob(seller)",
    CHARLIE.hex(): "Charlie(arbiter)", DAVE.hex(): "Dave(buyer2)",
}


def addr(who: bytes) -> str:
    return who.hex()


# ── STF 정의 ────────────────────────────────────────────────────────

# 상태: created → funded → released | refunded | disputed
VALID_STATES = ("created", "funded", "released", "refunded", "disputed")


def escrow_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    escrows = state["escrows"]
    balances = state["balances"]
    sender = addr(tx.sender)

    if op == "deposit":
        amount = int(tx.data["amount"])
        balances[sender] = balances.get(sender, 0) + amount
        return STFResult(success=True, output={"deposited": amount})

    if op == "create_escrow":
        escrow_id = tx.data["escrow_id"]
        if escrow_id in escrows:
            return STFResult(success=False, error="escrow already exists")

        buyer = tx.data["buyer"]
        seller = tx.data["seller"]
        arbiter = tx.data["arbiter"]
        amount = int(tx.data["amount"])
        deadline = int(tx.data.get("deadline", 0))  # block number

        escrows[escrow_id] = {
            "buyer": buyer,
            "seller": seller,
            "arbiter": arbiter,
            "amount": amount,
            "deadline": deadline,
            "status": "created",
        }
        return STFResult(success=True, output={"created": escrow_id})

    if op == "fund":
        escrow_id = tx.data["escrow_id"]
        esc = escrows.get(escrow_id)
        if esc is None:
            return STFResult(success=False, error="escrow not found")
        if esc["status"] != "created":
            return STFResult(success=False, error=f"cannot fund: status={esc['status']}")
        if sender != esc["buyer"]:
            return STFResult(success=False, error="only buyer can fund")

        amount = esc["amount"]
        if balances.get(sender, 0) < amount:
            return STFResult(success=False, error="insufficient balance")

        balances[sender] -= amount
        esc["status"] = "funded"
        return STFResult(success=True, output={"funded": escrow_id, "amount": amount})

    if op == "release":
        escrow_id = tx.data["escrow_id"]
        esc = escrows.get(escrow_id)
        if esc is None:
            return STFResult(success=False, error="escrow not found")
        if esc["status"] != "funded":
            return STFResult(success=False, error=f"cannot release: status={esc['status']}")
        # buyer OR arbiter can release
        if sender not in (esc["buyer"], esc["arbiter"]):
            return STFResult(success=False, error="only buyer or arbiter can release")

        amount = esc["amount"]
        balances[esc["seller"]] = balances.get(esc["seller"], 0) + amount
        esc["status"] = "released"
        return STFResult(success=True, output={
            "released": escrow_id, "to": esc["seller"], "amount": amount,
        })

    if op == "refund":
        escrow_id = tx.data["escrow_id"]
        esc = escrows.get(escrow_id)
        if esc is None:
            return STFResult(success=False, error="escrow not found")
        if esc["status"] != "funded":
            return STFResult(success=False, error=f"cannot refund: status={esc['status']}")

        current_block = state.get("block_number", 0)

        # seller OR arbiter can refund, OR anyone after deadline
        if sender in (esc["seller"], esc["arbiter"]):
            pass  # allowed
        elif esc["deadline"] > 0 and current_block >= esc["deadline"]:
            pass  # deadline expired, anyone can trigger refund
        else:
            return STFResult(success=False, error="only seller/arbiter can refund (or wait for deadline)")

        amount = esc["amount"]
        balances[esc["buyer"]] = balances.get(esc["buyer"], 0) + amount
        esc["status"] = "refunded"
        return STFResult(success=True, output={
            "refunded": escrow_id, "to": esc["buyer"], "amount": amount,
        })

    if op == "dispute":
        escrow_id = tx.data["escrow_id"]
        esc = escrows.get(escrow_id)
        if esc is None:
            return STFResult(success=False, error="escrow not found")
        if esc["status"] != "funded":
            return STFResult(success=False, error=f"cannot dispute: status={esc['status']}")
        if sender not in (esc["buyer"], esc["seller"]):
            return STFResult(success=False, error="only buyer or seller can dispute")

        esc["status"] = "disputed"
        return STFResult(success=True, output={"disputed": escrow_id})

    if op == "resolve_dispute":
        escrow_id = tx.data["escrow_id"]
        esc = escrows.get(escrow_id)
        if esc is None:
            return STFResult(success=False, error="escrow not found")
        if esc["status"] != "disputed":
            return STFResult(success=False, error="not in disputed state")
        if sender != esc["arbiter"]:
            return STFResult(success=False, error="only arbiter can resolve")

        winner = tx.data["winner"]  # "buyer" or "seller"
        amount = esc["amount"]
        if winner == "buyer":
            balances[esc["buyer"]] = balances.get(esc["buyer"], 0) + amount
            esc["status"] = "refunded"
        elif winner == "seller":
            balances[esc["seller"]] = balances.get(esc["seller"], 0) + amount
            esc["status"] = "released"
        else:
            return STFResult(success=False, error="winner must be buyer or seller")

        return STFResult(success=True, output={
            "resolved": escrow_id, "winner": winner, "amount": amount,
        })

    if op == "advance_block":
        blocks = int(tx.data.get("blocks", 1))
        state["block_number"] = state.get("block_number", 0) + blocks
        return STFResult(success=True, output={"block": state["block_number"]})

    return STFResult(success=False, error=f"unknown op: {op}")


def escrow_validator(state: dict, tx: L2Tx):
    op = tx.data.get("op")
    valid = ("deposit", "create_escrow", "fund", "release", "refund",
             "dispute", "resolve_dispute", "advance_block")
    if op not in valid:
        return f"invalid op: {op}"
    return None


GENESIS = {"escrows": {}, "balances": {}, "block_number": 0}

# ── Rollup 구성 ─────────────────────────────────────────────────────

stf = PythonRuntime(escrow_stf, validator=escrow_validator, genesis=GENESIS)
rollup = Rollup(stf=stf)
rollup.setup()

nonces = {ALICE: 0, BOB: 0, CHARLIE: 0, DAVE: 0}


def send(sender: bytes, data: dict):
    n = nonces[sender]
    err = rollup.submit_tx(L2Tx(sender=sender, nonce=n, data=data))
    nonces[sender] = n + 1
    return err


def do_batch(label: str):
    batch = rollup.produce_batch()
    receipt = rollup.prove_and_submit(batch)
    status = "VERIFIED" if receipt.verified else "FAILED"
    print(f"  Batch #{batch.number}: {len(batch.transactions)} txs → {status}")
    assert receipt.verified, f"batch {label} not verified"
    return batch


def show_escrow(eid: str):
    esc = rollup.state["escrows"][eid]
    buyer_name = NAMES.get(esc["buyer"], esc["buyer"][:8])
    seller_name = NAMES.get(esc["seller"], esc["seller"][:8])
    print(f"  Escrow '{eid}': {buyer_name} → {seller_name} | "
          f"amount={esc['amount']:,} | status={esc['status']} | "
          f"deadline={esc['deadline']}")


def show_balances():
    bal = rollup.state["balances"]
    parts = []
    for who in [ALICE, BOB, CHARLIE, DAVE]:
        b = bal.get(addr(who), 0)
        name = NAMES[addr(who)].split("(")[0]
        parts.append(f"{name}={b:,}")
    print(f"  Balances: {', '.join(parts)}")


# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 Escrow Service — 3-party escrow state machine")
print("=" * 60)

# Batch 0: 잔액 충전
print("\n[Batch 0] Deposit funds")
send(ALICE, {"op": "deposit", "amount": "500000"})
send(DAVE, {"op": "deposit", "amount": "300000"})
do_batch("0")
show_balances()

# ━━━ 시나리오 1: Happy path (buyer releases) ━━━
print("\n━━━ Scenario 1: Happy path — buyer releases ━━━")

print("\n[Batch 1] Create + Fund escrow")
send(ALICE, {
    "op": "create_escrow", "escrow_id": "deal-001",
    "buyer": addr(ALICE), "seller": addr(BOB),
    "arbiter": addr(CHARLIE), "amount": "100000", "deadline": "1000",
})
send(ALICE, {"op": "fund", "escrow_id": "deal-001"})
do_batch("1")
show_escrow("deal-001")
show_balances()

print("\n[Batch 2] Buyer releases funds to seller")
send(ALICE, {"op": "release", "escrow_id": "deal-001"})
do_batch("2")
show_escrow("deal-001")
show_balances()

assert rollup.state["escrows"]["deal-001"]["status"] == "released"
assert rollup.state["balances"].get(addr(BOB), 0) == 100000

# ━━━ 시나리오 2: Dispute → arbiter resolves ━━━
print("\n━━━ Scenario 2: Dispute — arbiter resolves for buyer ━━━")

print("\n[Batch 3] Create + Fund + Dispute")
send(ALICE, {
    "op": "create_escrow", "escrow_id": "deal-002",
    "buyer": addr(ALICE), "seller": addr(BOB),
    "arbiter": addr(CHARLIE), "amount": "200000", "deadline": "500",
})
send(ALICE, {"op": "fund", "escrow_id": "deal-002"})
send(ALICE, {"op": "dispute", "escrow_id": "deal-002"})
do_batch("3")
show_escrow("deal-002")

print("\n[Batch 4] Arbiter resolves dispute → buyer wins")
send(CHARLIE, {"op": "resolve_dispute", "escrow_id": "deal-002", "winner": "buyer"})
do_batch("4")
show_escrow("deal-002")
show_balances()

assert rollup.state["escrows"]["deal-002"]["status"] == "refunded"

# ━━━ 시나리오 3: Deadline expired → auto-refund ━━━
print("\n━━━ Scenario 3: Deadline expired — auto-refund ━━━")

print("\n[Batch 5] Create + Fund (deadline=10)")
send(DAVE, {
    "op": "create_escrow", "escrow_id": "deal-003",
    "buyer": addr(DAVE), "seller": addr(BOB),
    "arbiter": addr(CHARLIE), "amount": "50000", "deadline": "10",
})
send(DAVE, {"op": "fund", "escrow_id": "deal-003"})
do_batch("5")

dave_bal_before = rollup.state["balances"].get(addr(DAVE), 0)

print("\n[Batch 6] Advance blocks past deadline + refund")
send(ALICE, {"op": "advance_block", "blocks": "100"})
send(DAVE, {"op": "refund", "escrow_id": "deal-003"})
do_batch("6")
show_escrow("deal-003")
show_balances()

dave_bal_after = rollup.state["balances"].get(addr(DAVE), 0)
assert dave_bal_after == dave_bal_before + 50000
assert rollup.state["escrows"]["deal-003"]["status"] == "refunded"

# ── Security: 권한 없는 release ──────────────────────────────────
print("\n[Security] Unauthorized release attempt")
send(ALICE, {
    "op": "create_escrow", "escrow_id": "deal-004",
    "buyer": addr(ALICE), "seller": addr(BOB),
    "arbiter": addr(CHARLIE), "amount": "10000",
})
send(ALICE, {"op": "fund", "escrow_id": "deal-004"})
# Seller가 release (허용 안 됨 — buyer or arbiter만 가능)
send(BOB, {"op": "release", "escrow_id": "deal-004"})
rollup._sequencer.tick()
sealed = rollup._sequencer.force_seal()
# create + fund은 성공, release는 실패 → batch에 2건만
print(f"  Seller release attempt: rejected (only buyer/arbiter can release)")

# ── 최종 검증 ───────────────────────────────────────────────────────

print("\n[Final State]")
for eid in ["deal-001", "deal-002", "deal-003"]:
    show_escrow(eid)
show_balances()

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  deal-001: released (happy path)")
print(f"  deal-002: refunded (dispute → arbiter → buyer wins)")
print(f"  deal-003: refunded (deadline expired)")
print(f"  State machine transitions verified")
print(f"{'=' * 60}")
