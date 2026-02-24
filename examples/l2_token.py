#!/usr/bin/env python3
"""L2 ERC20 Token — mint / transfer / burn 데모

App-specific ZK Rollup 위에서 동작하는 펀저블 토큰.
admin만 mint 가능, 누구나 transfer/burn 가능.

Run:
    python examples/l2_token.py
"""

from ethclient.l2 import Rollup, L2Tx, STFResult, PythonRuntime

# ── 주소 헬퍼 ───────────────────────────────────────────────────────
ADMIN = b"\x01" * 20
ALICE = b"\x02" * 20
BOB = b"\x03" * 20
CHARLIE = b"\x04" * 20

NAMES = {
    ADMIN.hex(): "Admin",
    ALICE.hex(): "Alice",
    BOB.hex(): "Bob",
    CHARLIE.hex(): "Charlie",
}


def addr(who: bytes) -> str:
    return who.hex()


# ── STF 정의 ────────────────────────────────────────────────────────

def token_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    balances = state["balances"]

    if op == "mint":
        if addr(tx.sender) != state["admin"]:
            return STFResult(success=False, error="only admin can mint")
        to = tx.data["to"]
        amount = int(tx.data["amount"])
        balances[to] = balances.get(to, 0) + amount
        state["total_supply"] = state.get("total_supply", 0) + amount
        return STFResult(success=True, output={"minted": amount})

    if op == "transfer":
        sender_key = addr(tx.sender)
        to = tx.data["to"]
        amount = int(tx.data["amount"])
        if balances.get(sender_key, 0) < amount:
            return STFResult(success=False, error="insufficient balance")
        balances[sender_key] -= amount
        balances[to] = balances.get(to, 0) + amount
        return STFResult(success=True, output={"transferred": amount})

    if op == "burn":
        sender_key = addr(tx.sender)
        amount = int(tx.data["amount"])
        if balances.get(sender_key, 0) < amount:
            return STFResult(success=False, error="insufficient balance")
        balances[sender_key] -= amount
        state["total_supply"] -= amount
        return STFResult(success=True, output={"burned": amount})

    return STFResult(success=False, error=f"unknown op: {op}")


def token_validator(state: dict, tx: L2Tx):
    op = tx.data.get("op")
    if op not in ("mint", "transfer", "burn"):
        return f"invalid op: {op}"
    amount = tx.data.get("amount")
    if amount is None or int(amount) <= 0:
        return "amount must be positive"
    return None


GENESIS = {
    "total_supply": 0,
    "balances": {},
    "admin": addr(ADMIN),
}

# ── Rollup 구성 ─────────────────────────────────────────────────────

stf = PythonRuntime(token_stf, validator=token_validator, genesis=GENESIS)
rollup = Rollup(stf=stf)
rollup.setup()

nonces = {ADMIN: 0, ALICE: 0, BOB: 0, CHARLIE: 0}


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


def show_balances():
    bal = rollup.state["balances"]
    parts = []
    for who in [ALICE, BOB, CHARLIE]:
        b = bal.get(addr(who), 0)
        if b > 0:
            parts.append(f"{NAMES[addr(who)]}={b:,}")
    print(f"  Balances: {', '.join(parts)}  (supply={rollup.state['total_supply']:,})")


# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 ERC20 Token — mint / transfer / burn")
print("=" * 60)

# Batch 0: mint + transfer
print("\n[Batch 0] Mint + Transfer")
send(ADMIN, {"op": "mint", "to": addr(ALICE), "amount": "10000"})
send(ADMIN, {"op": "mint", "to": addr(BOB), "amount": "5000"})
send(ALICE, {"op": "transfer", "to": addr(CHARLIE), "amount": "2000"})
do_batch("0")
show_balances()

# Batch 1: transfer + burn
print("\n[Batch 1] Transfer + Burn")
send(BOB, {"op": "transfer", "to": addr(ALICE), "amount": "1000"})
send(ALICE, {"op": "burn", "amount": "500"})
do_batch("1")
show_balances()

# Security: non-admin mint → rejected
print("\n[Security] Non-admin mint attempt")
err = send(ALICE, {"op": "mint", "to": addr(ALICE), "amount": "999999"})
# This tx enters mempool but will fail in STF (rollback)
rollup._sequencer.tick()
sealed = rollup._sequencer.force_seal()
assert sealed is None, "bad tx should not produce a batch"
print(f"  Alice mint attempt: rejected (STF rollback)")

# ── 최종 검증 ───────────────────────────────────────────────────────

print("\n[Final State]")
bal = rollup.state["balances"]
alice_bal = bal.get(addr(ALICE), 0)
bob_bal = bal.get(addr(BOB), 0)
charlie_bal = bal.get(addr(CHARLIE), 0)
total = rollup.state["total_supply"]

show_balances()

assert alice_bal == 8500, f"Alice expected 8500, got {alice_bal}"
assert bob_bal == 4000, f"Bob expected 4000, got {bob_bal}"
assert charlie_bal == 2000, f"Charlie expected 2000, got {charlie_bal}"
assert total == 14500, f"Total supply expected 14500, got {total}"

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  Alice=8,500 / Bob=4,000 / Charlie=2,000 / supply=14,500")
print(f"{'=' * 60}")
