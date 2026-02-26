#!/usr/bin/env python3
"""L2 Rock-Paper-Scissors — commit-reveal 가위바위보 + 베팅 데모

App-specific ZK Rollup 위에서 동작하는 가위바위보 게임.
Commit-reveal 방식으로 공정성 보장, 베팅 토큰 정산.

Commit: keccak256((move + ":" + salt).encode()).hex()

Run:
    python examples/l2_rps_game.py
"""

from ethclient.common.crypto import keccak256
from ethclient.l2 import Rollup, L2Tx, STFResult, PythonRuntime

# ── 주소 헬퍼 ───────────────────────────────────────────────────────
ALICE = b"\x01" * 20
BOB = b"\x02" * 20
CHARLIE = b"\x03" * 20

NAMES = {ALICE.hex(): "Alice", BOB.hex(): "Bob", CHARLIE.hex(): "Charlie"}

VALID_MOVES = ("rock", "paper", "scissors")
WINS = {("rock", "scissors"), ("scissors", "paper"), ("paper", "rock")}


def addr(who: bytes) -> str:
    return who.hex()


def make_commit(move: str, salt: str) -> str:
    return keccak256((move + ":" + salt).encode()).hex()


# ── STF 정의 ────────────────────────────────────────────────────────

def rps_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    sender_hex = addr(tx.sender)
    matches = state["matches"]
    balances = state["balances"]
    scores = state["scores"]

    if op == "create":
        bet = int(tx.data["bet"])
        commit = tx.data["commit"]
        if balances.get(sender_hex, 0) < bet:
            return STFResult(success=False, error="insufficient balance for bet")
        mid = f"match_{state['match_count']}"
        balances[sender_hex] -= bet
        matches[mid] = {
            "creator": sender_hex,
            "opponent": "",
            "bet": bet,
            "creator_commit": commit,
            "opponent_commit": "",
            "creator_move": "",
            "opponent_move": "",
            "status": "open",
            "winner": "",
        }
        state["match_count"] = state.get("match_count", 0) + 1
        return STFResult(success=True, output={"match_id": mid})

    if op == "join":
        mid = tx.data["match_id"]
        commit = tx.data["commit"]
        if mid not in matches:
            return STFResult(success=False, error=f"match {mid} not found")
        m = matches[mid]
        if m["status"] != "open":
            return STFResult(success=False, error="match not open")
        if m["creator"] == sender_hex:
            return STFResult(success=False, error="cannot join own match")
        bet = m["bet"]
        if balances.get(sender_hex, 0) < bet:
            return STFResult(success=False, error="insufficient balance for bet")
        balances[sender_hex] -= bet
        m["opponent"] = sender_hex
        m["opponent_commit"] = commit
        m["status"] = "committed"
        return STFResult(success=True, output={"joined": mid})

    if op == "reveal":
        mid = tx.data["match_id"]
        move = tx.data["move"]
        salt = tx.data["salt"]
        if mid not in matches:
            return STFResult(success=False, error=f"match {mid} not found")
        m = matches[mid]
        if m["status"] not in ("committed", "revealed"):
            return STFResult(success=False, error="not in reveal phase")
        expected_commit = keccak256((move + ":" + salt).encode()).hex()
        if sender_hex == m["creator"]:
            if m["creator_commit"] != expected_commit:
                return STFResult(success=False, error="creator commit mismatch")
            m["creator_move"] = move
        elif sender_hex == m["opponent"]:
            if m["opponent_commit"] != expected_commit:
                return STFResult(success=False, error="opponent commit mismatch")
            m["opponent_move"] = move
        else:
            return STFResult(success=False, error="not a participant")
        if m["creator_move"] and m["opponent_move"]:
            m["status"] = "revealed"
        elif m["status"] == "committed":
            m["status"] = "revealed"  # partial reveal
        return STFResult(success=True, output={"revealed": move})

    if op == "settle":
        mid = tx.data["match_id"]
        if mid not in matches:
            return STFResult(success=False, error=f"match {mid} not found")
        m = matches[mid]
        if not m["creator_move"] or not m["opponent_move"]:
            return STFResult(success=False, error="both players must reveal first")
        if m["status"] == "settled":
            return STFResult(success=False, error="already settled")
        cm, om = m["creator_move"], m["opponent_move"]
        bet = m["bet"]
        pot = bet * 2
        if cm == om:
            # Draw: refund both
            balances[m["creator"]] = balances.get(m["creator"], 0) + bet
            balances[m["opponent"]] = balances.get(m["opponent"], 0) + bet
            m["winner"] = "draw"
        elif (cm, om) in WINS:
            balances[m["creator"]] = balances.get(m["creator"], 0) + pot
            m["winner"] = m["creator"]
            scores[m["creator"]] = scores.get(m["creator"], 0) + 1
        else:
            balances[m["opponent"]] = balances.get(m["opponent"], 0) + pot
            m["winner"] = m["opponent"]
            scores[m["opponent"]] = scores.get(m["opponent"], 0) + 1
        m["status"] = "settled"
        return STFResult(success=True, output={"winner": m["winner"]})

    return STFResult(success=False, error=f"unknown op: {op}")


def rps_genesis():
    return {
        "matches": {},
        "match_count": 0,
        "balances": {
            addr(ALICE): 1000,
            addr(BOB): 1000,
            addr(CHARLIE): 1000,
        },
        "scores": {
            addr(ALICE): 0,
            addr(BOB): 0,
            addr(CHARLIE): 0,
        },
    }


# ── Rollup 구성 ─────────────────────────────────────────────────────

stf = PythonRuntime(rps_stf, genesis=rps_genesis)
rollup = Rollup(stf=stf)
rollup.setup()

nonces = {ALICE: 0, BOB: 0, CHARLIE: 0}


def send(sender: bytes, data: dict) -> str | None:
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
    items = []
    for who in [ALICE, BOB, CHARLIE]:
        items.append(f"{NAMES[addr(who)]}={bal.get(addr(who), 0):,}")
    print(f"  Balances: {', '.join(items)}")


def show_match(mid: str):
    m = rollup.state["matches"][mid]
    creator = NAMES.get(m["creator"], m["creator"][:8])
    opponent = NAMES.get(m["opponent"], m["opponent"][:8]) if m["opponent"] else "—"
    winner = NAMES.get(m["winner"], m["winner"]) if m["winner"] else "—"
    print(f"    {mid}: {creator} vs {opponent} | bet={m['bet']} | status={m['status']} | winner={winner}")


# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 Rock-Paper-Scissors — commit-reveal + betting")
print("=" * 60)

# Alice: rock, salt="alice_salt_1"
alice_move, alice_salt = "rock", "alice_salt_1"
alice_commit = make_commit(alice_move, alice_salt)

# Bob: scissors, salt="bob_salt_1"
bob_move, bob_salt = "scissors", "bob_salt_1"
bob_commit = make_commit(bob_move, bob_salt)

# Batch 0: Alice creates match (bet=100)
print("\n[Batch 0] Alice creates match (bet=100)")
send(ALICE, {"op": "create", "bet": "100", "commit": alice_commit})
do_batch("0")
show_match("match_0")
show_balances()

# Batch 1: Bob joins
print("\n[Batch 1] Bob joins match_0")
send(BOB, {"op": "join", "match_id": "match_0", "commit": bob_commit})
do_batch("1")
show_match("match_0")
show_balances()

# Batch 2: Both reveal
print("\n[Batch 2] Both reveal moves")
send(ALICE, {"op": "reveal", "match_id": "match_0", "move": alice_move, "salt": alice_salt})
send(BOB, {"op": "reveal", "match_id": "match_0", "move": bob_move, "salt": bob_salt})
do_batch("2")
show_match("match_0")

# Batch 3: Settle
print("\n[Batch 3] Settle match_0")
send(ALICE, {"op": "settle", "match_id": "match_0"})
do_batch("3")
show_match("match_0")
show_balances()

# Security: wrong salt → reject
print("\n[Security] Wrong salt on reveal")
# Charlie creates + Alice joins a new match
charlie_move, charlie_salt = "paper", "charlie_salt"
charlie_commit = make_commit(charlie_move, charlie_salt)
alice_move2, alice_salt2 = "scissors", "alice_salt_2"
alice_commit2 = make_commit(alice_move2, alice_salt2)

send(CHARLIE, {"op": "create", "bet": "50", "commit": charlie_commit})
send(ALICE, {"op": "join", "match_id": "match_1", "commit": alice_commit2})
b = rollup.produce_batch()
rollup.prove_and_submit(b)
print(f"  Batch #{b.number}: match_1 created + joined")

# Charlie tries to reveal with wrong salt
send(CHARLIE, {"op": "reveal", "match_id": "match_1", "move": charlie_move, "salt": "WRONG_SALT"})
rollup._sequencer.tick()
sealed = rollup._sequencer.force_seal()
assert sealed is None, "wrong salt should be rejected"
print(f"  Charlie reveal with wrong salt: rejected")

# Security: self-join → reject
print("\n[Security] Self-join attempt")
send(CHARLIE, {"op": "create", "bet": "10", "commit": "dummy"})
b2 = rollup.produce_batch()
rollup.prove_and_submit(b2)
send(CHARLIE, {"op": "join", "match_id": "match_2", "commit": "dummy2"})
rollup._sequencer.tick()
sealed = rollup._sequencer.force_seal()
assert sealed is None, "self-join should be rejected"
print(f"  Charlie self-join match_2: rejected")

# ── 최종 검증 ───────────────────────────────────────────────────────

print("\n[Final State]")
bal = rollup.state["balances"]
scores = rollup.state["scores"]
alice_bal = bal.get(addr(ALICE), 0)
bob_bal = bal.get(addr(BOB), 0)

show_balances()
print(f"  Scores: Alice={scores.get(addr(ALICE), 0)}, Bob={scores.get(addr(BOB), 0)}")

# match_0: Alice had rock, Bob had scissors → Alice wins
# Alice: 1000 - 100(create bet) + 200(pot) - 50(join match_1) = 1050
assert alice_bal == 1050, f"Alice expected 1050, got {alice_bal}"
# Bob: 1000 - 100(join bet, lost) = 900
assert bob_bal == 900, f"Bob expected 900, got {bob_bal}"
assert scores.get(addr(ALICE), 0) == 1
assert rollup.state["matches"]["match_0"]["winner"] == addr(ALICE)

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  match_0: Alice(rock) beat Bob(scissors) — 100 tokens won")
print(f"  Alice=1,050 / Bob=900 / Alice wins=1")
print(f"{'=' * 60}")
