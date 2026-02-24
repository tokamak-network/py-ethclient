#!/usr/bin/env python3
"""L2 Voting / Governance — 제안 생성, 투표, 정족수 기반 확정 데모

App-specific ZK Rollup 위에서 동작하는 거버넌스 시스템.
사전 등록된 voter만 투표 가능, voting power에 비례한 투표력,
정족수(quorum) 도달 시 finalize로 확정.

Run:
    python examples/l2_voting.py
"""

from ethclient.l2 import Rollup, L2Tx, STFResult, PythonRuntime

# ── 주소 헬퍼 ───────────────────────────────────────────────────────
ALICE = b"\x01" * 20
BOB = b"\x02" * 20
CHARLIE = b"\x03" * 20
DAVE = b"\x04" * 20  # 미등록 사용자

NAMES = {
    ALICE.hex(): "Alice",
    BOB.hex(): "Bob",
    CHARLIE.hex(): "Charlie",
    DAVE.hex(): "Dave",
}


def addr(who: bytes) -> str:
    return who.hex()


# ── STF 정의 ────────────────────────────────────────────────────────

def voting_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    sender_hex = addr(tx.sender)
    proposals = state["proposals"]
    voters = state["voters"]

    if op == "create_proposal":
        title = tx.data["title"]
        pid = f"prop_{state['proposal_count']}"
        proposals[pid] = {
            "title": title,
            "creator": sender_hex,
            "votes_for": 0,
            "votes_against": 0,
            "status": "active",
            "voters": {},
        }
        state["proposal_count"] = state.get("proposal_count", 0) + 1
        return STFResult(success=True, output={"proposal_id": pid})

    if op == "vote":
        pid = tx.data["proposal_id"]
        choice = tx.data["choice"]  # "for" or "against"
        if pid not in proposals:
            return STFResult(success=False, error=f"proposal {pid} not found")
        prop = proposals[pid]
        if prop["status"] != "active":
            return STFResult(success=False, error="proposal not active")
        if sender_hex not in voters:
            return STFResult(success=False, error="not a registered voter")
        if sender_hex in prop["voters"]:
            return STFResult(success=False, error="already voted")
        power = int(voters[sender_hex])
        prop["voters"][sender_hex] = choice
        if choice == "for":
            prop["votes_for"] = prop.get("votes_for", 0) + power
        else:
            prop["votes_against"] = prop.get("votes_against", 0) + power
        return STFResult(success=True, output={"voted": choice, "power": power})

    if op == "finalize":
        pid = tx.data["proposal_id"]
        if pid not in proposals:
            return STFResult(success=False, error=f"proposal {pid} not found")
        prop = proposals[pid]
        if prop["status"] != "active":
            return STFResult(success=False, error="proposal not active")
        total_votes = prop.get("votes_for", 0) + prop.get("votes_against", 0)
        quorum = int(state["quorum"])
        if total_votes < quorum:
            return STFResult(success=False, error=f"quorum not met ({total_votes}<{quorum})")
        if prop.get("votes_for", 0) > prop.get("votes_against", 0):
            prop["status"] = "passed"
        else:
            prop["status"] = "rejected"
        return STFResult(success=True, output={"result": prop["status"]})

    return STFResult(success=False, error=f"unknown op: {op}")


GENESIS = {
    "proposals": {},
    "proposal_count": 0,
    "voters": {
        addr(ALICE): "100",
        addr(BOB): "80",
        addr(CHARLIE): "50",
    },
    "quorum": "100",
}

# ── Rollup 구성 ─────────────────────────────────────────────────────

stf = PythonRuntime(voting_stf, genesis=GENESIS)
rollup = Rollup(stf=stf)
rollup.setup()

nonces = {ALICE: 0, BOB: 0, CHARLIE: 0, DAVE: 0}


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


def show_proposals():
    for pid, prop in sorted(rollup.state["proposals"].items()):
        vf = prop.get("votes_for", 0)
        va = prop.get("votes_against", 0)
        print(f"    {pid}: \"{prop['title']}\" — FOR={vf} AGAINST={va} status={prop['status']}")


# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 Voting — create / vote / finalize")
print("=" * 60)

# Batch 0: Alice가 2개 제안 생성
print("\n[Batch 0] Create proposals")
send(ALICE, {"op": "create_proposal", "title": "Increase block size"})
send(ALICE, {"op": "create_proposal", "title": "Add new validator"})
do_batch("0")
show_proposals()

# Batch 1: 투표
print("\n[Batch 1] Vote on proposals")
send(ALICE, {"op": "vote", "proposal_id": "prop_0", "choice": "for"})
send(BOB, {"op": "vote", "proposal_id": "prop_0", "choice": "for"})
send(CHARLIE, {"op": "vote", "proposal_id": "prop_0", "choice": "against"})
send(BOB, {"op": "vote", "proposal_id": "prop_1", "choice": "for"})
do_batch("1")
show_proposals()

# Batch 2: finalize prop_0 + prop_1 투표 + finalize
print("\n[Batch 2] Finalize prop_0 + more votes on prop_1")
send(ALICE, {"op": "finalize", "proposal_id": "prop_0"})
send(CHARLIE, {"op": "vote", "proposal_id": "prop_1", "choice": "for"})
send(ALICE, {"op": "vote", "proposal_id": "prop_1", "choice": "for"})
do_batch("2")
show_proposals()

# Batch 3: finalize prop_1
print("\n[Batch 3] Finalize prop_1")
send(BOB, {"op": "finalize", "proposal_id": "prop_1"})
do_batch("3")
show_proposals()

# Security: 중복 투표 거부
print("\n[Security] Duplicate vote attempt")
send(ALICE, {"op": "vote", "proposal_id": "prop_0", "choice": "for"})
rollup._sequencer.tick()
sealed = rollup._sequencer.force_seal()
assert sealed is None, "duplicate vote should fail"
print(f"  Alice double-vote on prop_0: rejected")

# Security: 미등록 사용자 투표 거부
print("\n[Security] Unregistered voter attempt")
# Dave의 nonce가 이미 증가되었으므로 새 제안에 투표 시도
send(DAVE, {"op": "vote", "proposal_id": "prop_0", "choice": "for"})
rollup._sequencer.tick()
sealed = rollup._sequencer.force_seal()
assert sealed is None, "unregistered voter should fail"
print(f"  Dave (unregistered) vote: rejected")

# ── 최종 검증 ───────────────────────────────────────────────────────

print("\n[Final State]")
show_proposals()

props = rollup.state["proposals"]
assert props["prop_0"]["status"] == "passed"
assert props["prop_0"]["votes_for"] == 180  # Alice(100) + Bob(80)
assert props["prop_0"]["votes_against"] == 50  # Charlie(50)
assert props["prop_1"]["status"] == "passed"
assert props["prop_1"]["votes_for"] == 230  # Bob(80) + Charlie(50) + Alice(100)

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  prop_0: PASSED (FOR=180 > AGAINST=50, quorum=100)")
print(f"  prop_1: PASSED (FOR=230, quorum=100)")
print(f"{'=' * 60}")
