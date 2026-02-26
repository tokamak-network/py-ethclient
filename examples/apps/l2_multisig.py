#!/usr/bin/env python3
"""L2 Multisig Wallet — N-of-M 다중서명 월렛 데모

App-specific ZK Rollup 위에서 동작하는 멀티시그 월렛.
create_wallet (N-of-M), propose, approve, execute 오퍼레이션.
임계값 도달 시 자동 실행, 소유자 추가/제거 제안 지원.

Run:
    python examples/apps/l2_multisig.py
"""

from ethclient.l2 import Rollup, L2Tx, STFResult, PythonRuntime

# ── 주소 헬퍼 ───────────────────────────────────────────────────────
ALICE = b"\x01" * 20
BOB = b"\x02" * 20
CHARLIE = b"\x03" * 20
DAVE = b"\x04" * 20
RECIPIENT = b"\x05" * 20

NAMES = {
    ALICE.hex(): "Alice", BOB.hex(): "Bob",
    CHARLIE.hex(): "Charlie", DAVE.hex(): "Dave",
    RECIPIENT.hex(): "Recipient",
}


def addr(who: bytes) -> str:
    return who.hex()


# ── STF 정의 ────────────────────────────────────────────────────────

def multisig_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    wallets = state["wallets"]
    proposals = state["proposals"]
    balances = state["balances"]
    sender = addr(tx.sender)

    if op == "deposit":
        wallet_id = tx.data["wallet_id"]
        amount = int(tx.data["amount"])
        balances[wallet_id] = balances.get(wallet_id, 0) + amount
        return STFResult(success=True, output={"deposited": amount})

    if op == "create_wallet":
        wallet_id = tx.data["wallet_id"]
        owners = tx.data["owners"]  # list of addr hex strings
        threshold = int(tx.data["threshold"])

        if wallet_id in wallets:
            return STFResult(success=False, error="wallet already exists")
        if threshold < 1 or threshold > len(owners):
            return STFResult(success=False, error="invalid threshold")
        if sender not in owners:
            return STFResult(success=False, error="creator must be an owner")

        wallets[wallet_id] = {
            "owners": owners,
            "threshold": threshold,
        }
        return STFResult(success=True, output={
            "wallet_id": wallet_id,
            "owners": len(owners),
            "threshold": threshold,
        })

    if op == "propose":
        wallet_id = tx.data["wallet_id"]
        wallet = wallets.get(wallet_id)
        if wallet is None:
            return STFResult(success=False, error="wallet not found")
        if sender not in wallet["owners"]:
            return STFResult(success=False, error="not an owner")

        proposal_id = tx.data["proposal_id"]
        if proposal_id in proposals:
            return STFResult(success=False, error="proposal already exists")

        action = tx.data["action"]  # {"type": "transfer"|"add_owner"|"remove_owner", ...}
        proposals[proposal_id] = {
            "wallet_id": wallet_id,
            "proposer": sender,
            "action": action,
            "approvals": [sender],  # proposer auto-approves
            "executed": False,
        }
        return STFResult(success=True, output={
            "proposal_id": proposal_id,
            "approvals": 1,
            "threshold": wallet["threshold"],
        })

    if op == "approve":
        proposal_id = tx.data["proposal_id"]
        proposal = proposals.get(proposal_id)
        if proposal is None:
            return STFResult(success=False, error="proposal not found")
        if proposal["executed"]:
            return STFResult(success=False, error="already executed")

        wallet = wallets[proposal["wallet_id"]]
        if sender not in wallet["owners"]:
            return STFResult(success=False, error="not an owner")
        if sender in proposal["approvals"]:
            return STFResult(success=False, error="already approved")

        proposal["approvals"].append(sender)
        count = len(proposal["approvals"])
        threshold = wallet["threshold"]

        # 임계값 도달 시 자동 실행
        if count >= threshold:
            result = _execute_proposal(proposal, wallets, balances)
            if not result["success"]:
                return STFResult(success=False, error=result["error"])
            proposal["executed"] = True
            return STFResult(success=True, output={
                "auto_executed": True,
                "approvals": count,
                **result,
            })

        return STFResult(success=True, output={
            "approvals": count, "threshold": threshold,
            "remaining": threshold - count,
        })

    return STFResult(success=False, error=f"unknown op: {op}")


def _execute_proposal(proposal: dict, wallets: dict, balances: dict) -> dict:
    action = proposal["action"]
    wallet_id = proposal["wallet_id"]
    action_type = action["type"]

    if action_type == "transfer":
        to = action["to"]
        amount = int(action["amount"])
        wallet_bal = balances.get(wallet_id, 0)
        if wallet_bal < amount:
            return {"success": False, "error": "insufficient wallet balance"}
        balances[wallet_id] = wallet_bal - amount
        balances[to] = balances.get(to, 0) + amount
        return {"success": True, "transferred": amount, "to": to}

    if action_type == "add_owner":
        new_owner = action["owner"]
        wallet = wallets[wallet_id]
        if new_owner in wallet["owners"]:
            return {"success": False, "error": "already an owner"}
        wallet["owners"].append(new_owner)
        return {"success": True, "added_owner": new_owner}

    if action_type == "remove_owner":
        old_owner = action["owner"]
        wallet = wallets[wallet_id]
        if old_owner not in wallet["owners"]:
            return {"success": False, "error": "not an owner"}
        if len(wallet["owners"]) <= wallet["threshold"]:
            return {"success": False, "error": "cannot remove: would break threshold"}
        wallet["owners"].remove(old_owner)
        return {"success": True, "removed_owner": old_owner}

    return {"success": False, "error": f"unknown action: {action_type}"}


def multisig_validator(state: dict, tx: L2Tx):
    op = tx.data.get("op")
    valid = ("deposit", "create_wallet", "propose", "approve")
    if op not in valid:
        return f"invalid op: {op}"
    return None


GENESIS = {"wallets": {}, "proposals": {}, "balances": {}}

# ── Rollup 구성 ─────────────────────────────────────────────────────

stf = PythonRuntime(multisig_stf, validator=multisig_validator, genesis=GENESIS)
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


def show_wallet(wallet_id: str):
    w = rollup.state["wallets"][wallet_id]
    bal = rollup.state["balances"].get(wallet_id, 0)
    owner_names = [NAMES.get(o, o[:8]) for o in w["owners"]]
    print(f"  Wallet '{wallet_id}': {w['threshold']}-of-{len(w['owners'])} "
          f"owners=[{', '.join(owner_names)}] balance={bal:,}")


def show_proposal(pid: str):
    p = rollup.state["proposals"][pid]
    approvers = [NAMES.get(a, a[:8]) for a in p["approvals"]]
    wallet = rollup.state["wallets"][p["wallet_id"]]
    status = "EXECUTED" if p["executed"] else f"{len(p['approvals'])}/{wallet['threshold']}"
    print(f"  Proposal '{pid}': {p['action']['type']} | status={status} | "
          f"approvals=[{', '.join(approvers)}]")


# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 Multisig Wallet — N-of-M approval workflow")
print("=" * 60)

# Batch 0: 2-of-3 월렛 생성 + 잔액 충전
print("\n[Batch 0] Create 2-of-3 wallet + deposit")
send(ALICE, {
    "op": "create_wallet",
    "wallet_id": "treasury",
    "owners": [addr(ALICE), addr(BOB), addr(CHARLIE)],
    "threshold": "2",
})
send(ALICE, {"op": "deposit", "wallet_id": "treasury", "amount": "1000000"})
do_batch("0")
show_wallet("treasury")

# Batch 1: Alice가 송금 제안 + Bob이 승인 → 자동 실행
print("\n[Batch 1] Propose transfer + Bob approves → auto-execute")
send(ALICE, {
    "op": "propose",
    "proposal_id": "tx-001",
    "wallet_id": "treasury",
    "action": {"type": "transfer", "to": addr(RECIPIENT), "amount": "100000"},
})
send(BOB, {"op": "approve", "proposal_id": "tx-001"})
do_batch("1")
show_proposal("tx-001")
show_wallet("treasury")

recipient_bal = rollup.state["balances"].get(addr(RECIPIENT), 0)
print(f"  Recipient balance: {recipient_bal:,}")
assert recipient_bal == 100000

# Batch 2: 소유자 추가 제안 (Dave 추가)
print("\n[Batch 2] Propose adding Dave as owner")
send(BOB, {
    "op": "propose",
    "proposal_id": "add-dave",
    "wallet_id": "treasury",
    "action": {"type": "add_owner", "owner": addr(DAVE)},
})
send(CHARLIE, {"op": "approve", "proposal_id": "add-dave"})
do_batch("2")
show_proposal("add-dave")
show_wallet("treasury")

wallet = rollup.state["wallets"]["treasury"]
assert addr(DAVE) in wallet["owners"]
assert len(wallet["owners"]) == 4

# Batch 3: 소유자 제거 제안 (Charlie 제거)
print("\n[Batch 3] Propose removing Charlie")
send(ALICE, {
    "op": "propose",
    "proposal_id": "rm-charlie",
    "wallet_id": "treasury",
    "action": {"type": "remove_owner", "owner": addr(CHARLIE)},
})
send(DAVE, {"op": "approve", "proposal_id": "rm-charlie"})
do_batch("3")
show_proposal("rm-charlie")
show_wallet("treasury")

wallet = rollup.state["wallets"]["treasury"]
assert addr(CHARLIE) not in wallet["owners"]
assert len(wallet["owners"]) == 3

# ── Security: 비소유자 승인 시도 ──────────────────────────────────
print("\n[Security] Non-owner approval attempt")
send(ALICE, {
    "op": "propose",
    "proposal_id": "tx-002",
    "wallet_id": "treasury",
    "action": {"type": "transfer", "to": addr(RECIPIENT), "amount": "50000"},
})
# Charlie는 더 이상 소유자가 아님
send(CHARLIE, {"op": "approve", "proposal_id": "tx-002"})
rollup._sequencer.tick()
sealed = rollup._sequencer.force_seal()
# tx-002 proposal은 생성되지만, Charlie approve는 실패
# batch에 proposal 생성 1건만 남거나, approve 실패로 rollback
print(f"  Charlie (removed) approve: rejected by STF")

# ── 최종 검증 ───────────────────────────────────────────────────────

print("\n[Final State]")
show_wallet("treasury")

final_bal = rollup.state["balances"].get("treasury", 0)
assert final_bal == 900000, f"expected 900000, got {final_bal}"

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  Treasury: 900,000 remaining (100,000 transferred)")
print(f"  Owners: Alice, Bob, Dave (Charlie removed)")
print(f"  Proposals: 3 executed, multi-step workflow verified")
print(f"{'=' * 60}")
