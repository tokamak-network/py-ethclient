#!/usr/bin/env python3
"""L2 App-Specific ZK Rollup × Sepolia — 4개 예제 전부 온체인 검증

Token, NameService, Voting, RPS 예제를 Sepolia에 배포하고 검증.
각 앱마다 독립된 Groth16 verifier 컨트랙트를 배포.

사전 준비:
  export SEPOLIA_PRIVATE_KEY="hex_private_key"
  export SEPOLIA_RPC_URL="https://1rpc.io/sepolia"  (선택)

Run:
    python examples/l2_sepolia_all.py
"""

import os
import sys
import time

from ethclient.common.crypto import keccak256, private_key_to_address
from ethclient.l2 import Rollup, L2Tx, STFResult, PythonRuntime
from ethclient.l2.eth_l1_backend import EthL1Backend
from ethclient.l2.eth_rpc import EthRPCClient

# ── 설정 ────────────────────────────────────────────────────────────

RPC_URL = os.environ.get("SEPOLIA_RPC_URL", "https://1rpc.io/sepolia")
PK_HEX = os.environ.get("SEPOLIA_PRIVATE_KEY", "")
if not PK_HEX:
    print("ERROR: export SEPOLIA_PRIVATE_KEY=\"...\"")
    sys.exit(1)

PK = bytes.fromhex(PK_HEX)
ACCOUNT = private_key_to_address(PK)

rpc = EthRPCClient(RPC_URL)
bal_hex = rpc._call("eth_getBalance", [f"0x{ACCOUNT.hex()}", "latest"])
bal_eth = int(bal_hex, 16) / 1e18

print("=" * 65)
print("  L2 App-Specific ZK Rollup × Sepolia — 4 Apps On-Chain")
print("=" * 65)
print(f"  Account: 0x{ACCOUNT.hex()}")
print(f"  Balance: {bal_eth:.6f} ETH")
print(f"  RPC:     {RPC_URL}")

results = []

# ── 헬퍼 ────────────────────────────────────────────────────────────

ALICE = b"\x01" * 20
BOB = b"\x02" * 20
CHARLIE = b"\x03" * 20


def addr(who: bytes) -> str:
    return who.hex()


def make_l1():
    return EthL1Backend(
        rpc_url=RPC_URL, private_key=PK,
        chain_id=11155111, gas_multiplier=1.5, receipt_timeout=180,
    )


def run_app(name, stf_runtime, scenario_fn):
    """Deploy verifier, run scenario, prove & submit on Sepolia."""
    print(f"\n{'─' * 65}")
    print(f"  [{name}]")
    print(f"{'─' * 65}")

    l1 = make_l1()
    rollup = Rollup(stf=stf_runtime, l1=l1)

    t0 = time.time()
    rollup.setup()
    t_setup = time.time() - t0
    print(f"  Verifier deployed: 0x{l1._verifier_address.hex()} ({t_setup:.0f}s)")

    batch_results = scenario_fn(rollup)

    n_batches = len(batch_results)
    total_txs = sum(br["txs"] for br in batch_results)
    all_verified = all(br["verified"] for br in batch_results)
    status = "ALL VERIFIED" if all_verified else "SOME FAILED"
    print(f"  Result: {n_batches} batch, {total_txs} txs → {status}")

    results.append({
        "name": name,
        "verifier": f"0x{l1._verifier_address.hex()}",
        "batches": n_batches,
        "txs": total_txs,
        "verified": all_verified,
    })
    return all_verified


# ═══════════════════════════════════════════════════════════════════
# 1. ERC20 Token
# ═══════════════════════════════════════════════════════════════════

def token_stf(state, tx):
    op = tx.data.get("op")
    balances = state["balances"]
    if op == "mint":
        if addr(tx.sender) != state["admin"]:
            return STFResult(success=False, error="only admin can mint")
        to = tx.data["to"]
        amount = int(tx.data["amount"])
        balances[to] = balances.get(to, 0) + amount
        state["total_supply"] = state.get("total_supply", 0) + amount
        return STFResult(success=True)
    if op == "transfer":
        sender_key = addr(tx.sender)
        to = tx.data["to"]
        amount = int(tx.data["amount"])
        if balances.get(sender_key, 0) < amount:
            return STFResult(success=False, error="insufficient balance")
        balances[sender_key] -= amount
        balances[to] = balances.get(to, 0) + amount
        return STFResult(success=True)
    return STFResult(success=False, error=f"unknown op: {op}")

ADMIN = b"\xaa" * 20
token_genesis = {"total_supply": 0, "balances": {}, "admin": addr(ADMIN)}
token_runtime = PythonRuntime(token_stf, genesis=token_genesis)


def token_scenario(rollup):
    batch_results = []
    nonces = {ADMIN: 0, ALICE: 0}

    def send(who, data):
        n = nonces[who]
        rollup.submit_tx(L2Tx(sender=who, nonce=n, data=data))
        nonces[who] = n + 1

    # Batch 0: mint + transfer
    send(ADMIN, {"op": "mint", "to": addr(ALICE), "amount": "5000"})
    send(ADMIN, {"op": "mint", "to": addr(BOB), "amount": "3000"})
    send(ALICE, {"op": "transfer", "to": addr(CHARLIE), "amount": "1000"})

    t0 = time.time()
    batch = rollup.produce_batch()
    receipt = rollup.prove_and_submit(batch)
    print(f"  Batch #0: {len(batch.transactions)} txs → {'VERIFIED' if receipt.verified else 'FAILED'} ({time.time()-t0:.0f}s)")
    print(f"    L1 tx: 0x{receipt.l1_tx_hash.hex()}")

    bal = rollup.state["balances"]
    print(f"    Alice={bal.get(addr(ALICE),0)} Bob={bal.get(addr(BOB),0)} Charlie={bal.get(addr(CHARLIE),0)}")
    batch_results.append({"txs": len(batch.transactions), "verified": receipt.verified})
    return batch_results


# ═══════════════════════════════════════════════════════════════════
# 2. Name Service
# ═══════════════════════════════════════════════════════════════════

def ns_stf(state, tx):
    op = tx.data.get("op")
    names = state["names"]
    sender_hex = addr(tx.sender)
    if op == "register":
        name = tx.data["name"]
        if name in names:
            return STFResult(success=False, error="taken")
        names[name] = {"owner": sender_hex, "resolver": tx.data.get("resolver", "")}
        return STFResult(success=True)
    if op == "transfer":
        name = tx.data["name"]
        if name not in names or names[name]["owner"] != sender_hex:
            return STFResult(success=False, error="not owner")
        names[name]["owner"] = tx.data["new_owner"]
        return STFResult(success=True)
    return STFResult(success=False, error=f"unknown op: {op}")

ns_runtime = PythonRuntime(ns_stf, genesis={"names": {}})


def ns_scenario(rollup):
    batch_results = []
    nonces = {ALICE: 0, BOB: 0}

    def send(who, data):
        n = nonces[who]
        rollup.submit_tx(L2Tx(sender=who, nonce=n, data=data))
        nonces[who] = n + 1

    # Batch 0: register + transfer
    send(ALICE, {"op": "register", "name": "alice.eth", "resolver": "10.0.0.1"})
    send(BOB, {"op": "register", "name": "bob.eth", "resolver": "10.0.0.2"})
    send(ALICE, {"op": "transfer", "name": "alice.eth", "new_owner": addr(CHARLIE)})

    t0 = time.time()
    batch = rollup.produce_batch()
    receipt = rollup.prove_and_submit(batch)
    print(f"  Batch #0: {len(batch.transactions)} txs → {'VERIFIED' if receipt.verified else 'FAILED'} ({time.time()-t0:.0f}s)")
    print(f"    L1 tx: 0x{receipt.l1_tx_hash.hex()}")

    names = rollup.state["names"]
    print(f"    alice.eth → owner={names['alice.eth']['owner'][:8]}...")
    print(f"    bob.eth   → owner={names['bob.eth']['owner'][:8]}...")
    batch_results.append({"txs": len(batch.transactions), "verified": receipt.verified})
    return batch_results


# ═══════════════════════════════════════════════════════════════════
# 3. Voting
# ═══════════════════════════════════════════════════════════════════

def voting_stf(state, tx):
    op = tx.data.get("op")
    sender_hex = addr(tx.sender)
    proposals = state["proposals"]
    voters = state["voters"]
    if op == "create_proposal":
        pid = f"prop_{state['proposal_count']}"
        proposals[pid] = {
            "title": tx.data["title"], "votes_for": 0, "votes_against": 0,
            "status": "active", "voters": {},
        }
        state["proposal_count"] = state.get("proposal_count", 0) + 1
        return STFResult(success=True)
    if op == "vote":
        pid = tx.data["proposal_id"]
        if pid not in proposals or proposals[pid]["status"] != "active":
            return STFResult(success=False, error="invalid proposal")
        if sender_hex not in voters:
            return STFResult(success=False, error="not voter")
        if sender_hex in proposals[pid]["voters"]:
            return STFResult(success=False, error="already voted")
        power = int(voters[sender_hex])
        proposals[pid]["voters"][sender_hex] = tx.data["choice"]
        if tx.data["choice"] == "for":
            proposals[pid]["votes_for"] += power
        else:
            proposals[pid]["votes_against"] += power
        return STFResult(success=True)
    if op == "finalize":
        pid = tx.data["proposal_id"]
        prop = proposals.get(pid)
        if not prop or prop["status"] != "active":
            return STFResult(success=False, error="invalid")
        total = prop["votes_for"] + prop["votes_against"]
        if total < int(state["quorum"]):
            return STFResult(success=False, error="quorum not met")
        prop["status"] = "passed" if prop["votes_for"] > prop["votes_against"] else "rejected"
        return STFResult(success=True)
    return STFResult(success=False, error=f"unknown op: {op}")

voting_genesis = {
    "proposals": {}, "proposal_count": 0,
    "voters": {addr(ALICE): "100", addr(BOB): "80", addr(CHARLIE): "50"},
    "quorum": "100",
}
voting_runtime = PythonRuntime(voting_stf, genesis=voting_genesis)


def voting_scenario(rollup):
    batch_results = []
    nonces = {ALICE: 0, BOB: 0, CHARLIE: 0}

    def send(who, data):
        n = nonces[who]
        rollup.submit_tx(L2Tx(sender=who, nonce=n, data=data))
        nonces[who] = n + 1

    # Batch 0: create + vote + finalize
    send(ALICE, {"op": "create_proposal", "title": "Upgrade protocol"})
    send(ALICE, {"op": "vote", "proposal_id": "prop_0", "choice": "for"})
    send(BOB, {"op": "vote", "proposal_id": "prop_0", "choice": "for"})
    send(CHARLIE, {"op": "vote", "proposal_id": "prop_0", "choice": "against"})
    send(ALICE, {"op": "finalize", "proposal_id": "prop_0"})

    t0 = time.time()
    batch = rollup.produce_batch()
    receipt = rollup.prove_and_submit(batch)
    print(f"  Batch #0: {len(batch.transactions)} txs → {'VERIFIED' if receipt.verified else 'FAILED'} ({time.time()-t0:.0f}s)")
    print(f"    L1 tx: 0x{receipt.l1_tx_hash.hex()}")

    prop = rollup.state["proposals"]["prop_0"]
    print(f"    prop_0: FOR={prop['votes_for']} AGAINST={prop['votes_against']} → {prop['status'].upper()}")
    batch_results.append({"txs": len(batch.transactions), "verified": receipt.verified})
    return batch_results


# ═══════════════════════════════════════════════════════════════════
# 4. Rock-Paper-Scissors
# ═══════════════════════════════════════════════════════════════════

WINS = {("rock", "scissors"), ("scissors", "paper"), ("paper", "rock")}


def make_commit(move, salt):
    return keccak256((move + ":" + salt).encode()).hex()


def rps_stf(state, tx):
    op = tx.data.get("op")
    sender_hex = addr(tx.sender)
    matches = state["matches"]
    balances = state["balances"]
    scores = state["scores"]
    if op == "create":
        bet = int(tx.data["bet"])
        if balances.get(sender_hex, 0) < bet:
            return STFResult(success=False, error="insufficient balance")
        mid = f"match_{state['match_count']}"
        balances[sender_hex] -= bet
        matches[mid] = {
            "creator": sender_hex, "opponent": "", "bet": bet,
            "creator_commit": tx.data["commit"], "opponent_commit": "",
            "creator_move": "", "opponent_move": "",
            "status": "open", "winner": "",
        }
        state["match_count"] = state.get("match_count", 0) + 1
        return STFResult(success=True)
    if op == "join":
        mid = tx.data["match_id"]
        m = matches[mid]
        if m["status"] != "open" or m["creator"] == sender_hex:
            return STFResult(success=False, error="cannot join")
        bet = m["bet"]
        if balances.get(sender_hex, 0) < bet:
            return STFResult(success=False, error="insufficient balance")
        balances[sender_hex] -= bet
        m["opponent"] = sender_hex
        m["opponent_commit"] = tx.data["commit"]
        m["status"] = "committed"
        return STFResult(success=True)
    if op == "reveal":
        mid = tx.data["match_id"]
        m = matches[mid]
        expected = keccak256((tx.data["move"] + ":" + tx.data["salt"]).encode()).hex()
        if sender_hex == m["creator"]:
            if m["creator_commit"] != expected:
                return STFResult(success=False, error="commit mismatch")
            m["creator_move"] = tx.data["move"]
        elif sender_hex == m["opponent"]:
            if m["opponent_commit"] != expected:
                return STFResult(success=False, error="commit mismatch")
            m["opponent_move"] = tx.data["move"]
        else:
            return STFResult(success=False, error="not participant")
        if m["creator_move"] and m["opponent_move"]:
            m["status"] = "revealed"
        elif m["status"] == "committed":
            m["status"] = "revealed"
        return STFResult(success=True)
    if op == "settle":
        mid = tx.data["match_id"]
        m = matches[mid]
        if not m["creator_move"] or not m["opponent_move"]:
            return STFResult(success=False, error="not revealed")
        cm, om = m["creator_move"], m["opponent_move"]
        bet = m["bet"]
        if cm == om:
            balances[m["creator"]] = balances.get(m["creator"], 0) + bet
            balances[m["opponent"]] = balances.get(m["opponent"], 0) + bet
            m["winner"] = "draw"
        elif (cm, om) in WINS:
            balances[m["creator"]] = balances.get(m["creator"], 0) + bet * 2
            m["winner"] = m["creator"]
            scores[m["creator"]] = scores.get(m["creator"], 0) + 1
        else:
            balances[m["opponent"]] = balances.get(m["opponent"], 0) + bet * 2
            m["winner"] = m["opponent"]
            scores[m["opponent"]] = scores.get(m["opponent"], 0) + 1
        m["status"] = "settled"
        return STFResult(success=True)
    return STFResult(success=False, error=f"unknown op: {op}")


def rps_genesis():
    return {
        "matches": {}, "match_count": 0,
        "balances": {addr(ALICE): 1000, addr(BOB): 1000},
        "scores": {addr(ALICE): 0, addr(BOB): 0},
    }

rps_runtime = PythonRuntime(rps_stf, genesis=rps_genesis)


def rps_scenario(rollup):
    batch_results = []
    nonces = {ALICE: 0, BOB: 0}

    def send(who, data):
        n = nonces[who]
        rollup.submit_tx(L2Tx(sender=who, nonce=n, data=data))
        nonces[who] = n + 1

    alice_commit = make_commit("rock", "asalt")
    bob_commit = make_commit("scissors", "bsalt")

    # Batch 0: create + join + reveal + settle (full game in 1 batch)
    send(ALICE, {"op": "create", "bet": "100", "commit": alice_commit})
    send(BOB, {"op": "join", "match_id": "match_0", "commit": bob_commit})
    send(ALICE, {"op": "reveal", "match_id": "match_0", "move": "rock", "salt": "asalt"})
    send(BOB, {"op": "reveal", "match_id": "match_0", "move": "scissors", "salt": "bsalt"})
    send(ALICE, {"op": "settle", "match_id": "match_0"})

    t0 = time.time()
    batch = rollup.produce_batch()
    receipt = rollup.prove_and_submit(batch)
    print(f"  Batch #0: {len(batch.transactions)} txs → {'VERIFIED' if receipt.verified else 'FAILED'} ({time.time()-t0:.0f}s)")
    print(f"    L1 tx: 0x{receipt.l1_tx_hash.hex()}")

    bal = rollup.state["balances"]
    print(f"    match_0: rock vs scissors → winner=Alice")
    print(f"    Alice={bal[addr(ALICE)]} Bob={bal[addr(BOB)]}")
    batch_results.append({"txs": len(batch.transactions), "verified": receipt.verified})
    return batch_results


# ═══════════════════════════════════════════════════════════════════
# 실행
# ═══════════════════════════════════════════════════════════════════

t_total = time.time()

run_app("ERC20 Token", token_runtime, token_scenario)
run_app("Name Service", ns_runtime, ns_scenario)
run_app("Voting", voting_runtime, voting_scenario)
run_app("Rock-Paper-Scissors", rps_runtime, rps_scenario)

t_elapsed = time.time() - t_total

# ── 잔액 변화 ───────────────────────────────────────────────────────

bal_after_hex = rpc._call("eth_getBalance", [f"0x{ACCOUNT.hex()}", "latest"])
bal_after = int(bal_after_hex, 16) / 1e18
gas_total = bal_eth - bal_after

# ── 최종 결과 ───────────────────────────────────────────────────────

print(f"\n{'=' * 65}")
print(f"  RESULTS — {t_elapsed:.0f}s total, {gas_total:.6f} ETH gas")
print(f"{'=' * 65}")
for r in results:
    tag = "VERIFIED" if r["verified"] else "FAILED"
    print(f"  {r['name']:25s} {r['batches']} batch, {r['txs']} txs → {tag}")
    print(f"    Verifier: {r['verifier']}")

all_ok = all(r["verified"] for r in results)
print(f"\n  {'ALL 4 APPS ON-CHAIN VERIFIED!' if all_ok else 'SOME APPS FAILED'}")
print(f"  Gas: {gas_total:.6f} ETH ({bal_after:.6f} ETH remaining)")
print(f"{'=' * 65}")

assert all_ok, "Not all apps verified on Sepolia"
