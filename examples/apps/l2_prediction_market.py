#!/usr/bin/env python3
"""L2 Prediction Market — 예측 시장 데모

App-specific ZK Rollup 위에서 동작하는 예측 시장.
create_market, bet, resolve, claim 오퍼레이션.
각 옵션별 베팅 풀, 비례 배분 정산, 오라클 역할 (creator가 resolve).

Run:
    python examples/apps/l2_prediction_market.py
"""

from ethclient.l2 import Rollup, L2Tx, STFResult, PythonRuntime

# ── 주소 헬퍼 ───────────────────────────────────────────────────────
ORACLE = b"\x01" * 20  # market creator / oracle
ALICE = b"\x02" * 20
BOB = b"\x03" * 20
CHARLIE = b"\x04" * 20

NAMES = {
    ORACLE.hex(): "Oracle", ALICE.hex(): "Alice",
    BOB.hex(): "Bob", CHARLIE.hex(): "Charlie",
}


def addr(who: bytes) -> str:
    return who.hex()


# ── STF 정의 ────────────────────────────────────────────────────────

def market_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    markets = state["markets"]
    balances = state["balances"]
    bets = state["bets"]  # market_id → {user → {option → amount}}
    sender = addr(tx.sender)

    if op == "deposit":
        amount = int(tx.data["amount"])
        balances[sender] = balances.get(sender, 0) + amount
        return STFResult(success=True, output={"deposited": amount})

    if op == "create_market":
        market_id = tx.data["market_id"]
        if market_id in markets:
            return STFResult(success=False, error="market already exists")

        question = tx.data["question"]
        options = tx.data["options"]  # list of option names
        deadline = int(tx.data.get("deadline", 0))

        if len(options) < 2:
            return STFResult(success=False, error="need at least 2 options")

        pools = {}
        for opt in options:
            pools[opt] = 0

        markets[market_id] = {
            "creator": sender,
            "question": question,
            "options": options,
            "pools": pools,
            "total_pool": 0,
            "deadline": deadline,
            "resolved": False,
            "winning_option": None,
        }
        bets[market_id] = {}
        return STFResult(success=True, output={"created": market_id})

    if op == "bet":
        market_id = tx.data["market_id"]
        option = tx.data["option"]
        amount = int(tx.data["amount"])

        market = markets.get(market_id)
        if market is None:
            return STFResult(success=False, error="market not found")
        if market["resolved"]:
            return STFResult(success=False, error="market already resolved")
        if option not in market["options"]:
            return STFResult(success=False, error=f"invalid option: {option}")

        current_block = state.get("block_number", 0)
        if market["deadline"] > 0 and current_block >= market["deadline"]:
            return STFResult(success=False, error="betting deadline passed")

        if balances.get(sender, 0) < amount:
            return STFResult(success=False, error="insufficient balance")

        balances[sender] -= amount
        market["pools"][option] += amount
        market["total_pool"] += amount

        if sender not in bets[market_id]:
            bets[market_id][sender] = {}
        user_bets = bets[market_id][sender]
        user_bets[option] = user_bets.get(option, 0) + amount

        return STFResult(success=True, output={
            "market": market_id, "option": option, "amount": amount,
            "pool_total": market["total_pool"],
        })

    if op == "resolve":
        market_id = tx.data["market_id"]
        winning_option = tx.data["winning_option"]

        market = markets.get(market_id)
        if market is None:
            return STFResult(success=False, error="market not found")
        if market["resolved"]:
            return STFResult(success=False, error="already resolved")
        if sender != market["creator"]:
            return STFResult(success=False, error="only creator can resolve")
        if winning_option not in market["options"]:
            return STFResult(success=False, error="invalid winning option")

        market["resolved"] = True
        market["winning_option"] = winning_option

        return STFResult(success=True, output={
            "resolved": market_id,
            "winner": winning_option,
            "total_pool": market["total_pool"],
            "winning_pool": market["pools"][winning_option],
        })

    if op == "claim":
        market_id = tx.data["market_id"]

        market = markets.get(market_id)
        if market is None:
            return STFResult(success=False, error="market not found")
        if not market["resolved"]:
            return STFResult(success=False, error="market not resolved yet")

        user_bets = bets.get(market_id, {}).get(sender)
        if user_bets is None:
            return STFResult(success=False, error="no bets found")

        winning_option = market["winning_option"]
        user_winning_bet = user_bets.get(winning_option, 0)
        if user_winning_bet == 0:
            return STFResult(success=False, error="no winning bets")

        # 비례 배분: (user_bet / winning_pool) * total_pool
        winning_pool = market["pools"][winning_option]
        total_pool = market["total_pool"]
        payout = user_winning_bet * total_pool // winning_pool

        balances[sender] = balances.get(sender, 0) + payout

        # 재청구 방지
        user_bets[winning_option] = 0

        return STFResult(success=True, output={
            "claimed": market_id, "payout": payout,
            "bet": user_winning_bet, "ratio": f"{user_winning_bet}/{winning_pool}",
        })

    if op == "advance_block":
        blocks = int(tx.data.get("blocks", 1))
        state["block_number"] = state.get("block_number", 0) + blocks
        return STFResult(success=True, output={"block": state["block_number"]})

    return STFResult(success=False, error=f"unknown op: {op}")


def market_validator(state: dict, tx: L2Tx):
    op = tx.data.get("op")
    valid = ("deposit", "create_market", "bet", "resolve", "claim", "advance_block")
    if op not in valid:
        return f"invalid op: {op}"
    return None


GENESIS = {"markets": {}, "balances": {}, "bets": {}, "block_number": 0}

# ── Rollup 구성 ─────────────────────────────────────────────────────

stf = PythonRuntime(market_stf, validator=market_validator, genesis=GENESIS)
rollup = Rollup(stf=stf)
rollup.setup()

nonces = {ORACLE: 0, ALICE: 0, BOB: 0, CHARLIE: 0}


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


def show_market(mid: str):
    m = rollup.state["markets"][mid]
    status = "RESOLVED" if m["resolved"] else "OPEN"
    print(f"  Market '{mid}': {m['question']}")
    print(f"    Status: {status} | Total pool: {m['total_pool']:,}")
    for opt in m["options"]:
        pool = m["pools"][opt]
        pct = pool * 100 // m["total_pool"] if m["total_pool"] > 0 else 0
        marker = " ← WINNER" if m["winning_option"] == opt else ""
        print(f"    [{opt}]: {pool:,} ({pct}%){marker}")


def show_balances():
    bal = rollup.state["balances"]
    parts = []
    for who in [ORACLE, ALICE, BOB, CHARLIE]:
        b = bal.get(addr(who), 0)
        parts.append(f"{NAMES[addr(who)]}={b:,}")
    print(f"  Balances: {', '.join(parts)}")


# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 Prediction Market — bet / resolve / claim")
print("=" * 60)

# Batch 0: 잔액 충전
print("\n[Batch 0] Deposit funds")
send(ALICE, {"op": "deposit", "amount": "100000"})
send(BOB, {"op": "deposit", "amount": "100000"})
send(CHARLIE, {"op": "deposit", "amount": "100000"})
do_batch("0")

# Batch 1: 시장 생성
print("\n[Batch 1] Create prediction market")
send(ORACLE, {
    "op": "create_market",
    "market_id": "eth-10k",
    "question": "Will ETH reach $10,000 by 2025?",
    "options": ["YES", "NO"],
    "deadline": "100",
})
do_batch("1")

# Batch 2: 베팅
print("\n[Batch 2] Place bets")
send(ALICE, {"op": "bet", "market_id": "eth-10k", "option": "YES", "amount": "30000"})
send(BOB, {"op": "bet", "market_id": "eth-10k", "option": "YES", "amount": "20000"})
send(CHARLIE, {"op": "bet", "market_id": "eth-10k", "option": "NO", "amount": "50000"})
do_batch("2")
show_market("eth-10k")
show_balances()

# 베팅 비율: YES=50,000 (50%) vs NO=50,000 (50%)

# Batch 3: 추가 베팅
print("\n[Batch 3] Additional bets")
send(ALICE, {"op": "bet", "market_id": "eth-10k", "option": "YES", "amount": "10000"})
do_batch("3")
show_market("eth-10k")

# YES=60,000 (60%) vs NO=50,000 (40%)  total=110,000

# Batch 4: Oracle이 YES로 결정
print("\n[Batch 4] Oracle resolves → YES wins")
send(ORACLE, {"op": "resolve", "market_id": "eth-10k", "winning_option": "YES"})
do_batch("4")
show_market("eth-10k")

# Batch 5: 승자들이 청구
print("\n[Batch 5] Winners claim payouts")
send(ALICE, {"op": "claim", "market_id": "eth-10k"})
send(BOB, {"op": "claim", "market_id": "eth-10k"})
do_batch("5")
show_balances()

# 검증: Alice bet 40,000 on YES (of 60,000 YES pool), total 110,000
# Alice payout = 40000 * 110000 / 60000 = 73,333
# Bob payout = 20000 * 110000 / 60000 = 36,666
alice_bal = rollup.state["balances"].get(addr(ALICE), 0)
bob_bal = rollup.state["balances"].get(addr(BOB), 0)
charlie_bal = rollup.state["balances"].get(addr(CHARLIE), 0)

alice_payout = 40000 * 110000 // 60000  # 73,333
bob_payout = 20000 * 110000 // 60000    # 36,666

print(f"\n  Expected payouts (proportional):")
print(f"    Alice: bet 40,000 → payout {alice_payout:,}")
print(f"    Bob:   bet 20,000 → payout {bob_payout:,}")
print(f"    Charlie: bet 50,000 on NO → lost")

assert alice_bal == (100000 - 40000) + alice_payout  # remaining + payout
assert bob_bal == (100000 - 20000) + bob_payout
assert charlie_bal == 100000 - 50000  # lost everything bet on NO

# ── Security: 패배자 claim 시도 ──────────────────────────────────
print("\n[Security] Loser claim attempt")
send(CHARLIE, {"op": "claim", "market_id": "eth-10k"})
rollup._sequencer.tick()
sealed = rollup._sequencer.force_seal()
assert sealed is None, "loser claim should fail"
print(f"  Charlie claim (lost bet): rejected")

# ── Security: 이중 claim 방지 ────────────────────────────────────
print("\n[Security] Double-claim prevention")
send(ALICE, {"op": "claim", "market_id": "eth-10k"})
rollup._sequencer.tick()
sealed = rollup._sequencer.force_seal()
assert sealed is None, "double claim should fail"
print(f"  Alice double-claim: rejected")

# ── 최종 검증 ───────────────────────────────────────────────────────

print("\n[Final State]")
show_market("eth-10k")
show_balances()

total_in = 300000  # 3 * 100000 deposited
total_bal = alice_bal + bob_bal + charlie_bal
# Rounding loss: total payouts may not exactly match
print(f"\n  Total deposited: {total_in:,}")
print(f"  Total balances:  {total_bal:,}")
print(f"  Rounding dust:   {total_in - total_bal}")

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  Market resolved: YES wins")
print(f"  Proportional payouts: Alice={alice_payout:,}, Bob={bob_payout:,}")
print(f"  Loser (Charlie) and double-claim properly rejected")
print(f"{'=' * 60}")
