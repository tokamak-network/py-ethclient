#!/usr/bin/env python3
"""L2 DEX — Constant Product AMM (x*y=k) 데모

App-specific ZK Rollup 위에서 동작하는 AMM DEX.
add_liquidity / remove_liquidity / swap 오퍼레이션.
LP 토큰 발행, 0.3% 수수료, 슬리피지 검증.

Run:
    python examples/apps/l2_dex.py
"""

import math

from ethclient.l2 import Rollup, L2Tx, STFResult, PythonRuntime

# ── 주소 헬퍼 ───────────────────────────────────────────────────────
ADMIN = b"\x01" * 20
ALICE = b"\x02" * 20
BOB = b"\x03" * 20

NAMES = {ADMIN.hex(): "Admin", ALICE.hex(): "Alice", BOB.hex(): "Bob"}


def addr(who: bytes) -> str:
    return who.hex()


# ── STF 정의 ────────────────────────────────────────────────────────

FEE_BPS = 30  # 0.3% = 30 basis points


def dex_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    pools = state["pools"]
    lp_tokens = state["lp_tokens"]
    balances = state["balances"]
    sender = addr(tx.sender)

    if op == "mint":
        token = tx.data["token"]
        amount = int(tx.data["amount"])
        key = f"{sender}:{token}"
        balances[key] = balances.get(key, 0) + amount
        return STFResult(success=True, output={"minted": amount, "token": token})

    if op == "add_liquidity":
        pair = tx.data["pair"]  # e.g. "ETH:USDC"
        token_a, token_b = pair.split(":")
        amount_a = int(tx.data["amount_a"])
        amount_b = int(tx.data["amount_b"])

        # 잔액 확인
        bal_a = balances.get(f"{sender}:{token_a}", 0)
        bal_b = balances.get(f"{sender}:{token_b}", 0)
        if bal_a < amount_a:
            return STFResult(success=False, error=f"insufficient {token_a}")
        if bal_b < amount_b:
            return STFResult(success=False, error=f"insufficient {token_b}")

        pool = pools.get(pair)
        if pool is None:
            # 새 풀 생성
            lp_minted = int(math.isqrt(amount_a * amount_b))
            pools[pair] = {
                "reserve_a": amount_a,
                "reserve_b": amount_b,
                "total_lp": lp_minted,
                "token_a": token_a,
                "token_b": token_b,
            }
        else:
            # 기존 풀에 비례 추가
            ra, rb = pool["reserve_a"], pool["reserve_b"]
            lp_minted = min(amount_a * pool["total_lp"] // ra,
                           amount_b * pool["total_lp"] // rb)
            pool["reserve_a"] = ra + amount_a
            pool["reserve_b"] = rb + amount_b
            pool["total_lp"] += lp_minted

        balances[f"{sender}:{token_a}"] = bal_a - amount_a
        balances[f"{sender}:{token_b}"] = bal_b - amount_b

        lp_key = f"{sender}:LP:{pair}"
        lp_tokens[lp_key] = lp_tokens.get(lp_key, 0) + lp_minted

        return STFResult(success=True, output={
            "lp_minted": lp_minted, "pair": pair,
        })

    if op == "remove_liquidity":
        pair = tx.data["pair"]
        lp_amount = int(tx.data["lp_amount"])
        pool = pools.get(pair)
        if pool is None:
            return STFResult(success=False, error="pool not found")

        lp_key = f"{sender}:LP:{pair}"
        if lp_tokens.get(lp_key, 0) < lp_amount:
            return STFResult(success=False, error="insufficient LP tokens")

        total_lp = pool["total_lp"]
        amount_a = lp_amount * pool["reserve_a"] // total_lp
        amount_b = lp_amount * pool["reserve_b"] // total_lp

        pool["reserve_a"] -= amount_a
        pool["reserve_b"] -= amount_b
        pool["total_lp"] -= lp_amount
        lp_tokens[lp_key] -= lp_amount

        token_a, token_b = pool["token_a"], pool["token_b"]
        balances[f"{sender}:{token_a}"] = balances.get(f"{sender}:{token_a}", 0) + amount_a
        balances[f"{sender}:{token_b}"] = balances.get(f"{sender}:{token_b}", 0) + amount_b

        return STFResult(success=True, output={
            "withdrawn_a": amount_a, "withdrawn_b": amount_b,
        })

    if op == "swap":
        pair = tx.data["pair"]
        token_in = tx.data["token_in"]
        amount_in = int(tx.data["amount_in"])
        min_out = int(tx.data.get("min_out", 0))

        pool = pools.get(pair)
        if pool is None:
            return STFResult(success=False, error="pool not found")

        bal_in = balances.get(f"{sender}:{token_in}", 0)
        if bal_in < amount_in:
            return STFResult(success=False, error=f"insufficient {token_in}")

        # x*y=k with 0.3% fee
        token_a, token_b = pool["token_a"], pool["token_b"]
        if token_in == token_a:
            r_in, r_out = pool["reserve_a"], pool["reserve_b"]
            token_out = token_b
        elif token_in == token_b:
            r_in, r_out = pool["reserve_b"], pool["reserve_a"]
            token_out = token_a
        else:
            return STFResult(success=False, error=f"{token_in} not in pool")

        amount_in_after_fee = amount_in * (10000 - FEE_BPS) // 10000
        amount_out = r_out * amount_in_after_fee // (r_in + amount_in_after_fee)

        if amount_out < min_out:
            return STFResult(success=False, error=f"slippage: got {amount_out} < min {min_out}")
        if amount_out == 0:
            return STFResult(success=False, error="zero output")

        # invariant check: new k >= old k
        new_r_in = r_in + amount_in
        new_r_out = r_out - amount_out
        assert new_r_in * new_r_out >= r_in * r_out, "k invariant broken"

        if token_in == token_a:
            pool["reserve_a"] = new_r_in
            pool["reserve_b"] = new_r_out
        else:
            pool["reserve_b"] = new_r_in
            pool["reserve_a"] = new_r_out

        balances[f"{sender}:{token_in}"] = bal_in - amount_in
        balances[f"{sender}:{token_out}"] = balances.get(f"{sender}:{token_out}", 0) + amount_out

        return STFResult(success=True, output={
            "amount_in": amount_in, "amount_out": amount_out,
            "token_in": token_in, "token_out": token_out,
            "price_impact_bps": int((1 - amount_out * r_in / (amount_in * r_out)) * 10000),
        })

    return STFResult(success=False, error=f"unknown op: {op}")


def dex_validator(state: dict, tx: L2Tx):
    op = tx.data.get("op")
    valid_ops = ("mint", "add_liquidity", "remove_liquidity", "swap")
    if op not in valid_ops:
        return f"invalid op: {op}"
    return None


GENESIS = {"pools": {}, "lp_tokens": {}, "balances": {}}

# ── Rollup 구성 ─────────────────────────────────────────────────────

stf = PythonRuntime(dex_stf, validator=dex_validator, genesis=GENESIS)
rollup = Rollup(stf=stf)
rollup.setup()

nonces = {ADMIN: 0, ALICE: 0, BOB: 0}


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


def show_pool(pair: str):
    pool = rollup.state["pools"].get(pair)
    if pool is None:
        print(f"  Pool {pair}: (none)")
        return
    ra, rb = pool["reserve_a"], pool["reserve_b"]
    price = rb / ra if ra > 0 else 0
    print(f"  Pool {pair}: {ra:,} / {rb:,}  (k={ra*rb:,}, price={price:.2f}, LP={pool['total_lp']:,})")


def show_balance(who: bytes, tokens: list[str]):
    bal = rollup.state["balances"]
    parts = []
    for t in tokens:
        b = bal.get(f"{addr(who)}:{t}", 0)
        parts.append(f"{t}={b:,}")
    name = NAMES[addr(who)]
    print(f"  {name}: {', '.join(parts)}")


# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 DEX — Constant Product AMM (x*y=k)")
print("=" * 60)

# Batch 0: 토큰 민트
print("\n[Batch 0] Mint tokens")
send(ADMIN, {"op": "mint", "token": "ETH", "amount": "100000"})
send(ADMIN, {"op": "mint", "token": "USDC", "amount": "200000000"})
send(ALICE, {"op": "mint", "token": "ETH", "amount": "50000"})
send(ALICE, {"op": "mint", "token": "USDC", "amount": "100000000"})
send(BOB, {"op": "mint", "token": "ETH", "amount": "10000"})
send(BOB, {"op": "mint", "token": "USDC", "amount": "20000000"})
do_batch("0")

# Batch 1: 유동성 공급 (Admin이 초기 풀 생성)
print("\n[Batch 1] Add liquidity — create ETH:USDC pool")
send(ADMIN, {"op": "add_liquidity", "pair": "ETH:USDC",
             "amount_a": "100000", "amount_b": "200000000"})
do_batch("1")
show_pool("ETH:USDC")

# Batch 2: Alice도 유동성 추가
print("\n[Batch 2] Alice adds liquidity")
send(ALICE, {"op": "add_liquidity", "pair": "ETH:USDC",
             "amount_a": "50000", "amount_b": "100000000"})
do_batch("2")
show_pool("ETH:USDC")

# Batch 3: Bob이 ETH → USDC 스왑 (0.3% 수수료 적용)
print("\n[Batch 3] Bob swaps 1,000 ETH → USDC")
send(BOB, {"op": "swap", "pair": "ETH:USDC",
           "token_in": "ETH", "amount_in": "1000", "min_out": "1"})
do_batch("3")
show_pool("ETH:USDC")
show_balance(BOB, ["ETH", "USDC"])

# Batch 4: Alice가 유동성 제거
print("\n[Batch 4] Alice removes half LP")
lp_key = f"{addr(ALICE)}:LP:ETH:USDC"
alice_lp = rollup.state["lp_tokens"].get(lp_key, 0)
remove_amount = alice_lp // 2
send(ALICE, {"op": "remove_liquidity", "pair": "ETH:USDC",
             "lp_amount": str(remove_amount)})
do_batch("4")
show_pool("ETH:USDC")
show_balance(ALICE, ["ETH", "USDC"])

# ── 슬리피지 검증 ───────────────────────────────────────────────────

print("\n[Security] Slippage protection test")
# 매우 높은 min_out으로 슬리피지 실패
send(BOB, {"op": "swap", "pair": "ETH:USDC",
           "token_in": "ETH", "amount_in": "100", "min_out": "999999999"})
rollup._sequencer.tick()
sealed = rollup._sequencer.force_seal()
assert sealed is None, "slippage fail should rollback"
print(f"  High slippage swap: rejected (STF rollback)")

# ── 최종 검증 ───────────────────────────────────────────────────────

print("\n[Final State]")
pool = rollup.state["pools"]["ETH:USDC"]
ra, rb = pool["reserve_a"], pool["reserve_b"]
k = ra * rb
show_pool("ETH:USDC")

# k invariant: new reserves should maintain or grow k
assert k > 0, "k should be positive"
assert pool["total_lp"] > 0, "total LP should be positive"

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  k invariant maintained: {k:,}")
print(f"  Pool ETH:USDC active with {pool['total_lp']:,} LP tokens")
print(f"{'=' * 60}")
