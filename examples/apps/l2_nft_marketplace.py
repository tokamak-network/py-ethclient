#!/usr/bin/env python3
"""L2 NFT Marketplace — mint / transfer / list / buy / cancel 데모

App-specific ZK Rollup 위에서 동작하는 NFT 마켓플레이스.
컬렉션 개념, 소유권 추적, 판매 등록, 로열티 (creator에게 5%).

Run:
    python examples/apps/l2_nft_marketplace.py
"""

from ethclient.l2 import Rollup, L2Tx, STFResult, PythonRuntime

# ── 주소 헬퍼 ───────────────────────────────────────────────────────
ALICE = b"\x01" * 20
BOB = b"\x02" * 20
CHARLIE = b"\x03" * 20

NAMES = {ALICE.hex(): "Alice", BOB.hex(): "Bob", CHARLIE.hex(): "Charlie"}


def addr(who: bytes) -> str:
    return who.hex()


# ── STF 정의 ────────────────────────────────────────────────────────

ROYALTY_BPS = 500  # 5%


def nft_stf(state: dict, tx: L2Tx) -> STFResult:
    op = tx.data.get("op")
    owners = state["owners"]          # token_id → owner_addr
    listings = state["listings"]      # token_id → {price, seller}
    collections = state["collections"]  # collection → {creator, tokens[]}
    balances = state["balances"]      # addr → coin balance
    metadata = state["metadata"]      # token_id → {name, collection, creator}
    sender = addr(tx.sender)

    if op == "deposit":
        amount = int(tx.data["amount"])
        balances[sender] = balances.get(sender, 0) + amount
        return STFResult(success=True, output={"deposited": amount})

    if op == "mint":
        token_id = tx.data["token_id"]
        collection = tx.data.get("collection", "default")
        name = tx.data.get("name", token_id)

        if token_id in owners:
            return STFResult(success=False, error=f"token {token_id} already exists")

        owners[token_id] = sender
        metadata[token_id] = {
            "name": name,
            "collection": collection,
            "creator": sender,
        }

        if collection not in collections:
            collections[collection] = {"creator": sender, "tokens": []}
        collections[collection]["tokens"].append(token_id)

        state["next_id"] = state.get("next_id", 0) + 1
        return STFResult(success=True, output={"minted": token_id})

    if op == "transfer":
        token_id = tx.data["token_id"]
        to = tx.data["to"]
        if owners.get(token_id) != sender:
            return STFResult(success=False, error="not the owner")
        if token_id in listings:
            return STFResult(success=False, error="delist before transfer")
        owners[token_id] = to
        return STFResult(success=True, output={"transferred": token_id})

    if op == "list":
        token_id = tx.data["token_id"]
        price = int(tx.data["price"])
        if owners.get(token_id) != sender:
            return STFResult(success=False, error="not the owner")
        if price <= 0:
            return STFResult(success=False, error="price must be positive")
        listings[token_id] = {"price": price, "seller": sender}
        return STFResult(success=True, output={"listed": token_id, "price": price})

    if op == "cancel":
        token_id = tx.data["token_id"]
        listing = listings.get(token_id)
        if listing is None:
            return STFResult(success=False, error="not listed")
        if listing["seller"] != sender:
            return STFResult(success=False, error="not the seller")
        del listings[token_id]
        return STFResult(success=True, output={"cancelled": token_id})

    if op == "buy":
        token_id = tx.data["token_id"]
        listing = listings.get(token_id)
        if listing is None:
            return STFResult(success=False, error="not listed")
        if listing["seller"] == sender:
            return STFResult(success=False, error="cannot buy own listing")

        price = listing["price"]
        buyer_bal = balances.get(sender, 0)
        if buyer_bal < price:
            return STFResult(success=False, error="insufficient balance")

        # 로열티 계산
        creator = metadata[token_id]["creator"]
        royalty = price * ROYALTY_BPS // 10000
        seller_revenue = price - royalty

        # 잔액 이동
        balances[sender] = buyer_bal - price
        seller = listing["seller"]
        balances[seller] = balances.get(seller, 0) + seller_revenue
        balances[creator] = balances.get(creator, 0) + royalty

        # 소유권 이전
        owners[token_id] = sender
        del listings[token_id]

        return STFResult(success=True, output={
            "bought": token_id, "price": price,
            "royalty": royalty, "seller_revenue": seller_revenue,
        })

    return STFResult(success=False, error=f"unknown op: {op}")


def nft_validator(state: dict, tx: L2Tx):
    op = tx.data.get("op")
    valid = ("deposit", "mint", "transfer", "list", "buy", "cancel")
    if op not in valid:
        return f"invalid op: {op}"
    if op == "mint" and not tx.data.get("token_id"):
        return "token_id required"
    return None


GENESIS = {
    "owners": {},
    "listings": {},
    "collections": {},
    "balances": {},
    "metadata": {},
    "next_id": 0,
}

# ── Rollup 구성 ─────────────────────────────────────────────────────

stf = PythonRuntime(nft_stf, validator=nft_validator, genesis=GENESIS)
rollup = Rollup(stf=stf)
rollup.setup()

nonces = {ALICE: 0, BOB: 0, CHARLIE: 0}


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


def show_state():
    owners = rollup.state["owners"]
    listings = rollup.state["listings"]
    balances = rollup.state["balances"]
    print("  Ownership:")
    for tid, owner in sorted(owners.items()):
        name = NAMES.get(owner, owner[:8])
        listed = " [LISTED]" if tid in listings else ""
        print(f"    {tid}: {name}{listed}")
    print("  Balances:")
    for a, b in sorted(balances.items()):
        name = NAMES.get(a, a[:8])
        if b > 0:
            print(f"    {name}: {b:,}")


# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 NFT Marketplace — mint / list / buy with royalties")
print("=" * 60)

# Batch 0: 잔액 충전 + NFT 민트
print("\n[Batch 0] Deposit funds + Mint NFTs")
send(ALICE, {"op": "deposit", "amount": "0"})  # Alice는 creator, 잔액 불필요
send(BOB, {"op": "deposit", "amount": "100000"})
send(CHARLIE, {"op": "deposit", "amount": "100000"})

send(ALICE, {"op": "mint", "token_id": "punk#001", "collection": "CryptoPunks",
             "name": "Punk #001"})
send(ALICE, {"op": "mint", "token_id": "punk#002", "collection": "CryptoPunks",
             "name": "Punk #002"})
send(ALICE, {"op": "mint", "token_id": "ape#001", "collection": "BoredApes",
             "name": "Ape #001"})
do_batch("0")
show_state()

# Batch 1: Alice가 판매 등록
print("\n[Batch 1] Alice lists NFTs for sale")
send(ALICE, {"op": "list", "token_id": "punk#001", "price": "50000"})
send(ALICE, {"op": "list", "token_id": "ape#001", "price": "80000"})
do_batch("1")

# Batch 2: Bob이 punk#001 구매 (Alice에게 로열티)
print("\n[Batch 2] Bob buys punk#001 (royalty to Alice)")
send(BOB, {"op": "buy", "token_id": "punk#001"})
do_batch("2")
show_state()

# 로열티 확인: Alice = creator, price 50000, royalty 5% = 2500
alice_bal = rollup.state["balances"].get(addr(ALICE), 0)
# Alice는 seller이면서 creator이므로 seller_revenue + royalty = 47500 + 2500 = 50000
print(f"\n  Alice received: {alice_bal:,} (seller_revenue + royalty)")

# Batch 3: Bob이 punk#001 재판매 → Charlie 구매 (Alice에게 로열티)
print("\n[Batch 3] Bob re-lists punk#001, Charlie buys (royalty to Alice)")
send(BOB, {"op": "list", "token_id": "punk#001", "price": "70000"})
send(CHARLIE, {"op": "buy", "token_id": "punk#001"})
do_batch("3")
show_state()

# 이번엔 Alice는 순수 creator 로열티만 수령 (70000 * 5% = 3500)
alice_bal_after = rollup.state["balances"].get(addr(ALICE), 0)
royalty_received = alice_bal_after - alice_bal
print(f"  Alice royalty from resale: {royalty_received:,} (5% of 70,000)")
assert royalty_received == 3500

# Batch 4: 직접 transfer (listing 없이)
print("\n[Batch 4] Charlie transfers punk#001 to Bob (no sale)")
send(CHARLIE, {"op": "transfer", "token_id": "punk#001", "to": addr(BOB)})
do_batch("4")

# ── Security: 비소유자 판매/이전 ──────────────────────────────────
print("\n[Security] Non-owner attempts")
send(ALICE, {"op": "transfer", "token_id": "punk#001", "to": addr(ALICE)})
rollup._sequencer.tick()
sealed = rollup._sequencer.force_seal()
assert sealed is None, "non-owner transfer should fail"
print(f"  Alice transfer punk#001 (not owner): rejected")

# ── 최종 검증 ───────────────────────────────────────────────────────

print("\n[Final State]")
show_state()

owners = rollup.state["owners"]
assert owners["punk#001"] == addr(BOB)
assert owners["punk#002"] == addr(ALICE)
assert owners["ape#001"] == addr(ALICE)  # ape#001 was listed but not bought → still Alice

collections = rollup.state["collections"]
assert len(collections["CryptoPunks"]["tokens"]) == 2
assert len(collections["BoredApes"]["tokens"]) == 1

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  punk#001 → Bob, punk#002 → Alice, ape#001 → Alice")
print(f"  Collections: CryptoPunks(2), BoredApes(1)")
print(f"  Royalty system: 5% to original creator on every sale")
print(f"{'=' * 60}")
