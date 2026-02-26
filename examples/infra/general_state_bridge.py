#!/usr/bin/env python3
"""General State Bridge — L1↔L2 임의 상태 릴레이 데모

py-ethclient의 EVM을 사용하여 L1과 L2를 한 프로세스에서 실행하고,
CrossDomainMessenger로 임의의 상태를 릴레이합니다.

데모 시나리오:
  1. ETH value transfer (L1→L2)
  2. 임의 상태 릴레이: 오라클 가격 (L1→L2)
  3. ZK proof 릴레이 (L2→L1)
  4. 양방향 상태 릴레이

Run:
    python examples/general_state_bridge.py
"""

import time

from ethclient.bridge import BridgeEnvironment
from ethclient.common.types import Account
from ethclient.common.crypto import keccak256

ALICE = b"\x01" * 20
BOB = b"\x02" * 20
ORACLE = b"\x0a" * 20
ZK_VERIFIER = b"\x0b" * 20

print("=" * 60)
print("  General State Bridge — L1/L2 Cross-Domain Messaging")
print("=" * 60)

env = BridgeEnvironment()

# ━━━ 1. ETH Value Transfer (L1 → L2) ━━━
print(f"\n[1] ETH Deposit: L1 → L2")
env.send_l1(sender=ALICE, target=BOB, value=1_000_000)
result = env.relay()
print(f"    Alice deposits 1,000,000 wei to Bob on L2")
print(f"    Relay: {'PASS' if result.all_success else 'FAIL'}")
print(f"    Bob L2 balance: {env.l2_balance(BOB):,} wei")
assert env.l2_balance(BOB) == 1_000_000

# ━━━ 2. Oracle Price Relay (L1 → L2) ━━━
print(f"\n[2] Oracle Price Relay: L1 → L2")

# Deploy a simple SSTORE contract on L2 (stores calldata[0:32] at slot 0, [32:64] at slot 1)
code = bytes([
    0x60, 0x00, 0x35, 0x60, 0x00, 0x55,  # SSTORE(0, calldata[0:32])
    0x60, 0x20, 0x35, 0x60, 0x01, 0x55,  # SSTORE(1, calldata[32:64])
    0x00,                                  # STOP
])
acc = Account()
acc.code_hash = keccak256(code)
env.l2_store.put_account(ORACLE, acc)
env.l2_store.put_code(acc.code_hash, code)

# Relay ETH/USD and BTC/USD prices
eth_price = 1850
btc_price = 43500
calldata = eth_price.to_bytes(32, "big") + btc_price.to_bytes(32, "big")
env.send_l1(sender=ALICE, target=ORACLE, data=calldata)
result = env.relay()
print(f"    ETH/USD = {eth_price}, BTC/USD = {btc_price}")
print(f"    Relay: {'PASS' if result.all_success else 'FAIL'}")
print(f"    L2 Oracle slot[0] = {env.l2_storage(ORACLE, 0)} (ETH/USD)")
print(f"    L2 Oracle slot[1] = {env.l2_storage(ORACLE, 1)} (BTC/USD)")
assert env.l2_storage(ORACLE, 0) == eth_price
assert env.l2_storage(ORACLE, 1) == btc_price

# ━━━ 3. ZK Proof Relay (L2 → L1) ━━━
print(f"\n[3] ZK Proof Relay: L2 → L1")

from ethclient.zk import Circuit, groth16

# Build circuit on L2
c = Circuit()
secret = c.private("secret")
amount = c.private("amount")
commitment = c.public("commitment")
c.constrain(secret * amount, commitment)

pk, vk = groth16.setup(c)
t0 = time.time()
proof = groth16.prove(
    pk,
    private={"secret": 42, "amount": 100},
    public={"commitment": 4200},
    circuit=c,
)
t_prove = time.time() - t0
print(f"    ZK proof generated: {t_prove:.1f}s")

# Serialize proof + public input as calldata
# (In production, this would be ABI-encoded for a verifier contract)
proof_data = b"ZKPROOF:" + str(4200).encode()

# Deploy a contract on L1 that stores the proof data
code_l1 = bytes([
    0x60, 0x00, 0x35, 0x60, 0x00, 0x55,  # SSTORE(0, calldata[0:32])
    0x00,
])
acc_l1 = Account()
acc_l1.code_hash = keccak256(code_l1)
env.l1_store.put_account(ZK_VERIFIER, acc_l1)
env.l1_store.put_code(acc_l1.code_hash, code_l1)

env.send_l2(sender=BOB, target=ZK_VERIFIER, data=proof_data.ljust(32, b"\x00"))
result = env.relay()
print(f"    L2 → L1 relay: {'PASS' if result.all_success else 'FAIL'}")

# Also verify natively
t0 = time.time()
valid = groth16.verify(vk, proof, [4200])
t_verify = time.time() - t0
print(f"    Native Groth16 verify: {'PASS' if valid else 'FAIL'} ({t_verify:.2f}s)")
assert valid

# ━━━ 4. ETH Withdrawal (L2 → L1) ━━━
print(f"\n[4] ETH Withdrawal: L2 → L1")
env.send_l2(sender=BOB, target=ALICE, value=300_000)
result = env.relay()
print(f"    Bob withdraws 300,000 wei to Alice on L1")
print(f"    Relay: {'PASS' if result.all_success else 'FAIL'}")
print(f"    Alice L1 balance: {env.l1_balance(ALICE):,} wei")
assert env.l1_balance(ALICE) == 300_000

# ━━━ 5. Replay Protection ━━━
print(f"\n[5] Security: Replay Protection")
msg = env.send_l1(sender=ALICE, target=BOB, value=999)
env.relay()
old_balance = env.l2_balance(BOB)
replay = env.l2_messenger.relay_message(msg)
print(f"    Replay attempt: {'REJECTED' if not replay.success else 'ACCEPTED'}")
print(f"    Error: {replay.error}")
assert not replay.success
assert env.l2_balance(BOB) == old_balance

# ━━━ 6. State Root Verification ━━━
print(f"\n[6] State Roots")
l1_root = env.l1_state_root()
l2_root = env.l2_state_root()
print(f"    L1 state root: {l1_root[:8].hex()}...")
print(f"    L2 state root: {l2_root[:8].hex()}...")
print(f"    Independent: {'YES' if l1_root != l2_root else 'NO'}")
assert l1_root != l2_root

# ━━━ Summary ━━━
print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  Messages relayed: {env.watcher.total_relayed}")
print(f"  L1 state root: {l1_root[:8].hex()}...")
print(f"  L2 state root: {l2_root[:8].hex()}...")
print(f"  Scenarios: ETH deposit, oracle relay, ZK proof, withdrawal, replay")
print(f"{'=' * 60}")
