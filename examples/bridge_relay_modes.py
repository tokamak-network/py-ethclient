#!/usr/bin/env python3
"""Proof-Based Relay Modes — 5가지 릴레이 핸들러 비교 데모

py-ethclient 브릿지는 플러거블 릴레이 핸들러를 지원합니다.
EVM 외에도 Merkle proof, ZK proof, Direct State, TinyDB 모드를 사용할 수 있습니다.

데모 시나리오:
  1. EVM relay (기본, 하위 호환)
  2. Direct state relay (신뢰 릴레이어)
  3. Merkle proof relay (L1 상태 증명)
  4. TinyDB relay (문서 DB 백엔드)
  5. ZK proof relay (Groth16 검증) — 느림, ~20초

Run:
    python examples/bridge_relay_modes.py
"""

import time

from ethclient.bridge import (
    BridgeEnvironment,
    StateUpdate,
    EVMRelayHandler,
    DirectStateHandler,
    MerkleProofHandler,
    TinyDBHandler,
    encode_state_updates,
)
from ethclient.common import rlp
from ethclient.common.crypto import keccak256
from ethclient.common.trie import Trie

ALICE = b"\x01" * 20
BOB = b"\x02" * 20

def addr_short(a: bytes) -> str:
    return "0x" + a[:4].hex() + "..."


print("=" * 60)
print("  Proof-Based Relay Modes — 5 Handler Comparison")
print("=" * 60)

# ─────────────────────────────────────────────────────────────
# 1. EVM Relay (기본)
# ─────────────────────────────────────────────────────────────
print("\n[1/5] EVM Relay (default)")
print("-" * 40)

t0 = time.perf_counter()
env = BridgeEnvironment()  # default: EVMRelayHandler
msg = env.send_l1(sender=ALICE, target=BOB, value=1_000)
result = env.relay()
dt = time.perf_counter() - t0

print(f"  Handler: {type(env.l2_messenger.relay_handler).__name__}")
print(f"  L1 → L2: {result.l1_to_l2[0].success}")
print(f"  BOB L2 balance: {env.l2_balance(BOB)}")
print(f"  Time: {dt*1000:.1f}ms")

# ─────────────────────────────────────────────────────────────
# 2. Direct State Relay (신뢰 릴레이어)
# ─────────────────────────────────────────────────────────────
print("\n[2/5] Direct State Relay (trusted relayer)")
print("-" * 40)

t0 = time.perf_counter()
env = BridgeEnvironment.with_direct_state()

updates = [
    StateUpdate(address=ALICE, balance=5_000, nonce=1),
    StateUpdate(address=BOB, balance=3_000, nonce=2),
]
data = encode_state_updates(updates)
env.send_l1(sender=ALICE, target=BOB, data=data)
result = env.relay()
dt = time.perf_counter() - t0

print(f"  Handler: {type(env.l2_messenger.relay_handler).__name__}")
print(f"  L1 → L2: {result.l1_to_l2[0].success}")
print(f"  ALICE L2 balance: {env.l2_store.get_balance(ALICE)}")
print(f"  BOB L2 balance: {env.l2_store.get_balance(BOB)}")
print(f"  Time: {dt*1000:.1f}ms")

# ─────────────────────────────────────────────────────────────
# 3. Merkle Proof Relay
# ─────────────────────────────────────────────────────────────
print("\n[3/5] Merkle Proof Relay")
print("-" * 40)

EMPTY_ROOT = b"\x56\xe8\x1f\x17\x1b\xcc\x55\xa6\xff\x83\x45\xe6\x92\xc0\xf8\x6e\x5b\x48\xe0\x1b\x99\x6c\xad\xc0\x01\x62\x2f\xb5\xe3\x63\xb4\x21"
EMPTY_CODE = b"\xc5\xd2\x46\x01\x86\xf7\x23\x3c\x92\x7e\x7d\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6\x53\xca\x82\x27\x3b\x7b\xfa\xd8\x04\x5d\x85\xa4\x70"

t0 = time.perf_counter()
env = BridgeEnvironment.with_merkle_proof()

# Set up L1 state
env.l1_store.set_balance(ALICE, 10_000)
env.l1_store.set_nonce(ALICE, 42)

# Build Merkle proof from L1 state
trie = Trie()
for addr, acc in env.l1_store.iter_accounts():
    account_rlp = rlp.encode([acc.nonce, acc.balance, EMPTY_ROOT, EMPTY_CODE])
    trie.put_raw(keccak256(addr), account_rlp)

root = trie.root_hash
proof_nodes = trie.prove(keccak256(ALICE))
account_rlp = rlp.encode([42, 10_000, EMPTY_ROOT, EMPTY_CODE])

# Register trusted root and send
handler = env.l2_messenger.relay_handler
handler.add_trusted_root(root)

data = rlp.encode([root, ALICE, account_rlp, proof_nodes])
env.send_l1(sender=ALICE, target=BOB, data=data)
result = env.relay()
dt = time.perf_counter() - t0

print(f"  Handler: {type(handler).__name__}")
print(f"  L1 state root: 0x{root[:8].hex()}...")
print(f"  Proof nodes: {len(proof_nodes)}")
print(f"  L1 → L2: {result.l1_to_l2[0].success}")
print(f"  ALICE L2 balance (proven): {env.l2_store.get_balance(ALICE)}")
print(f"  ALICE L2 nonce (proven): {env.l2_store.get_nonce(ALICE)}")
print(f"  Time: {dt*1000:.1f}ms")

# ─────────────────────────────────────────────────────────────
# 4. TinyDB Relay (문서 DB 백엔드)
# ─────────────────────────────────────────────────────────────
print("\n[4/5] TinyDB Relay (document DB backend)")
print("-" * 40)

t0 = time.perf_counter()
tinydb_handler = TinyDBHandler()
env = BridgeEnvironment(l2_handler=tinydb_handler)

updates = [
    StateUpdate(address=ALICE, balance=7_777, nonce=10, storage={1: 42}),
    StateUpdate(address=BOB, balance=3_333, storage={100: 200}),
]
data = encode_state_updates(updates)
env.send_l1(sender=ALICE, target=BOB, data=data)
result = env.relay()
dt = time.perf_counter() - t0

print(f"  Handler: {type(tinydb_handler).__name__}")
print(f"  L1 → L2: {result.l1_to_l2[0].success}")
print(f"  TinyDB documents: {len(tinydb_handler.db.all())}")
for doc in tinydb_handler.db.all():
    print(f"    {doc['address'][:14]}... → "
          f"balance={doc.get('balance', 'N/A')}, "
          f"nonce={doc.get('nonce', 'N/A')}, "
          f"storage={doc.get('storage', {})}")
print(f"  Ethereum Store untouched: ALICE balance={env.l2_store.get_balance(ALICE)}")
print(f"  Time: {dt*1000:.1f}ms")

# ─────────────────────────────────────────────────────────────
# 5. ZK Proof Relay (Groth16)
# ─────────────────────────────────────────────────────────────
print("\n[5/5] ZK Proof Relay (Groth16)")
print("-" * 40)
print("  Setting up circuit + trusted setup...")

t0 = time.perf_counter()
from ethclient.zk import Circuit, groth16

c = Circuit()
old_bal = c.public("old_balance")
amount = c.public("amount")
new_bal = c.public("new_balance")
one = c.private("one")
product = (old_bal + amount) * one
c.constrain(product, new_bal)

pk, vk = groth16.setup(c)
t_setup = time.perf_counter() - t0
print(f"  Circuit: old_balance + amount = new_balance (1 constraint)")
print(f"  Setup time: {t_setup:.1f}s")

# Generate proof
t0 = time.perf_counter()
proof = groth16.prove(
    pk,
    private={"one": 1},
    public={"old_balance": 1000, "amount": 500, "new_balance": 1500},
    circuit=c,
)
t_prove = time.perf_counter() - t0
print(f"  Prove time: {t_prove:.1f}s")

# Build msg.data
proof_a = proof.a.to_evm_bytes()
proof_b = proof.b.to_evm_bytes()
proof_c = proof.c.to_evm_bytes()

public_inputs = [
    (1000).to_bytes(32, "big"),
    (500).to_bytes(32, "big"),
    (1500).to_bytes(32, "big"),
]

updates = [StateUpdate(address=BOB, balance=1500)]
state_updates_rlp = [rlp.decode(u.encode()) for u in updates]

zk_data = rlp.encode([
    proof_a, proof_b, proof_c,
    public_inputs, state_updates_rlp,
])

# Relay
t0 = time.perf_counter()
env = BridgeEnvironment.with_zk_proof(vk)
env.send_l1(sender=ALICE, target=BOB, data=zk_data)
result = env.relay()
t_verify = time.perf_counter() - t0

print(f"  Verify + apply time: {t_verify:.1f}s")
print(f"  L1 → L2: {result.l1_to_l2[0].success}")
print(f"  BOB L2 balance (ZK proven): {env.l2_store.get_balance(BOB)}")

# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("  Summary")
print("=" * 60)
print("""
  Handler             | Trust Model           | EVM Required
  ────────────────────┼───────────────────────┼─────────────
  EVMRelayHandler     | On-chain execution    | Yes
  DirectStateHandler  | Trusted relayer       | No
  MerkleProofHandler  | Merkle proof (L1→L2)  | No
  TinyDBHandler       | Trusted + TinyDB      | No
  ZKProofHandler      | ZK proof (Groth16)    | No

  With proof-based relay, L2 can use ANY runtime — not just EVM.
""")
