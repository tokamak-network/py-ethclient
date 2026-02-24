#!/usr/bin/env python3
"""L2 Censorship Resistance — Force Inclusion + Escape Hatch 데모

시나리오 1: Sequencer가 검열 → force_include → advance_l1_block → force_relay
시나리오 2: L2 완전 다운 → escape_hatch로 L1에서 자금 회수
CrossDomainMessenger 상태 변화를 추적합니다.

Run:
    python examples/infra/l2_censorship_resistance.py
"""

from ethclient.bridge import BridgeEnvironment

# ── 주소 ──────────────────────────────────────────────────────────
ALICE = b"\x01" * 20
BOB = b"\x02" * 20
SEQUENCER = b"\x0f" * 20

NAMES = {ALICE.hex(): "Alice", BOB.hex(): "Bob", SEQUENCER.hex(): "Sequencer"}


def addr_short(a: bytes) -> str:
    return "0x" + a[:4].hex() + "..."


# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 Censorship Resistance — Force Inclusion + Escape Hatch")
print("=" * 60)

# ━━━ Scenario 1: Sequencer 검열 → Force Inclusion ━━━
print("\n━━━ Scenario 1: Sequencer Censorship → Force Inclusion ━━━")

env = BridgeEnvironment()

# Step 1: Alice가 L1에서 L2로 메시지 전송 (Sequencer가 검열한다고 가정)
print("\n[Step 1] Alice sends L1→L2 message (censored by sequencer)")
msg = env.send_l1(sender=ALICE, target=BOB, value=1_000_000)
print(f"  Message: {addr_short(ALICE)} → {addr_short(BOB)}, value=1,000,000 wei")
print(f"  Message hash: {msg.message_hash.hex()[:16]}...")

# 일반 relay는 Sequencer가 거부 → 여기서는 relay 하지 않음
print(f"  Sequencer refuses to relay this message.")

# Step 2: Force Inclusion (L1에 강제 등록)
print("\n[Step 2] Force include on L1")
entry = env.force_include(msg)
print(f"  Force inclusion registered at L1 block #{entry.registered_block}")

from ethclient.bridge import FORCE_INCLUSION_WINDOW
print(f"  Inclusion window: {FORCE_INCLUSION_WINDOW} blocks")

# Step 3: L1 블록 전진 (inclusion window 이후)
print("\n[Step 3] Advance L1 blocks past inclusion window")
blocks_to_advance = FORCE_INCLUSION_WINDOW + 1
env.advance_l1_block(blocks_to_advance)
print(f"  Advanced {blocks_to_advance} blocks (now past window)")

# Step 4: Force Relay
print("\n[Step 4] Force relay — bypass sequencer")
result = env.force_relay(msg)
print(f"  Force relay: {'SUCCESS' if result.success else 'FAILED'}")
if not result.success:
    print(f"  Error: {result.error}")
assert result.success, f"Force relay failed: {result.error}"

# 결과 확인
bob_balance = env.l2_balance(BOB)
print(f"  Bob L2 balance: {bob_balance:,} wei")
assert bob_balance == 1_000_000, f"Expected 1,000,000, got {bob_balance}"
print(f"  Censorship bypassed successfully!")

# ━━━ Scenario 2: L2 Down → Escape Hatch ━━━
print("\n━━━ Scenario 2: L2 Completely Down → Escape Hatch ━━━")

env2 = BridgeEnvironment()

# Step 1: Bob이 L2에 자금을 가지고 있음
print("\n[Step 1] Bob deposits funds to L2")
deposit_msg = env2.send_l1(sender=BOB, target=BOB, value=5_000_000)
result = env2.relay()
print(f"  Deposit: {'SUCCESS' if result.all_success else 'FAILED'}")
bob_l2 = env2.l2_balance(BOB)
print(f"  Bob L2 balance: {bob_l2:,} wei")
assert bob_l2 == 5_000_000

# Step 2: L2가 완전히 다운됨 (Sequencer 없음)
print("\n[Step 2] L2 goes down — sequencer offline")
print(f"  Simulating L2 failure (no relay available)")

# Step 3: Bob이 L2→L1 탈출 메시지 전송
print("\n[Step 3] Bob sends L2→L1 escape message")
escape_msg = env2.send_l2(sender=BOB, target=BOB, value=2_000_000)
print(f"  Escape message: {addr_short(BOB)} → L1, value=2,000,000 wei")

# Step 4: Force include on L1 (escape hatch requires force queue registration)
print("\n[Step 4] Force include escape message on L1")
entry = env2.force_include(escape_msg)
print(f"  Registered at L1 block #{entry.registered_block}")

# Step 5: Advance blocks past inclusion window
print("\n[Step 5] Advance L1 blocks past inclusion window")
env2.advance_l1_block(FORCE_INCLUSION_WINDOW + 1)
print(f"  Advanced {FORCE_INCLUSION_WINDOW + 1} blocks")

# Step 6: Escape hatch — L1에서 직접 자금 회수
print("\n[Step 6] Execute escape hatch on L1")
escape_result = env2.escape_hatch(escape_msg)
print(f"  Escape hatch: {'SUCCESS' if escape_result.success else 'FAILED'}")
if not escape_result.success:
    print(f"  Error: {escape_result.error}")
assert escape_result.success, f"Escape hatch failed: {escape_result.error}"

bob_l1 = env2.l1_balance(BOB)
print(f"  Bob L1 balance: {bob_l1:,} wei")
assert bob_l1 == 2_000_000, f"Expected 2,000,000, got {bob_l1}"
print(f"  Funds recovered from L2 via escape hatch!")

# ━━━ Scenario 3: 정상 경로와 비교 ━━━
print("\n━━━ Scenario 3: Normal Path (for comparison) ━━━")

env3 = BridgeEnvironment()

# 정상적인 L1→L2 릴레이
msg_normal = env3.send_l1(sender=ALICE, target=BOB, value=500_000)
result_normal = env3.relay()

print(f"  Normal relay: {'SUCCESS' if result_normal.all_success else 'FAILED'}")
print(f"  Bob L2: {env3.l2_balance(BOB):,} wei")

# 정상적인 L2→L1 릴레이
msg_withdraw = env3.send_l2(sender=BOB, target=ALICE, value=200_000)
result_withdraw = env3.relay()

print(f"  Normal withdrawal: {'SUCCESS' if result_withdraw.all_success else 'FAILED'}")
print(f"  Alice L1: {env3.l1_balance(ALICE):,} wei")

# Replay protection (모든 경로에 적용)
print(f"\n  Replay protection:")
replay = env3.l2_messenger.relay_message(msg_normal)
print(f"    L1→L2 replay: {'BLOCKED' if not replay.success else 'ALLOWED'}")
assert not replay.success

# ━━━ State Root Tracking ━━━
print(f"\n━━━ State Root Tracking ━━━")
for label, e in [("Scenario 1", env), ("Scenario 2", env2), ("Scenario 3", env3)]:
    l1_root = e.l1_state_root()
    l2_root = e.l2_state_root()
    print(f"  {label}: L1={l1_root[:6].hex()}... L2={l2_root[:6].hex()}...")

# ── Summary ──
print(f"\n{'=' * 60}")
print(f"  Censorship Resistance Summary")
print(f"{'=' * 60}")
print("""
  Mechanism        | Trigger                   | Who Can Use
  ─────────────────┼───────────────────────────┼─────────────────
  Normal Relay     | Watcher detects message   | Watcher (auto)
  Force Inclusion  | Sequencer censors tx      | Anyone (L1 tx)
  Force Relay      | After inclusion window    | Anyone (L1 tx)
  Escape Hatch     | L2 completely down        | Users (L1 tx)

  All paths maintain integrity: replay-protected, state-root tracked.
""")

print(f"{'=' * 60}")
print(f"  All checks passed!")
print(f"  Force inclusion: censored tx → L1 → L2 (after window)")
print(f"  Escape hatch: L2 down → funds recovered on L1")
print(f"  Normal path: relay + replay protection")
print(f"{'=' * 60}")
