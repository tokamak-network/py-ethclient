#!/usr/bin/env python3
"""L2 Hello World on Sepolia — 실제 이더리움 테스트넷에 ZK rollup 배포

Sepolia 테스트넷에 Groth16 verifier 컨트랙트를 배포하고,
hello world STF의 batch를 증명 후 on-chain 검증까지 수행.

사전 준비:
  1. Sepolia ETH가 있는 계정 (faucet: https://cloud.google.com/application/web3/faucet/ethereum/sepolia)
  2. 환경변수 설정:
       export SEPOLIA_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
       export SEPOLIA_PRIVATE_KEY="your_hex_private_key_without_0x"

Run:
    python examples/l2_sepolia_hello.py
"""

import os
import sys
import time

from ethclient.common.crypto import private_key_to_address
from ethclient.l2 import Rollup, L2Tx, STFResult, PythonRuntime, L2Config
from ethclient.l2.eth_l1_backend import EthL1Backend
from ethclient.l2.eth_rpc import EthRPCClient

# ── 설정 로드 ───────────────────────────────────────────────────────

RPC_URL = os.environ.get("SEPOLIA_RPC_URL", "https://1rpc.io/sepolia")
PRIVATE_KEY_HEX = os.environ.get("SEPOLIA_PRIVATE_KEY", "")

if not PRIVATE_KEY_HEX:
    print("ERROR: SEPOLIA_PRIVATE_KEY 환경변수를 설정하세요")
    print("  export SEPOLIA_PRIVATE_KEY=\"your_hex_private_key\"")
    sys.exit(1)

PRIVATE_KEY = bytes.fromhex(PRIVATE_KEY_HEX)
SENDER_ADDR = private_key_to_address(PRIVATE_KEY)

print("=" * 60)
print("  L2 Hello World — Sepolia Testnet")
print("=" * 60)
print(f"\n  RPC:     {RPC_URL}")
print(f"  Account: 0x{SENDER_ADDR.hex()}")

# ── 잔액 확인 ───────────────────────────────────────────────────────

rpc = EthRPCClient(RPC_URL)
balance_hex = rpc._call("eth_getBalance", [f"0x{SENDER_ADDR.hex()}", "latest"])
balance_wei = int(balance_hex, 16)
balance_eth = balance_wei / 1e18
print(f"  Balance: {balance_eth:.6f} ETH")

if balance_wei < 1_000_000_000_000_000:  # 0.001 ETH
    print("\n  ERROR: Sepolia ETH가 부족합니다 (최소 0.001 ETH 필요)")
    print("  Faucet: https://cloud.google.com/application/web3/faucet/ethereum/sepolia")
    sys.exit(1)

# ── Hello World STF ─────────────────────────────────────────────────

def hello_stf(state: dict, tx: L2Tx) -> STFResult:
    """가장 단순한 STF: 메시지를 state에 기록."""
    msg = tx.data.get("message", "hello")
    sender_hex = tx.sender.hex()
    messages = state.get("messages", [])
    messages.append({"from": sender_hex, "text": msg})
    state["messages"] = messages
    state["message_count"] = len(messages)
    return STFResult(success=True, output={"recorded": msg})


GENESIS = {"messages": [], "message_count": 0}
stf = PythonRuntime(hello_stf, genesis=GENESIS)

# ── Rollup 구성 (EthL1Backend → Sepolia) ────────────────────────────

l1_backend = EthL1Backend(
    rpc_url=RPC_URL,
    private_key=PRIVATE_KEY,
    chain_id=11155111,  # Sepolia chain ID
    gas_multiplier=1.5,
    receipt_timeout=180,
)

rollup = Rollup(stf=stf, l1=l1_backend)

# ── 1. Trusted Setup + Verifier 배포 ────────────────────────────────

print("\n[1] Trusted setup + Verifier 배포 (Sepolia)...")
t0 = time.time()
rollup.setup()
t_setup = time.time() - t0
print(f"    Verifier 배포 완료: {t_setup:.1f}s")
print(f"    Contract: 0x{l1_backend._verifier_address.hex()}")

# ── 2. Hello World tx 제출 ──────────────────────────────────────────

print("\n[2] Hello World tx 제출")
USER = b"\xde\xad" + b"\x00" * 18  # dummy L2 user address

err = rollup.submit_tx(L2Tx(
    sender=USER,
    nonce=0,
    data={"message": "hello world from py-ethclient L2!"},
))
assert err is None, f"tx submit failed: {err}"
print("    tx submitted to sequencer")

# ── 3. Batch 생성 + 증명 ────────────────────────────────────────────

print("\n[3] Batch 생성 + Groth16 증명")
t0 = time.time()
batch = rollup.produce_batch()
t_batch = time.time() - t0
print(f"    Batch #{batch.number}: {len(batch.transactions)} tx, sealed in {t_batch:.2f}s")

# ── 4. L1에 증명 제출 + On-chain 검증 ───────────────────────────────

print("\n[4] Sepolia L1에 증명 제출...")
t0 = time.time()
receipt = rollup.prove_and_submit(batch)
t_prove = time.time() - t0

if receipt.verified:
    print(f"    ON-CHAIN VERIFIED! ({t_prove:.1f}s)")
    print(f"    L1 tx: 0x{receipt.l1_tx_hash.hex()}")
else:
    print(f"    Verification FAILED ({t_prove:.1f}s)")
    print(f"    L1 tx: 0x{receipt.l1_tx_hash.hex()}")

# ── 5. 최종 상태 확인 ───────────────────────────────────────────────

print("\n[5] L2 State")
state = rollup.state
print(f"    message_count: {state['message_count']}")
for msg in state["messages"]:
    print(f"    - {msg['text']}")

assert receipt.verified, "On-chain verification failed!"
assert state["message_count"] == 1

# ── 잔액 변화 ───────────────────────────────────────────────────────

balance_after_hex = rpc._call("eth_getBalance", [f"0x{SENDER_ADDR.hex()}", "latest"])
balance_after = int(balance_after_hex, 16)
gas_used_eth = (balance_wei - balance_after) / 1e18

print(f"\n{'=' * 60}")
print(f"  Sepolia L2 Hello World — SUCCESS")
print(f"  Verifier: 0x{l1_backend._verifier_address.hex()}")
print(f"  Batch #0: ON-CHAIN VERIFIED")
print(f"  Gas cost: {gas_used_eth:.6f} ETH")
print(f"  Etherscan: https://sepolia.etherscan.io/tx/0x{receipt.l1_tx_hash.hex()}")
print(f"{'=' * 60}")
