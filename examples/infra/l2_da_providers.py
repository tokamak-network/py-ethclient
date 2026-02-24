#!/usr/bin/env python3
"""L2 DA Providers — Local vs Calldata vs Blob 비교 데모

동일한 STF + 배치 데이터로 3가지 DA 프로바이더를 비교합니다.
- LocalDAProvider: 메모리 기반 (테스트용)
- CalldataDAProvider: EIP-1559 calldata (개념 설명, mock)
- BlobDAProvider: EIP-4844 blob encoding/decoding (로컬 실행)

Run:
    python examples/infra/l2_da_providers.py
"""

from ethclient.l2 import (
    Rollup, L2Tx, STFResult, PythonRuntime,
    LocalDAProvider,
)
from ethclient.l2.da_blob import encode_blob, decode_blob, versioned_hash, BYTES_PER_BLOB, MAX_DATA_PER_BLOB
from ethclient.common.crypto import keccak256

# ── STF 정의 ────────────────────────────────────────────────────────

def simple_stf(state: dict, tx: L2Tx) -> STFResult:
    msgs = state.get("messages", [])
    msgs.append(tx.data.get("msg", ""))
    state["messages"] = msgs
    return STFResult(success=True)


GENESIS = {"messages": []}
SENDER = b"\x01" * 20

# ── 시나리오 실행 ───────────────────────────────────────────────────

print("=" * 60)
print("  L2 DA Providers — Local / Calldata / Blob Comparison")
print("=" * 60)

# ━━━ 1. LocalDAProvider (In-Memory) ━━━
print("\n━━━ 1. LocalDAProvider (In-Memory) ━━━")
print("-" * 40)

local_da = LocalDAProvider()
stf = PythonRuntime(simple_stf, genesis=GENESIS)
rollup = Rollup(stf=stf, da=local_da)
rollup.setup()

for i in range(3):
    rollup.submit_tx(L2Tx(sender=SENDER, nonce=i, data={"msg": f"hello-{i}"}))

batch = rollup.produce_batch()
receipt = rollup.prove_and_submit(batch)

print(f"  DA Provider: LocalDAProvider")
print(f"  Batch #{batch.number}: {len(batch.transactions)} txs → "
      f"{'VERIFIED' if receipt.verified else 'FAILED'}")
print(f"  Stored batches: {local_da.batch_count}")

# Store & retrieve
test_data = b"batch data for commitment test"
commitment = local_da.store_batch(999, test_data)
retrieved = local_da.retrieve_batch(999)
verified = local_da.verify_commitment(999, commitment)
print(f"  Commitment: {commitment.hex()[:16]}...")
print(f"  Retrieved: {retrieved == test_data}")
print(f"  Verified: {verified}")
assert retrieved == test_data
assert verified

# ━━━ 2. CalldataDAProvider (Concept) ━━━
print("\n━━━ 2. CalldataDAProvider (EIP-1559 Calldata) ━━━")
print("-" * 40)

print(f"  CalldataDAProvider stores batch data in L1 tx calldata.")
print(f"  How it works:")
print(f"    1. Encode: 8-byte batch_number prefix + batch data")
print(f"    2. Sign: EIP-1559 (type 2) transaction")
print(f"    3. Commit: keccak256(batch_number || data)")
print(f"    4. Post: Send signed tx to L1")
print(f"    5. Retrieve: Read input data from L1 tx receipt")

# Demonstrate commitment calculation (same as Calldata DA)
batch_number = 42
batch_data = b"compressed batch: 100 transactions"
calldata = batch_number.to_bytes(8, "big") + batch_data
commitment = keccak256(batch_number.to_bytes(8, "big") + batch_data)

# Gas estimation (same logic as CalldataDAProvider)
nonzero = sum(1 for b in calldata if b != 0)
zero = len(calldata) - nonzero
gas = 21000 + 16 * nonzero + 4 * zero + 5000
cost_at_30gwei = gas * 30  # 30 Gwei base fee

print(f"\n  Example for batch #{batch_number}:")
print(f"    Calldata size: {len(calldata)} bytes")
print(f"    Commitment: {commitment.hex()[:16]}...")
print(f"    Gas estimate: {gas:,}")
print(f"    Cost @ 30 Gwei: {cost_at_30gwei:,} wei ({cost_at_30gwei / 1e9:.4f} ETH)")

# 실제 사용시:
# da = CalldataDAProvider(
#     rpc_url="https://sepolia.infura.io/v3/YOUR_KEY",
#     private_key=bytes.fromhex("YOUR_PRIVATE_KEY"),
#     chain_id=11155111,
# )

# ━━━ 3. BlobDAProvider (EIP-4844) ━━━
print("\n━━━ 3. BlobDAProvider (EIP-4844 Blob) ━━━")
print("-" * 40)

print(f"  Blob parameters:")
print(f"    Blob size: {BYTES_PER_BLOB:,} bytes (131,072)")
print(f"    Max data per blob: {MAX_DATA_PER_BLOB:,} bytes")
print(f"    Field elements: 4,096 × 32 bytes")
print(f"    Usable bytes per element: 31 (high byte = 0x00)")

# Blob encode/decode 테스트
test_data = b"EIP-4844 blob test data - batch of 500 transactions " * 20
print(f"\n  Test data: {len(test_data)} bytes")

blob = encode_blob(test_data)
print(f"  Encoded blob: {len(blob):,} bytes")
assert len(blob) == BYTES_PER_BLOB

decoded = decode_blob(blob)
print(f"  Decoded data: {len(decoded)} bytes")
assert decoded == test_data
print(f"  Round-trip: PASS")

# Versioned hash (simulated commitment)
fake_commitment = keccak256(blob[:48])  # 48-byte KZG commitment placeholder
v_hash = versioned_hash(fake_commitment)
print(f"\n  KZG commitment (mock): {fake_commitment.hex()[:16]}...")
print(f"  Versioned hash: {v_hash.hex()[:16]}...")
print(f"  Version byte: 0x{v_hash[0]:02x} (EIP-4844)")
assert v_hash[0] == 0x01

# 최대 용량 테스트
max_data = bytes([0xab]) * MAX_DATA_PER_BLOB
blob_max = encode_blob(max_data)
decoded_max = decode_blob(blob_max)
assert decoded_max == max_data
print(f"  Max capacity: {MAX_DATA_PER_BLOB:,} bytes → encode/decode PASS")

# 비용 비교
calldata_gas_1kb = 21000 + 16 * 1024 + 5000
blob_gas_1blob = 131072  # ~131k gas for 1 blob (current pricing)
print(f"\n  Cost comparison (1 KB batch data):")
print(f"    Calldata: ~{calldata_gas_1kb:,} gas")
print(f"    Blob (1 blob): ~{blob_gas_1blob:,} blob gas (separate fee market)")
print(f"    Blob capacity: ~{MAX_DATA_PER_BLOB // 1024} KB vs 1 KB calldata")

# 실제 사용시:
# da = BlobDAProvider(
#     rpc_url="https://sepolia.infura.io/v3/YOUR_KEY",
#     private_key=bytes.fromhex("YOUR_PRIVATE_KEY"),
#     chain_id=11155111,
#     beacon_url="https://sepolia-beacon.example.com",
# )

# ━━━ Summary ━━━
print(f"\n{'=' * 60}")
print(f"  DA Provider Comparison")
print(f"{'=' * 60}")
print("""
  Provider      | Storage     | Cost        | Retrieval    | Use Case
  ──────────────┼─────────────┼─────────────┼──────────────┼─────────────
  Local         | In-memory   | Free        | Instant      | Testing
  Calldata      | L1 tx input | ~16 gas/byte| From L1 tx   | Small batches
  Blob (4844)   | L1 blob     | Blob gas    | Beacon API   | Large batches
  S3            | AWS S3      | S3 pricing  | S3 GET       | Off-chain DA
""")
print(f"  All DA providers share the same interface:")
print(f"    store_batch(batch_number, data) → commitment")
print(f"    retrieve_batch(batch_number) → data")
print(f"    verify_commitment(batch_number, commitment) → bool")

print(f"\n{'=' * 60}")
print(f"  All checks passed!")
print(f"  Local: store/retrieve/verify")
print(f"  Calldata: commitment + gas estimation")
print(f"  Blob: encode/decode round-trip + versioned hash")
print(f"{'=' * 60}")
