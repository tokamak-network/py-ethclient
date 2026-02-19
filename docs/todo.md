# Sync Investigation and Fix

## Plan
- [x] Reproduce and observe sync behavior on Sepolia.
- [x] Identify why sync progress did not persist across peer reconnects.
- [x] Patch full sync persistence path to commit canonical headers.
- [x] Make `--sync-mode snap` actually prefer snap sync path.
- [x] Run targeted regression tests.
- [x] Validate runtime behavior with live Sepolia monitoring.

## Step Summary
- Root cause #1: full sync advanced only in-memory `current_block` in the non-execution path, so progress was lost on reconnect and RPC stayed near genesis.
- Fix #1: persist canonical progress on each synced header via `put_block_header` + `put_canonical_hash`.
- Root cause #2: sync supervisor only called full sync entrypoint even when `sync-mode=snap`.
- Fix #2: `P2PServer.start_sync()` now prioritizes snap peers, discovers a head header, derives `(state_root, block_number)`, and invokes `start_snap_sync`.

## Review
- Tests run:
  - `pytest tests/test_p2p.py tests/test_snap_sync.py tests/test_rpc.py -q` (158 passed)
- Runtime verification:
  - Full-sync persistence fix verified: `eth_blockNumber` increased from `0x900` to `0xcc0` during reconnect cycles.
  - Snap path verified: logs show `Starting snap sync: target block=..., root=...`.
- Remaining operational issue:
  - Snap account-range proof failures/timeouts were observed against tested peers (`Invalid account range proof`, request timeouts), so snap may still fall back/complete with zero downloaded state depending on peer quality.
