# Sync Investigation and Fix

## Plan
- [x] Reproduce and observe sync behavior on Sepolia.
- [x] Identify why sync progress did not persist across peer reconnects.
- [x] Patch full sync persistence path to commit canonical headers.
- [x] Make `--sync-mode snap` actually prefer snap sync path.
- [x] Run targeted regression tests.
- [x] Validate runtime behavior with live Sepolia monitoring.
- [x] Analyze repeated `paused before account completion/timeout` loop.
- [x] Patch snap sync peer-refresh/wait logic for churn-heavy peers.
- [x] Add regression tests for dynamic peer rejoin handling.
- [x] Patch full sync timeout/failover behavior to avoid false completion.
- [x] Add snap sync adaptive timeout + peer health scoring/ban.
- [x] Add snap sync parallel request workers for storage/bytecode/trie phases.
- [x] Strengthen snap progress persistence and resume.
- [x] Prevent premature account-phase termination on empty AccountRange responses.

## Step Summary
- Root cause #1: full sync advanced only in-memory `current_block` in the non-execution path, so progress was lost on reconnect and RPC stayed near genesis.
- Fix #1: persist canonical progress on each synced header via `put_block_header` + `put_canonical_hash`.
- Root cause #2: sync supervisor only called full sync entrypoint even when `sync-mode=snap`.
- Fix #2: `P2PServer.start_sync()` now prioritizes snap peers, discovers a head header, derives `(state_root, block_number)`, and invokes `start_snap_sync`.
- Root cause #3: snap phase loops used a startup-time peer snapshot; when that peer disconnected, loops timed out and paused before incorporating newly connected peers.
- Fix #3: `SnapSync` now receives a live `peer_provider`, refreshes connected peers every request loop, and waits up to a bounded window for peer recovery before pausing.
- Root cause #4: full sync treated header request timeouts as empty-header completion and used a single fixed peer.
- Fix #4: full sync now distinguishes timeout failures (`None`) from real empty responses (`[]`), retries with backoff, performs peer failover, and refreshes target height from connected peers.
- Root cause #5: snap sync used a fixed timeout/peer model and had weak retry quality control under churn.
- Fix #5: adaptive timeout (RTT-based), peer cooldown/ban on repeated timeout/proof failures, and round-robin peer selection were added.
- Root cause #6: snap storage/bytecode/trie phases were strictly serial, causing slow progress and fragile recovery.
- Fix #6: in-flight parallel requests were added for phase 2/3/4 with failed-batch requeue.
- Root cause #7: persisted snap progress lacked cursor/target context for reliable resume.
- Fix #7: progress payload now stores target/cursor/queue lengths and resume restores cursor/counters for matching target.
- Root cause #8: some peers intermittently return empty `AccountRange`; previous logic treated this as completion and paused sync too early.
- Fix #8: empty account responses now trigger bounded retries across peers (`MAX_EMPTY_ACCOUNT_RESPONSES`) instead of immediate completion.

## Review
- Tests run:
  - `pytest tests/test_p2p.py tests/test_snap_sync.py tests/test_rpc.py -q` (158 passed)
  - `pytest tests/test_snap_sync.py tests/test_p2p.py -q` (87 passed)
  - `pytest tests/test_p2p.py tests/test_snap_sync.py -q` (89 passed)
  - `pytest tests/test_snap_sync.py tests/test_p2p.py -q` (92 passed)
  - `pytest tests/test_snap_sync.py -q` (26 passed)
- Runtime verification:
  - Full-sync persistence fix verified: `eth_blockNumber` increased from `0x900` to `0xcc0` during reconnect cycles.
  - Snap path verified: logs show `Starting snap sync: target block=..., root=...`.
- Remaining operational issue:
  - Snap account-range proof failures/timeouts were observed against tested peers (`Invalid account range proof`, request timeouts), so snap may still fall back/complete with zero downloaded state depending on peer quality.
