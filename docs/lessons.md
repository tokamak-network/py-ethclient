# Lessons

- Full sync progress must always be persisted to canonical storage, not tracked only in process memory.
- If RPC block height is sourced from `store.get_latest_block_number()`, sync code must update canonical mapping on every accepted header.
- Reconnect-heavy environments require resume-from-store behavior; otherwise sync repeatedly restarts from genesis and appears stalled.
- `sync-mode` flags must map to the actual runtime sync entrypoint; enabling snap capability alone is insufficient.
- For snap sync, deriving target from a fresh head header (`state_root`, `number`) is necessary before starting account-range requests.
