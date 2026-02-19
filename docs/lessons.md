# Lessons

- Full sync progress must always be persisted to canonical storage, not tracked only in process memory.
- If RPC block height is sourced from `store.get_latest_block_number()`, sync code must update canonical mapping on every accepted header.
- Reconnect-heavy environments require resume-from-store behavior; otherwise sync repeatedly restarts from genesis and appears stalled.
- `sync-mode` flags must map to the actual runtime sync entrypoint; enabling snap capability alone is insufficient.
- For snap sync, deriving target from a fresh head header (`state_root`, `number`) is necessary before starting account-range requests.
- In churn-heavy networks, sync workers must use live peer snapshots instead of fixed peer lists captured at phase start.
- For snap phases, treat temporary zero-peer windows as recoverable and wait for reconnection before pausing the phase.
- In full sync, timeout must be modeled as a transport failure (retry/failover), not as an empty chain response.
- Single-peer full sync is fragile under churn; failover and target refresh should be part of the main loop.
- Snap sync timeout should be adaptive to observed peer RTT; fixed thresholds amplify churn.
- Repeated timeout/proof-failure peers should enter cooldown/ban to protect sync throughput.
- Serial snap phase pipelines are fragile on public testnets; limited in-flight parallelism improves resilience.
- Resume metadata should include target and cursor context, not only aggregate counters.
- Empty AccountRange from a single peer should be treated as peer-quality noise first, not end-of-state by default.
- Repeated pause cursor detection should not automatically force full sync; prioritize peer-quality/dial stabilization before mode switching.
