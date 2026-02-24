"""L2 metrics collector for monitoring."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ethclient.l2.rollup import Rollup


class L2MetricsCollector:
    """Collects operational metrics from the L2 rollup."""

    def __init__(self, rollup: Rollup) -> None:
        self._rollup = rollup
        self._tx_submitted_total = 0
        self._tx_failed_total = 0
        self._prove_durations: list[float] = []
        self._submit_durations: list[float] = []

    def collect(self) -> dict:
        """Collect current metrics snapshot."""
        info = self._rollup.chain_info()
        batches = self._rollup.get_sealed_batches()

        proven_count = sum(1 for b in batches if b.proven)
        submitted_count = sum(1 for b in batches if b.submitted)

        result = {
            "l2_mempool_size": info.get("pending_txs", 0),
            "l2_sealed_batches_total": info.get("sealed_batches", 0),
            "l2_proven_batches_total": proven_count,
            "l2_submitted_batches_total": submitted_count,
            "l2_tx_submitted_total": self._tx_submitted_total,
            "l2_tx_failed_total": self._tx_failed_total,
        }

        if self._prove_durations:
            result["l2_prove_duration_seconds_avg"] = (
                sum(self._prove_durations) / len(self._prove_durations)
            )
        if self._submit_durations:
            result["l2_submit_duration_seconds_avg"] = (
                sum(self._submit_durations) / len(self._submit_durations)
            )

        return result

    def record_prove_duration(self, seconds: float) -> None:
        self._prove_durations.append(seconds)

    def record_submit_duration(self, seconds: float) -> None:
        self._submit_durations.append(seconds)

    def increment_tx_submitted(self) -> None:
        self._tx_submitted_total += 1

    def increment_tx_failed(self) -> None:
        self._tx_failed_total += 1
