"""BridgeWatcher — relay pending messages between L1 and L2 messengers."""

from __future__ import annotations

from ethclient.bridge.messenger import CrossDomainMessenger
from ethclient.bridge.types import BatchRelayResult, RelayResult


class BridgeWatcher:
    """Watches both domain outboxes and relays messages to the other side.

    In production, this would be a long-running process monitoring events.
    Here it operates synchronously: call tick() to drain both outboxes
    and relay all pending messages.
    """

    def __init__(
        self,
        l1_messenger: CrossDomainMessenger,
        l2_messenger: CrossDomainMessenger,
    ) -> None:
        self.l1 = l1_messenger
        self.l2 = l2_messenger
        self._history: list[BatchRelayResult] = []

    def relay_l1_to_l2(self) -> list[RelayResult]:
        """Drain L1 outbox and relay each message to L2."""
        results = []
        for msg in self.l1.drain_outbox():
            result = self.l2.relay_message(msg)
            results.append(result)
        return results

    def relay_l2_to_l1(self) -> list[RelayResult]:
        """Drain L2 outbox and relay each message to L1."""
        results = []
        for msg in self.l2.drain_outbox():
            result = self.l1.relay_message(msg)
            results.append(result)
        return results

    def process_force_queue(self) -> list[RelayResult]:
        """Attempt to force-relay all eligible messages from L1's force queue."""
        results = []
        for entry in self.l1.get_force_queue():
            result = self.l1.force_relay(entry.message, self.l2)
            results.append(result)
        return results

    def tick(self) -> BatchRelayResult:
        """One relay cycle: drain both outboxes, relay all pending messages,
        and process any eligible force inclusions."""
        batch = BatchRelayResult(
            l1_to_l2=self.relay_l1_to_l2(),
            l2_to_l1=self.relay_l2_to_l1(),
            forced=self.process_force_queue(),
        )
        self._history.append(batch)
        return batch

    @property
    def total_relayed(self) -> int:
        """Total messages relayed across all ticks."""
        return sum(b.total_relayed for b in self._history)
