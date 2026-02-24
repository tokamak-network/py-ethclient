"""Cross-domain message types for the General State Bridge."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# Force inclusion window: after this many blocks, anyone can force-relay.
FORCE_INCLUSION_WINDOW = 50


class Domain(str, Enum):
    """Bridge domain identifier."""
    L1 = "l1"
    L2 = "l2"


@dataclass
class CrossDomainMessage:
    """A message sent between L1 and L2 domains.

    The data field carries arbitrary state as bytes — tokens, storage slots,
    ZK proofs, game items, or anything else. The receiving contract decides
    how to decode and apply it.
    """
    nonce: int                          # unique per-domain, prevents replay
    sender: bytes                       # 20-byte originating address
    target: bytes                       # 20-byte destination address
    data: bytes                         # arbitrary calldata (ABI-encoded)
    value: int = 0                      # ETH value to transfer
    gas_limit: int = 1_000_000          # gas budget for execution on target
    source_domain: Domain = Domain.L1   # which domain sent this

    # metadata (set by messenger)
    block_number: int = 0               # block in which the message was sent
    message_hash: bytes = b""           # keccak256 of the message (set on send)


@dataclass
class ForceInclusionEntry:
    """A message registered for force inclusion on L1."""
    message: CrossDomainMessage
    registered_block: int               # L1 block when force_include() was called
    resolved: bool = False              # True if relayed or escaped


@dataclass
class RelayResult:
    """Result of relaying a single message to the target domain."""
    message: CrossDomainMessage
    success: bool = False
    return_data: bytes = b""
    gas_used: int = 0
    error: Optional[str] = None


@dataclass
class BatchRelayResult:
    """Result of a watcher tick — relay all pending messages."""
    l1_to_l2: list[RelayResult] = field(default_factory=list)
    l2_to_l1: list[RelayResult] = field(default_factory=list)
    forced: list[RelayResult] = field(default_factory=list)

    @property
    def all_success(self) -> bool:
        return all(r.success for r in self.l1_to_l2 + self.l2_to_l1 + self.forced)

    @property
    def total_relayed(self) -> int:
        return len(self.l1_to_l2) + len(self.l2_to_l1) + len(self.forced)
