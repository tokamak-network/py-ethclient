"""L2 rollup configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class L2Config:
    """Configuration for the L2 rollup."""

    name: str = "py-rollup"
    chain_id: int = 42170
    max_txs_per_batch: int = 64
    batch_timeout: int = 10  # seconds
    sequencer_address: bytes = b"\x00" * 20
    genesis_state: dict[str, Any] = field(default_factory=dict)
    rpc_port: int = 9545
