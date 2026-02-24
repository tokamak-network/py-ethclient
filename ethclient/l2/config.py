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

    # DA provider: "local" | "s3" | "calldata" | "blob"
    da_provider: str = "local"

    # L1 connection (for calldata/blob DA)
    l1_rpc_url: str = ""
    l1_chain_id: int = 1
    l1_private_key: str = ""  # hex, no 0x prefix

    # Beacon node (for blob retrieval)
    beacon_url: str = "http://localhost:5052"

    # S3 DA settings
    s3_bucket: str = ""
    s3_prefix: str = "batches/"
    s3_region: str = ""
    s3_endpoint_url: str = ""
