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

    # State backend: "memory" | "lmdb"
    state_backend: str = "memory"
    data_dir: str = "./l2data"

    # Prover backend: "python" | "native"
    prover_backend: str = "python"
    prover_binary: str = "rapidsnark"
    prover_working_dir: str = ""

    # L1 backend: "memory" | "eth_rpc"
    l1_backend: str = "memory"

    # Sequencer hardening
    mempool_max_size: int = 10000
    api_keys: list[str] = field(default_factory=list)
    rate_limit_rps: float = 10.0
    rate_limit_burst: int = 50
    max_request_size: int = 1_048_576  # 1 MB
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    enable_metrics: bool = True
