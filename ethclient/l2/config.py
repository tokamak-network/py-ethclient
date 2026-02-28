"""L2 rollup configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


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

    # Hash function: "keccak256" | "poseidon"
    hash_function: str = "keccak256"

    # Sequencer hardening
    mempool_max_size: int = 10000
    api_keys: list[str] = field(default_factory=list)
    rate_limit_rps: float = 10.0
    rate_limit_burst: int = 50
    max_request_size: int = 1_048_576  # 1 MB
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    enable_metrics: bool = True

    # L1 finality
    l1_confirmations: int = 0

    def __post_init__(self):
        if self.max_txs_per_batch <= 0:
            raise ValueError(f"max_txs_per_batch must be positive, got {self.max_txs_per_batch}")
        if self.batch_timeout < 0:
            raise ValueError(f"batch_timeout must be non-negative, got {self.batch_timeout}")
        if self.hash_function not in ("keccak256", "poseidon"):
            raise ValueError(f"hash_function must be 'keccak256' or 'poseidon', got {self.hash_function!r}")
        if self.state_backend not in ("memory", "lmdb"):
            raise ValueError(f"state_backend must be 'memory' or 'lmdb', got {self.state_backend!r}")
        if self.prover_backend not in ("python", "native"):
            raise ValueError(f"prover_backend must be 'python' or 'native', got {self.prover_backend!r}")
        if self.l1_backend not in ("memory", "eth_rpc"):
            raise ValueError(f"l1_backend must be 'memory' or 'eth_rpc', got {self.l1_backend!r}")
        if self.da_provider not in ("local", "s3", "calldata", "blob"):
            raise ValueError(f"da_provider must be 'local'|'s3'|'calldata'|'blob', got {self.da_provider!r}")
        if self.rate_limit_rps <= 0:
            raise ValueError(f"rate_limit_rps must be positive, got {self.rate_limit_rps}")
        if self.max_request_size <= 0:
            raise ValueError(f"max_request_size must be positive, got {self.max_request_size}")
        if self.mempool_max_size <= 0:
            raise ValueError(f"mempool_max_size must be positive, got {self.mempool_max_size}")


def resolve_hash_function(name: str) -> Callable[[bytes], bytes]:
    """Resolve hash function name to callable."""
    if name == "keccak256":
        from ethclient.common.crypto import keccak256
        return keccak256
    if name == "poseidon":
        from ethclient.common.hash import poseidon_bytes
        return poseidon_bytes
    raise ValueError(f"Unknown hash function: {name!r} (expected 'keccak256' or 'poseidon')")
