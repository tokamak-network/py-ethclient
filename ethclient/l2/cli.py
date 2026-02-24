"""CLI for L2 rollup commands."""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import sys
from pathlib import Path

from ethclient.l2.config import L2Config
from ethclient.l2.rollup import Rollup

logger = logging.getLogger(__name__)


def add_l2_subparser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'l2' subcommand to the main CLI parser."""
    l2_parser = subparsers.add_parser("l2", help="L2 rollup commands")
    l2_sub = l2_parser.add_subparsers(dest="l2_command")

    # l2 init
    init_parser = l2_sub.add_parser("init", help="Initialize a new L2 rollup project")
    init_parser.add_argument("--name", type=str, default="my-rollup", help="Rollup name")
    init_parser.add_argument("--dir", type=str, default=".", help="Project directory")

    # l2 start
    start_parser = l2_sub.add_parser("start", help="Start the L2 sequencer + RPC server")
    start_parser.add_argument("--config", type=str, default="l2.json", help="L2 config file")
    start_parser.add_argument("--rpc-port", type=int, default=9545, help="L2 RPC port")

    # l2 prove
    prove_parser = l2_sub.add_parser("prove", help="Generate ZK proofs for pending batches")
    prove_parser.add_argument("--config", type=str, default="l2.json", help="L2 config file")

    # l2 submit
    submit_parser = l2_sub.add_parser("submit", help="Submit proven batches to L1")
    submit_parser.add_argument("--config", type=str, default="l2.json", help="L2 config file")


def handle_l2_command(args: argparse.Namespace) -> None:
    """Dispatch L2 subcommands."""
    cmd = getattr(args, "l2_command", None)
    if cmd is None:
        print("Usage: ethclient l2 {init|start|prove|submit}")
        return

    if cmd == "init":
        _handle_init(args)
    elif cmd == "start":
        _handle_start(args)
    elif cmd == "prove":
        _handle_prove(args)
    elif cmd == "submit":
        _handle_submit(args)


def _handle_init(args: argparse.Namespace) -> None:
    """Scaffold a new L2 rollup project."""
    project_dir = Path(args.dir)
    project_dir.mkdir(parents=True, exist_ok=True)

    config = {
        "name": args.name,
        "chain_id": 42170,
        "max_txs_per_batch": 64,
        "batch_timeout": 10,
        "rpc_port": 9545,
    }

    config_path = project_dir / "l2.json"
    config_path.write_text(json.dumps(config, indent=2))

    stf_path = project_dir / "stf.py"
    if not stf_path.exists():
        stf_path.write_text(
            '"""Custom State Transition Function."""\n\n'
            "from ethclient.l2.types import L2State, L2Tx, STFResult\n\n\n"
            "def apply_tx(state: L2State, tx: L2Tx) -> STFResult:\n"
            '    state["counter"] = state.get("counter", 0) + 1\n'
            "    return STFResult(success=True)\n"
        )

    print(f"Initialized L2 rollup '{args.name}' in {project_dir}")
    print(f"  Config: {config_path}")
    print(f"  STF:    {stf_path}")


def _load_stf(stf_path: Path):
    """Dynamically load apply_tx from an STF module file."""
    if not stf_path.exists():
        print(f"STF file not found: {stf_path}")
        sys.exit(1)

    spec = importlib.util.spec_from_file_location("stf_module", stf_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if not hasattr(module, "apply_tx"):
        print(f"STF file must define apply_tx(): {stf_path}")
        sys.exit(1)

    return module.apply_tx


def _load_rollup(config_arg: str) -> tuple[dict, Rollup]:
    """Load config and create a setup'd Rollup instance."""
    config_path = Path(config_arg)
    if not config_path.exists():
        print(f"Config file not found: {config_path}")
        print("Run 'ethclient l2 init' first.")
        sys.exit(1)

    config_data = json.loads(config_path.read_text())

    stf_path = config_path.parent / "stf.py"
    stf = _load_stf(stf_path)

    fields = {k for k in L2Config.__dataclass_fields__}
    l2_config = L2Config(**{k: v for k, v in config_data.items() if k in fields})
    rollup = Rollup(stf=stf, config=l2_config)
    rollup.setup()

    return config_data, rollup


def _handle_start(args: argparse.Namespace) -> None:
    """Start L2 sequencer + RPC server."""
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Config file not found: {config_path}")
        print("Run 'ethclient l2 init' first.")
        return

    config_data = json.loads(config_path.read_text())

    stf_path = config_path.parent / "stf.py"
    stf = _load_stf(stf_path)

    fields = {k for k in L2Config.__dataclass_fields__}
    l2_config = L2Config(**{k: v for k, v in config_data.items() if k in fields})
    rollup = Rollup(stf=stf, config=l2_config)
    rollup.setup()

    from ethclient.rpc.server import RPCServer
    from ethclient.l2.rpc_api import register_l2_api
    from ethclient.l2.health import register_health_endpoints
    from ethclient.l2.metrics import L2MetricsCollector
    from ethclient.l2.middleware import (
        APIKeyMiddleware,
        RateLimitMiddleware,
        RequestSizeLimitMiddleware,
    )
    from starlette.middleware.cors import CORSMiddleware

    rpc = RPCServer()
    register_l2_api(rpc, rollup)
    register_health_endpoints(rpc.app, rollup)

    if l2_config.enable_metrics:
        metrics = L2MetricsCollector(rollup)

        @rpc.app.get("/metrics")
        async def get_metrics():
            return metrics.collect()

    if l2_config.api_keys:
        rpc.app.add_middleware(APIKeyMiddleware, api_keys=set(l2_config.api_keys))
    rpc.app.add_middleware(
        RateLimitMiddleware,
        rps=l2_config.rate_limit_rps,
        burst=l2_config.rate_limit_burst,
    )
    rpc.app.add_middleware(
        RequestSizeLimitMiddleware,
        max_bytes=l2_config.max_request_size,
    )
    rpc.app.add_middleware(
        CORSMiddleware,
        allow_origins=l2_config.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    import uvicorn

    rpc_port = getattr(args, "rpc_port", config_data.get("rpc_port", 9545))
    logger.info("L2 rollup '%s' listening on :%d", l2_config.name, rpc_port)
    uvicorn.run(rpc.app, host="0.0.0.0", port=rpc_port, log_level="info")


def _handle_prove(args: argparse.Namespace) -> None:
    """Generate proofs for pending batches."""
    _, rollup = _load_rollup(args.config)

    sealed = rollup.get_sealed_batches()
    if not sealed:
        print("No sealed batches to prove.")
        return

    count = 0
    for batch in sealed:
        if not batch.proven:
            rollup.prove_batch(batch)
            count += 1
            print(f"  Batch #{batch.number} proven ({len(batch.transactions)} txs)")

    if count == 0:
        print("All batches already proven.")
    else:
        print(f"Proved {count} batch(es).")


def _handle_submit(args: argparse.Namespace) -> None:
    """Submit proven batches to L1."""
    _, rollup = _load_rollup(args.config)

    sealed = rollup.get_sealed_batches()
    if not sealed:
        print("No sealed batches to submit.")
        return

    count = 0
    for batch in sealed:
        if batch.proven and not batch.submitted:
            receipt = rollup.submit_batch(batch)
            count += 1
            print(f"  Batch #{batch.number} submitted, verified={receipt.verified}")

    if count == 0:
        print("No proven batches pending submission.")
    else:
        print(f"Submitted {count} batch(es).")
