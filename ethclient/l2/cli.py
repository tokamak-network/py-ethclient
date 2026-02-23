"""CLI for L2 rollup commands."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Optional

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


def _handle_start(args: argparse.Namespace) -> None:
    """Start L2 sequencer + RPC server."""
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Config file not found: {config_path}")
        print("Run 'ethclient l2 init' first.")
        return

    config_data = json.loads(config_path.read_text())
    rpc_port = getattr(args, "rpc_port", config_data.get("rpc_port", 9545))

    print(f"Starting L2 rollup '{config_data.get('name', 'unknown')}'")
    print(f"  RPC port: {rpc_port}")
    print("  (Start logic uses Rollup + RPCServer — see rollup.py for full integration)")


def _handle_prove(args: argparse.Namespace) -> None:
    """Generate proofs for pending batches."""
    print("Generating ZK proofs for pending batches...")
    print("  (Use the Rollup API for full proving pipeline)")


def _handle_submit(args: argparse.Namespace) -> None:
    """Submit proven batches to L1."""
    print("Submitting proven batches to L1...")
    print("  (Use the Rollup API for full submission pipeline)")
