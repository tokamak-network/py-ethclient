"""
py-ethclient — Python Ethereum L1 execution client.

Entry point for the node. Initializes all subsystems:
  1. Parse CLI arguments
  2. Load genesis / chain config
  3. Initialize storage backend
  4. Start P2P networking
  5. Start JSON-RPC server
  6. Begin block synchronization
  7. Handle graceful shutdown
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

from coincurve import PrivateKey

from ethclient.common.config import (
    ChainConfig, Genesis, MAINNET_CONFIG, SEPOLIA_CONFIG, HOLESKY_CONFIG,
    GENESIS_HASHES, get_network_fork_id,
)
from ethclient.storage.memory_backend import MemoryBackend
from ethclient.blockchain.mempool import Mempool
from ethclient.blockchain.fork_choice import ForkChoice
from ethclient.networking.discv4.routing import Node
from ethclient.networking.server import P2PServer
from ethclient.rpc.server import RPCServer
from ethclient.rpc.eth_api import register_eth_api


logger = logging.getLogger("ethclient")

# ---------------------------------------------------------------------------
# Default bootnodes (Ethereum mainnet)
# ---------------------------------------------------------------------------

MAINNET_BOOTNODES = [
    # Ethereum Foundation bootnodes
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",
    "enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",
]

SEPOLIA_BOOTNODES = [
    # EF DevOps bootnodes (go-ethereum)
    "enode://4e5e92199ee224a01932a377160aa432f31d0b351f84ab413a8e0a42f4f36476f8fb1cbe914af0d9aef0d51665c214cf653c651c4bbd9d5550a934f241f1682b@138.197.51.181:30303",
    "enode://143e11fb766781d22d92a2e33f8f104cddae4411a122295ed1fdb6638de96a6ce65f5b7c964ba3763bba27961738fef7d3ecc739268f3e5e771fb4c87b6234ba@146.190.1.103:30303",
    "enode://8b61dc2d06c3f96fddcbebb0efb29d60d3598650275dc469c22229d3e5620369b0d3dedafd929835fe7f489618f19f456fe7c0df572bf2d914a9f4e006f783a9@170.64.250.88:30303",
    "enode://10d62eff032205fcef19497f35ca8477bea0eadfff6d769a147e895d8b2b8f8ae6341630c645c30f5df6e67547c03494ced3d9c5764e8622a26587b083b028e8@139.59.49.206:30303",
    "enode://9e9492e2e8836114cc75f5b929784f4f46c324ad01daf87d956f98b3b6c5fcba95524d6e5cf9861dc96a2c8a171ea7105bb554a197455058de185fa870970c7c@138.68.123.152:30303",
]


def parse_enode(enode: str) -> Optional[Node]:
    """Parse an enode URL into a Node."""
    try:
        # enode://<pubkey>@<ip>:<port>
        if not enode.startswith("enode://"):
            return None
        rest = enode[8:]
        pubkey_hex, addr = rest.split("@")
        ip, port_str = addr.split(":")
        port = int(port_str)
        pubkey = bytes.fromhex(pubkey_hex)
        return Node(id=pubkey, ip=ip, udp_port=port, tcp_port=port)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Node class
# ---------------------------------------------------------------------------

class EthNode:
    """Main Ethereum node coordinating all subsystems."""

    def __init__(
        self,
        private_key: bytes,
        chain_config: ChainConfig,
        genesis: Optional[Genesis] = None,
        listen_port: int = 30303,
        rpc_port: int = 8545,
        boot_nodes: Optional[list[Node]] = None,
        max_peers: int = 25,
        sync_mode: str = "snap",
    ) -> None:
        self.private_key = private_key
        self.chain_config = chain_config
        self.listen_port = listen_port
        self.rpc_port = rpc_port
        self.sync_mode = sync_mode

        # Initialize storage
        self.store = MemoryBackend()
        if genesis:
            self.store.init_from_genesis(genesis)
            header0 = self.store.get_block_header_by_number(0)
            self.genesis_hash = header0.block_hash() if header0 else b"\x00" * 32
        else:
            # Use well-known genesis hash for known networks
            self.genesis_hash = GENESIS_HASHES.get(chain_config.chain_id, b"\x00" * 32)

        # Compute ForkID for Status handshake
        self.fork_id = get_network_fork_id(chain_config.chain_id)

        # Blockchain engine
        self.mempool = Mempool()
        self.fork_choice = ForkChoice(self.store)

        # P2P server
        enable_snap = sync_mode == "snap"
        self.p2p = P2PServer(
            private_key=private_key,
            listen_port=listen_port,
            max_peers=max_peers,
            boot_nodes=boot_nodes or [],
            network_id=chain_config.chain_id,
            genesis_hash=self.genesis_hash,
            fork_id=self.fork_id,
            store=self.store,
            enable_snap=enable_snap,
        )

        # Snap sync engine
        if enable_snap:
            from ethclient.networking.sync.snap_sync import SnapSync
            self.snap_syncer = SnapSync(store=self.store)
            self.p2p.snap_syncer = self.snap_syncer
        else:
            self.snap_syncer = None

        # RPC server
        self.rpc = RPCServer()
        register_eth_api(self.rpc, store=self.store, mempool=self.mempool,
                         network_chain_id=chain_config.chain_id, config=chain_config)

        self._running = False

    async def start(self) -> None:
        """Start all node subsystems."""
        self._running = True

        pk = PrivateKey(self.private_key)
        node_id = pk.public_key.format(compressed=False)[1:].hex()
        logger.info("Starting py-ethclient node")
        logger.info("  Node ID: %s...", node_id[:32])
        logger.info("  Chain ID: %d", self.chain_config.chain_id)
        logger.info("  P2P port: %d", self.listen_port)
        logger.info("  RPC port: %d", self.rpc_port)

        # Start P2P
        await self.p2p.start()

        # Start RPC server in background
        import uvicorn
        config = uvicorn.Config(
            self.rpc.app,
            host="0.0.0.0",
            port=self.rpc_port,
            log_level="warning",
            loop="asyncio",
        )
        self._rpc_server = uvicorn.Server(config)
        self._rpc_server.config.setup_event_loop = lambda: None
        self._rpc_task = asyncio.create_task(self._rpc_server.serve())

        logger.info("Node started successfully")

        # Start sync after a brief delay
        await asyncio.sleep(2.0)
        asyncio.create_task(self.p2p.start_sync())

    async def stop(self) -> None:
        """Gracefully stop all subsystems."""
        logger.info("Shutting down...")
        self._running = False

        await self.p2p.stop()

        if hasattr(self, "_rpc_server"):
            self._rpc_server.should_exit = True

        logger.info("Node stopped")

    async def run_until_stopped(self) -> None:
        """Run until shutdown signal is received."""
        stop_event = asyncio.Event()

        def _signal_handler():
            stop_event.set()

        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _signal_handler)

        await self.start()
        await stop_event.wait()
        await self.stop()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="py-ethclient",
        description="Python Ethereum L1 execution client",
    )
    parser.add_argument(
        "--network",
        choices=["mainnet", "sepolia", "holesky"],
        default="mainnet",
        help="Network to join (default: mainnet)",
    )
    parser.add_argument(
        "--genesis",
        type=str,
        default=None,
        help="Path to custom genesis.json file",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=30303,
        help="P2P listen port (default: 30303)",
    )
    parser.add_argument(
        "--rpc-port",
        type=int,
        default=8545,
        help="JSON-RPC listen port (default: 8545)",
    )
    parser.add_argument(
        "--max-peers",
        type=int,
        default=25,
        help="Maximum number of peers (default: 25)",
    )
    parser.add_argument(
        "--bootnodes",
        type=str,
        default=None,
        help="Comma-separated enode URLs for bootstrap",
    )
    parser.add_argument(
        "--private-key",
        type=str,
        default=None,
        help="Hex-encoded private key for node identity (generated if not set)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--sync-mode",
        choices=["full", "snap"],
        default="snap",
        help="Sync mode: full or snap (default: snap)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Chain config
    if args.network == "mainnet":
        chain_config = MAINNET_CONFIG
    elif args.network == "sepolia":
        chain_config = SEPOLIA_CONFIG
    else:
        chain_config = HOLESKY_CONFIG

    # Genesis
    genesis = None
    if args.genesis:
        genesis_path = Path(args.genesis)
        if genesis_path.exists():
            with open(genesis_path) as f:
                genesis_data = json.load(f)
            genesis = Genesis.from_json(genesis_data)
            logger.info("Loaded custom genesis from %s", args.genesis)
        else:
            logger.error("Genesis file not found: %s", args.genesis)
            sys.exit(1)

    # Private key
    if args.private_key:
        private_key = bytes.fromhex(args.private_key.removeprefix("0x"))
    else:
        import os
        private_key = os.urandom(32)
        logger.info("Generated new node identity")

    # Boot nodes
    boot_nodes: list[Node] = []
    if args.bootnodes:
        for enode in args.bootnodes.split(","):
            node = parse_enode(enode.strip())
            if node:
                boot_nodes.append(node)
    elif args.network == "mainnet":
        for enode in MAINNET_BOOTNODES:
            node = parse_enode(enode)
            if node:
                boot_nodes.append(node)
    elif args.network == "sepolia":
        for enode in SEPOLIA_BOOTNODES:
            node = parse_enode(enode)
            if node:
                boot_nodes.append(node)

    # Create and run node
    node = EthNode(
        private_key=private_key,
        chain_config=chain_config,
        genesis=genesis,
        listen_port=args.port,
        rpc_port=args.rpc_port,
        boot_nodes=boot_nodes,
        max_peers=args.max_peers,
        sync_mode=args.sync_mode,
    )

    try:
        asyncio.run(node.run_until_stopped())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
