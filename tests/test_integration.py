"""
Tests for Phase 7: Integration and entry point.

Tests CLI argument parsing, node initialization, and enode parsing.
"""

import os
import pytest

from coincurve import PrivateKey


# ===================================================================
# enode parsing tests
# ===================================================================

class TestEnodeParsing:
    def test_parse_valid_enode(self):
        from ethclient.main import parse_enode

        pubkey_hex = "ab" * 64  # 64-byte pubkey
        enode = f"enode://{pubkey_hex}@127.0.0.1:30303"
        node = parse_enode(enode)

        assert node is not None
        assert node.ip == "127.0.0.1"
        assert node.udp_port == 30303
        assert node.tcp_port == 30303
        assert node.id == bytes.fromhex(pubkey_hex)

    def test_parse_invalid_enode(self):
        from ethclient.main import parse_enode

        assert parse_enode("invalid") is None
        assert parse_enode("") is None
        assert parse_enode("enode://baddata") is None

    def test_parse_mainnet_bootnode(self):
        from ethclient.main import parse_enode, MAINNET_BOOTNODES

        for enode in MAINNET_BOOTNODES:
            node = parse_enode(enode)
            assert node is not None
            assert len(node.id) == 64
            assert node.udp_port == 30303


# ===================================================================
# CLI argument parsing tests
# ===================================================================

class TestCLIParsing:
    def test_default_args(self):
        from ethclient.main import build_parser

        parser = build_parser()
        args = parser.parse_args([])

        assert args.network == "mainnet"
        assert args.port == 30303
        assert args.rpc_port == 8545
        assert args.max_peers == 25
        assert args.log_level == "INFO"
        assert args.genesis is None
        assert args.private_key is None
        assert args.bootnodes is None

    def test_custom_args(self):
        from ethclient.main import build_parser

        parser = build_parser()
        args = parser.parse_args([
            "--network", "sepolia",
            "--port", "30304",
            "--rpc-port", "8546",
            "--max-peers", "10",
            "--log-level", "DEBUG",
        ])

        assert args.network == "sepolia"
        assert args.port == 30304
        assert args.rpc_port == 8546
        assert args.max_peers == 10
        assert args.log_level == "DEBUG"

    def test_bootnode_args(self):
        from ethclient.main import build_parser

        parser = build_parser()
        args = parser.parse_args([
            "--bootnodes", "enode://aa@1.2.3.4:30303,enode://bb@5.6.7.8:30304",
        ])

        assert args.bootnodes is not None
        assert "," in args.bootnodes

    def test_private_key_arg(self):
        from ethclient.main import build_parser

        parser = build_parser()
        key = PrivateKey()
        args = parser.parse_args([
            "--private-key", key.secret.hex(),
        ])

        assert args.private_key == key.secret.hex()

    def test_rpc_process_arg(self):
        from ethclient.main import build_parser

        parser = build_parser()
        args = parser.parse_args(["--rpc-process"])

        assert args.rpc_process is True


# ===================================================================
# Node initialization tests
# ===================================================================

class TestNodeInit:
    def test_node_creates_with_defaults(self):
        from ethclient.main import EthNode
        from ethclient.common.config import MAINNET_CONFIG

        key = PrivateKey()
        node = EthNode(
            private_key=key.secret,
            chain_config=MAINNET_CONFIG,
        )

        assert node.store is not None
        assert node.mempool is not None
        assert node.p2p is not None
        assert node.rpc is not None
        assert node._running is False

    def test_node_with_custom_ports(self):
        from ethclient.main import EthNode
        from ethclient.common.config import SEPOLIA_CONFIG

        key = PrivateKey()
        node = EthNode(
            private_key=key.secret,
            chain_config=SEPOLIA_CONFIG,
            listen_port=30304,
            rpc_port=8546,
            max_peers=10,
        )

        assert node.listen_port == 30304
        assert node.rpc_port == 8546
        assert node.p2p.max_peers == 10

    def test_node_with_genesis(self):
        from ethclient.main import EthNode
        from ethclient.common.config import MAINNET_CONFIG, Genesis, GenesisAlloc

        genesis = Genesis(
            config=MAINNET_CONFIG,
            nonce=0,
            timestamp=0,
            gas_limit=5000,
            difficulty=0x400000,
            alloc=[
                GenesisAlloc(address=b"\x01" * 20, balance=1000000),
            ],
        )

        key = PrivateKey()
        node = EthNode(
            private_key=key.secret,
            chain_config=MAINNET_CONFIG,
            genesis=genesis,
        )

        # Store should have the genesis block
        header = node.store.get_block_header_by_number(0)
        assert header is not None
        assert header.number == 0

    def test_rpc_server_has_methods(self):
        from ethclient.main import EthNode
        from ethclient.common.config import MAINNET_CONFIG

        key = PrivateKey()
        node = EthNode(
            private_key=key.secret,
            chain_config=MAINNET_CONFIG,
        )

        # Verify eth_ methods are registered
        assert "eth_blockNumber" in node.rpc._methods
        assert "eth_getBalance" in node.rpc._methods
        assert "eth_chainId" in node.rpc._methods
        assert "web3_clientVersion" in node.rpc._methods
        assert "net_version" in node.rpc._methods

    def test_node_rpc_process_mode_flag(self):
        from ethclient.main import EthNode
        from ethclient.common.config import MAINNET_CONFIG

        key = PrivateKey()
        node = EthNode(
            private_key=key.secret,
            chain_config=MAINNET_CONFIG,
            data_dir="data/test-rpc-process",
            rpc_process_mode=True,
        )

        assert node.rpc_process_mode is True


# ===================================================================
# Full integration test — end-to-end via RPC
# ===================================================================

class TestEndToEnd:
    def test_rpc_against_store(self):
        """Initialize a node with genesis and query via RPC."""
        from ethclient.main import EthNode
        from ethclient.common.config import MAINNET_CONFIG, Genesis, GenesisAlloc
        from ethclient.rpc.server import hex_to_int, hex_to_bytes
        from fastapi.testclient import TestClient

        alloc_addr = b"\xde\xad" + b"\x00" * 18
        genesis = Genesis(
            config=MAINNET_CONFIG,
            nonce=0,
            timestamp=0,
            gas_limit=5000,
            difficulty=0x400000,
            alloc=[
                GenesisAlloc(address=alloc_addr, balance=10**18),
            ],
        )

        key = PrivateKey()
        node = EthNode(
            private_key=key.secret,
            chain_config=MAINNET_CONFIG,
            genesis=genesis,
        )

        client = TestClient(node.rpc.app)

        def rpc_call(method, params=None):
            body = {"jsonrpc": "2.0", "method": method, "id": 1}
            if params:
                body["params"] = params
            return client.post("/", json=body).json()

        # Block number should be 0 (genesis only)
        result = rpc_call("eth_blockNumber")
        assert hex_to_int(result["result"]) == 0

        # Check balance of allocated address
        result = rpc_call("eth_getBalance", ["0x" + alloc_addr.hex(), "latest"])
        assert hex_to_int(result["result"]) == 10**18

        # Check chain ID
        result = rpc_call("eth_chainId")
        assert hex_to_int(result["result"]) == MAINNET_CONFIG.chain_id

        # web3 client version
        result = rpc_call("web3_clientVersion")
        assert "py-ethclient" in result["result"]

        # Get genesis block
        result = rpc_call("eth_getBlockByNumber", ["0x0", False])
        assert result["result"] is not None
        assert hex_to_int(result["result"]["number"]) == 0
