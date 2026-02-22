"""
Mainnet connection test via discv4 discovery.

Uses UDP discovery to find peers beyond the full bootnodes,
then connects via TCP for RLPx handshake + block verification.
"""

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from coincurve import PrivateKey

from ethclient.common.config import (
    MAINNET_CONFIG, MAINNET_GENESIS_HASH,
    compute_fork_id,
)
from ethclient.networking.discv4.discovery import start_discovery
from ethclient.networking.discv4.routing import Node
from ethclient.networking.rlpx.connection import RLPxConnection
from ethclient.networking.eth.protocol import EthMsg, ETH_VERSION, ETH_VERSION_FALLBACK, P2P_VERSION, CLIENT_NAME
from ethclient.networking.eth.messages import (
    HelloMessage, StatusMessage, DisconnectMessage,
    GetBlockHeadersMessage, BlockHeadersMessage,
    GetBlockBodiesMessage, BlockBodiesMessage,
    encode_pong,
)
from ethclient.common.types import (
    Transaction, TxType, EMPTY_TRIE_ROOT,
)
from ethclient.common.trie import ordered_trie_root

PRIVATE_KEY = os.urandom(32)
LOCAL_PUBKEY = PrivateKey(PRIVATE_KEY).public_key.format(compressed=False)[1:]

MAINNET_BOOTNODES = [
    "enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303",
    "enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303",
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",
    "enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",
]

fork_id = compute_fork_id(
    MAINNET_GENESIS_HASH, MAINNET_CONFIG,
    head_block=100_000_000, head_time=2_000_000_000,
)


def parse_enode(enode: str) -> Node:
    rest = enode.removeprefix("enode://")
    pubkey_hex, addr = rest.split("@")
    ip, port_str = addr.split(":")
    port = int(port_str)
    return Node(id=bytes.fromhex(pubkey_hex), ip=ip, udp_port=port, tcp_port=port)


def decode_transactions(tx_list_rlp: list) -> list[Transaction]:
    txs = []
    for raw in tx_list_rlp:
        if isinstance(raw, list):
            tx = Transaction.from_rlp_list(raw, TxType.LEGACY)
        elif isinstance(raw, bytes):
            tx = Transaction.decode_rlp(raw)
        else:
            raise ValueError(f"Unexpected tx format: {type(raw)}")
        txs.append(tx)
    return txs


def _negotiate_eth_version(remote_caps: list[tuple[str, int]]) -> int | None:
    """Find highest common eth version between us and remote."""
    our_versions = {ETH_VERSION, ETH_VERSION_FALLBACK}
    remote_eth = {v for name, v in remote_caps if name == "eth"}
    common = our_versions & remote_eth
    if not common:
        return None
    return max(common)


async def do_handshake(conn: RLPxConnection, remote_pubkey: bytes) -> tuple[StatusMessage, int] | None:
    """Complete RLPx + Hello + Status handshake. Returns (remote_status, negotiated_version)."""
    ok = await conn.initiate_handshake(b"\x04" + remote_pubkey)
    if not ok:
        return None

    hello = HelloMessage(
        p2p_version=P2P_VERSION,
        client_id=CLIENT_NAME,
        capabilities=[("eth", ETH_VERSION), ("eth", ETH_VERSION_FALLBACK)],
        listen_port=0,
        node_id=LOCAL_PUBKEY,
    )
    await conn.send_message(0x00, hello.encode())

    result = await conn.recv_message(timeout=10.0)
    if result is None:
        return None
    msg_code, payload = result
    if msg_code == 0x01:
        try:
            dm = DisconnectMessage.decode(payload)
            print(f"    Disconnect(Hello): {dm.reason.name} ({dm.reason.value})")
        except Exception:
            print(f"    Disconnect(Hello): raw={payload.hex()[:40] if payload else 'empty'}")
        return None
    if msg_code != 0x00:
        print(f"    Expected Hello, got msg_code={msg_code}")
        return None

    remote_hello = HelloMessage.decode(payload)
    print(f"    Client: {remote_hello.client_id}")
    print(f"    Caps: {remote_hello.capabilities}")

    # Skip non-Ethereum clients (Polygon bor, BSC, Energi, PulseChain)
    client_lower = remote_hello.client_id.lower()
    if any(x in client_lower for x in ["bor/", "energi", "pulse"]):
        print(f"    Skipping non-Ethereum client")
        return None

    # Negotiate eth version
    negotiated = _negotiate_eth_version(remote_hello.capabilities)
    if negotiated is None:
        print(f"    No common eth version")
        return None

    conn.use_snappy = True

    # Send Status in the negotiated format
    if negotiated >= 69:
        status_msg = StatusMessage(
            protocol_version=negotiated,
            network_id=1,
            genesis_hash=MAINNET_GENESIS_HASH,
            fork_id=fork_id,
            earliest_block=0,
            latest_block=0,
            latest_block_hash=MAINNET_GENESIS_HASH,
        )
    else:
        # Post-merge: TD = TTD (mainnet = 58750000000000000000000)
        status_msg = StatusMessage(
            protocol_version=negotiated,
            network_id=1,
            total_difficulty=58_750_000_000_000_000_000_000,
            best_hash=MAINNET_GENESIS_HASH,
            genesis_hash=MAINNET_GENESIS_HASH,
            fork_id=fork_id,
        )
    await conn.send_message(0x10, status_msg.encode())

    for _ in range(10):
        result = await conn.recv_message(timeout=10.0)
        if result is None:
            return None
        msg_code, payload = result
        if msg_code == 0x01:
            try:
                dm = DisconnectMessage.decode(payload)
                print(f"    Disconnect(Status): {dm.reason.name} ({dm.reason.value})")
            except Exception:
                print(f"    Disconnect(Status): raw={payload.hex()[:40] if payload else 'empty'}")
            return None
        if msg_code == 0x10:
            rs = StatusMessage.decode(payload)
            # Verify this is an Ethereum mainnet peer
            if rs.network_id != 1:
                print(f"    Wrong network: {rs.network_id} (not mainnet)")
                return None
            if rs.genesis_hash != MAINNET_GENESIS_HASH:
                print(f"    Wrong genesis: {rs.genesis_hash.hex()[:16]}...")
                return None
            if rs.protocol_version >= 69:
                print(f"    eth/{negotiated}: latest_block={rs.latest_block}")
            else:
                print(f"    eth/{negotiated}: TD={rs.total_difficulty}")
            return rs, negotiated
        if msg_code == 0x02:
            await conn.send_message(0x03, encode_pong())
    return None


async def recv_eth_message(conn: RLPxConnection, expected_code: int, timeout: float = 30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = max(0.1, deadline - time.time())
        result = await conn.recv_message(timeout=remaining)
        if result is None:
            return None
        msg_code, payload = result
        if msg_code == 0x02:
            await conn.send_message(0x03, encode_pong())
            continue
        if msg_code == 0x01:
            try:
                dm = DisconnectMessage.decode(payload)
                print(f"    Disconnect: {dm.reason.name}")
            except Exception:
                pass
            return None
        if msg_code == expected_code:
            return payload
    return None


async def try_connect(node: Node) -> tuple[RLPxConnection, StatusMessage, int] | None:
    """Try TCP connection + handshake. Returns (conn, remote_status, negotiated_version)."""
    ip = node.ip
    port = node.tcp_port if node.tcp_port > 0 else node.udp_port
    if port <= 0:
        return None

    print(f"\n  Trying {ip}:{port}...")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=3.0
        )
        conn = RLPxConnection(PRIVATE_KEY, reader, writer)
        result = await asyncio.wait_for(
            do_handshake(conn, node.id), timeout=10.0
        )
        if result is not None:
            rs, ver = result
            return conn, rs, ver
        conn.close()
    except asyncio.TimeoutError:
        print(f"    Timeout")
    except Exception as e:
        print(f"    Failed: {e}")
    return None


async def run_block_verification(conn: RLPxConnection, remote_status: StatusMessage, negotiated_version: int) -> bool:
    """Download and verify recent blocks."""
    # Determine head info
    if negotiated_version >= 69:
        head_number = remote_status.latest_block
        head_hash = remote_status.latest_block_hash
    else:
        head_hash = remote_status.best_hash
        head_number = 0  # unknown for eth/68, will discover

    # Step 1: If we don't know head number (eth/68), discover it
    if head_number == 0 and head_hash != MAINNET_GENESIS_HASH:
        print(f"\n  --- Discovering head block number ---")
        try:
            req = GetBlockHeadersMessage(request_id=1, origin=head_hash, amount=1)
            await conn.send_message(EthMsg.GET_BLOCK_HEADERS, req.encode())
        except (ConnectionError, OSError) as e:
            print(f"    Connection lost: {e}")
            return False
        payload = await recv_eth_message(conn, EthMsg.BLOCK_HEADERS, timeout=15.0)
        if payload:
            resp = BlockHeadersMessage.decode(payload)
            if resp.headers:
                head_number = resp.headers[0].number
                print(f"    Head block: #{head_number}")

    if head_number == 0:
        print(f"    Could not determine head block, trying from block 1000")
        head_number = 1000

    # Step 2: Request 32 headers from (head - 31) forward
    start_block = max(0, head_number - 31)
    print(f"\n  --- Requesting headers #{start_block} → #{start_block + 31} ---")
    try:
        req = GetBlockHeadersMessage(request_id=2, origin=start_block, amount=32)
        await conn.send_message(EthMsg.GET_BLOCK_HEADERS, req.encode())
    except (ConnectionError, OSError) as e:
        print(f"    Connection lost: {e}")
        return False

    payload = await recv_eth_message(conn, EthMsg.BLOCK_HEADERS)
    if payload is None:
        print("    No headers received")
        return False

    resp = BlockHeadersMessage.decode(payload)
    headers = resp.headers
    if not headers:
        print("    Empty headers response")
        return False

    headers.sort(key=lambda h: h.number)
    print(f"    Received {len(headers)} headers: #{headers[0].number} → #{headers[-1].number}")

    # Validate chain links
    valid_links = 0
    for i in range(1, len(headers)):
        if (headers[i].parent_hash == headers[i-1].block_hash()
                and headers[i].number == headers[i-1].number + 1):
            valid_links += 1

    print(f"    Chain links: {valid_links}/{len(headers)-1} valid")

    # Step 3: Download bodies
    try:
        hashes = [h.block_hash() for h in headers]
        body_req = GetBlockBodiesMessage(request_id=3, hashes=hashes)
        await conn.send_message(EthMsg.GET_BLOCK_BODIES, body_req.encode())
    except (ConnectionError, OSError) as e:
        print(f"    Connection lost: {e}")
        return False

    payload = await recv_eth_message(conn, EthMsg.BLOCK_BODIES)
    if payload is None:
        print("    No bodies received")
        return False

    body_resp = BlockBodiesMessage.decode(payload)
    bodies = body_resp.bodies
    print(f"    Received {len(bodies)} bodies")

    # Verify tx roots
    tx_root_ok = 0
    total_txs = 0
    sender_ok = 0
    type_counts = {t: 0 for t in TxType}
    n = min(len(headers), len(bodies))

    for idx in range(n):
        header = headers[idx]
        body = bodies[idx]
        try:
            txs = decode_transactions(body[0])
        except Exception as e:
            print(f"    Block {header.number}: tx decode error: {e}")
            continue

        tx_rlps = [tx.encode_rlp() for tx in txs]
        computed_root = ordered_trie_root(tx_rlps) if tx_rlps else EMPTY_TRIE_ROOT
        if computed_root == header.transactions_root:
            tx_root_ok += 1

        total_txs += len(txs)
        for tx in txs:
            type_counts[tx.tx_type] = type_counts.get(tx.tx_type, 0) + 1
            try:
                tx.sender()
                sender_ok += 1
            except Exception:
                pass

    print(f"\n  === Mainnet Verification Results ===")
    print(f"    Headers: {len(headers)} (#{headers[0].number}..#{headers[-1].number})")
    print(f"    Chain links: {valid_links}/{len(headers)-1}")
    print(f"    Tx roots: {tx_root_ok}/{n}")
    print(f"    Total txs: {total_txs}")
    for t, c in type_counts.items():
        if c > 0:
            print(f"      {t.name}: {c}")
    print(f"    ECDSA recoveries: {sender_ok}/{total_txs}")

    success = tx_root_ok == n and total_txs > 0
    if success:
        print(f"\n  ✓ Mainnet verification PASSED!")
    return success


async def main():
    print("=" * 70)
    print("Mainnet Connection Test via discv4 Discovery")
    print("=" * 70)
    print(f"ForkID: {fork_id[0].hex()} / next={fork_id[1]}")
    print(f"ETH version: {ETH_VERSION}")

    boot_nodes = [parse_enode(e) for e in MAINNET_BOOTNODES]
    local_node = Node(
        id=LOCAL_PUBKEY,
        ip="0.0.0.0",
        udp_port=30304,  # avoid conflict with running geth
        tcp_port=30304,
    )

    # Phase 1: Start UDP discovery
    print("\n--- Phase 1: UDP Discovery ---")
    transport, protocol = await start_discovery(
        PRIVATE_KEY, local_node, boot_nodes, listen_port=30304,
    )

    print(f"  Pinging {len(boot_nodes)} bootnodes...")
    await protocol.bootstrap()
    node_count = protocol.table.total_nodes()
    print(f"  After bootstrap: {node_count} nodes in routing table")

    # Do more lookups to discover more peers
    for i in range(6):
        target = os.urandom(64)
        await protocol.lookup(target)
        await asyncio.sleep(1.0)
        new_count = protocol.table.total_nodes()
        print(f"  Lookup {i+1}: {new_count} nodes")

    all_nodes = protocol.table.all_nodes()
    # Filter nodes with routable TCP port
    tcp_nodes = [n for n in all_nodes if n.tcp_port > 0 and n.ip and n.ip != "0.0.0.0"]
    print(f"\n  Total discovered: {len(all_nodes)} nodes, {len(tcp_nodes)} with TCP port")

    # Phase 2: Try connecting to discovered peers
    print("\n--- Phase 2: TCP Connection Attempts ---")

    # Prioritize nodes that responded with pong (have last_pong > 0)
    ponged = [n for n in tcp_nodes if n.last_pong > 0]
    unponged = [n for n in tcp_nodes if n.last_pong == 0]
    # Also include bootnodes as fallback
    candidates = ponged + unponged + boot_nodes

    # De-duplicate by node id
    seen_ids: set[bytes] = set()
    unique_candidates: list[Node] = []
    for n in candidates:
        if n.id not in seen_ids:
            seen_ids.add(n.id)
            unique_candidates.append(n)

    print(f"  Candidates: {len(ponged)} ponged, {len(unponged)} unponged, {len(boot_nodes)} bootnodes")
    print(f"  Unique: {len(unique_candidates)}")

    connected = False
    attempts = 0
    max_attempts = min(80, len(unique_candidates))

    for node in unique_candidates[:max_attempts]:
        attempts += 1
        result = await try_connect(node)
        if result is None:
            continue

        conn, remote_status, neg_ver = result
        print(f"\n  ✓ Connected! (attempt {attempts}/{max_attempts})")

        success = await run_block_verification(conn, remote_status, neg_ver)
        conn.close()

        if success:
            connected = True
            break
        print("  Block verification failed, trying next peer...")

    # Phase 3: If still not connected, do more discovery rounds
    if not connected:
        print("\n--- Phase 3: Extended Discovery ---")
        for round_num in range(6):
            print(f"\n  Round {round_num + 1}: discovering more peers...")
            for _ in range(8):
                target = os.urandom(64)
                await protocol.lookup(target)
                await asyncio.sleep(0.5)

            all_nodes = protocol.table.all_nodes()
            new_tcp = [n for n in all_nodes
                       if n.tcp_port > 0 and n.ip and n.ip != "0.0.0.0"
                       and n.id not in seen_ids]
            print(f"  Found {len(new_tcp)} new TCP peers (total table: {protocol.table.total_nodes()})")

            for node in new_tcp[:20]:
                seen_ids.add(node.id)
                attempts += 1
                result = await try_connect(node)
                if result is None:
                    continue

                conn, remote_status, neg_ver = result
                print(f"\n  ✓ Connected! (attempt {attempts})")

                success = await run_block_verification(conn, remote_status, neg_ver)
                conn.close()

                if success:
                    connected = True
                    break
                print("  Block verification failed, trying next peer...")

            if connected:
                break

    # Cleanup
    transport.close()

    # Summary
    print("\n" + "=" * 70)
    if connected:
        print("✓ Mainnet discovery + connection test PASSED!")
    else:
        print(f"✗ Could not connect after {attempts} attempts")
        print(f"  Discovered {protocol.table.total_nodes()} nodes total")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
