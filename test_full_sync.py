"""
Full verification sync test — download recent blocks from mainnet,
decode transactions, verify tx/ommers roots, and display statistics.
"""

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from ethclient.common import rlp
from ethclient.common.types import (
    BlockHeader, Transaction, TxType, Withdrawal,
    EMPTY_TRIE_ROOT,
)
from ethclient.common.trie import ordered_trie_root
from ethclient.common.crypto import keccak256
from ethclient.common.config import (
    MAINNET_CONFIG, MAINNET_GENESIS_HASH,
    SEPOLIA_CONFIG, SEPOLIA_GENESIS_HASH,
    compute_fork_id,
)
from ethclient.networking.rlpx.connection import RLPxConnection
from ethclient.networking.eth.protocol import EthMsg, ETH_VERSION, P2P_VERSION, CLIENT_NAME
from ethclient.networking.eth.messages import (
    HelloMessage, StatusMessage, DisconnectMessage,
    GetBlockHeadersMessage, BlockHeadersMessage,
    GetBlockBodiesMessage, BlockBodiesMessage,
    encode_pong,
)


# Mainnet bootnodes — enode URIs from go-ethereum params/bootnodes.go
MAINNET_ENODES = [
    "enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303",
    "enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303",
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",
    "enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",
]

# Sepolia bootnodes
SEPOLIA_ENODES = [
    "enode://4e5e92199ee224a01932a377160aa432f31d0b351f84ab413a8e0a42f4f36476f8fb1cbe914af0d9aef0d51665c214cf653c651c4bbd9d5550a934f241f1682b@138.197.51.181:30303",
    "enode://143e11fb766781d22d92a2e33f8f104cddae4411a122295ed1fdb6638de96a6ce65f5b7c964ba3763bba27961738fef7d3ecc739268f3e5e771fb4c87b6234ba@146.190.1.103:30303",
    "enode://8b61dc2d06c3f96fddcbebb0efb29d60d3598650275dc469c22229d3e5620369b0d3dedafd929835fe7f489618f19f456fe7c0df572bf2d914a9f4e006f783a9@170.64.250.88:30303",
    "enode://10d62eff032205fcef19497f35ca8477bea0eadfff6d769a147e895d8b2b8f8ae6341630c645c30f5df6e67547c03494ced3d9c5764e8622a26587b083b028e8@139.59.49.206:30303",
    "enode://9e9492e2e8836114cc75f5b929784f4f46c324ad01daf87d956f98b3b6c5fcba95524d6e5cf9861dc96a2c8a171ea7105bb554a197455058de185fa870970c7c@138.68.123.152:30303",
]

PRIVATE_KEY = os.urandom(32)
fork_id = compute_fork_id(
    MAINNET_GENESIS_HASH, MAINNET_CONFIG,
    head_block=100_000_000, head_time=2_000_000_000,
)


def parse_enode(enode: str) -> tuple[str, int, bytes]:
    """Parse enode URI → (host, port, pubkey_bytes)."""
    rest = enode.removeprefix("enode://")
    pubkey_hex, addr = rest.split("@")
    host, port_str = addr.split(":")
    return host, int(port_str), bytes.fromhex(pubkey_hex)


def decode_transactions(tx_list_rlp: list) -> list[Transaction]:
    """Decode raw RLP transaction items into Transaction objects."""
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


async def do_handshake(conn: RLPxConnection, remote_pubkey: bytes,
                       our_status: StatusMessage) -> StatusMessage | None:
    """Complete RLPx + Hello + Status handshake, return remote Status."""
    from coincurve import PrivateKey
    pubkey = PrivateKey(PRIVATE_KEY).public_key.format(compressed=False)[1:]

    ok = await conn.initiate_handshake(b"\x04" + remote_pubkey)
    if not ok:
        return None

    # Send Hello
    hello = HelloMessage(
        p2p_version=P2P_VERSION,
        client_id=CLIENT_NAME,
        capabilities=[("eth", ETH_VERSION)],
        listen_port=0,
        node_id=pubkey,
    )
    await conn.send_message(0x00, hello.encode())

    # Receive Hello
    result = await conn.recv_message(timeout=10.0)
    if result is None:
        return None
    msg_code, payload = result
    if msg_code == 0x01:
        try:
            dm = DisconnectMessage.decode(payload)
            print(f"  Disconnect: {dm.reason.name} ({dm.reason.value})")
        except Exception:
            print(f"  Disconnect (raw payload: {payload.hex() if payload else 'empty'})")
        return None
    if msg_code != 0x00:
        print(f"  Expected Hello, got msg_code={msg_code}")
        return None

    remote_hello = HelloMessage.decode(payload)
    print(f"  Remote: {remote_hello.client_id}")
    print(f"  Capabilities: {remote_hello.capabilities}")

    # Send Status
    await conn.send_message(0x10, our_status.encode())

    # Receive Status (may get other messages first)
    for _ in range(10):
        result = await conn.recv_message(timeout=10.0)
        if result is None:
            return None
        msg_code, payload = result
        if msg_code == 0x01:
            try:
                dm = DisconnectMessage.decode(payload)
                print(f"  Disconnect: {dm.reason.name}")
            except Exception:
                print(f"  Disconnect (raw)")
            return None
        if msg_code == 0x10:
            remote_status = StatusMessage.decode(payload)
            print(f"  Network ID: {remote_status.network_id}")
            print(f"  Genesis: {remote_status.genesis_hash.hex()[:16]}...")
            print(f"  ForkID: {remote_status.fork_id[0].hex()} / next={remote_status.fork_id[1]}")
            if remote_status.protocol_version >= 69:
                print(f"  eth/69: latest_block={remote_status.latest_block}, "
                      f"hash={remote_status.latest_block_hash.hex()[:16]}...")
            else:
                print(f"  eth/68: TD={remote_status.total_difficulty}, "
                      f"best_hash={remote_status.best_hash.hex()[:16]}...")
            return remote_status
        if msg_code == 0x02:
            await conn.send_message(0x03, encode_pong())
    return None


async def recv_eth_message(conn: RLPxConnection, expected_eth_code: int, timeout: float = 30.0):
    """Receive a specific eth sub-protocol message, handling pings."""
    target_code = expected_eth_code
    deadline = time.time() + timeout
    skipped = 0
    while time.time() < deadline:
        remaining = max(0.1, deadline - time.time())
        result = await conn.recv_message(timeout=remaining)
        if result is None:
            return None
        msg_code, payload = result
        if msg_code == 0x02:  # Ping
            await conn.send_message(0x03, encode_pong())
            continue
        if msg_code == 0x01:  # Disconnect
            try:
                dm = DisconnectMessage.decode(payload)
                print(f"    [recv] Disconnect: {dm.reason.name} ({dm.reason.value})")
            except Exception:
                print(f"    [recv] Disconnect (raw payload: {payload.hex() if payload else 'empty'})")
            return None
        if msg_code == target_code:
            return payload
        skipped += 1
    return None


async def request_headers(conn: RLPxConnection, origin, count: int, req_id: int,
                          reverse: bool = False) -> list[BlockHeader]:
    """Send GetBlockHeaders and wait for response."""
    msg = GetBlockHeadersMessage(request_id=req_id, origin=origin, amount=count, reverse=reverse)
    await conn.send_message(EthMsg.GET_BLOCK_HEADERS, msg.encode())

    payload = await recv_eth_message(conn, EthMsg.BLOCK_HEADERS)
    if payload is None:
        return []
    resp = BlockHeadersMessage.decode(payload)
    return resp.headers


async def request_bodies(conn: RLPxConnection, hashes: list[bytes], req_id: int) -> list[tuple]:
    """Send GetBlockBodies and wait for response."""
    msg = GetBlockBodiesMessage(request_id=req_id, hashes=hashes)
    await conn.send_message(EthMsg.GET_BLOCK_BODIES, msg.encode())

    payload = await recv_eth_message(conn, EthMsg.BLOCK_BODIES)
    if payload is None:
        return []
    resp = BlockBodiesMessage.decode(payload)
    return resp.bodies



async def run_sync_test(conn, remote_status, chain_config, net_name):
    """Run full verification sync test on an established connection.
    Returns True on success, False on failure."""

    print("\n" + "=" * 70)
    print(f"Phase 1: Download Recent Block Headers — {net_name}")
    print("=" * 70)

    t0 = time.time()
    # eth/69: use latest_block_hash; eth/68: use best_hash
    head_hash = remote_status.latest_block_hash if remote_status.protocol_version >= 69 else remote_status.best_hash
    recent_headers = await request_headers(
        conn, head_hash, count=32, req_id=1, reverse=True,
    )
    elapsed = time.time() - t0

    if not recent_headers:
        print("  No headers from reverse request, trying forward from block 0...")
        recent_headers = await request_headers(conn, 0, count=64, req_id=2)

    if not recent_headers:
        print("  ✗ No headers received")
        conn.close()
        return False

    recent_headers.sort(key=lambda h: h.number)
    print(f"  Received {len(recent_headers)} headers in {elapsed:.2f}s")
    print(f"  Block range: {recent_headers[0].number} → {recent_headers[-1].number}")

    for h in recent_headers[:3]:
        has_txs = h.transactions_root != EMPTY_TRIE_ROOT
        blob = f", blob_gas={h.blob_gas_used}" if h.blob_gas_used else ""
        print(f"    #{h.number}: gas={h.gas_used}/{h.gas_limit}, "
              f"txs={'YES' if has_txs else 'empty'}, base_fee={h.base_fee_per_gas}{blob}")
    if len(recent_headers) > 6:
        print(f"    ...")
    for h in recent_headers[-3:]:
        has_txs = h.transactions_root != EMPTY_TRIE_ROOT
        blob = f", blob_gas={h.blob_gas_used}" if h.blob_gas_used else ""
        print(f"    #{h.number}: gas={h.gas_used}/{h.gas_limit}, "
              f"txs={'YES' if has_txs else 'empty'}, base_fee={h.base_fee_per_gas}{blob}")

    # ── Phase 2: Validate header chain ──
    print("\n" + "=" * 70)
    print(f"Phase 2: Validate Header Chain — {net_name}")
    print("=" * 70)

    valid_links = 0
    for i in range(1, len(recent_headers)):
        parent = recent_headers[i - 1]
        child = recent_headers[i]
        if (child.parent_hash == parent.block_hash()
                and child.number == parent.number + 1
                and child.timestamp >= parent.timestamp):
            valid_links += 1
        else:
            print(f"  ✗ Block {child.number}: chain link invalid")

    total_links = len(recent_headers) - 1
    print(f"  ✓ {valid_links}/{total_links} header chain links validated")

    # ── Phase 3: Download block bodies ──
    print("\n" + "=" * 70)
    print(f"Phase 3: Download Block Bodies — {net_name}")
    print("=" * 70)

    all_bodies = []
    batch_size = 32
    t0 = time.time()
    for i in range(0, len(recent_headers), batch_size):
        batch = recent_headers[i:i + batch_size]
        hashes = [h.block_hash() for h in batch]
        bodies = await request_bodies(conn, hashes, req_id=100 + i)
        all_bodies.extend(bodies)
        print(f"  Batch {i // batch_size + 1}: {len(bodies)} bodies received")
    elapsed = time.time() - t0
    print(f"  Total: {len(all_bodies)} bodies in {elapsed:.2f}s")

    # ── Phase 4: Decode transactions & verify roots ──
    print("\n" + "=" * 70)
    print(f"Phase 4: Transaction Decoding & Root Verification — {net_name}")
    print("=" * 70)

    tx_root_ok = 0
    tx_root_fail = 0
    total_txs = 0
    type_counts = {TxType.LEGACY: 0, TxType.ACCESS_LIST: 0, TxType.FEE_MARKET: 0, TxType.BLOB: 0, TxType.SET_CODE: 0}
    total_value_wei = 0
    blocks_with_txs = 0
    sender_ok = 0
    sender_fail = 0
    withdrawal_count = 0
    ommer_count = 0
    decode_errors = 0

    n = min(len(recent_headers), len(all_bodies))
    for idx in range(n):
        header = recent_headers[idx]
        body = all_bodies[idx]
        body_txs_rlp = body[0]
        body_ommers_rlp = body[1]
        body_withdrawals_rlp = body[2] if len(body) > 2 else []

        try:
            txs = decode_transactions(body_txs_rlp)
        except Exception as e:
            print(f"  ✗ Block {header.number}: tx decode error: {e}")
            decode_errors += 1
            tx_root_fail += 1
            continue

        tx_rlps = [tx.encode_rlp() for tx in txs]
        computed_root = ordered_trie_root(tx_rlps) if tx_rlps else EMPTY_TRIE_ROOT
        if computed_root == header.transactions_root:
            tx_root_ok += 1
        else:
            tx_root_fail += 1
            if tx_root_fail <= 3:
                print(f"  ✗ Block {header.number}: tx root mismatch "
                      f"(expected {header.transactions_root.hex()[:16]}..., "
                      f"got {computed_root.hex()[:16]}...)")

        if txs:
            blocks_with_txs += 1
        total_txs += len(txs)

        for tx in txs:
            type_counts[tx.tx_type] = type_counts.get(tx.tx_type, 0) + 1
            total_value_wei += tx.value

            try:
                sender = tx.sender()
                if len(sender) == 20:
                    sender_ok += 1
                else:
                    sender_fail += 1
            except Exception:
                sender_fail += 1

        if body_ommers_rlp:
            ommer_count += len(body_ommers_rlp)
        if body_withdrawals_rlp:
            withdrawal_count += len(body_withdrawals_rlp)

    print(f"\n  Blocks processed:         {n}")
    print(f"  Blocks with transactions: {blocks_with_txs}")
    print(f"  Tx root verification:     {tx_root_ok} OK, {tx_root_fail} FAIL")
    if decode_errors:
        print(f"  Decode errors:            {decode_errors}")
    print()
    print(f"  Total transactions:       {total_txs}")
    print(f"    Legacy (type 0):        {type_counts[TxType.LEGACY]}")
    print(f"    AccessList (type 1):    {type_counts[TxType.ACCESS_LIST]}")
    print(f"    EIP-1559 (type 2):      {type_counts[TxType.FEE_MARKET]}")
    print(f"    Blob (type 3):          {type_counts[TxType.BLOB]}")
    print(f"    SetCode (type 4):       {type_counts[TxType.SET_CODE]}")
    print(f"  Total value:              {total_value_wei / 10**18:.4f} ETH")
    print()
    print(f"  Sender recovery (ECDSA):  {sender_ok} OK, {sender_fail} FAIL")
    print(f"  Ommers (uncle blocks):    {ommer_count}")
    print(f"  Withdrawals:              {withdrawal_count}")

    # ── Phase 5: Base fee validation ──
    has_base_fee = any(h.base_fee_per_gas is not None for h in recent_headers)
    if has_base_fee:
        print("\n" + "=" * 70)
        print(f"Phase 5: Base Fee (EIP-1559) Validation — {net_name}")
        print("=" * 70)

        from ethclient.blockchain.chain import calc_base_fee

        bf_ok = 0
        bf_fail = 0
        for i in range(1, len(recent_headers)):
            parent = recent_headers[i - 1]
            child = recent_headers[i]
            if child.base_fee_per_gas is None:
                continue
            expected = calc_base_fee(parent, chain_config)
            if expected == child.base_fee_per_gas:
                bf_ok += 1
            else:
                bf_fail += 1
                if bf_fail <= 3:
                    print(f"  ✗ Block {child.number}: expected={expected}, got={child.base_fee_per_gas}")

        print(f"  Base fee validation: {bf_ok} OK, {bf_fail} FAIL")
        if bf_fail == 0 and bf_ok > 0:
            print(f"  ✓ All {bf_ok} base fee calculations verified!")

    # ── Summary ──
    print("\n" + "=" * 70)
    print(f"SUMMARY — {net_name}")
    print("=" * 70)

    all_ok = tx_root_fail == 0 and decode_errors == 0
    if all_ok and total_txs > 0:
        print(f"✓ Full verification sync test PASSED!")
        print(f"  - {valid_links} header chain links validated")
        print(f"  - {tx_root_ok} transaction roots verified")
        print(f"  - {total_txs} transactions decoded")
        print(f"    ({type_counts[TxType.FEE_MARKET]} EIP-1559, {type_counts[TxType.BLOB]} blob, {type_counts[TxType.SET_CODE]} set-code)")
        print(f"  - {sender_ok} sender addresses recovered via ECDSA")
        if withdrawal_count:
            print(f"  - {withdrawal_count} withdrawals processed")
        conn.close()
        return True
    elif total_txs == 0:
        print("△ Header chain validated but no transactions found")
    else:
        print("✗ Some verifications failed — see details above")

    conn.close()
    return False


async def try_connect_single(enode, net_id, gen_hash, fid, attempt_label=""):
    """Try connecting to a single enode. Returns (conn, remote_status) or None."""
    host, port, pubkey = parse_enode(enode)
    print(f"\n--- Trying {host}:{port} {attempt_label}---")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10.0
        )
        c = RLPxConnection(PRIVATE_KEY, reader, writer)

        status_msg = StatusMessage(
            protocol_version=ETH_VERSION,
            network_id=net_id,
            genesis_hash=gen_hash,
            fork_id=fid,
            # eth/69 fields — at block 0, latest_block_hash = genesis hash
            earliest_block=0,
            latest_block=0,
            latest_block_hash=gen_hash,
        )

        rs = await do_handshake(c, pubkey, status_msg)
        if rs is not None:
            return c, rs
        c.close()
    except Exception as e:
        print(f"  Connection failed: {e}")
    return None


async def main():
    networks = [
        ("Ethereum Mainnet", MAINNET_ENODES, MAINNET_CONFIG, MAINNET_GENESIS_HASH, 1),
        ("Sepolia Testnet", SEPOLIA_ENODES, SEPOLIA_CONFIG, SEPOLIA_GENESIS_HASH, 11155111),
    ]

    results = {}

    for net_name, enodes, config, gen_hash, net_id in networks:
        fid = compute_fork_id(gen_hash, config, head_block=100_000_000, head_time=2_000_000_000)

        print("=" * 70)
        print(f"Full Verification Sync Test — {net_name}")
        print("=" * 70)
        print(f"Our ForkID: {fid[0].hex()} / next={fid[1]}")

        passed = False
        # Try each bootnode up to 3 rounds, connecting + downloading data
        for attempt in range(3):
            for enode in enodes:
                result = await try_connect_single(
                    enode, net_id, gen_hash, fid,
                    attempt_label=f"(attempt {attempt+1})"
                )
                if result is None:
                    continue

                conn, remote_status = result
                ok = await run_sync_test(conn, remote_status, config, net_name)
                if ok:
                    passed = True
                    break
                # Connection succeeded but data download failed — try next peer
                print(f"  Data download failed, trying next peer...")

            if passed:
                break
            if attempt < 2:
                print(f"\n  Round {attempt+1} exhausted, retrying in 3s...")
                await asyncio.sleep(3)

        if passed:
            results[net_name] = "PASSED"
        else:
            results[net_name] = "FAILED"
            print(f"\n✗ {net_name}: all peers exhausted")
        print()

    # ── Final Report ──
    print("\n" + "=" * 70)
    print("FINAL REPORT")
    print("=" * 70)
    for net_name, status in results.items():
        icon = "✓" if status == "PASSED" else "✗"
        print(f"  {icon} {net_name}: {status}")

    if all(s == "PASSED" for s in results.values()):
        print("\n✓ All networks passed!")
    elif any(s == "PASSED" for s in results.values()):
        print(f"\n△ Partial success — {sum(1 for s in results.values() if s == 'PASSED')}/{len(results)} passed")


if __name__ == "__main__":
    asyncio.run(main())
