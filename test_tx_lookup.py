"""
Live transaction hash lookup test — connect to Sepolia, download blocks,
store them in MemoryBackend, and verify tx/receipt lookup via RPC layer.
"""

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from ethclient.common import rlp
from ethclient.common.types import (
    Block, Transaction, TxType, Receipt, Withdrawal,
    EMPTY_TRIE_ROOT,
)
from ethclient.common.trie import ordered_trie_root
from ethclient.common.crypto import keccak256  # noqa: F401
from ethclient.common.config import (
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
from ethclient.storage.memory_backend import MemoryBackend
from ethclient.rpc.server import RPCServer, int_to_hex, bytes_to_hex, hex_to_bytes
from ethclient.rpc.eth_api import register_eth_api


# Sepolia bootnodes
SEPOLIA_ENODES = [
    "enode://4e5e92199ee224a01932a377160aa432f31d0b351f84ab413a8e0a42f4f36476f8fb1cbe914af0d9aef0d51665c214cf653c651c4bbd9d5550a934f241f1682b@138.197.51.181:30303",
    "enode://143e11fb766781d22d92a2e33f8f104cddae4411a122295ed1fdb6638de96a6ce65f5b7c964ba3763bba27961738fef7d3ecc739268f3e5e771fb4c87b6234ba@146.190.1.103:30303",
    "enode://8b61dc2d06c3f96fddcbebb0efb29d60d3598650275dc469c22229d3e5620369b0d3dedafd929835fe7f489618f19f456fe7c0df572bf2d914a9f4e006f783a9@170.64.250.88:30303",
    "enode://10d62eff032205fcef19497f35ca8477bea0eadfff6d769a147e895d8b2b8f8ae6341630c645c30f5df6e67547c03494ced3d9c5764e8622a26587b083b028e8@139.59.49.206:30303",
    "enode://9e9492e2e8836114cc75f5b929784f4f46c324ad01daf87d956f98b3b6c5fcba95524d6e5cf9861dc96a2c8a171ea7105bb554a197455058de185fa870970c7c@138.68.123.152:30303",
]

PRIVATE_KEY = os.urandom(32)


def parse_enode(enode: str) -> tuple[str, int, bytes]:
    rest = enode.removeprefix("enode://")
    pubkey_hex, addr = rest.split("@")
    host, port_str = addr.split(":")
    return host, int(port_str), bytes.fromhex(pubkey_hex)


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


async def do_handshake(conn, remote_pubkey, our_status):
    from coincurve import PrivateKey
    pubkey = PrivateKey(PRIVATE_KEY).public_key.format(compressed=False)[1:]

    ok = await conn.initiate_handshake(b"\x04" + remote_pubkey)
    if not ok:
        return None

    hello = HelloMessage(
        p2p_version=P2P_VERSION,
        client_id=CLIENT_NAME,
        capabilities=[("eth", ETH_VERSION)],
        listen_port=0,
        node_id=pubkey,
    )
    await conn.send_message(0x00, hello.encode())

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
    if msg_code != 0x00:
        return None

    remote_hello = HelloMessage.decode(payload)
    print(f"  Remote: {remote_hello.client_id}")
    print(f"  Capabilities: {remote_hello.capabilities}")

    await conn.send_message(0x10, our_status.encode())

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
            return remote_status
        if msg_code == 0x02:
            await conn.send_message(0x03, encode_pong())
    return None


async def recv_eth_message(conn, expected_code, timeout=30.0):
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
                print(f"    [recv] Disconnect: {dm.reason.name}")
            except Exception:
                print(f"    [recv] Disconnect (raw)")
            return None
        if msg_code == expected_code:
            return payload
    return None


async def request_headers(conn, origin, count, req_id, reverse=False):
    msg = GetBlockHeadersMessage(request_id=req_id, origin=origin, amount=count, reverse=reverse)
    await conn.send_message(EthMsg.GET_BLOCK_HEADERS, msg.encode())
    payload = await recv_eth_message(conn, EthMsg.BLOCK_HEADERS)
    if payload is None:
        return []
    resp = BlockHeadersMessage.decode(payload)
    return resp.headers


async def request_bodies(conn, hashes, req_id):
    msg = GetBlockBodiesMessage(request_id=req_id, hashes=hashes)
    await conn.send_message(EthMsg.GET_BLOCK_BODIES, msg.encode())
    payload = await recv_eth_message(conn, EthMsg.BLOCK_BODIES)
    if payload is None:
        return []
    resp = BlockBodiesMessage.decode(payload)
    return resp.bodies


async def main():
    print("=" * 70)
    print("Transaction Hash Lookup — Live Test (Sepolia)")
    print("=" * 70)

    fork_id = compute_fork_id(
        SEPOLIA_GENESIS_HASH, SEPOLIA_CONFIG,
        head_block=100_000_000, head_time=2_000_000_000,
    )
    print(f"Our ForkID: {fork_id[0].hex()} / next={fork_id[1]}")

    # ================================================================
    # Phase 1: Connect to Sepolia peer
    # ================================================================
    print("\n" + "=" * 70)
    print("Phase 1: Connect to Sepolia Peer")
    print("=" * 70)

    conn = None
    remote_status = None

    for attempt in range(2):
        for enode in SEPOLIA_ENODES:
            host, port, pubkey = parse_enode(enode)
            print(f"\n--- Trying {host}:{port} (attempt {attempt+1}) ---")
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=10.0
                )
                c = RLPxConnection(PRIVATE_KEY, reader, writer)

                status_msg = StatusMessage(
                    protocol_version=ETH_VERSION,
                    network_id=11155111,
                    total_difficulty=17_000_000_000_000_000,
                    best_hash=SEPOLIA_GENESIS_HASH,
                    genesis_hash=SEPOLIA_GENESIS_HASH,
                    fork_id=fork_id,
                )

                rs = await do_handshake(c, pubkey, status_msg)
                if rs is not None:
                    conn = c
                    remote_status = rs
                    break
                c.close()
            except Exception as e:
                print(f"  Connection failed: {e}")

        if conn is not None:
            break
        if attempt == 0:
            print("\n  Retrying in 3 seconds...")
            await asyncio.sleep(3)

    if conn is None:
        print("\n  Could not connect to any Sepolia bootnode")
        return

    # ================================================================
    # Phase 2: Download recent blocks with transactions
    # ================================================================
    print("\n" + "=" * 70)
    print("Phase 2: Download Recent Blocks")
    print("=" * 70)

    # Get headers ending at best_hash (reverse)
    t0 = time.time()
    recent_headers = await request_headers(
        conn, remote_status.best_hash, count=32, req_id=1, reverse=True,
    )
    elapsed = time.time() - t0

    if not recent_headers:
        print("  No headers received from reverse request")
        conn.close()
        return

    recent_headers.sort(key=lambda h: h.number)
    print(f"  Received {len(recent_headers)} headers in {elapsed:.2f}s")
    print(f"  Block range: {recent_headers[0].number} -> {recent_headers[-1].number}")

    # Find blocks with transactions
    blocks_with_txs = [h for h in recent_headers if h.transactions_root != EMPTY_TRIE_ROOT]
    print(f"  Blocks with transactions: {len(blocks_with_txs)}")

    if not blocks_with_txs:
        print("  No blocks with transactions found, trying forward from block 1...")
        recent_headers = await request_headers(conn, 1, count=128, req_id=2)
        if recent_headers:
            recent_headers.sort(key=lambda h: h.number)
            blocks_with_txs = [h for h in recent_headers if h.transactions_root != EMPTY_TRIE_ROOT]
            print(f"  Found {len(blocks_with_txs)} blocks with txs in range {recent_headers[0].number}-{recent_headers[-1].number}")

    if not blocks_with_txs:
        print("  Still no blocks with transactions")
        conn.close()
        return

    # Download bodies for blocks with transactions (up to 16 blocks)
    target_headers = blocks_with_txs[:16]
    hashes = [h.block_hash() for h in target_headers]
    print(f"\n  Downloading bodies for {len(target_headers)} blocks...")

    t0 = time.time()
    bodies = await request_bodies(conn, hashes, req_id=10)
    elapsed = time.time() - t0
    print(f"  Got {len(bodies)} bodies in {elapsed:.2f}s")

    conn.close()

    if not bodies:
        print("  No bodies received")
        return

    # ================================================================
    # Phase 3: Store blocks in MemoryBackend
    # ================================================================
    print("\n" + "=" * 70)
    print("Phase 3: Store Blocks in MemoryBackend")
    print("=" * 70)

    store = MemoryBackend()
    stored_txs = []  # (tx, block_hash, block_number, tx_index)
    total_txs = 0

    n = min(len(target_headers), len(bodies))
    for idx in range(n):
        header = target_headers[idx]
        body = bodies[idx]
        body_txs_rlp = body[0]
        body_ommers_rlp = body[1]
        body_withdrawals_rlp = body[2] if len(body) > 2 else []

        # Decode transactions
        try:
            txs = decode_transactions(body_txs_rlp)
        except Exception as e:
            print(f"  Block {header.number}: tx decode error: {e}")
            continue

        # Verify tx root
        tx_rlps = [tx.encode_rlp() for tx in txs]
        computed_root = ordered_trie_root(tx_rlps) if tx_rlps else EMPTY_TRIE_ROOT
        if computed_root != header.transactions_root:
            print(f"  Block {header.number}: tx root mismatch, skipping")
            continue

        # Build Block object
        ommers = []  # Post-merge, always empty
        withdrawals = None
        if body_withdrawals_rlp:
            withdrawals = []
            for w_rlp in body_withdrawals_rlp:
                if isinstance(w_rlp, list):
                    wd = Withdrawal(
                        index=rlp.decode_uint(w_rlp[0]) if isinstance(w_rlp[0], bytes) else w_rlp[0],
                        validator_index=rlp.decode_uint(w_rlp[1]) if isinstance(w_rlp[1], bytes) else w_rlp[1],
                        address=w_rlp[2],
                        amount=rlp.decode_uint(w_rlp[3]) if isinstance(w_rlp[3], bytes) else w_rlp[3],
                    )
                    withdrawals.append(wd)

        block = Block(
            header=header,
            transactions=txs,
            ommers=ommers,
            withdrawals=withdrawals,
        )

        block_hash = header.block_hash()
        store.put_block(block)
        store.put_canonical_hash(header.number, block_hash)

        # Create synthetic receipts (we don't have real ones from the network)
        receipts = []
        cum_gas = 0
        for i, tx in enumerate(txs):
            cum_gas += 21000  # Minimum gas, approximate
            receipt = Receipt(
                tx_type=tx.tx_type,
                succeeded=True,
                cumulative_gas_used=cum_gas,
                logs_bloom=b"\x00" * 256,
                logs=[],
            )
            receipts.append(receipt)
        store.put_receipts(block_hash, receipts)

        # Track stored txs for verification
        for i, tx in enumerate(txs):
            stored_txs.append((tx, block_hash, header.number, i))

        total_txs += len(txs)
        print(f"  Block #{header.number}: {len(txs)} txs stored (hash={block_hash.hex()[:16]}...)")

    print(f"\n  Total: {n} blocks, {total_txs} transactions stored")
    print(f"  Tx index size: {len(store._tx_index)} entries")

    if total_txs == 0:
        print("  No transactions to test")
        return

    # ================================================================
    # Phase 4: Test direct store lookups
    # ================================================================
    print("\n" + "=" * 70)
    print("Phase 4: Direct Store Lookups")
    print("=" * 70)

    store_ok = 0
    store_fail = 0

    for tx, expected_bh, expected_num, expected_idx in stored_txs[:10]:
        tx_hash = tx.tx_hash()
        result = store.get_transaction_by_hash(tx_hash)
        if result is None:
            print(f"  FAIL: tx {tx_hash.hex()[:16]}... not found in store")
            store_fail += 1
            continue

        found_tx, found_bh, found_idx = result
        if found_bh == expected_bh and found_idx == expected_idx:
            store_ok += 1
        else:
            print(f"  FAIL: tx {tx_hash.hex()[:16]}... wrong block/index")
            store_fail += 1

    # Test receipt lookup
    receipt_ok = 0
    receipt_fail = 0
    for tx, expected_bh, expected_num, expected_idx in stored_txs[:10]:
        tx_hash = tx.tx_hash()
        result = store.get_transaction_receipt(tx_hash)
        if result is None:
            print(f"  FAIL: receipt for {tx_hash.hex()[:16]}... not found")
            receipt_fail += 1
            continue
        receipt, found_bh, found_idx = result
        if found_bh == expected_bh and found_idx == expected_idx:
            receipt_ok += 1
        else:
            receipt_fail += 1

    tested = min(10, len(stored_txs))
    print(f"  Transaction lookup: {store_ok}/{tested} OK, {store_fail} FAIL")
    print(f"  Receipt lookup:     {receipt_ok}/{tested} OK, {receipt_fail} FAIL")

    # ================================================================
    # Phase 5: Test RPC formatting chain
    # ================================================================
    print("\n" + "=" * 70)
    print("Phase 5: RPC Formatting Chain")
    print("=" * 70)

    rpc = RPCServer()
    register_eth_api(rpc, store=store, network_chain_id=11155111, config=SEPOLIA_CONFIG)

    # Helper to call registered RPC methods directly
    def rpc_call(method, *args):
        return rpc._methods[method](*args)

    rpc_tx_ok = 0
    rpc_tx_fail = 0
    rpc_receipt_ok = 0
    rpc_receipt_fail = 0

    for tx, expected_bh, expected_num, expected_idx in stored_txs[:10]:
        tx_hash = tx.tx_hash()
        tx_hash_hex = "0x" + tx_hash.hex()

        # Test eth_getTransactionByHash
        try:
            result = rpc_call("eth_getTransactionByHash", tx_hash_hex)
            if result is None:
                print(f"  FAIL: RPC tx {tx_hash_hex[:18]}... returned None")
                rpc_tx_fail += 1
            elif result.get("hash") != tx_hash_hex:
                print(f"  FAIL: RPC tx hash mismatch")
                rpc_tx_fail += 1
            else:
                rpc_tx_ok += 1
                if rpc_tx_ok <= 3:
                    sender_addr = result.get("from", "unknown")
                    to_addr = result.get("to", "contract creation")
                    value_hex = result.get("value", "0x0")
                    value_wei = int(value_hex, 16)
                    tx_type = int(result.get("type", "0x0"), 16)
                    print(f"  TX {tx_hash_hex[:18]}...")
                    print(f"     type={tx_type} from={sender_addr[:18]}... to={to_addr[:18] if to_addr else 'CREATE'}...")
                    print(f"     value={value_wei / 10**18:.6f} ETH, block=#{expected_num}, index={expected_idx}")
        except Exception as e:
            print(f"  FAIL: RPC tx error: {e}")
            rpc_tx_fail += 1

        # Test eth_getTransactionReceipt
        try:
            result = rpc_call("eth_getTransactionReceipt", tx_hash_hex)
            if result is None:
                print(f"  FAIL: RPC receipt {tx_hash_hex[:18]}... returned None")
                rpc_receipt_fail += 1
            elif result.get("transactionHash") != tx_hash_hex:
                print(f"  FAIL: RPC receipt hash mismatch")
                rpc_receipt_fail += 1
            else:
                rpc_receipt_ok += 1
        except Exception as e:
            print(f"  FAIL: RPC receipt error: {e}")
            rpc_receipt_fail += 1

    print(f"\n  eth_getTransactionByHash:  {rpc_tx_ok}/{tested} OK, {rpc_tx_fail} FAIL")
    print(f"  eth_getTransactionReceipt: {rpc_receipt_ok}/{tested} OK, {rpc_receipt_fail} FAIL")

    # Test eth_getBlockByNumber with full_txs=true
    sample_header = target_headers[0]
    block_num_hex = "0x" + hex(sample_header.number)[2:]
    try:
        block_result = rpc_call("eth_getBlockByNumber", block_num_hex, True)
        if block_result and block_result.get("transactions"):
            tx_count = len(block_result["transactions"])
            first_tx = block_result["transactions"][0]
            print(f"\n  eth_getBlockByNumber(#{sample_header.number}, full_txs=true):")
            print(f"     {tx_count} transactions returned")
            print(f"     First tx hash: {first_tx.get('hash', 'N/A')[:18]}...")
            print(f"     First tx from: {first_tx.get('from', 'N/A')[:18]}...")
    except Exception as e:
        print(f"  eth_getBlockByNumber error: {e}")

    # Test eth_getBlockByNumber with full_txs=false (hash list)
    try:
        block_result = rpc_call("eth_getBlockByNumber", block_num_hex, False)
        if block_result and block_result.get("transactions"):
            tx_count = len(block_result["transactions"])
            first_hash = block_result["transactions"][0]
            print(f"\n  eth_getBlockByNumber(#{sample_header.number}, full_txs=false):")
            print(f"     {tx_count} transaction hashes returned")
            print(f"     First hash: {first_hash[:18]}...")
    except Exception as e:
        print(f"  eth_getBlockByNumber(hashes) error: {e}")

    # Test eth_getBlockTransactionCountByNumber
    try:
        count_result = rpc_call("eth_getBlockTransactionCountByNumber", block_num_hex)
        if count_result:
            print(f"\n  eth_getBlockTransactionCountByNumber(#{sample_header.number}): {count_result}")
    except Exception as e:
        print(f"  eth_getBlockTransactionCountByNumber error: {e}")

    # Test eth_getBlockReceipts
    try:
        receipts_result = rpc_call("eth_getBlockReceipts", block_num_hex)
        if receipts_result:
            print(f"  eth_getBlockReceipts(#{sample_header.number}): {len(receipts_result)} receipts")
            if receipts_result:
                r0 = receipts_result[0]
                print(f"     First receipt: status={r0.get('status')}, gasUsed={r0.get('gasUsed')}")
    except Exception as e:
        print(f"  eth_getBlockReceipts error: {e}")

    # Test not-found cases
    fake_hash = "0x" + "00" * 32
    try:
        result = rpc_call("eth_getTransactionByHash", fake_hash)
        not_found_ok = result is None
        print(f"\n  eth_getTransactionByHash(fake): {'None (correct)' if not_found_ok else 'FAIL: returned data'}")
    except Exception as e:
        print(f"  eth_getTransactionByHash(fake) error: {e}")

    try:
        result = rpc_call("eth_getTransactionReceipt", fake_hash)
        not_found_ok = result is None
        print(f"  eth_getTransactionReceipt(fake): {'None (correct)' if not_found_ok else 'FAIL: returned data'}")
    except Exception as e:
        print(f"  eth_getTransactionReceipt(fake) error: {e}")

    # ================================================================
    # Summary
    # ================================================================
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    all_ok = (store_fail == 0 and receipt_fail == 0 and
              rpc_tx_fail == 0 and rpc_receipt_fail == 0)

    if all_ok and total_txs > 0:
        print(f"  Transaction hash lookup test PASSED!")
        print(f"  - {n} blocks downloaded from Sepolia")
        print(f"  - {total_txs} transactions indexed")
        print(f"  - {store_ok} direct store lookups verified")
        print(f"  - {receipt_ok} receipt lookups verified")
        print(f"  - {rpc_tx_ok} RPC eth_getTransactionByHash calls verified")
        print(f"  - {rpc_receipt_ok} RPC eth_getTransactionReceipt calls verified")
    else:
        print(f"  Some verifications FAILED — see details above")
        print(f"  Store: {store_fail} fail, Receipt: {receipt_fail} fail")
        print(f"  RPC tx: {rpc_tx_fail} fail, RPC receipt: {rpc_receipt_fail} fail")


if __name__ == "__main__":
    asyncio.run(main())
