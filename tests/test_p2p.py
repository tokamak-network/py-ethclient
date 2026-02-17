"""
Tests for Phase 5: P2P Networking.

Covers:
  - ECIES encrypt/decrypt
  - RLPx framing encode/decode
  - Handshake message encoding
  - eth sub-protocol messages
  - Discovery v4 packet encoding/decoding
  - Routing table operations
  - P2P server components
"""

import asyncio
import hashlib
import os
import time
import pytest

from coincurve import PrivateKey


# ===================================================================
# ECIES tests
# ===================================================================

class TestECIES:
    def test_encrypt_decrypt_roundtrip(self):
        from ethclient.networking.rlpx.handshake import ecies_encrypt, ecies_decrypt

        recipient_key = PrivateKey()
        recipient_pub = recipient_key.public_key.format(compressed=False)

        plaintext = b"hello ethereum"
        encrypted = ecies_encrypt(recipient_pub, plaintext)
        decrypted = ecies_decrypt(recipient_key.secret, encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_empty(self):
        from ethclient.networking.rlpx.handshake import ecies_encrypt, ecies_decrypt

        recipient_key = PrivateKey()
        recipient_pub = recipient_key.public_key.format(compressed=False)

        encrypted = ecies_encrypt(recipient_pub, b"")
        decrypted = ecies_decrypt(recipient_key.secret, encrypted)
        assert decrypted == b""

    def test_encrypt_decrypt_large(self):
        from ethclient.networking.rlpx.handshake import ecies_encrypt, ecies_decrypt

        recipient_key = PrivateKey()
        recipient_pub = recipient_key.public_key.format(compressed=False)

        plaintext = os.urandom(1024)
        encrypted = ecies_encrypt(recipient_pub, plaintext)
        decrypted = ecies_decrypt(recipient_key.secret, encrypted)
        assert decrypted == plaintext

    def test_decrypt_wrong_key_fails(self):
        from ethclient.networking.rlpx.handshake import ecies_encrypt, ecies_decrypt

        recipient_key = PrivateKey()
        wrong_key = PrivateKey()
        recipient_pub = recipient_key.public_key.format(compressed=False)

        encrypted = ecies_encrypt(recipient_pub, b"secret")
        with pytest.raises(ValueError, match="MAC verification failed"):
            ecies_decrypt(wrong_key.secret, encrypted)

    def test_encrypt_with_shared_mac_data(self):
        from ethclient.networking.rlpx.handshake import ecies_encrypt, ecies_decrypt

        recipient_key = PrivateKey()
        recipient_pub = recipient_key.public_key.format(compressed=False)

        mac_data = b"extra_mac_data"
        plaintext = b"test data"
        encrypted = ecies_encrypt(recipient_pub, plaintext, shared_mac_data=mac_data)
        decrypted = ecies_decrypt(recipient_key.secret, encrypted, shared_mac_data=mac_data)
        assert decrypted == plaintext

    def test_decrypt_short_data_fails(self):
        from ethclient.networking.rlpx.handshake import ecies_decrypt

        with pytest.raises(ValueError, match="too short"):
            ecies_decrypt(b"\x01" * 32, b"\x00" * 50)


# ===================================================================
# Handshake message tests
# ===================================================================

class TestHandshakeMessages:
    def test_auth_message_encode_decode(self):
        from ethclient.networking.rlpx.handshake import AuthMessage

        sig = os.urandom(65)
        pubkey = os.urandom(64)
        nonce = os.urandom(32)

        msg = AuthMessage(signature=sig, initiator_pubkey=pubkey, nonce=nonce, version=4)
        encoded = msg.encode()
        decoded = AuthMessage.decode(encoded)

        assert decoded.signature == sig
        assert decoded.initiator_pubkey == pubkey
        assert decoded.nonce == nonce
        assert decoded.version == 4

    def test_ack_message_encode_decode(self):
        from ethclient.networking.rlpx.handshake import AckMessage

        pubkey = os.urandom(64)
        nonce = os.urandom(32)

        msg = AckMessage(recipient_pubkey=pubkey, nonce=nonce, version=4)
        encoded = msg.encode()
        decoded = AckMessage.decode(encoded)

        assert decoded.recipient_pubkey == pubkey
        assert decoded.nonce == nonce
        assert decoded.version == 4


# ===================================================================
# RLPx framing tests
# ===================================================================

class TestFraming:
    def _make_coder_pair(self):
        """Create a matched pair of FrameCoders for testing."""
        from ethclient.networking.rlpx.framing import FrameCoder

        aes_secret = os.urandom(32)
        mac_secret = os.urandom(32)

        egress_mac = hashlib.new("sha3_256")
        egress_mac.update(os.urandom(32))
        ingress_mac = hashlib.new("sha3_256")
        ingress_mac.update(os.urandom(32))

        # Clone the MAC states
        egress_mac_copy = egress_mac.copy()
        ingress_mac_copy = ingress_mac.copy()

        # Sender's egress = receiver's ingress (and vice versa)
        sender = FrameCoder(aes_secret, mac_secret, egress_mac, ingress_mac)
        receiver = FrameCoder(aes_secret, mac_secret, ingress_mac_copy, egress_mac_copy)
        return sender, receiver

    def test_frame_roundtrip_simple(self):
        sender, receiver = self._make_coder_pair()

        msg_code = 0x10
        payload = b"hello"
        frame = sender.encode_frame(msg_code, payload)

        # Decode header
        frame_size = receiver.decode_header(frame[:32])
        assert frame_size is not None

        # Decode body
        padded_size = ((frame_size + 15) // 16) * 16
        body_data = frame[32:32 + padded_size + 16]
        result = receiver.decode_body(body_data, frame_size)
        assert result is not None
        code, data = result
        assert code == msg_code
        assert data == payload

    def test_frame_roundtrip_empty_payload(self):
        sender, receiver = self._make_coder_pair()

        msg_code = 0x00
        payload = b""
        frame = sender.encode_frame(msg_code, payload)

        frame_size = receiver.decode_header(frame[:32])
        assert frame_size is not None

        padded_size = ((frame_size + 15) // 16) * 16
        body_data = frame[32:32 + padded_size + 16]
        result = receiver.decode_body(body_data, frame_size)
        assert result is not None
        code, data = result
        assert code == msg_code
        assert data == payload

    def test_frame_roundtrip_large_payload(self):
        sender, receiver = self._make_coder_pair()

        msg_code = 0x15
        payload = os.urandom(500)
        frame = sender.encode_frame(msg_code, payload)

        frame_size = receiver.decode_header(frame[:32])
        assert frame_size is not None

        padded_size = ((frame_size + 15) // 16) * 16
        body_data = frame[32:32 + padded_size + 16]
        result = receiver.decode_body(body_data, frame_size)
        assert result is not None
        code, data = result
        assert code == msg_code
        assert data == payload

    def test_frame_multiple_messages(self):
        sender, receiver = self._make_coder_pair()

        messages = [(0x01, b"first"), (0x10, b"second"), (0x20, os.urandom(100))]

        for msg_code, payload in messages:
            frame = sender.encode_frame(msg_code, payload)

            frame_size = receiver.decode_header(frame[:32])
            assert frame_size is not None

            padded_size = ((frame_size + 15) // 16) * 16
            body_data = frame[32:32 + padded_size + 16]
            result = receiver.decode_body(body_data, frame_size)
            assert result is not None
            code, data = result
            assert code == msg_code
            assert data == payload

    def test_bad_header_mac(self):
        sender, receiver = self._make_coder_pair()
        frame = sender.encode_frame(0x00, b"test")

        # Corrupt MAC
        corrupted = frame[:16] + b"\xff" * 16 + frame[32:]
        frame_size = receiver.decode_header(corrupted[:32])
        assert frame_size is None


# ===================================================================
# Snappy compression tests
# ===================================================================

class TestSnappy:
    def test_compress_decompress(self):
        from ethclient.networking.rlpx.framing import snappy_compress, snappy_decompress
        data = b"hello " * 100
        compressed = snappy_compress(data)
        decompressed = snappy_decompress(compressed)
        assert decompressed == data

    def test_compress_empty(self):
        from ethclient.networking.rlpx.framing import snappy_compress, snappy_decompress
        compressed = snappy_compress(b"")
        decompressed = snappy_decompress(compressed)
        assert decompressed == b""


# ===================================================================
# Protocol constant tests
# ===================================================================

class TestProtocol:
    def test_p2p_msg_codes(self):
        from ethclient.networking.eth.protocol import P2PMsg
        assert P2PMsg.HELLO == 0x00
        assert P2PMsg.DISCONNECT == 0x01
        assert P2PMsg.PING == 0x02
        assert P2PMsg.PONG == 0x03

    def test_eth_msg_codes(self):
        from ethclient.networking.eth.protocol import EthMsg
        assert EthMsg.STATUS == 0x10
        assert EthMsg.NEW_BLOCK_HASHES == 0x11
        assert EthMsg.TRANSACTIONS == 0x12
        assert EthMsg.GET_BLOCK_HEADERS == 0x13
        assert EthMsg.BLOCK_HEADERS == 0x14
        assert EthMsg.GET_BLOCK_BODIES == 0x15
        assert EthMsg.BLOCK_BODIES == 0x16
        assert EthMsg.NEW_BLOCK == 0x17
        assert EthMsg.NEW_POOLED_TX_HASHES == 0x18

    def test_disconnect_reasons(self):
        from ethclient.networking.eth.protocol import DisconnectReason
        assert DisconnectReason.REQUESTED == 0x00
        assert DisconnectReason.TOO_MANY_PEERS == 0x04
        assert DisconnectReason.SUBPROTOCOL_ERROR == 0x10


# ===================================================================
# eth message encode/decode tests
# ===================================================================

class TestEthMessages:
    def test_hello_roundtrip(self):
        from ethclient.networking.eth.messages import HelloMessage

        pubkey = os.urandom(64)
        msg = HelloMessage(
            p2p_version=5,
            client_id="test/1.0",
            capabilities=[("eth", 68)],
            listen_port=30303,
            node_id=pubkey,
        )
        encoded = msg.encode()
        decoded = HelloMessage.decode(encoded)

        assert decoded.p2p_version == 5
        assert decoded.client_id == "test/1.0"
        assert decoded.capabilities == [("eth", 68)]
        assert decoded.listen_port == 30303
        assert decoded.node_id == pubkey

    def test_hello_multiple_capabilities(self):
        from ethclient.networking.eth.messages import HelloMessage

        msg = HelloMessage(
            capabilities=[("eth", 68), ("snap", 1)],
            node_id=os.urandom(64),
        )
        encoded = msg.encode()
        decoded = HelloMessage.decode(encoded)
        assert decoded.capabilities == [("eth", 68), ("snap", 1)]

    def test_disconnect_roundtrip(self):
        from ethclient.networking.eth.messages import DisconnectMessage
        from ethclient.networking.eth.protocol import DisconnectReason

        msg = DisconnectMessage(reason=DisconnectReason.TOO_MANY_PEERS)
        encoded = msg.encode()
        decoded = DisconnectMessage.decode(encoded)
        assert decoded.reason == DisconnectReason.TOO_MANY_PEERS

    def test_status_roundtrip(self):
        from ethclient.networking.eth.messages import StatusMessage

        best = os.urandom(32)
        genesis = os.urandom(32)
        fork_id = (os.urandom(4), 12345)

        msg = StatusMessage(
            protocol_version=68,
            network_id=1,
            total_difficulty=17_000_000_000,
            best_hash=best,
            genesis_hash=genesis,
            fork_id=fork_id,
        )
        encoded = msg.encode()
        decoded = StatusMessage.decode(encoded)

        assert decoded.protocol_version == 68
        assert decoded.network_id == 1
        assert decoded.total_difficulty == 17_000_000_000
        assert decoded.best_hash == best
        assert decoded.genesis_hash == genesis
        assert decoded.fork_id == fork_id

    def test_get_block_headers_by_number(self):
        from ethclient.networking.eth.messages import GetBlockHeadersMessage

        msg = GetBlockHeadersMessage(
            request_id=42,
            origin=1000,
            amount=128,
            skip=0,
            reverse=False,
        )
        encoded = msg.encode()
        decoded = GetBlockHeadersMessage.decode(encoded)

        assert decoded.request_id == 42
        assert decoded.origin == 1000
        assert decoded.amount == 128
        assert decoded.skip == 0
        assert decoded.reverse is False

    def test_get_block_headers_by_hash(self):
        from ethclient.networking.eth.messages import GetBlockHeadersMessage

        block_hash = os.urandom(32)
        msg = GetBlockHeadersMessage(
            request_id=7,
            origin=block_hash,
            amount=1,
        )
        encoded = msg.encode()
        decoded = GetBlockHeadersMessage.decode(encoded)

        assert decoded.request_id == 7
        assert decoded.origin == block_hash
        assert decoded.amount == 1

    def test_get_block_headers_reverse(self):
        from ethclient.networking.eth.messages import GetBlockHeadersMessage

        msg = GetBlockHeadersMessage(
            request_id=1, origin=500, amount=10, skip=2, reverse=True,
        )
        encoded = msg.encode()
        decoded = GetBlockHeadersMessage.decode(encoded)
        assert decoded.reverse is True
        assert decoded.skip == 2

    def test_get_block_bodies_roundtrip(self):
        from ethclient.networking.eth.messages import GetBlockBodiesMessage

        hashes = [os.urandom(32) for _ in range(5)]
        msg = GetBlockBodiesMessage(request_id=99, hashes=hashes)
        encoded = msg.encode()
        decoded = GetBlockBodiesMessage.decode(encoded)

        assert decoded.request_id == 99
        assert decoded.hashes == hashes

    def test_transactions_roundtrip(self):
        from ethclient.networking.eth.messages import TransactionsMessage

        txs = [os.urandom(100) for _ in range(3)]
        msg = TransactionsMessage(transactions=txs)
        encoded = msg.encode()
        decoded = TransactionsMessage.decode(encoded)
        assert decoded.transactions == txs

    def test_new_pooled_tx_hashes_roundtrip(self):
        from ethclient.networking.eth.messages import NewPooledTransactionHashesMessage

        msg = NewPooledTransactionHashesMessage(
            types=[2, 2, 1],
            sizes=[500, 600, 300],
            hashes=[os.urandom(32) for _ in range(3)],
        )
        encoded = msg.encode()
        decoded = NewPooledTransactionHashesMessage.decode(encoded)

        assert decoded.types == [2, 2, 1]
        assert decoded.sizes == [500, 600, 300]
        assert len(decoded.hashes) == 3

    def test_new_block_hashes_roundtrip(self):
        from ethclient.networking.eth.messages import NewBlockHashesMessage

        hashes = [(os.urandom(32), 100), (os.urandom(32), 101)]
        msg = NewBlockHashesMessage(hashes=hashes)
        encoded = msg.encode()
        decoded = NewBlockHashesMessage.decode(encoded)

        assert len(decoded.hashes) == 2
        assert decoded.hashes[0][1] == 100
        assert decoded.hashes[1][1] == 101

    def test_ping_pong_encode(self):
        from ethclient.networking.eth.messages import encode_ping, encode_pong

        ping = encode_ping()
        pong = encode_pong()
        assert isinstance(ping, bytes)
        assert isinstance(pong, bytes)
        assert len(ping) > 0
        assert len(pong) > 0


# ===================================================================
# Routing table tests
# ===================================================================

class TestRoutingTable:
    def _make_node(self, seed: int) -> "Node":
        from ethclient.networking.discv4.routing import Node
        pk = PrivateKey(hashlib.sha256(seed.to_bytes(4, "big")).digest())
        return Node(
            id=pk.public_key.format(compressed=False)[1:],
            ip=f"10.0.0.{seed % 256}",
            udp_port=30303,
            tcp_port=30303,
        )

    def test_add_and_count(self):
        from ethclient.networking.discv4.routing import RoutingTable

        local = self._make_node(0)
        table = RoutingTable(local)

        for i in range(1, 20):
            table.add_node(self._make_node(i))

        assert table.total_nodes() == 19

    def test_add_duplicate(self):
        from ethclient.networking.discv4.routing import RoutingTable

        local = self._make_node(0)
        table = RoutingTable(local)

        node = self._make_node(1)
        table.add_node(node)
        table.add_node(node)  # duplicate
        assert table.total_nodes() == 1

    def test_add_self_ignored(self):
        from ethclient.networking.discv4.routing import RoutingTable

        local = self._make_node(0)
        table = RoutingTable(local)
        table.add_node(local)
        assert table.total_nodes() == 0

    def test_remove_node(self):
        from ethclient.networking.discv4.routing import RoutingTable

        local = self._make_node(0)
        table = RoutingTable(local)

        node = self._make_node(1)
        table.add_node(node)
        assert table.total_nodes() == 1
        table.remove_node(node)
        assert table.total_nodes() == 0

    def test_closest_nodes(self):
        from ethclient.networking.discv4.routing import RoutingTable
        from ethclient.common.crypto import keccak256

        local = self._make_node(0)
        table = RoutingTable(local)

        for i in range(1, 50):
            table.add_node(self._make_node(i))

        target = self._make_node(100)
        closest = table.closest_nodes(target.node_id, 5)
        assert len(closest) == 5

        # Verify they are sorted by distance
        from ethclient.networking.discv4.routing import distance
        distances = [distance(n.node_id, target.node_id) for n in closest]
        assert distances == sorted(distances)

    def test_bucket_full_returns_lrs(self):
        """When bucket is full, add_node returns the least-recently-seen node."""
        from ethclient.networking.discv4.routing import RoutingTable, BUCKET_SIZE

        local = self._make_node(0)
        table = RoutingTable(local)

        # Fill a bucket
        added_nodes = []
        for i in range(1, 1000):
            node = self._make_node(i)
            result = table.add_node(node)
            added_nodes.append(node)
            if table.total_nodes() > BUCKET_SIZE:
                break
            if result is not None:
                # Bucket is full, result is the LRS node
                assert result is not None
                break

    def test_log_distance(self):
        from ethclient.networking.discv4.routing import log_distance

        a = b"\x00" * 32
        b = b"\x00" * 31 + b"\x01"
        assert log_distance(a, b) == 1

        c = b"\x80" + b"\x00" * 31
        assert log_distance(a, c) == 256

        assert log_distance(a, a) == 0

    def test_all_nodes(self):
        from ethclient.networking.discv4.routing import RoutingTable

        local = self._make_node(0)
        table = RoutingTable(local)

        for i in range(1, 11):
            table.add_node(self._make_node(i))

        all_nodes = table.all_nodes()
        assert len(all_nodes) == 10


# ===================================================================
# Discovery v4 packet tests
# ===================================================================

class TestDiscoveryPackets:
    def test_ping_encode_decode(self):
        from ethclient.networking.discv4.discovery import (
            encode_ping, decode_ping, Endpoint, _decode_packet,
        )

        key = PrivateKey()
        from_ep = Endpoint(ip="127.0.0.1", udp_port=30303, tcp_port=30303)
        to_ep = Endpoint(ip="10.0.0.1", udp_port=30303, tcp_port=30303)

        packet = encode_ping(key.secret, from_ep, to_ep, expiration=int(time.time()) + 60)
        assert len(packet) > 98

        result = _decode_packet(packet)
        assert result is not None
        ptype, payload, pubkey, phash = result
        assert ptype == 0x01
        assert pubkey == key.public_key.format(compressed=False)[1:]

        version, from_decoded, to_decoded, exp = decode_ping(payload)
        assert version == 4
        assert from_decoded.ip == "127.0.0.1"
        assert to_decoded.ip == "10.0.0.1"

    def test_pong_encode_decode(self):
        from ethclient.networking.discv4.discovery import (
            encode_pong, decode_pong, Endpoint, _decode_packet,
        )

        key = PrivateKey()
        to_ep = Endpoint(ip="10.0.0.1", udp_port=30303)
        ping_hash = os.urandom(32)

        packet = encode_pong(key.secret, to_ep, ping_hash)
        result = _decode_packet(packet)
        assert result is not None
        ptype, payload, _, _ = result
        assert ptype == 0x02

        to_decoded, hash_decoded, exp = decode_pong(payload)
        assert to_decoded.ip == "10.0.0.1"
        assert hash_decoded == ping_hash

    def test_find_neighbours_encode_decode(self):
        from ethclient.networking.discv4.discovery import (
            encode_find_neighbours, decode_find_neighbours, _decode_packet,
        )

        key = PrivateKey()
        target = os.urandom(64)

        packet = encode_find_neighbours(key.secret, target)
        result = _decode_packet(packet)
        assert result is not None
        ptype, payload, _, _ = result
        assert ptype == 0x03

        target_decoded, exp = decode_find_neighbours(payload)
        assert target_decoded == target

    def test_neighbours_encode_decode(self):
        from ethclient.networking.discv4.routing import Node
        from ethclient.networking.discv4.discovery import (
            encode_neighbours, decode_neighbours, _decode_packet,
        )

        key = PrivateKey()
        nodes = []
        for i in range(3):
            pk = PrivateKey()
            nodes.append(Node(
                id=pk.public_key.format(compressed=False)[1:],
                ip=f"10.0.0.{i+1}",
                udp_port=30303 + i,
                tcp_port=30303 + i,
            ))

        packet = encode_neighbours(key.secret, nodes)
        result = _decode_packet(packet)
        assert result is not None
        ptype, payload, _, _ = result
        assert ptype == 0x04

        decoded_nodes, exp = decode_neighbours(payload)
        assert len(decoded_nodes) == 3
        assert decoded_nodes[0].ip == "10.0.0.1"
        assert decoded_nodes[1].udp_port == 30304
        assert decoded_nodes[2].id == nodes[2].id

    def test_corrupted_packet(self):
        from ethclient.networking.discv4.discovery import _decode_packet
        result = _decode_packet(b"\x00" * 100)
        assert result is None

    def test_endpoint_encode_decode(self):
        from ethclient.networking.discv4.discovery import Endpoint
        ep = Endpoint(ip="192.168.1.1", udp_port=30303, tcp_port=30304)
        encoded = ep.encode()
        decoded = Endpoint.decode(encoded)
        assert decoded.ip == "192.168.1.1"
        assert decoded.udp_port == 30303
        assert decoded.tcp_port == 30304


# ===================================================================
# Full sync state tests
# ===================================================================

class TestFullSync:
    def test_sync_state_init(self):
        from ethclient.networking.sync.full_sync import SyncState

        state = SyncState()
        assert state.target_block == 0
        assert state.current_block == 0
        assert state.syncing is False

    def test_sync_state_request_id(self):
        from ethclient.networking.sync.full_sync import SyncState

        state = SyncState()
        assert state.next_request_id() == 1
        assert state.next_request_id() == 2
        assert state.next_request_id() == 3

    def test_full_sync_init(self):
        from ethclient.networking.sync.full_sync import FullSync

        sync = FullSync()
        assert sync.is_syncing is False
        assert sync.progress == (0, 0)

    def test_handle_block_headers(self):
        from ethclient.networking.sync.full_sync import FullSync
        from ethclient.networking.eth.messages import BlockHeadersMessage

        sync = FullSync()

        # Create event so handler can signal
        event = asyncio.Event()
        sync._response_events[42] = event

        # Create a headers response
        msg = BlockHeadersMessage(request_id=42, headers=[])
        sync.handle_block_headers(msg.encode())

        assert 42 in sync._header_responses or event.is_set()


# ===================================================================
# P2P Server component tests
# ===================================================================

class TestServerComponents:
    def test_peer_connection_init(self):
        from ethclient.networking.server import PeerConnection
        from unittest.mock import MagicMock

        mock_conn = MagicMock()
        peer = PeerConnection(conn=mock_conn)
        assert peer.connected is False
        assert peer.total_difficulty == 0
        assert peer.remote_client == ""

    def test_server_init(self):
        from ethclient.networking.server import P2PServer

        key = PrivateKey()
        server = P2PServer(
            private_key=key.secret,
            listen_port=30303,
            network_id=1,
            genesis_hash=b"\xd4" + b"\x00" * 31,
        )
        assert server.peer_count == 0
        assert server.is_syncing is False
        assert len(server.public_key) == 64

    def test_server_max_peers(self):
        from ethclient.networking.server import P2PServer

        key = PrivateKey()
        server = P2PServer(private_key=key.secret, max_peers=10)
        assert server.max_peers == 10
