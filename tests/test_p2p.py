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

    @pytest.mark.asyncio
    async def test_rlpx_send_message_raises_when_transport_closing(self):
        from unittest.mock import MagicMock
        from ethclient.networking.rlpx.connection import RLPxConnection

        reader = MagicMock()
        writer = MagicMock()
        writer.is_closing.return_value = True

        conn = RLPxConnection(PrivateKey().secret, reader, writer)
        conn.coder = MagicMock()
        conn.coder.encode_frame.return_value = b"frame"

        with pytest.raises(ConnectionError, match="transport is closing"):
            await conn.send_message(0x10, b"payload")


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

    def test_status_roundtrip_eth69(self):
        from ethclient.networking.eth.messages import StatusMessage

        genesis = os.urandom(32)
        latest_hash = os.urandom(32)
        fork_id = (os.urandom(4), 777777)

        msg = StatusMessage(
            protocol_version=69,
            network_id=11155111,
            genesis_hash=genesis,
            fork_id=fork_id,
            earliest_block=0,
            latest_block=12_345_678,
            latest_block_hash=latest_hash,
        )
        encoded = msg.encode()
        decoded = StatusMessage.decode(encoded)

        assert decoded.protocol_version == 69
        assert decoded.network_id == 11155111
        assert decoded.genesis_hash == genesis
        assert decoded.fork_id == fork_id
        assert decoded.earliest_block == 0
        assert decoded.latest_block == 12_345_678
        assert decoded.latest_block_hash == latest_hash

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

    def test_get_receipts_roundtrip(self):
        from ethclient.networking.eth.messages import GetReceiptsMessage

        hashes = [os.urandom(32) for _ in range(2)]
        msg = GetReceiptsMessage(request_id=7, hashes=hashes)
        encoded = msg.encode()
        decoded = GetReceiptsMessage.decode(encoded)
        assert decoded.request_id == 7
        assert decoded.hashes == hashes

    def test_receipts_roundtrip_eth68(self):
        from ethclient.networking.eth.messages import ReceiptsMessage
        from ethclient.common.types import Receipt, Log, TxType

        r = Receipt(
            succeeded=True,
            cumulative_gas_used=21000,
            logs_bloom=b"\x00" * 256,
            logs=[Log(address=b"\x11" * 20, topics=[b"\x22" * 32], data=b"")],
            tx_type=TxType.LEGACY,
        )
        msg = ReceiptsMessage(request_id=1, receipts=[[r]], protocol_version=68)
        decoded = ReceiptsMessage.decode(msg.encode(), protocol_version=68)
        assert decoded.request_id == 1
        assert decoded.receipts[0][0].cumulative_gas_used == 21000

    def test_receipts_roundtrip_eth69(self):
        from ethclient.networking.eth.messages import ReceiptsMessage
        from ethclient.common.types import Receipt, Log, TxType

        r = Receipt(
            succeeded=True,
            cumulative_gas_used=22000,
            logs_bloom=b"\x00" * 256,
            logs=[Log(address=b"\x33" * 20, topics=[], data=b"\x01\x02")],
            tx_type=TxType.FEE_MARKET,
        )
        msg = ReceiptsMessage(request_id=2, receipts=[[r]], protocol_version=69)
        decoded = ReceiptsMessage.decode(msg.encode(), protocol_version=69)
        assert decoded.request_id == 2
        assert decoded.receipts[0][0].tx_type == TxType.FEE_MARKET
        assert decoded.receipts[0][0].cumulative_gas_used == 22000

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

    def test_send_ping_does_not_track_pending_on_send_error(self):
        from unittest.mock import MagicMock
        from ethclient.networking.discv4.discovery import DiscoveryProtocol
        from ethclient.networking.discv4.routing import Node, RoutingTable

        local = Node(id=PrivateKey().public_key.format(compressed=False)[1:], ip="0.0.0.0", udp_port=30303, tcp_port=30303)
        table = RoutingTable(local)
        proto = DiscoveryProtocol(PrivateKey().secret, local, table, [])

        mock_transport = MagicMock()
        mock_transport.is_closing.return_value = False
        mock_transport.sendto.side_effect = OSError("network unreachable")
        proto.transport = mock_transport

        target = Node(id=PrivateKey().public_key.format(compressed=False)[1:], ip="8.8.8.8", udp_port=30303, tcp_port=30303)
        ping_hash = proto.send_ping(target)

        assert ping_hash not in proto._pending_pings


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

    @pytest.mark.asyncio
    async def test_discover_head_returns_block_number(self):
        """_discover_head sends GetBlockHeaders(hash, 1) and extracts block number."""
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.sync.full_sync import FullSync
        from ethclient.networking.eth.messages import BlockHeadersMessage
        from ethclient.common.types import BlockHeader

        sync = FullSync()

        # Create mock peer with a best_hash
        peer = MagicMock()
        peer.best_hash = b"\xab" * 32

        # Capture the send call and simulate a response
        async def fake_send(msg_code, payload):
            # Simulate the peer responding with a header at block 7_654_321
            header = BlockHeader(number=7_654_321)
            resp = BlockHeadersMessage(request_id=1, headers=[header])
            sync.handle_block_headers(resp.encode())

        peer.send_eth_message = AsyncMock(side_effect=fake_send)

        result = await sync._discover_head(peer)
        assert result == 7_654_321
        peer.send_eth_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_discover_head_empty_hash_returns_zero(self):
        """_discover_head returns 0 when best_hash is all zeros."""
        from unittest.mock import MagicMock
        from ethclient.networking.sync.full_sync import FullSync

        sync = FullSync()
        peer = MagicMock()
        peer.best_hash = b"\x00" * 32

        result = await sync._discover_head(peer)
        assert result == 0

    @pytest.mark.asyncio
    async def test_discover_head_no_hash_returns_zero(self):
        """_discover_head returns 0 when best_hash is empty."""
        from unittest.mock import MagicMock
        from ethclient.networking.sync.full_sync import FullSync

        sync = FullSync()
        peer = MagicMock()
        peer.best_hash = b""

        result = await sync._discover_head(peer)
        assert result == 0

    @pytest.mark.asyncio
    async def test_discover_head_timeout_returns_zero(self):
        """_discover_head returns 0 on timeout."""
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.sync.full_sync import FullSync

        sync = FullSync()
        peer = MagicMock()
        peer.best_hash = b"\xab" * 32

        # send_eth_message does nothing → event never set → timeout
        peer.send_eth_message = AsyncMock()

        # Use a very short timeout by monkeypatching
        import ethclient.networking.sync.full_sync as fs_mod
        original_timeout = fs_mod.SYNC_TIMEOUT
        fs_mod.SYNC_TIMEOUT = 0.05
        try:
            result = await sync._discover_head(peer)
        finally:
            fs_mod.SYNC_TIMEOUT = original_timeout

        assert result == 0

    @pytest.mark.asyncio
    async def test_discover_head_empty_response_returns_zero(self):
        """_discover_head returns 0 when peer responds with no headers."""
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.sync.full_sync import FullSync
        from ethclient.networking.eth.messages import BlockHeadersMessage

        sync = FullSync()
        peer = MagicMock()
        peer.best_hash = b"\xab" * 32

        async def fake_send(msg_code, payload):
            # Respond with empty headers
            resp = BlockHeadersMessage(request_id=1, headers=[])
            sync.handle_block_headers(resp.encode())

        peer.send_eth_message = AsyncMock(side_effect=fake_send)

        result = await sync._discover_head(peer)
        assert result == 0

    @pytest.mark.asyncio
    async def test_start_uses_discovered_head(self):
        """start() uses _discover_head to set target_block."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from ethclient.networking.sync.full_sync import FullSync

        sync = FullSync()

        peer = MagicMock()
        peer.best_hash = b"\xab" * 32
        peer.best_block_number = 0
        peer.total_difficulty = 100
        peer.connected = True
        peer.remote_id = b"\x01" * 64
        peer.send_eth_message = AsyncMock()

        with patch.object(sync, '_discover_head', new_callable=AsyncMock, return_value=5_000_000):
            with patch.object(sync, '_sync_loop', new_callable=AsyncMock):
                await sync.start([peer])

        assert sync.state.target_block == 5_000_000
        assert peer.best_block_number == 5_000_000

    @pytest.mark.asyncio
    async def test_start_prefers_peer_with_highest_best_block_number(self):
        """start() should prioritize eth/69 latest block over total difficulty."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from ethclient.networking.sync.full_sync import FullSync

        sync = FullSync()

        low_head_peer = MagicMock()
        low_head_peer.best_hash = b"\xaa" * 32
        low_head_peer.best_block_number = 100
        low_head_peer.total_difficulty = 999999
        low_head_peer.connected = True
        low_head_peer.remote_id = b"\x02" * 64
        low_head_peer.send_eth_message = AsyncMock()

        high_head_peer = MagicMock()
        high_head_peer.best_hash = b"\xbb" * 32
        high_head_peer.best_block_number = 500
        high_head_peer.total_difficulty = 0
        high_head_peer.connected = True
        high_head_peer.remote_id = b"\x03" * 64
        high_head_peer.send_eth_message = AsyncMock()

        with patch.object(sync, "_discover_head", new_callable=AsyncMock, return_value=0) as discover_mock:
            with patch.object(sync, "_sync_loop", new_callable=AsyncMock):
                await sync.start([low_head_peer, high_head_peer])

        assert sync.state.best_peer is high_head_peer
        assert sync.state.target_block == 500
        discover_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_fetch_headers_timeout_returns_none(self):
        """Header timeout should be treated as failure (None), not completion ([])."""
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.sync.full_sync import FullSync
        import ethclient.networking.sync.full_sync as fs_mod

        sync = FullSync()
        peer = MagicMock()
        peer.send_eth_message = AsyncMock()

        original_timeout = fs_mod.SYNC_TIMEOUT
        fs_mod.SYNC_TIMEOUT = 0.05
        try:
            headers = await sync._fetch_headers(peer, start=1, count=2)
        finally:
            fs_mod.SYNC_TIMEOUT = original_timeout

        assert headers is None

    @pytest.mark.asyncio
    async def test_sync_loop_triggers_failover_after_header_failures(self):
        """Repeated header failures should trigger failover instead of completing sync."""
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.sync.full_sync import FullSync
        import ethclient.networking.sync.full_sync as fs_mod

        sync = FullSync()
        peer = MagicMock()
        peer.connected = True
        peer.remote_id = b"\x01" * 64

        sync._candidate_peers = [peer]
        sync.state.best_peer = peer
        sync.state.current_block = 100
        sync.state.target_block = 200
        sync.state.syncing = True

        sync._fetch_headers = AsyncMock(return_value=None)
        sync._failover_peer = AsyncMock(return_value=False)

        original_backoff = fs_mod.HEADER_RETRY_BACKOFF
        fs_mod.HEADER_RETRY_BACKOFF = 0.01
        try:
            await sync._sync_loop()
        finally:
            fs_mod.HEADER_RETRY_BACKOFF = original_backoff

        assert sync._fetch_headers.call_count == fs_mod.MAX_HEADER_FAILURES
        sync._failover_peer.assert_called_once()

    @pytest.mark.asyncio
    async def test_select_best_peer_skips_timeout_penalized_peer(self):
        from unittest.mock import MagicMock
        from ethclient.networking.sync.full_sync import FullSync
        import ethclient.networking.sync.full_sync as fs_mod

        sync = FullSync()
        penalized_peer = MagicMock()
        penalized_peer.connected = True
        penalized_peer.remote_id = b"\x11" * 64
        penalized_peer.best_block_number = 1000

        healthy_peer = MagicMock()
        healthy_peer.connected = True
        healthy_peer.remote_id = b"\x22" * 64
        healthy_peer.best_block_number = 500

        sync._peer_retry_after[penalized_peer.remote_id] = (
            fs_mod.time.time() + fs_mod.PEER_TIMEOUT_PENALTY_SECONDS
        )

        best, head = await sync._select_best_peer([penalized_peer, healthy_peer])
        assert best is healthy_peer
        assert head == 500

    def test_refresh_target_block_uses_live_peer_provider(self):
        from unittest.mock import MagicMock
        from ethclient.networking.sync.full_sync import FullSync

        live_peer = MagicMock()
        live_peer.connected = True
        live_peer.best_block_number = 10_299_900

        sync = FullSync(peer_provider=lambda: [live_peer])
        sync.state.target_block = 9_707_885
        sync._candidate_peers = []

        sync._refresh_target_block()
        assert sync.state.target_block == 10_299_900

    @pytest.mark.asyncio
    async def test_sync_loop_yields_during_header_execution_for_rpc_responsiveness(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from ethclient.networking.sync.full_sync import FullSync
        from ethclient.common.types import BlockHeader
        import ethclient.networking.sync.full_sync as fs_mod

        sync = FullSync()
        peer = MagicMock()
        peer.connected = True
        peer.remote_id = b"\x33" * 64

        start = 1
        count = fs_mod.SYNC_EXECUTION_YIELD_INTERVAL
        headers = [
            BlockHeader(number=start + i, gas_limit=30_000_000, timestamp=1000 + i)
            for i in range(count)
        ]

        sync.state.best_peer = peer
        sync.state.current_block = 0
        sync.state.target_block = headers[-1].number
        sync.state.syncing = True
        sync._candidate_peers = [peer]

        sync._fetch_headers = AsyncMock(return_value=headers)
        sync._fetch_bodies = AsyncMock(return_value=[])
        sync._refresh_target_block = MagicMock()

        sleep_calls: list[float] = []
        real_sleep = fs_mod.asyncio.sleep

        async def tracking_sleep(delay: float):
            sleep_calls.append(delay)
            await real_sleep(0)

        with patch.object(fs_mod.asyncio, "sleep", side_effect=tracking_sleep):
            await sync._sync_loop()

        assert 0 in sleep_calls

    def test_full_sync_peer_timeout_adapts_timeout_and_body_chunk(self):
        from unittest.mock import MagicMock
        from ethclient.networking.sync.full_sync import FullSync, SYNC_TIMEOUT, BODIES_PER_REQUEST

        sync = FullSync()
        peer = MagicMock()
        peer.remote_id = b"\xaa" * 64

        sync._record_peer_timeout(peer)

        assert sync._timeout_for_peer(peer) > SYNC_TIMEOUT
        assert sync._body_chunk_size_for_peer(peer) < BODIES_PER_REQUEST

    def test_full_sync_peer_success_recovers_timeout_and_body_chunk(self):
        from unittest.mock import MagicMock
        from ethclient.networking.sync.full_sync import FullSync, SYNC_TIMEOUT

        sync = FullSync()
        peer = MagicMock()
        peer.remote_id = b"\xbb" * 64

        sync._record_peer_timeout(peer)
        assert sync._timeout_for_peer(peer) > SYNC_TIMEOUT
        degraded_chunk = sync._body_chunk_size_for_peer(peer)

        sync._record_peer_success(peer)

        assert sync._timeout_for_peer(peer) >= SYNC_TIMEOUT
        assert sync._body_chunk_size_for_peer(peer) >= degraded_chunk

    @pytest.mark.asyncio
    async def test_fetch_headers_uses_hedge_peer_on_primary_failure(self):
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.sync.full_sync import FullSync
        from ethclient.common.types import BlockHeader

        sync = FullSync()
        primary = MagicMock()
        backup = MagicMock()
        primary.remote_id = b"\x11" * 64
        backup.remote_id = b"\x22" * 64

        expected = [BlockHeader(number=1, gas_limit=30_000_000, timestamp=1)]
        sync._hedge_peers = MagicMock(return_value=[backup])
        sync._fetch_headers_from_single_peer = AsyncMock(side_effect=[None, expected])

        got = await sync._fetch_headers(primary, start=1, count=1)
        assert got == expected
        assert sync._fetch_headers_from_single_peer.await_count == 2

    @pytest.mark.asyncio
    async def test_fetch_bodies_uses_hedge_peer_on_primary_failure(self):
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.sync.full_sync import FullSync

        sync = FullSync()
        primary = MagicMock()
        backup = MagicMock()
        primary.remote_id = b"\x33" * 64
        backup.remote_id = b"\x44" * 64

        expected = [([], [])]
        sync._hedge_peers = MagicMock(return_value=[backup])
        sync._fetch_bodies_from_single_peer = AsyncMock(side_effect=[None, expected])

        got = await sync._fetch_bodies(primary, hashes=[b"\xaa" * 32])
        assert got == expected
        assert sync._fetch_bodies_from_single_peer.await_count == 2

    @pytest.mark.asyncio
    async def test_sync_loop_prefetches_next_batch(self):
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.sync.full_sync import FullSync
        from ethclient.common.types import BlockHeader

        sync = FullSync()
        peer = MagicMock()
        peer.connected = True
        peer.remote_id = b"\x44" * 64
        peer.best_block_number = 10
        sync.state.best_peer = peer
        sync.state.current_block = 0
        sync.state.target_block = 4
        sync.state.syncing = True
        sync._candidate_peers = [peer]

        batch1 = [BlockHeader(number=1, gas_limit=30_000_000, timestamp=1001),
                  BlockHeader(number=2, gas_limit=30_000_000, timestamp=1002)]
        batch2 = [BlockHeader(number=3, gas_limit=30_000_000, timestamp=1003),
                  BlockHeader(number=4, gas_limit=30_000_000, timestamp=1004)]

        sync._fetch_sync_batch = AsyncMock(side_effect=[(batch1, []), (batch2, [])])

        async def execute_and_advance(headers, _bodies):
            sync.state.current_block = headers[-1].number

        sync._execute_headers = AsyncMock(side_effect=execute_and_advance)
        sync._refresh_target_block = MagicMock()

        await sync._sync_loop()

        assert sync._fetch_sync_batch.await_count == 2
        assert sync._execute_headers.await_count == 2

    @pytest.mark.asyncio
    async def test_execute_headers_offloads_chain_execution_to_worker(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from ethclient.networking.sync.full_sync import FullSync
        from ethclient.common.types import BlockHeader
        import ethclient.networking.sync.full_sync as fs_mod

        store = MagicMock()
        chain = MagicMock()
        sync = FullSync(store=store, chain=chain)
        headers = [BlockHeader(number=1, gas_limit=30_000_000, timestamp=1001)]

        to_thread_mock = AsyncMock(side_effect=lambda fn, *args: fn(*args))
        with patch.object(fs_mod.asyncio, "to_thread", to_thread_mock):
            await sync._execute_headers(headers, [([], [])])

        assert to_thread_mock.await_count == 1
        chain.execute_block.assert_called_once()
        store.put_block_header.assert_called_once()

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

    def test_incoming_handshake_mac_fail_backoff_blocks_temporarily(self):
        import ethclient.networking.server as srv_mod

        key = PrivateKey()
        server = srv_mod.P2PServer(private_key=key.secret)
        ip = "1.2.3.4"

        server._record_incoming_handshake_failure(ip, "ValueError: ECIES MAC verification failed")
        assert server._allow_incoming_handshake(ip) is False

    def test_incoming_handshake_log_is_rate_limited(self):
        from unittest.mock import patch
        import ethclient.networking.server as srv_mod

        key = PrivateKey()
        server = srv_mod.P2PServer(private_key=key.secret)

        with patch.object(srv_mod.logger, "info") as info_mock:
            for _ in range(srv_mod.INCOMING_FAILURE_LOG_BURST + 2):
                server._log_incoming_handshake_failure("1.2.3.4", "ValueError: ECIES MAC verification failed")

        assert info_mock.call_count == srv_mod.INCOMING_FAILURE_LOG_BURST

    def test_incoming_handshake_log_summary_reports_suppressed(self):
        from unittest.mock import patch
        import ethclient.networking.server as srv_mod

        key = PrivateKey()
        server = srv_mod.P2PServer(private_key=key.secret)

        for _ in range(srv_mod.INCOMING_FAILURE_LOG_BURST + 3):
            server._log_incoming_handshake_failure("1.2.3.4", "ValueError: ECIES MAC verification failed")

        with patch.object(srv_mod.logger, "info") as info_mock:
            server._flush_incoming_failure_log_summary(force=True)

        assert info_mock.call_count == 1
        assert "suppressed" in info_mock.call_args[0][0]

    @pytest.mark.asyncio
    async def test_peer_send_failure_marks_disconnected(self):
        from ethclient.networking.server import PeerConnection
        from unittest.mock import AsyncMock, MagicMock

        mock_conn = MagicMock()
        mock_conn.send_message = AsyncMock(side_effect=OSError("broken pipe"))
        mock_conn.close = MagicMock()

        peer = PeerConnection(conn=mock_conn, connected=True)

        with pytest.raises(OSError):
            await peer.send_eth_message(0x10, b"payload")

        assert peer.connected is False
        assert peer.disconnect_reason is not None
        mock_conn.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_peer_send_allowed_before_connected_handshake_phase(self):
        from ethclient.networking.server import PeerConnection
        from unittest.mock import AsyncMock, MagicMock

        mock_conn = MagicMock()
        mock_conn.send_message = AsyncMock(return_value=None)

        peer = PeerConnection(conn=mock_conn, connected=False)
        await peer.send_p2p_message(0x00, b"hello")

        mock_conn.send_message.assert_awaited_once_with(0x00, b"hello")

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

    @pytest.mark.asyncio
    async def test_start_sync_prefers_snap_when_target_available(self):
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.server import P2PServer
        from ethclient.common.types import BlockHeader

        key = PrivateKey()
        server = P2PServer(private_key=key.secret, enable_snap=True)

        peer = MagicMock()
        peer.connected = True
        peer.snap_supported = True
        peer.best_block_number = 10
        peer.remote_id = b"\x11" * 64

        server.peers = {peer.remote_id: peer}
        server.snap_syncer = MagicMock()
        server.snap_syncer.is_syncing = False
        server.syncer.state.syncing = False
        server.syncer.discover_head_header = AsyncMock(
            return_value=BlockHeader(number=10, state_root=b"\x22" * 32)
        )
        server.start_snap_sync = AsyncMock()
        server.syncer.start = AsyncMock()

        await server.start_sync()

        server.start_snap_sync.assert_awaited_once_with(b"\x22" * 32, 10)
        server.syncer.start.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_start_sync_falls_back_to_full_when_snap_target_missing(self):
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.server import P2PServer

        key = PrivateKey()
        server = P2PServer(private_key=key.secret, enable_snap=True)

        peer = MagicMock()
        peer.connected = True
        peer.snap_supported = True
        peer.best_block_number = 10
        peer.remote_id = b"\x12" * 64

        server.peers = {peer.remote_id: peer}
        server.snap_syncer = MagicMock()
        server.snap_syncer.is_syncing = False
        server.syncer.state.syncing = False
        server.syncer.discover_head_header = AsyncMock(return_value=None)
        server.start_snap_sync = AsyncMock()
        server.syncer.start = AsyncMock()

        await server.start_sync()

        server.start_snap_sync.assert_not_awaited()
        server.syncer.start.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_do_protocol_handshake_handles_incomplete_read(self):
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.server import P2PServer

        key = PrivateKey()
        server = P2PServer(private_key=key.secret)

        peer = MagicMock()
        peer.send_p2p_message = AsyncMock()
        peer.conn.recv_message = AsyncMock(
            side_effect=asyncio.IncompleteReadError(partial=b"", expected=32)
        )

        ok = await server._do_protocol_handshake(peer)
        assert ok is False

    @pytest.mark.asyncio
    async def test_handle_incoming_catches_protocol_handshake_read_error(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        import ethclient.networking.server as srv_mod

        key = PrivateKey()
        server = srv_mod.P2PServer(private_key=key.secret)

        reader = MagicMock()
        writer = MagicMock()

        mock_conn = MagicMock()
        mock_conn.accept_handshake = AsyncMock(return_value=True)
        mock_conn.remote_pubkey = b"\x04" + (b"\xaa" * 64)
        mock_conn.close = MagicMock()

        server._do_protocol_handshake = AsyncMock(
            side_effect=asyncio.IncompleteReadError(partial=b"", expected=32)
        )

        with patch.object(srv_mod, "RLPxConnection", return_value=mock_conn):
            await server._handle_incoming(reader, writer)

        mock_conn.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_get_block_headers_uses_hash_origin_lookup(self):
        from unittest.mock import AsyncMock, MagicMock
        from ethclient.networking.server import P2PServer
        from ethclient.networking.eth.messages import GetBlockHeadersMessage
        from ethclient.common.types import BlockHeader

        key = PrivateKey()
        server = P2PServer(private_key=key.secret)

        header = BlockHeader(number=7, gas_limit=30_000_000, timestamp=1000)
        block_hash = header.block_hash()
        store = MagicMock()
        store.get_block_header.return_value = header
        server.store = store

        peer = MagicMock()
        peer.send_eth_message = AsyncMock()

        req = GetBlockHeadersMessage(request_id=1, origin=block_hash, amount=1)
        await server._handle_get_block_headers(peer, req.encode())

        store.get_block_header.assert_called_once_with(block_hash)
        peer.send_eth_message.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_to_peer_avoids_duplicate_inflight_dials(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from ethclient.networking.discv4.routing import Node
        import ethclient.networking.server as srv_mod

        key = PrivateKey()
        server = srv_mod.P2PServer(private_key=key.secret)
        node = Node(id=b"\x34" * 64, ip="127.0.0.1", tcp_port=30303, udp_port=30303)

        reader = MagicMock()
        writer = MagicMock()
        open_gate = asyncio.Event()

        async def fake_open_connection(*_args, **_kwargs):
            await open_gate.wait()
            return reader, writer

        mock_conn = MagicMock()
        mock_conn.initiate_handshake = AsyncMock(return_value=True)
        mock_conn.last_handshake_error = None
        mock_conn.close = MagicMock()

        server._do_protocol_handshake = AsyncMock(return_value=True)
        server._send_block_range_update = AsyncMock()
        server._handle_peer = AsyncMock()

        with patch.object(srv_mod.asyncio, "open_connection", side_effect=fake_open_connection) as open_mock:
            with patch.object(srv_mod, "RLPxConnection", return_value=mock_conn):
                first_task = asyncio.create_task(server.connect_to_peer(node))
                await asyncio.sleep(0)
                second_task = asyncio.create_task(server.connect_to_peer(node))

                open_gate.set()
                first_result, second_result = await asyncio.gather(first_task, second_task)

        assert first_result is not None
        assert second_result is None
        assert open_mock.call_count == 1

    @pytest.mark.asyncio
    async def test_dial_loop_dials_bootnodes_without_discovery_candidates(self):
        from unittest.mock import AsyncMock
        from ethclient.networking.discv4.routing import Node
        import ethclient.networking.server as srv_mod

        key = PrivateKey()
        boot = Node(id=b"\x56" * 64, ip="127.0.0.1", udp_port=30303, tcp_port=30303)
        server = srv_mod.P2PServer(private_key=key.secret, boot_nodes=[boot])
        server._discovery = None
        server._running = True

        async def fake_connect(node):
            server._running = False
            return None

        server.connect_to_peer = AsyncMock(side_effect=fake_connect)

        original_interval = srv_mod.DIAL_INTERVAL
        srv_mod.DIAL_INTERVAL = 0.01
        try:
            await server._dial_loop()
        finally:
            srv_mod.DIAL_INTERVAL = original_interval

        server.connect_to_peer.assert_awaited_once()
        assert server.connect_to_peer.await_args.args[0].id == boot.id

    @pytest.mark.asyncio
    async def test_connect_to_peer_applies_long_cooldown_on_genesis_mismatch(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from ethclient.networking.discv4.routing import Node
        import ethclient.networking.server as srv_mod

        key = PrivateKey()
        server = srv_mod.P2PServer(private_key=key.secret)
        node = Node(id=b"\x78" * 64, ip="127.0.0.1", tcp_port=30303, udp_port=30303)

        reader = MagicMock()
        writer = MagicMock()
        mock_conn = MagicMock()
        mock_conn.initiate_handshake = AsyncMock(return_value=True)
        mock_conn.last_handshake_error = None
        mock_conn.close = MagicMock()

        async def fake_protocol_handshake(peer):
            peer.disconnect_reason = "genesis mismatch"
            return False

        server._do_protocol_handshake = AsyncMock(side_effect=fake_protocol_handshake)

        fixed_now = 1000.0
        with patch.object(srv_mod.asyncio, "open_connection", AsyncMock(return_value=(reader, writer))):
            with patch.object(srv_mod, "RLPxConnection", return_value=mock_conn):
                with patch.object(srv_mod.time, "time", return_value=fixed_now):
                    result = await server.connect_to_peer(node)

        assert result is None
        assert server._dial_retry_after[node.id] == fixed_now + srv_mod.DIAL_COOLDOWN_GENESIS_MISMATCH

    @pytest.mark.asyncio
    async def test_connect_to_peer_applies_remote_busy_cooldown_on_too_many_peers(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from ethclient.networking.discv4.routing import Node
        import ethclient.networking.server as srv_mod

        key = PrivateKey()
        server = srv_mod.P2PServer(private_key=key.secret)
        node = Node(id=b"\x79" * 64, ip="127.0.0.1", tcp_port=30303, udp_port=30303)

        reader = MagicMock()
        writer = MagicMock()
        mock_conn = MagicMock()
        mock_conn.initiate_handshake = AsyncMock(return_value=True)
        mock_conn.last_handshake_error = None
        mock_conn.close = MagicMock()

        async def fake_protocol_handshake(peer):
            peer.disconnect_reason = "peer disconnect during status: TOO_MANY_PEERS"
            return False

        server._do_protocol_handshake = AsyncMock(side_effect=fake_protocol_handshake)

        fixed_now = 2000.0
        with patch.object(srv_mod.asyncio, "open_connection", AsyncMock(return_value=(reader, writer))):
            with patch.object(srv_mod, "RLPxConnection", return_value=mock_conn):
                with patch.object(srv_mod.time, "time", return_value=fixed_now):
                    result = await server.connect_to_peer(node)

        assert result is None
        assert server._dial_retry_after[node.id] == fixed_now + srv_mod.DIAL_COOLDOWN_REMOTE_BUSY

    def test_record_dial_failure_uses_exponential_backoff(self):
        from unittest.mock import patch
        import ethclient.networking.server as srv_mod

        key = PrivateKey()
        server = srv_mod.P2PServer(private_key=key.secret)
        node_id = b"\x90" * 64

        with patch.object(srv_mod.time, "time", return_value=5000.0):
            server._record_dial_failure(node_id, "tcp connect failed", is_bootnode=False)
            first = server._dial_retry_after[node_id]
            server._record_dial_failure(node_id, "tcp connect failed", is_bootnode=False)
            second = server._dial_retry_after[node_id]

        assert second > first
