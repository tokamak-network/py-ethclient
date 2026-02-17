"""
devp2p base protocol and eth/68 sub-protocol.

p2p base messages: Hello (0x00), Disconnect (0x01), Ping (0x02), Pong (0x03)
eth messages: Status (0x10), GetBlockHeaders (0x13), BlockHeaders (0x14), etc.
"""

from __future__ import annotations

from enum import IntEnum


# ---------------------------------------------------------------------------
# p2p base protocol message codes
# ---------------------------------------------------------------------------

class P2PMsg(IntEnum):
    HELLO = 0x00
    DISCONNECT = 0x01
    PING = 0x02
    PONG = 0x03


# ---------------------------------------------------------------------------
# eth sub-protocol message codes (offset = 0x10)
# ---------------------------------------------------------------------------

ETH_OFFSET = 0x10


class EthMsg(IntEnum):
    STATUS = ETH_OFFSET + 0             # 0x10
    NEW_BLOCK_HASHES = ETH_OFFSET + 1   # 0x11
    TRANSACTIONS = ETH_OFFSET + 2       # 0x12
    GET_BLOCK_HEADERS = ETH_OFFSET + 3  # 0x13
    BLOCK_HEADERS = ETH_OFFSET + 4      # 0x14
    GET_BLOCK_BODIES = ETH_OFFSET + 5   # 0x15
    BLOCK_BODIES = ETH_OFFSET + 6       # 0x16
    NEW_BLOCK = ETH_OFFSET + 7          # 0x17
    NEW_POOLED_TX_HASHES = ETH_OFFSET + 8  # 0x18 (eth/68)
    GET_POOLED_TXS = ETH_OFFSET + 9    # 0x19
    POOLED_TXS = ETH_OFFSET + 10       # 0x1a
    GET_RECEIPTS = ETH_OFFSET + 15      # 0x1f
    RECEIPTS = ETH_OFFSET + 16          # 0x20


# ---------------------------------------------------------------------------
# Disconnect reasons
# ---------------------------------------------------------------------------

class DisconnectReason(IntEnum):
    REQUESTED = 0x00
    TCP_ERROR = 0x01
    PROTOCOL_ERROR = 0x02
    USELESS_PEER = 0x03
    TOO_MANY_PEERS = 0x04
    ALREADY_CONNECTED = 0x05
    INCOMPATIBLE_VERSION = 0x06
    NULL_IDENTITY = 0x07
    CLIENT_QUIT = 0x08
    UNEXPECTED_IDENTITY = 0x09
    CONNECTED_TO_SELF = 0x0A
    TIMEOUT = 0x0B
    SUBPROTOCOL_ERROR = 0x10


# ---------------------------------------------------------------------------
# Protocol version constants
# ---------------------------------------------------------------------------

P2P_VERSION = 5
ETH_VERSION = 68
CLIENT_NAME = "py-ethclient/0.1.0"
