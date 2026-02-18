"""
snap/1 sub-protocol message codes.

Unlike EthMsg which embeds the offset (0x10+), SnapMsg uses relative codes (0-7).
The absolute wire code is computed at runtime by the protocol registry.
"""

from __future__ import annotations

from enum import IntEnum


SNAP_VERSION = 1


class SnapMsg(IntEnum):
    GET_ACCOUNT_RANGE = 0
    ACCOUNT_RANGE = 1
    GET_STORAGE_RANGES = 2
    STORAGE_RANGES = 3
    GET_BYTE_CODES = 4
    BYTE_CODES = 5
    GET_TRIE_NODES = 6
    TRIE_NODES = 7
