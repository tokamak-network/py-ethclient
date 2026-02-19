"""
RLP (Recursive Length Prefix) encoding and decoding.

Implements the Ethereum RLP serialization format as specified in:
https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/

RLP encodes two types of items:
- Byte strings (bytes)
- Lists of items (which can contain byte strings or nested lists)
"""

from __future__ import annotations

from typing import Union

# RLP item: either raw bytes or a list of RLP items
RLPItem = Union[bytes, list["RLPItem"]]


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def encode(item: RLPItem | int | str | bool) -> bytes:
    """Encode a Python object into RLP bytes.

    Accepted types:
    - bytes: encoded directly
    - int: converted to big-endian bytes (0 encodes as b'')
    - str: UTF-8 encoded then treated as bytes
    - bool: True -> b'\\x01', False -> b''
    - list/tuple: each element is recursively encoded
    """
    if isinstance(item, bool):
        return encode(b"\x01" if item else b"")
    if isinstance(item, int):
        if item < 0:
            raise ValueError("RLP cannot encode negative integers")
        if item == 0:
            return encode(b"")
        return encode(item.to_bytes((item.bit_length() + 7) // 8, "big"))
    if isinstance(item, str):
        return encode(item.encode("utf-8"))
    if isinstance(item, (bytes, bytearray, memoryview)):
        return _encode_bytes(bytes(item))
    if isinstance(item, (list, tuple)):
        return _encode_list(item)
    raise TypeError(f"Cannot RLP-encode type {type(item).__name__}")


def _encode_bytes(data: bytes) -> bytes:
    length = len(data)
    if length == 1 and data[0] < 0x80:
        # Single byte in [0x00, 0x7f]: encoded as itself
        return data
    if length <= 55:
        return bytes([0x80 + length]) + data
    # Long string
    len_bytes = _encode_length(length)
    return bytes([0xb7 + len(len_bytes)]) + len_bytes + data


def _encode_list(items: list | tuple) -> bytes:
    payload = b"".join(encode(item) for item in items)
    length = len(payload)
    if length <= 55:
        return bytes([0xc0 + length]) + payload
    len_bytes = _encode_length(length)
    return bytes([0xf7 + len(len_bytes)]) + len_bytes + payload


def _encode_length(length: int) -> bytes:
    """Encode a length as big-endian bytes with no leading zeros."""
    return length.to_bytes((length.bit_length() + 7) // 8, "big")


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

class RLPDecodingError(Exception):
    pass


def decode(data: bytes | bytearray | memoryview, strict: bool = True) -> RLPItem:
    """Decode RLP bytes into a Python object (bytes or nested list of bytes).

    If strict=False, trailing bytes after the first RLP item are ignored
    (used for EIP-8 handshake messages with random padding).
    """
    data = memoryview(bytes(data))
    item, consumed = _decode_item(data, 0)
    if strict and consumed != len(data):
        raise RLPDecodingError(
            f"Trailing bytes: consumed {consumed} of {len(data)}"
        )
    return item


def decode_list(data: bytes | bytearray | memoryview, strict: bool = True) -> list[RLPItem]:
    """Decode RLP bytes, asserting the top-level item is a list."""
    result = decode(data, strict=strict)
    if not isinstance(result, list):
        raise RLPDecodingError("Expected RLP list, got bytes")
    return result


def _decode_item(data: memoryview, offset: int) -> tuple[RLPItem, int]:
    """Decode one RLP item starting at offset, return (item, new_offset)."""
    if offset >= len(data):
        raise RLPDecodingError("Unexpected end of data")

    prefix = data[offset]

    if prefix < 0x80:
        # Single byte
        return bytes(data[offset : offset + 1]), offset + 1

    if prefix <= 0xb7:
        # Short string: 0-55 bytes
        str_len = prefix - 0x80
        start = offset + 1
        end = start + str_len
        if end > len(data):
            raise RLPDecodingError("String length exceeds data")
        if str_len == 1 and data[start] < 0x80:
            raise RLPDecodingError("Single byte should not have string prefix")
        return bytes(data[start:end]), end

    if prefix <= 0xbf:
        # Long string: >55 bytes
        len_of_len = prefix - 0xb7
        len_start = offset + 1
        len_end = len_start + len_of_len
        if len_end > len(data):
            raise RLPDecodingError("Length-of-length exceeds data")
        str_len = int.from_bytes(data[len_start:len_end], "big")
        if str_len <= 55:
            raise RLPDecodingError("Should have used short string encoding")
        if len_of_len > 1 and data[len_start] == 0:
            raise RLPDecodingError("Leading zeros in length")
        start = len_end
        end = start + str_len
        if end > len(data):
            raise RLPDecodingError("String data exceeds buffer")
        return bytes(data[start:end]), end

    if prefix <= 0xf7:
        # Short list: 0-55 bytes of payload
        list_len = prefix - 0xc0
        start = offset + 1
        end = start + list_len
        if end > len(data):
            raise RLPDecodingError("List length exceeds data")
        items = _decode_items(data, start, end)
        return items, end

    # Long list: >55 bytes of payload
    len_of_len = prefix - 0xf7
    len_start = offset + 1
    len_end = len_start + len_of_len
    if len_end > len(data):
        raise RLPDecodingError("List length-of-length exceeds data")
    list_len = int.from_bytes(data[len_start:len_end], "big")
    if list_len <= 55:
        raise RLPDecodingError("Should have used short list encoding")
    if len_of_len > 1 and data[len_start] == 0:
        raise RLPDecodingError("Leading zeros in list length")
    start = len_end
    end = start + list_len
    if end > len(data):
        raise RLPDecodingError("List data exceeds buffer")
    items = _decode_items(data, start, end)
    return items, end


def _decode_items(data: memoryview, start: int, end: int) -> list[RLPItem]:
    """Decode consecutive RLP items within [start, end)."""
    items: list[RLPItem] = []
    pos = start
    while pos < end:
        item, pos = _decode_item(data, pos)
        items.append(item)
    if pos != end:
        raise RLPDecodingError("List items did not consume exact payload")
    return items


# ---------------------------------------------------------------------------
# Helpers for typed encoding/decoding
# ---------------------------------------------------------------------------

def encode_uint(value: int) -> bytes:
    """Encode unsigned integer as RLP bytes (without leading zeros)."""
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def decode_uint(data: bytes) -> int:
    """Decode RLP bytes to unsigned integer.

    Tolerates non-canonical leading zeros for compatibility with data
    produced by other Ethereum clients (e.g., op-geth).
    """
    if len(data) == 0:
        return 0
    return int.from_bytes(data, "big")


def encode_fixed(value: int, length: int) -> bytes:
    """Encode integer as fixed-length big-endian bytes (e.g., 32 for hashes)."""
    return value.to_bytes(length, "big")


def decode_fixed(data: bytes, expected_length: int) -> int:
    """Decode fixed-length bytes to integer."""
    if len(data) != expected_length:
        raise RLPDecodingError(
            f"Expected {expected_length} bytes, got {len(data)}"
        )
    return int.from_bytes(data, "big")


def encode_address(addr: bytes) -> bytes:
    """Encode a 20-byte address for RLP."""
    if len(addr) != 20:
        raise ValueError(f"Address must be 20 bytes, got {len(addr)}")
    return addr


def decode_address(data: bytes) -> bytes:
    """Decode RLP bytes as 20-byte address."""
    if len(data) == 0:
        return b"\x00" * 20
    if len(data) != 20:
        raise RLPDecodingError(f"Address must be 20 bytes, got {len(data)}")
    return data
