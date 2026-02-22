"""Tests for RLP encoding/decoding."""

import pytest
from ethclient.common.rlp import (
    encode,
    decode,
    decode_list,
    decode_uint,
    encode_uint,
    RLPDecodingError,
)


class TestRLPEncodeSingleBytes:
    def test_single_byte_low(self):
        # Single byte in [0x00, 0x7f] encodes as itself
        assert encode(b"\x00") == b"\x00"
        assert encode(b"\x7f") == b"\x7f"

    def test_single_byte_high(self):
        # Single byte >= 0x80 gets a length prefix
        assert encode(b"\x80") == b"\x81\x80"
        assert encode(b"\xff") == b"\x81\xff"

    def test_empty_bytes(self):
        assert encode(b"") == b"\x80"

    def test_short_string(self):
        # "dog" = [0x64, 0x6f, 0x67], length 3
        assert encode(b"dog") == b"\x83dog"

    def test_55_byte_string(self):
        data = b"a" * 55
        assert encode(data) == bytes([0x80 + 55]) + data

    def test_long_string(self):
        data = b"b" * 56
        # length 56 = 0x38, fits in 1 byte
        assert encode(data) == b"\xb8\x38" + data

    def test_very_long_string(self):
        data = b"c" * 1024
        # length 1024 = 0x0400, 2 bytes
        assert encode(data) == b"\xb9\x04\x00" + data


class TestRLPEncodeList:
    def test_empty_list(self):
        assert encode([]) == b"\xc0"

    def test_list_of_strings(self):
        # ["cat", "dog"]
        result = encode([b"cat", b"dog"])
        expected = b"\xc8\x83cat\x83dog"
        assert result == expected

    def test_nested_list(self):
        # [[], [[]], [[], [[]]]]
        result = encode([[], [[]], [[], [[]]]])
        expected = b"\xc7\xc0\xc1\xc0\xc3\xc0\xc1\xc0"
        assert result == expected

    def test_set_theoretical_repr(self):
        # The set theoretical representation of three
        result = encode([[], [[]], [[], [[]]]])
        assert result == bytes.fromhex("c7c0c1c0c3c0c1c0")

    def test_short_list_max(self):
        items = [b"a"] * 55
        result = encode(items)
        # Each "a" encodes as 0x61 (1 byte), total payload = 55 bytes
        assert result[0] == 0xc0 + 55
        assert len(result) == 56

    def test_long_list(self):
        items = [b"a"] * 60
        result = encode(items)
        # payload = 60 bytes, > 55 so uses long list encoding
        assert result[0] == 0xf7 + 1  # 0xf8
        assert result[1] == 60
        assert len(result) == 62


class TestRLPEncodeIntegers:
    def test_zero(self):
        assert encode(0) == b"\x80"

    def test_small_int(self):
        assert encode(1) == b"\x01"
        assert encode(127) == b"\x7f"

    def test_medium_int(self):
        assert encode(128) == b"\x81\x80"
        assert encode(256) == b"\x82\x01\x00"

    def test_large_int(self):
        assert encode(0xFFFF) == b"\x82\xff\xff"
        assert encode(0x010000) == b"\x83\x01\x00\x00"

    def test_negative_int_raises(self):
        with pytest.raises(ValueError):
            encode(-1)


class TestRLPEncodeStrings:
    def test_string_encoding(self):
        assert encode("dog") == b"\x83dog"
        assert encode("") == b"\x80"


class TestRLPDecode:
    def test_single_byte(self):
        assert decode(b"\x00") == b"\x00"
        assert decode(b"\x7f") == b"\x7f"

    def test_empty_string(self):
        assert decode(b"\x80") == b""

    def test_short_string(self):
        assert decode(b"\x83dog") == b"dog"

    def test_long_string(self):
        data = b"b" * 56
        assert decode(b"\xb8\x38" + data) == data

    def test_empty_list(self):
        assert decode(b"\xc0") == []

    def test_list_of_strings(self):
        result = decode(b"\xc8\x83cat\x83dog")
        assert result == [b"cat", b"dog"]

    def test_nested_list(self):
        result = decode(bytes.fromhex("c7c0c1c0c3c0c1c0"))
        assert result == [[], [[]], [[], [[]]]]

    def test_integer_encoded(self):
        # 128 encoded as b'\x81\x80', decoded as bytes b'\x80'
        raw = decode(b"\x81\x80")
        assert raw == b"\x80"
        assert decode_uint(raw) == 128


class TestRLPRoundTrip:
    @pytest.mark.parametrize(
        "value",
        [
            b"",
            b"\x00",
            b"\x7f",
            b"\x80",
            b"hello world",
            b"a" * 55,
            b"a" * 56,
            b"a" * 1024,
            [],
            [b""],
            [b"cat", b"dog"],
            [[], [[]], [[], [[]]]],
            [[b"a", b"b"], [b"c"]],
        ],
    )
    def test_roundtrip(self, value):
        assert decode(encode(value)) == value

    @pytest.mark.parametrize(
        "value",
        [0, 1, 127, 128, 255, 256, 1024, 0xFFFFFF, 2**64],
    )
    def test_integer_roundtrip(self, value):
        encoded = encode(value)
        decoded_bytes = decode(encoded)
        assert decode_uint(decoded_bytes) == value


class TestRLPErrors:
    def test_trailing_bytes(self):
        with pytest.raises(RLPDecodingError, match="Trailing bytes"):
            decode(b"\x80\x80")

    def test_truncated(self):
        with pytest.raises(RLPDecodingError):
            decode(b"\x83do")  # claims 3 bytes but only 2

    def test_leading_zeros_in_length(self):
        # Construct invalid: 0xb8 0x00 0x38 + data (leading zero in length)
        with pytest.raises(RLPDecodingError):
            decode(b"\xb9\x00\x38" + b"x" * 56)


class TestEncodeDecodeUint:
    def test_zero(self):
        assert encode_uint(0) == b""
        assert decode_uint(b"") == 0

    def test_small(self):
        assert encode_uint(1) == b"\x01"
        assert decode_uint(b"\x01") == 1

    def test_256(self):
        assert encode_uint(256) == b"\x01\x00"
        assert decode_uint(b"\x01\x00") == 256

    def test_leading_zero_tolerated(self):
        # decode_uint tolerates non-canonical leading zeros for compatibility
        # with data produced by other Ethereum clients (e.g., op-geth).
        assert decode_uint(b"\x00\x01") == 1
