"""Tests for protocol registry — capability negotiation and offset calculation."""

import pytest
from ethclient.networking.protocol_registry import (
    Capability,
    NegotiatedCapabilities,
    negotiate_capabilities,
    PROTOCOL_LENGTHS,
    P2P_OFFSET,
)


class TestCapability:
    def test_ordering(self):
        cap_eth = Capability("eth", 68)
        cap_snap = Capability("snap", 1)
        assert cap_eth < cap_snap  # alphabetical: "eth" < "snap"

    def test_length_lookup(self):
        assert Capability("eth", 68).length == 17
        assert Capability("snap", 1).length == 8
        assert Capability("unknown", 1).length == 0

    def test_frozen(self):
        cap = Capability("eth", 68)
        with pytest.raises(AttributeError):
            cap.name = "foo"


class TestNegotiateCapabilities:
    def test_eth_only(self):
        local = [Capability("eth", 68)]
        remote = [Capability("eth", 68)]
        result = negotiate_capabilities(local, remote)

        assert result.supports("eth")
        assert not result.supports("snap")
        assert result.offsets["eth"] == P2P_OFFSET  # 0x10
        assert len(result.caps) == 1

    def test_eth_and_snap(self):
        local = [Capability("eth", 68), Capability("snap", 1)]
        remote = [Capability("eth", 68), Capability("snap", 1)]
        result = negotiate_capabilities(local, remote)

        assert result.supports("eth")
        assert result.supports("snap")
        # eth comes first alphabetically
        assert result.offsets["eth"] == 0x10
        # snap offset = 0x10 + 17 = 0x21
        assert result.offsets["snap"] == 0x10 + 17  # 0x21

    def test_alphabetical_ordering(self):
        """Caps must be sorted alphabetically for offset assignment."""
        local = [Capability("snap", 1), Capability("eth", 68)]
        remote = [Capability("eth", 68), Capability("snap", 1)]
        result = negotiate_capabilities(local, remote)

        # Despite local listing snap first, eth still gets lower offset
        assert result.offsets["eth"] == 0x10
        assert result.offsets["snap"] == 0x10 + 17

    def test_no_common_protocol(self):
        local = [Capability("eth", 68)]
        remote = [Capability("snap", 1)]
        result = negotiate_capabilities(local, remote)

        assert not result.supports("eth")
        assert not result.supports("snap")
        assert len(result.caps) == 0

    def test_highest_common_version(self):
        local = [Capability("eth", 67), Capability("eth", 68)]
        remote = [Capability("eth", 67), Capability("eth", 68)]
        result = negotiate_capabilities(local, remote)

        assert result.supports("eth")
        eth_cap = next(c for c in result.caps if c.name == "eth")
        assert eth_cap.version == 68

    def test_version_mismatch_fallback(self):
        """When no exact version match, pick min(max_local, max_remote)."""
        local = [Capability("eth", 68)]
        remote = [Capability("eth", 67)]
        result = negotiate_capabilities(local, remote)

        # min(68, 67) = 67, which is a known length
        assert result.supports("eth")
        eth_cap = next(c for c in result.caps if c.name == "eth")
        assert eth_cap.version == 67

    def test_remote_lacks_snap(self):
        local = [Capability("eth", 68), Capability("snap", 1)]
        remote = [Capability("eth", 68)]
        result = negotiate_capabilities(local, remote)

        assert result.supports("eth")
        assert not result.supports("snap")


class TestResolveMessageCode:
    def test_resolve_eth_message(self):
        local = [Capability("eth", 68), Capability("snap", 1)]
        remote = [Capability("eth", 68), Capability("snap", 1)]
        result = negotiate_capabilities(local, remote)

        # EthMsg.STATUS = 0x10 (offset 0x10 + relative 0 = 0x10)
        proto, rel = result.resolve_msg_code(0x10)
        assert proto == "eth"
        assert rel == 0

        # EthMsg.BLOCK_HEADERS = 0x14 (offset 0x10 + relative 4)
        proto, rel = result.resolve_msg_code(0x14)
        assert proto == "eth"
        assert rel == 4

        # Last eth message: 0x10 + 16 = 0x20
        proto, rel = result.resolve_msg_code(0x20)
        assert proto == "eth"
        assert rel == 16

    def test_resolve_snap_message(self):
        local = [Capability("eth", 68), Capability("snap", 1)]
        remote = [Capability("eth", 68), Capability("snap", 1)]
        result = negotiate_capabilities(local, remote)

        # SnapMsg.GET_ACCOUNT_RANGE = snap offset (0x21) + 0
        snap_offset = result.offsets["snap"]
        proto, rel = result.resolve_msg_code(snap_offset)
        assert proto == "snap"
        assert rel == 0  # GET_ACCOUNT_RANGE

        # SnapMsg.TRIE_NODES = snap offset + 7
        proto, rel = result.resolve_msg_code(snap_offset + 7)
        assert proto == "snap"
        assert rel == 7  # TRIE_NODES

    def test_resolve_unknown_code(self):
        local = [Capability("eth", 68)]
        remote = [Capability("eth", 68)]
        result = negotiate_capabilities(local, remote)

        with pytest.raises(ValueError):
            result.resolve_msg_code(0xFF)

    def test_absolute_code(self):
        local = [Capability("eth", 68), Capability("snap", 1)]
        remote = [Capability("eth", 68), Capability("snap", 1)]
        result = negotiate_capabilities(local, remote)

        assert result.absolute_code("snap", 0) == 0x21
        assert result.absolute_code("snap", 7) == 0x28
        assert result.absolute_code("eth", 0) == 0x10

    def test_absolute_code_unknown_proto(self):
        local = [Capability("eth", 68)]
        remote = [Capability("eth", 68)]
        result = negotiate_capabilities(local, remote)

        with pytest.raises(ValueError):
            result.absolute_code("snap", 0)


class TestProtocolLengths:
    def test_known_lengths(self):
        assert PROTOCOL_LENGTHS[("eth", 68)] == 17
        assert PROTOCOL_LENGTHS[("eth", 67)] == 17
        assert PROTOCOL_LENGTHS[("snap", 1)] == 8
