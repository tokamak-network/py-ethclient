"""
Protocol registry — dynamic capability negotiation and message ID offset calculation.

RLPx caps are sorted alphabetically by name, then by version (ascending).
After matching the highest common version per protocol, message ID offsets
are assigned contiguously starting after the p2p reserved range (0x10).

Example (eth/68 + snap/1):
  p2p: 0x00-0x0F (reserved)
  eth/68: 0x10-0x20 (length=17)
  snap/1: 0x21-0x28 (length=8)
"""

from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Protocol length table — how many message codes each (name, version) uses
# ---------------------------------------------------------------------------

PROTOCOL_LENGTHS: dict[tuple[str, int], int] = {
    ("eth", 67): 17,
    ("eth", 68): 17,
    ("eth", 69): 18,
    ("snap", 1): 8,
}

P2P_OFFSET = 0x10  # first sub-protocol message code


# ---------------------------------------------------------------------------
# Capability
# ---------------------------------------------------------------------------

@dataclass(frozen=True, order=True)
class Capability:
    """A sub-protocol capability advertised in the Hello message."""
    name: str
    version: int

    @property
    def length(self) -> int:
        return PROTOCOL_LENGTHS.get((self.name, self.version), 0)


# ---------------------------------------------------------------------------
# Negotiated capabilities — offset map + resolver
# ---------------------------------------------------------------------------

@dataclass
class NegotiatedCapabilities:
    """Result of capability negotiation with a remote peer.

    Provides offset map and resolves absolute msg codes to (protocol, relative_code).
    """
    caps: list[Capability]
    offsets: dict[str, int]       # protocol name -> base offset
    _ranges: list[tuple[int, int, str]]  # [(start, end, proto_name), ...] sorted

    def resolve_msg_code(self, abs_code: int) -> tuple[str, int]:
        """Map an absolute wire message code to (protocol_name, relative_code).

        Raises ValueError if the code doesn't belong to any negotiated protocol.
        """
        for start, end, proto in self._ranges:
            if start <= abs_code < end:
                return proto, abs_code - start
        raise ValueError(f"Unknown message code: 0x{abs_code:02x}")

    def absolute_code(self, protocol: str, relative_code: int) -> int:
        """Convert (protocol, relative_code) to absolute wire message code."""
        base = self.offsets.get(protocol)
        if base is None:
            raise ValueError(f"Protocol not negotiated: {protocol}")
        return base + relative_code

    def supports(self, protocol: str) -> bool:
        """Check if a protocol was successfully negotiated."""
        return protocol in self.offsets


# ---------------------------------------------------------------------------
# Negotiation
# ---------------------------------------------------------------------------

def negotiate_capabilities(
    local: list[Capability],
    remote: list[Capability],
) -> NegotiatedCapabilities:
    """Negotiate capabilities between local and remote peer.

    For each protocol name present in both sides, pick the highest common
    version. Then sort matched caps alphabetically by name and assign
    contiguous message ID offsets starting at P2P_OFFSET (0x10).

    Returns a NegotiatedCapabilities instance.
    """
    # Build name -> set of versions for each side
    local_map: dict[str, set[int]] = {}
    for cap in local:
        local_map.setdefault(cap.name, set()).add(cap.version)

    remote_map: dict[str, set[int]] = {}
    for cap in remote:
        remote_map.setdefault(cap.name, set()).add(cap.version)

    # Find highest common version per protocol
    matched: list[Capability] = []
    for name in local_map:
        if name not in remote_map:
            continue
        common_versions = local_map[name] & remote_map[name]
        if not common_versions:
            # No exact version match — try highest that both support
            # (RLPx spec: pick highest version each side supports)
            max_local = max(local_map[name])
            max_remote = max(remote_map[name])
            best = min(max_local, max_remote)
            # Only if the length is known
            if (name, best) in PROTOCOL_LENGTHS:
                matched.append(Capability(name, best))
            continue
        best = max(common_versions)
        if (name, best) in PROTOCOL_LENGTHS:
            matched.append(Capability(name, best))

    # Sort alphabetically by name (RLPx spec)
    matched.sort(key=lambda c: c.name)

    # Assign contiguous offsets
    offsets: dict[str, int] = {}
    ranges: list[tuple[int, int, str]] = []
    offset = P2P_OFFSET

    for cap in matched:
        length = cap.length
        if length == 0:
            continue
        offsets[cap.name] = offset
        ranges.append((offset, offset + length, cap.name))
        offset += length

    return NegotiatedCapabilities(caps=matched, offsets=offsets, _ranges=ranges)
