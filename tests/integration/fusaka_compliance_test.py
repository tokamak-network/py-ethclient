from __future__ import annotations

from ethclient.networking.eth.protocol import ETH_VERSION
from ethclient.vm.opcodes import Op


def test_eth_protocol_version_is_at_least_68() -> None:
    """[RK-005] Fusaka용 eth/69 기본 버전 보장."""
    assert ETH_VERSION >= 69


def test_clz_opcode_gap_is_visible() -> None:
    """[RK-005] CLZ opcode가 정의되어 있어야 한다."""
    assert hasattr(Op, "CLZ")
