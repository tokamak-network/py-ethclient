from __future__ import annotations

import pytest

from ethclient.rpc.server import RPCError
from ethclient.rpc.server import RPCServer
from ethclient.rpc.eth_api import register_eth_api


class _DummyStore:
    def get_latest_block_number(self):
        return 1


def test_archive_query_rejected_when_disabled() -> None:
    """[RK-004] archive 비활성 시 과거 상태 조회를 명시적으로 차단해야 한다."""
    rpc = RPCServer()
    register_eth_api(rpc, store=_DummyStore(), archive_enabled=False)

    handler = rpc._methods["eth_getBalance"]
    with pytest.raises(RPCError, match="archive mode is not enabled"):
        handler("0x" + "00" * 20, "0x1")


def test_archive_query_allowed_when_enabled() -> None:
    """[RK-004] archive 활성 시 과거 블록 파라미터를 거부하지 않는다."""
    rpc = RPCServer()
    register_eth_api(rpc, store=None, archive_enabled=True)

    handler = rpc._methods["eth_getBalance"]
    result = handler("0x" + "00" * 20, "0x1")
    assert result.startswith("0x")
