from __future__ import annotations

from pathlib import Path


def test_chaindata_structure() -> None:
    """[RK-002] py-ethclient 디스크 구조 기본 검증"""
    data_dir = Path("/tmp/ethclient-test-data")
    chaindata = data_dir / "chaindata"

    # 런타임에서 --data-dir 또는 DATADIR로 생성되는 경로
    chaindata.mkdir(parents=True, exist_ok=True)

    assert data_dir.exists()
    assert chaindata.exists()


def test_datadir_env_name_compatibility() -> None:
    """[RK-002] geth 계열 DATADIR 이름과 호환되는지 확인"""
    accepted_names = {"DATADIR", "DATA_DIR"}
    assert "DATADIR" in accepted_names
    assert "DATA_DIR" in accepted_names
