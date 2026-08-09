from __future__ import annotations

from pathlib import Path

import pytest

from weflow_chat.settings import (
    HostSettings,
    read_settings,
    settings_path,
    write_settings,
)


def source_account(tmp_path: Path) -> Path:
    source = tmp_path / "source" / "wxid_test_account"
    (source / "db_storage").mkdir(parents=True)
    return source


def test_settings_roundtrip(tmp_path: Path) -> None:
    local = tmp_path / "local"
    local.mkdir()
    source = source_account(tmp_path)
    data_root = tmp_path / "data"
    data_root.mkdir()
    path = settings_path(local)

    written = write_settings(
        path,
        HostSettings(source_account=source, data_root=data_root),
    )

    assert written == HostSettings(
        source.resolve(), data_root.resolve()
    )
    assert read_settings(path) == written


def test_settings_rejects_source_overlap(tmp_path: Path) -> None:
    local = tmp_path / "local"
    local.mkdir()
    source = source_account(tmp_path)

    with pytest.raises(RuntimeError, match="^settings_contract_invalid$"):
        write_settings(
            settings_path(local),
            HostSettings(
                source_account=source,
                data_root=source / "output",
            ),
        )


def test_settings_rejects_extra_json_property(tmp_path: Path) -> None:
    local = tmp_path / "local"
    local.mkdir()
    source = source_account(tmp_path)
    data_root = tmp_path / "data"
    data_root.mkdir()
    path = settings_path(local)
    path.parent.mkdir(parents=True)
    path.write_text(
        "{\"schemaVersion\":1,\"sourceAccount\":\""
        + str(source).replace("\\", "\\\\")
        + "\",\"dataRoot\":\""
        + str(data_root).replace("\\", "\\\\")
        + "\",\"extra\":true}",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="^settings_file_invalid$"):
        read_settings(path)
