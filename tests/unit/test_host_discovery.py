from __future__ import annotations

import json
from pathlib import Path

import pytest

from weflow_chat.host_discovery import (
    KnownFolders,
    VolumeCandidate,
    discover_source_accounts,
    initialize_host_contract,
    load_host_contract,
    recommend_volumes,
    required_storage_bytes,
)
from weflow_chat.preflight import require_fixed_host


ACCOUNT = "wxid_test_account"


def folders(tmp_path: Path) -> KnownFolders:
    values = KnownFolders(
        local_app_data=tmp_path / "local",
        roaming_app_data=tmp_path / "roaming",
        documents=tmp_path / "documents",
        desktop=tmp_path / "desktop",
        program_files=tmp_path / "program-files",
        program_files_x86=tmp_path / "program-files-x86",
    )
    for value in (
        values.local_app_data,
        values.roaming_app_data,
        values.documents,
        values.desktop,
        values.program_files,
        values.program_files_x86,
    ):
        value.mkdir(parents=True, exist_ok=True)
    return values


def initialized_host(tmp_path: Path) -> tuple[KnownFolders, Path]:
    known = folders(tmp_path)
    config = known.roaming_app_data / "weflow" / "WeFlow-config.json"
    config.parent.mkdir()
    config.write_text(
        json.dumps(
            {
                "myWxid": ACCOUNT,
                "decryptKey": "safe:synthetic",
                "wxidConfigs": {
                    ACCOUNT: {"decryptKey": "safe:synthetic"}
                },
            }
        ),
        encoding="utf-8",
    )
    weflow = known.local_app_data / "Programs" / "WeFlow" / "WeFlow.exe"
    weflow.parent.mkdir(parents=True)
    weflow.write_bytes(b"synthetic-weflow")
    weixin = known.program_files / "Tencent" / "Weixin" / "Weixin.exe"
    weixin.parent.mkdir(parents=True)
    weixin.write_bytes(b"synthetic-weixin")
    volume = tmp_path / "volume"
    source = volume / "holder" / "xwechat_files" / ACCOUNT
    session = source / "db_storage" / "session" / "session.db"
    session.parent.mkdir(parents=True)
    session.write_bytes(b"synthetic-session")
    return known, volume


def test_discovers_only_structurally_valid_account(tmp_path: Path) -> None:
    valid = tmp_path / "root" / ACCOUNT
    session = valid / "db_storage" / "session" / "session.db"
    session.parent.mkdir(parents=True)
    session.write_bytes(b"synthetic")
    invalid = tmp_path / "other" / ACCOUNT
    invalid.mkdir(parents=True)

    assert discover_source_accounts(
        account_id=ACCOUNT,
        data_roots=(tmp_path / "root", tmp_path / "other"),
    ) == (valid.resolve(),)


def test_recommend_volumes_requires_fixed_ntfs_and_space(tmp_path: Path) -> None:
    values = (
        VolumeCandidate(tmp_path / "a", 5_000, True, "NTFS"),
        VolumeCandidate(tmp_path / "b", 8_000, False, "NTFS"),
        VolumeCandidate(tmp_path / "c", 9_000, True, "exFAT"),
        VolumeCandidate(tmp_path / "d", 7_000, True, "ntfs"),
    )

    assert recommend_volumes(values, required_bytes=4_000) == (
        values[3],
        values[0],
    )


def test_initialize_then_load_contract(tmp_path: Path) -> None:
    known, volume = initialized_host(tmp_path)
    answers = iter(("USE",))
    output: list[str] = []

    contract = initialize_host_contract(
        folders=known,
        volumes=(
            VolumeCandidate(
                root=volume,
                free_bytes=4 * 1024**3,
                is_fixed=True,
                file_system="NTFS",
            ),
        ),
        input_fn=lambda _: next(answers),
        output_fn=output.append,
    )

    assert require_fixed_host(contract) is contract
    assert contract.account_id == ACCOUNT
    assert contract.source_account.name == ACCOUNT
    assert contract.snapshots_root.parent.name == "Data"
    assert load_host_contract(folders=known) == contract
    assert output


def test_required_storage_includes_three_copies_and_margin(
    tmp_path: Path,
) -> None:
    source = tmp_path / ACCOUNT
    database = source / "db_storage" / "session" / "session.db"
    database.parent.mkdir(parents=True)
    database.write_bytes(b"x" * 100)

    assert required_storage_bytes(source) == 3 * 100 + 1024**3


def test_initialize_rejects_unknown_choice(tmp_path: Path) -> None:
    known, volume = initialized_host(tmp_path)

    with pytest.raises(RuntimeError, match="^storage_selection_cancelled$"):
        initialize_host_contract(
            folders=known,
            volumes=(
                VolumeCandidate(
                    root=volume,
                    free_bytes=4 * 1024**3,
                    is_fixed=True,
                    file_system="NTFS",
                ),
            ),
            input_fn=lambda _: "NO",
            output_fn=lambda _: None,
        )
