from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path, PureWindowsPath
import subprocess

import pytest

import weflow_chat.vss as vss

from weflow_chat.vss import (
    MediaStagingReceipt,
    StagingReceipt,
    VssCleanupError,
    VssHelperClient,
    VssJournalError,
    VssPathError,
    acquire_vss_staging,
    account_db_relative_path,
    assert_device_object,
    copy_owned_shadow_to_staging,
    copy_owned_shadow_media_to_staging,
    map_shadow_path,
    map_volume_path,
    read_vss_journal,
    remove_synthetic_tree,
)

RUN_ID = "11111111-1111-1111-1111-111111111111"
SHADOW_ID = "{22222222-2222-2222-2222-222222222222}"
DEVICE = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy99"
ACCOUNT_NAME = "wxid_test"


def test_media_staging_publishes_only_fixed_weflow_media_roots(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "shadow-account"
    expected = {
        "msg/attach/a.dat": b"attach",
        "msg/video/b.jpg": b"video",
    }
    rejected = {
        "cache/c.dat": b"cache",
        "temp/head_image/avatar": b"avatar",
    }
    for relative, payload in {**expected, **rejected}.items():
        target = source / Path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    run_root = tmp_path / "run"
    run_root.mkdir()

    monkeypatch.setattr(
        vss,
        "_assert_shadow_account_source",
        lambda path, **kwargs: path,
    )
    monkeypatch.setattr(
        vss, "_assert_fixed_run_root", lambda path, **_kwargs: path
    )
    monkeypatch.setattr(
        vss.shutil,
        "disk_usage",
        lambda path: type("Usage", (), {"free": 2**30 + 22})(),
    )

    receipt = copy_owned_shadow_media_to_staging(
        shadow_account=source,
        run_root=run_root,
        snapshots_root=run_root.parent,
        source_account_name=ACCOUNT_NAME,
    )

    assert isinstance(receipt, MediaStagingReceipt)
    assert receipt.staging_path == run_root / "media-staging"
    assert receipt.source_account_name == ACCOUNT_NAME
    assert receipt.file_count == 2
    assert receipt.byte_count == 11
    assert receipt.manifest_sha256 == (
        "E13267E6CE198FA5A2EBD4BC1B72C5CC"
        "40B381E9BFAC552FE272F2F70F899FD6"
    )
    assert tuple(item.relative_path for item in receipt.files) == tuple(expected)
    for relative, payload in expected.items():
        assert (
            receipt.staging_path / ACCOUNT_NAME / Path(relative)
        ).read_bytes() == payload
    for relative in rejected:
        assert not (
            receipt.staging_path / ACCOUNT_NAME / Path(relative)
        ).exists()


def test_media_staging_identical_prior_inventory_publishes_empty_delta(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "shadow-account"
    target = source / "msg" / "attach" / "a.dat"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"attach")
    run_root = tmp_path / "run"
    run_root.mkdir()
    prior_inventory = (
        vss.MediaStagingFile(
            "msg/attach/a.dat",
            6,
            "A919007637ABD504F123DB0CBC8F290A"
            "B16DB93ADF24B1FC03C50E6131D2B98E",
        ),
    )

    monkeypatch.setattr(
        vss,
        "_assert_shadow_account_source",
        lambda path, **kwargs: path,
    )
    monkeypatch.setattr(
        vss, "_assert_fixed_run_root", lambda path, **_kwargs: path
    )
    monkeypatch.setattr(
        vss.shutil,
        "disk_usage",
        lambda path: type("Usage", (), {"free": 2**30})(),
    )

    receipt = copy_owned_shadow_media_to_staging(
        shadow_account=source,
        run_root=run_root,
        snapshots_root=run_root.parent,
        source_account_name=ACCOUNT_NAME,
        prior_inventory=prior_inventory,
    )

    assert receipt.files == ()
    assert receipt.file_count == 0
    assert receipt.byte_count == 0
    assert receipt.manifest_sha256 == (
        "4F53CDA18C2BAA0C0354BB5F9A3ECBE"
        "5ED12AB4D8E11BA873C2F11161202B945"
    )
    assert tuple((receipt.staging_path / ACCOUNT_NAME).rglob("*")) == ()


def test_media_staging_same_size_changed_hash_is_in_delta(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "shadow-account"
    target = source / "msg" / "video" / "clip.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"new-bb")
    run_root = tmp_path / "run"
    run_root.mkdir()
    prior_inventory = (
        vss.MediaStagingFile(
            "msg/video/clip.bin",
            6,
            "0E072D9113349CD2A67AF54A24399D"
            "DF13C129045E5AB1E4B37B2657357F4602",
        ),
    )

    monkeypatch.setattr(
        vss,
        "_assert_shadow_account_source",
        lambda path, **kwargs: path,
    )
    monkeypatch.setattr(
        vss, "_assert_fixed_run_root", lambda path, **_kwargs: path
    )
    monkeypatch.setattr(
        vss.shutil,
        "disk_usage",
        lambda path: type("Usage", (), {"free": 2**30 + 12})(),
    )

    receipt = copy_owned_shadow_media_to_staging(
        shadow_account=source,
        run_root=run_root,
        snapshots_root=run_root.parent,
        source_account_name=ACCOUNT_NAME,
        prior_inventory=prior_inventory,
    )

    assert receipt.files == (
        vss.MediaStagingFile(
            "msg/video/clip.bin",
            6,
            "0DC80AFF275BA40733D6FB74E490C952"
            "ABE589DD75BF2393B0D0502C70A6EA50",
        ),
    )
    assert (
        receipt.staging_path / ACCOUNT_NAME / "msg" / "video" / "clip.bin"
    ).read_bytes() == b"new-bb"


def test_media_staging_disappearance_emits_no_file_or_tombstone(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "shadow-account"
    source.mkdir()
    run_root = tmp_path / "run"
    run_root.mkdir()
    prior_inventory = (
        vss.MediaStagingFile("msg/attach/gone.dat", 7, "A" * 64),
    )
    monkeypatch.setattr(
        vss,
        "_assert_shadow_account_source",
        lambda path, **kwargs: path,
    )
    monkeypatch.setattr(
        vss, "_assert_fixed_run_root", lambda path, **_kwargs: path
    )
    monkeypatch.setattr(
        vss.shutil,
        "disk_usage",
        lambda path: type("Usage", (), {"free": 2**30})(),
    )

    receipt = copy_owned_shadow_media_to_staging(
        shadow_account=source,
        run_root=run_root,
        snapshots_root=run_root.parent,
        source_account_name=ACCOUNT_NAME,
        prior_inventory=prior_inventory,
    )

    assert receipt.files == ()
    assert receipt.file_count == 0
    assert tuple((receipt.staging_path / ACCOUNT_NAME).rglob("*")) == ()


def test_media_staging_rehashes_full_shadow_after_an_empty_delta(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "shadow-account"
    target = source / "msg" / "attach" / "a.dat"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"attach")
    run_root = tmp_path / "run"
    run_root.mkdir()
    prior_inventory = (
        vss.MediaStagingFile(
            "msg/attach/a.dat",
            6,
            "A919007637ABD504F123DB0CBC8F290A"
            "B16DB93ADF24B1FC03C50E6131D2B98E",
        ),
    )
    monkeypatch.setattr(
        vss,
        "_assert_shadow_account_source",
        lambda path, **kwargs: path,
    )
    monkeypatch.setattr(
        vss, "_assert_fixed_run_root", lambda path, **_kwargs: path
    )

    def mutate_after_first_full_manifest(path: Path) -> object:
        target.write_bytes(b"detach")
        return type("Usage", (), {"free": 2**30})()

    monkeypatch.setattr(vss.shutil, "disk_usage", mutate_after_first_full_manifest)

    with pytest.raises(
            vss.VssError, match="media_staging_copy_verification_failed"):
        copy_owned_shadow_media_to_staging(
            shadow_account=source,
            run_root=run_root,
            snapshots_root=run_root.parent,
            source_account_name=ACCOUNT_NAME,
            prior_inventory=prior_inventory,
        )

    assert not (run_root / "media-staging").exists()


@pytest.mark.parametrize(
    "prior_inventory",
    [
        [vss.MediaStagingFile("msg/attach/a", 1, "A" * 64)],
        (object(),),
        (vss.MediaStagingFile("msg/attach/a", True, "A" * 64),),
        (vss.MediaStagingFile("msg/attach/a", -1, "A" * 64),),
        (vss.MediaStagingFile("msg/attach/a", 1, "a" * 64),),
        (vss.MediaStagingFile("msg/attach", 1, "A" * 64),),
        (vss.MediaStagingFile("msg/attach/../video/a", 1, "A" * 64),),
        (vss.MediaStagingFile(r"msg\attach\a", 1, "A" * 64),),
        (vss.MediaStagingFile("cache/a", 1, "A" * 64),),
        (
            vss.MediaStagingFile("msg/video/b", 1, "B" * 64),
            vss.MediaStagingFile("msg/attach/a", 1, "A" * 64),
        ),
        (
            vss.MediaStagingFile("msg/attach/A", 1, "A" * 64),
            vss.MediaStagingFile("msg/attach/a", 1, "B" * 64),
        ),
    ],
    ids=[
        "not-tuple",
        "wrong-entry-type",
        "bool-size",
        "negative-size",
        "noncanonical-hash",
        "root-without-file",
        "parent-segment",
        "backslash-path",
        "outside-whitelist",
        "unsorted",
        "case-collision",
    ],
)
def test_media_staging_rejects_noncanonical_prior_inventory(
        prior_inventory: object, tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "shadow-account"
    source.mkdir()
    run_root = tmp_path / "run"
    run_root.mkdir()
    monkeypatch.setattr(
        vss,
        "_assert_shadow_account_source",
        lambda path, **kwargs: path,
    )
    monkeypatch.setattr(
        vss, "_assert_fixed_run_root", lambda path, **_kwargs: path
    )

    with pytest.raises(
            VssPathError, match="prior_media_inventory_invalid"):
        copy_owned_shadow_media_to_staging(
            shadow_account=source,
            run_root=run_root,
            snapshots_root=run_root.parent,
            source_account_name=ACCOUNT_NAME,
            prior_inventory=prior_inventory,  # type: ignore[arg-type]
        )

    assert tuple(run_root.iterdir()) == ()


def test_media_staging_space_gate_precedes_every_partial_copy(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "shadow-account"
    target = source / "msg" / "attach" / "a.dat"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"attach")
    run_root = tmp_path / "run"
    run_root.mkdir()
    monkeypatch.setattr(
        vss,
        "_assert_shadow_account_source",
        lambda path, **kwargs: path,
    )
    monkeypatch.setattr(
        vss, "_assert_fixed_run_root", lambda path, **_kwargs: path
    )
    monkeypatch.setattr(
        vss.shutil,
        "disk_usage",
        lambda path: type("Usage", (), {"free": 2**30 + 11})(),
    )

    with pytest.raises(
            vss.VssError, match="media_staging_insufficient_space"):
        copy_owned_shadow_media_to_staging(
            shadow_account=source,
            run_root=run_root,
            snapshots_root=run_root.parent,
            source_account_name=ACCOUNT_NAME,
        )

    assert tuple(run_root.iterdir()) == ()


def test_media_staging_rejects_reparse_in_allowed_root_chain(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "shadow-account"
    target = source / "msg" / "attach" / "a.dat"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"attach")
    run_root = tmp_path / "run"
    run_root.mkdir()

    monkeypatch.setattr(
        vss,
        "_assert_shadow_account_source",
        lambda path, **kwargs: path,
    )
    monkeypatch.setattr(
        vss, "_assert_fixed_run_root", lambda path, **_kwargs: path
    )
    real_is_reparse = vss._is_reparse_point
    monkeypatch.setattr(
        vss,
        "_is_reparse_point",
        lambda path: path.name == "msg" or real_is_reparse(path),
    )

    with pytest.raises(VssPathError, match="media_root_chain_reparse"):
        copy_owned_shadow_media_to_staging(
            shadow_account=source,
            run_root=run_root,
            snapshots_root=run_root.parent,
            source_account_name=ACCOUNT_NAME,
        )

    assert not (run_root / "media-staging").exists()


def test_device_object_and_mapping_are_exact() -> None:
    assert assert_device_object(DEVICE) == DEVICE
    assert str(map_shadow_path(DEVICE, r"AppData\db\session.db")) == (
        DEVICE + r"\AppData\db\session.db")
    assert str(map_volume_path(
        DEVICE,
        source_volume="F:\\",
        live_path=r"F:\synthetic-data\xwechat_files\wxid_test\db_storage",
    )) == DEVICE + r"\synthetic-data\xwechat_files\wxid_test\db_storage"
    for value in (
        DEVICE + "\\",
        DEVICE + r"\extra",
        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy0",
        r"\\server\share",
    ):
        with pytest.raises(VssPathError):
            assert_device_object(value)
    with pytest.raises(VssPathError):
        map_shadow_path(DEVICE, r"..\Windows")
    with pytest.raises(VssPathError):
        map_volume_path(DEVICE, source_volume="F:\\",
                        live_path=r"C:\outside")


def test_account_relative_contract_is_one_exact_wxid_component() -> None:
    assert account_db_relative_path(ACCOUNT_NAME) == PureWindowsPath(
        ACCOUNT_NAME, "db_storage")
    for value in (
        "wxid_", "other", "wxid_test/other", r"wxid_test\other",
        "wxid_..", "wxid_test:", ".", "..",
    ):
        with pytest.raises(VssPathError, match="source_account_name_invalid"):
            account_db_relative_path(value)


def test_direct_copy_binds_shadow_tail_to_account_and_db_storage() -> None:
    snapshots_root = Path(r"X:\synthetic\Snapshots")
    run_root = snapshots_root / "unit-run"
    for source in (
        Path(DEVICE + r"\synthetic\wxid_other\db_storage"),
        Path(DEVICE + r"\synthetic\wxid_test\..\db_storage"),
        Path(DEVICE + r"\synthetic\wxid_test\media"),
    ):
        with pytest.raises(VssPathError, match="shadow_account_db_path_invalid"):
            copy_owned_shadow_to_staging(
                shadow_source=source, run_root=run_root,
                snapshots_root=snapshots_root,
                source_account_name=ACCOUNT_NAME)
    with pytest.raises(VssPathError, match="staging_run_root_not_fixed"):
        copy_owned_shadow_to_staging(
            shadow_source=Path(
                DEVICE + r"\synthetic\wxid_test\db_storage"),
            run_root=Path(r"X:\outside\unit-run"),
            snapshots_root=snapshots_root,
            source_account_name=ACCOUNT_NAME)


def test_reader_rejects_unknown_fields_and_invalid_state(tmp_path: Path) -> None:
    base = {
        "version": 1, "runId": RUN_ID, "sourceVolume": "F:\\",
        "volumeDeviceId": None, "state": "creating", "shadowId": None,
        "deviceObject": None, "createdAtUtc": "2026-07-21T00:00:00.0000000Z",
        "updatedAtUtc": "2026-07-21T00:00:00.0000000Z",
    }
    path = tmp_path / f"{RUN_ID}.json"
    path.write_text(json.dumps({**base, "extra": True}), encoding="utf-8")
    with pytest.raises(VssJournalError, match="journal_schema_invalid"):
        read_vss_journal(path, expected_run_id=RUN_ID)
    path.write_text(json.dumps({**base, "state": "other"}), encoding="utf-8")
    with pytest.raises(VssJournalError, match="journal_state_invalid"):
        read_vss_journal(path, expected_run_id=RUN_ID)
    duplicate = json.dumps(base).replace(
        '"version": 1', '"version": 1, "version": 1', 1)
    path.write_text(duplicate, encoding="utf-8")
    with pytest.raises(VssJournalError, match="journal_duplicate_key"):
        read_vss_journal(path, expected_run_id=RUN_ID)
    escaped_key = json.dumps(base).replace(
        '"version"', '"\\u0076ersion"', 1)
    path.write_text(escaped_key, encoding="utf-8")
    with pytest.raises(VssJournalError, match="journal_json_keys_invalid"):
        read_vss_journal(path, expected_run_id=RUN_ID)
    for replacement, message in (
        ({"version": True}, "journal_identity_invalid"),
        ({"version": "1"}, "journal_identity_invalid"),
        ({"runId": 7}, "journal_identity_invalid"),
        ({"sourceVolume": 7}, "journal_source_volume_invalid"),
        ({"state": 7}, "journal_state_invalid"),
        ({"updatedAtUtc": "2026-07-21T00:00:00Z"},
         "journal_timestamp_invalid"),
    ):
        path.write_text(
            json.dumps({**base, **replacement}), encoding="utf-8")
        with pytest.raises(VssJournalError, match=message):
            read_vss_journal(path, expected_run_id=RUN_ID)


def test_reader_rejects_updated_timestamp_before_created_timestamp(
        tmp_path: Path) -> None:
    path = tmp_path / f"{RUN_ID}.json"
    path.write_text(json.dumps({
        "version": 1, "runId": RUN_ID, "sourceVolume": "F:\\",
        "volumeDeviceId": None, "state": "creating", "shadowId": None,
        "deviceObject": None,
        "createdAtUtc": "2026-07-21T00:00:01.0000000Z",
        "updatedAtUtc": "2026-07-21T00:00:00.9999999Z",
    }), encoding="utf-8")

    with pytest.raises(
            VssJournalError, match="journal_timestamp_order_invalid"):
        read_vss_journal(path, expected_run_id=RUN_ID)


def test_public_client_rejects_arbitrary_script_and_all_injection(
        tmp_path: Path) -> None:
    arbitrary = tmp_path / "Invoke-WeFlowVssHelper.ps1"
    arbitrary.write_text("Write-Host untrusted", encoding="utf-8")
    for injected in (
        {"script": arbitrary},
        {"powershell": arbitrary},
        {"journal_root": tmp_path},
        {"runner": lambda *args, **kwargs: None},
    ):
        with pytest.raises(TypeError):
            VssHelperClient(source_volume="F:\\", **injected)
    with pytest.raises(TypeError):
        VssHelperClient(arbitrary)


def test_generated_allowlist_matches_repository_helper_bytes() -> None:
    assert vss._FIXED_TRUST.allowed_helper_root == "vss-helper"
    assert set(vss._FIXED_TRUST.helper_sha256) == {
        "Invoke-WeFlowVssHelper.ps1", "WeFlowVssHelper.psm1",
    }
    for name, expected in vss._FIXED_TRUST.helper_sha256.items():
        assert vss._sha256_file(vss._FIXED_TRUST.helper_root / name) == expected


@pytest.mark.parametrize(
    ("action", "arguments", "elevated"),
    [
        ("PrepareCreate", {"source_volume": "F:\\"}, False),
        ("Create", {"source_volume": "F:\\"}, True),
        ("Adopt", {"expected_shadow_id": SHADOW_ID}, False),
        ("InspectOwned", {}, False),
        ("DeleteExact", {"expected_shadow_id": SHADOW_ID}, True),
    ],
)
def test_private_builder_enforces_the_fixed_elevation_matrix(
        action: str, arguments: dict[str, str], elevated: bool) -> None:
    runtime = vss._TrustedRuntime(
        powershell=Path(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        script=Path(r"C:\repo\vss-helper\Invoke-WeFlowVssHelper.ps1"),
        journal_root=Path(r"C:\ProgramData\WeFlowRecovery\shadows"),
    )
    command = vss._build_helper_command(
        runtime, action=action, run_id=RUN_ID, **arguments)
    joined = " ".join(command)
    assert ("-Verb RunAs" in joined) is elevated
    assert ("-WindowStyle Hidden" in joined) is elevated
    assert command[0] == str(runtime.powershell)
    assert str(runtime.script) in joined
    if elevated:
        assert command[1:4] == ["-NoProfile", "-NonInteractive", "-Command"]
        assert "-Wait" not in joined
        assert f".WaitForExit({vss._RUNAS_TIMEOUT_MILLISECONDS})" in joined
        assert f"exit {vss._RUNAS_TIMEOUT_EXIT_CODE}" in joined
    else:
        assert command[1:5] == [
            "-NoProfile", "-NonInteractive", "-File", str(runtime.script)]
        assert "-Command" not in command
    assert "AppData" not in joined
    assert "decryptKey" not in joined


def test_runner_injection_exists_only_on_private_process_adapter(
        tmp_path: Path) -> None:
    journal_root = tmp_path / "journals"
    journal_root.mkdir()
    (journal_root / f"{RUN_ID}.json").write_text(json.dumps({
        "version": 1, "runId": RUN_ID, "sourceVolume": "F:\\",
        "volumeDeviceId": (
            r"\\?\Volume{33333333-3333-3333-3333-333333333333}" + "\\"),
        "state": "created", "shadowId": SHADOW_ID,
        "deviceObject": DEVICE,
        "createdAtUtc": "2026-07-21T00:00:00.0000000Z",
        "updatedAtUtc": "2026-07-21T00:00:01.0000000Z",
    }), encoding="utf-8")
    runtime = vss._TrustedRuntime(
        powershell=Path(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        script=Path(r"C:\repo\vss-helper\Invoke-WeFlowVssHelper.ps1"),
        journal_root=journal_root,
    )
    calls: list[list[str]] = []

    def private_runner(
        command: list[str], **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs["timeout"] == vss._HELPER_OUTER_TIMEOUT_SECONDS
        return subprocess.CompletedProcess(command, 0, "", "")

    adapter = vss._HelperProcessAdapter(runtime, private_runner)
    result = adapter.invoke(
        action="Create", run_id=RUN_ID, source_volume="F:\\")
    assert result.state is vss.ShadowState.CREATED
    assert len(calls) == 1


def test_reader_adapter_and_command_canonicalize_mixed_case_shadow_id(
        tmp_path: Path) -> None:
    mixed = "{abcdefab-cdef-abcd-efab-cdefabcdefab}"
    canonical = "{ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB}"
    journal_root = tmp_path / "journals"
    journal_root.mkdir()
    _write_timeout_journal(
        journal_root, "adopted", shadow_id=mixed)
    runtime = vss._TrustedRuntime(
        powershell=Path("powershell.exe"), script=Path("helper.ps1"),
        journal_root=journal_root)
    commands: list[list[str]] = []

    def runner(command: list[str], **kwargs: object):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    result = vss._HelperProcessAdapter(runtime, runner).invoke(
        action="Adopt", run_id=RUN_ID, expected_shadow_id=mixed)
    assert result.shadow_id == canonical
    assert canonical in commands[0]
    assert mixed not in commands[0]


def test_public_create_pins_f_and_prepares_before_runas(
        monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, str | None]] = []
    prepared = type(
        "Prepared",
        (),
        {"state": vss.ShadowState.CREATING, "source_volume": "F:\\"},
    )()
    created = type(
        "Created",
        (),
        {"state": vss.ShadowState.CREATED, "source_volume": "F:\\"},
    )()

    def invoke(
        self: VssHelperClient, **arguments: str | None,
    ) -> object:
        calls.append(arguments)
        if arguments["action"] == "PrepareCreate":
            assert len(calls) == 1
            return prepared
        assert arguments["action"] == "Create"
        assert len(calls) == 2
        return created

    monkeypatch.setattr(VssHelperClient, "_invoke", invoke)
    client = object.__new__(VssHelperClient)
    client._source_volume = "F:\\"
    assert client.create(run_id=RUN_ID, source_volume="F:\\") is created
    assert [call["action"] for call in calls] == ["PrepareCreate", "Create"]
    with pytest.raises(vss.VssError, match="production_source_volume_invalid"):
        client.create(run_id=RUN_ID, source_volume="E:\\")
    assert len(calls) == 2


def test_public_create_stops_after_unconfirmed_prepare_timeout(
        monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def invoke(
        self: VssHelperClient, **arguments: str | None,
    ) -> object:
        calls.append(str(arguments["action"]))
        raise vss.VssError("prepare_create_timeout_unconfirmed")

    monkeypatch.setattr(VssHelperClient, "_invoke", invoke)
    client = object.__new__(VssHelperClient)
    client._source_volume = "F:\\"
    with pytest.raises(vss.VssError, match="prepare_create_timeout_unconfirmed"):
        client.create(run_id=RUN_ID, source_volume="F:\\")
    assert calls == ["PrepareCreate"]


def _write_timeout_journal(
    root: Path, state: str, *, source_volume: str = "F:\\",
    shadow_id: str = SHADOW_ID,
) -> None:
    identified = state != "creating"
    (root / f"{RUN_ID}.json").write_text(json.dumps({
        "version": 1, "runId": RUN_ID, "sourceVolume": source_volume,
        "volumeDeviceId": (
            r"\\?\Volume{33333333-3333-3333-3333-333333333333}" + "\\"
            if identified else None),
        "state": state, "shadowId": shadow_id if identified else None,
        "deviceObject": DEVICE if identified else None,
        "createdAtUtc": "2026-07-21T00:00:00.0000000Z",
        "updatedAtUtc": "2026-07-21T00:00:01.0000000Z",
    }), encoding="utf-8")


def test_prepare_create_timeout_rejects_visible_but_unconfirmed_journal(
        tmp_path: Path) -> None:
    journal_root = tmp_path / "journals"
    journal_root.mkdir()
    _write_timeout_journal(journal_root, "creating")
    runtime = vss._TrustedRuntime(
        powershell=Path("powershell.exe"), script=Path("helper.ps1"),
        journal_root=journal_root)

    def timeout(command: list[str], **kwargs: object):
        raise subprocess.TimeoutExpired(
            command, vss._HELPER_OUTER_TIMEOUT_SECONDS)

    with pytest.raises(vss.VssError, match="prepare_create_timeout_unconfirmed"):
        vss._HelperProcessAdapter(runtime, timeout).invoke(
            action="PrepareCreate", run_id=RUN_ID, source_volume="F:\\")


@pytest.mark.parametrize("outcome", ["outer_timeout", "runas_timeout"])
@pytest.mark.parametrize("state", ["creating", "created"])
def test_helper_timeout_rereads_and_returns_only_durable_journal_state(
        tmp_path: Path, outcome: str, state: str) -> None:
    journal_root = tmp_path / "journals"
    journal_root.mkdir()
    _write_timeout_journal(journal_root, state)
    runtime = vss._TrustedRuntime(
        powershell=Path("powershell.exe"), script=Path("helper.ps1"),
        journal_root=journal_root)
    def timed_runner(command: list[str], **kwargs: object):
        assert kwargs["timeout"] == vss._HELPER_OUTER_TIMEOUT_SECONDS
        if outcome == "outer_timeout":
            raise subprocess.TimeoutExpired(
                command, vss._HELPER_OUTER_TIMEOUT_SECONDS)
        return subprocess.CompletedProcess(
            command, vss._RUNAS_TIMEOUT_EXIT_CODE, "", "")
    result = vss._HelperProcessAdapter(runtime, timed_runner).invoke(
        action="Create", run_id=RUN_ID, source_volume="F:\\")
    assert result.state.value == state


def test_helper_timeout_with_no_durable_journal_fails_closed(tmp_path: Path) -> None:
    journal_root = tmp_path / "journals"
    journal_root.mkdir()
    runtime = vss._TrustedRuntime(
        powershell=Path("powershell.exe"), script=Path("helper.ps1"),
        journal_root=journal_root)
    def timeout(command: list[str], **kwargs: object):
        raise subprocess.TimeoutExpired(
            command, vss._HELPER_OUTER_TIMEOUT_SECONDS)
    with pytest.raises(vss.VssError, match="helper_timeout_journal_unreadable"):
        vss._HelperProcessAdapter(runtime, timeout).invoke(
            action="Create", run_id=RUN_ID, source_volume="F:\\")


@pytest.mark.parametrize("field,value", [
    ("sourceVolume", 7),
    ("volumeDeviceId", "not-a-volume-device"),
    ("deviceObject", r"\\server\share"),
])
def test_helper_timeout_wraps_every_malformed_durable_journal(
        tmp_path: Path, field: str, value: object) -> None:
    journal_root = tmp_path / "journals"
    journal_root.mkdir()
    _write_timeout_journal(journal_root, "created")
    path = journal_root / f"{RUN_ID}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[field] = value
    path.write_text(json.dumps(payload), encoding="utf-8")
    runtime = vss._TrustedRuntime(
        powershell=Path("powershell.exe"), script=Path("helper.ps1"),
        journal_root=journal_root)

    def timeout(command: list[str], **kwargs: object):
        raise subprocess.TimeoutExpired(
            command, vss._HELPER_OUTER_TIMEOUT_SECONDS)

    with pytest.raises(vss.VssError, match="helper_timeout_journal_unreadable"):
        vss._HelperProcessAdapter(runtime, timeout).invoke(
            action="Create", run_id=RUN_ID, source_volume="F:\\")


@pytest.mark.parametrize(
    ("outcome", "message"),
    [
        ("normal", "journal_identity_invalid"),
        ("outer_timeout", "helper_timeout_journal_unreadable"),
    ],
)
def test_inspect_owned_rejects_wrong_embedded_run_on_normal_and_timeout(
        tmp_path: Path, outcome: str, message: str) -> None:
    journal_root = tmp_path / "journals"
    journal_root.mkdir()
    _write_timeout_journal(journal_root, "created")
    path = journal_root / f"{RUN_ID}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["runId"] = "99999999-9999-4999-8999-999999999999"
    path.write_text(json.dumps(payload), encoding="utf-8")
    runtime = vss._TrustedRuntime(
        powershell=Path("powershell.exe"), script=Path("helper.ps1"),
        journal_root=journal_root)

    def runner(command: list[str], **kwargs: object):
        if outcome == "outer_timeout":
            raise subprocess.TimeoutExpired(
                command, vss._HELPER_OUTER_TIMEOUT_SECONDS)
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(vss.VssError, match=message):
        vss._HelperProcessAdapter(runtime, runner).invoke(
            action="InspectOwned", run_id=RUN_ID)


@pytest.mark.parametrize(
    ("outcome", "action", "arguments", "state", "source_volume",
     "shadow_id", "message"),
    [
        ("normal", "PrepareCreate", {"source_volume": "F:\\"},
         "creating", "E:\\", SHADOW_ID, "helper_source_volume_mismatch"),
        ("normal", "Create", {"source_volume": "F:\\"},
         "created", "E:\\", SHADOW_ID, "helper_source_volume_mismatch"),
        ("outer_timeout", "Create", {"source_volume": "F:\\"},
         "created", "E:\\", SHADOW_ID, "helper_source_volume_mismatch"),
        ("runas_timeout", "Create", {"source_volume": "F:\\"},
         "created", "E:\\", SHADOW_ID, "helper_source_volume_mismatch"),
        ("normal", "Adopt", {"expected_shadow_id":
             "{33333333-3333-3333-3333-333333333333}"},
         "adopted", "F:\\", SHADOW_ID, "helper_shadow_id_mismatch"),
        ("outer_timeout", "Adopt", {"expected_shadow_id":
             "{33333333-3333-3333-3333-333333333333}"},
         "adopted", "F:\\", SHADOW_ID, "helper_shadow_id_mismatch"),
        ("normal", "DeleteExact", {"expected_shadow_id":
             "{33333333-3333-3333-3333-333333333333}"},
         "deleted", "F:\\", SHADOW_ID, "helper_shadow_id_mismatch"),
        ("outer_timeout", "DeleteExact", {"expected_shadow_id":
             "{33333333-3333-3333-3333-333333333333}"},
         "deleted", "F:\\", SHADOW_ID, "helper_shadow_id_mismatch"),
        ("runas_timeout", "DeleteExact", {"expected_shadow_id":
             "{33333333-3333-3333-3333-333333333333}"},
         "deleted", "F:\\", SHADOW_ID, "helper_shadow_id_mismatch"),
    ],
)
def test_normal_and_timeout_returns_require_action_specific_identity(
        tmp_path: Path, outcome: str, action: str,
        arguments: dict[str, str], state: str, source_volume: str,
        shadow_id: str, message: str) -> None:
    journal_root = tmp_path / "journals"
    journal_root.mkdir()
    _write_timeout_journal(
        journal_root, state, source_volume=source_volume,
        shadow_id=shadow_id)
    runtime = vss._TrustedRuntime(
        powershell=Path("powershell.exe"), script=Path("helper.ps1"),
        journal_root=journal_root)

    def runner(command: list[str], **kwargs: object):
        if outcome == "outer_timeout":
            raise subprocess.TimeoutExpired(
                command, vss._HELPER_OUTER_TIMEOUT_SECONDS)
        return subprocess.CompletedProcess(
            command,
            vss._RUNAS_TIMEOUT_EXIT_CODE if outcome == "runas_timeout" else 0,
            "", "")

    with pytest.raises(vss.VssJournalError, match=message):
        vss._HelperProcessAdapter(runtime, runner).invoke(
            action=action, run_id=RUN_ID, **arguments)


@pytest.mark.parametrize(
    ("action", "arguments", "state", "outcome"),
    [
        ("Adopt", {"expected_shadow_id": SHADOW_ID}, "adopted", "normal"),
        ("Adopt", {"expected_shadow_id": SHADOW_ID}, "adopted",
         "outer_timeout"),
        ("DeleteExact", {"expected_shadow_id": SHADOW_ID}, "deleted",
         "normal"),
        ("DeleteExact", {"expected_shadow_id": SHADOW_ID}, "deleted",
         "outer_timeout"),
        ("DeleteExact", {"expected_shadow_id": SHADOW_ID}, "deleted",
         "runas_timeout"),
        ("InspectOwned", {}, "adopted", "normal"),
        ("InspectOwned", {}, "adopted", "outer_timeout"),
    ],
)
def test_every_owned_action_rejects_unexpected_source_volume(
        tmp_path: Path, action: str, arguments: dict[str, str],
        state: str, outcome: str) -> None:
    journal_root = tmp_path / "journals"
    journal_root.mkdir()
    _write_timeout_journal(
        journal_root, state, source_volume="E:\\")
    runtime = vss._TrustedRuntime(
        powershell=Path("powershell.exe"), script=Path("helper.ps1"),
        journal_root=journal_root)

    def runner(command: list[str], **kwargs: object):
        if outcome == "outer_timeout":
            raise subprocess.TimeoutExpired(
                command, vss._HELPER_OUTER_TIMEOUT_SECONDS)
        return subprocess.CompletedProcess(
            command,
            vss._RUNAS_TIMEOUT_EXIT_CODE
            if outcome == "runas_timeout" else 0,
            "", "")

    adapter = vss._HelperProcessAdapter(runtime, runner)
    class BoundClient(VssHelperClient):
        def _invoke(self, **values):
            return adapter.invoke(**values)

    client = object.__new__(BoundClient)
    client._source_volume = "F:\\"
    public_call = {
        "Adopt": lambda: client.adopt(
            run_id=RUN_ID, shadow_id=SHADOW_ID
        ),
        "DeleteExact": lambda: client.delete_exact(
            run_id=RUN_ID, shadow_id=SHADOW_ID
        ),
        "InspectOwned": lambda: client.inspect_owned(run_id=RUN_ID),
    }[action]
    with pytest.raises(
        vss.VssJournalError, match="helper_source_volume_mismatch"
    ):
        public_call()


def test_acl_probe_has_finite_timeout_and_fails_closed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(command: list[str], **kwargs: object):
        assert kwargs["timeout"] == vss._ACL_PROBE_TIMEOUT_SECONDS
        raise subprocess.TimeoutExpired(
            command, vss._ACL_PROBE_TIMEOUT_SECONDS)
    monkeypatch.setattr(vss.subprocess, "run", timeout)
    with pytest.raises(vss.VssTrustError, match="journal_acl_probe_timeout"):
        vss._read_fixed_acl_evidence()


class _PrivateTestTrustProbe:
    """Tests own all injectable trust evidence; production never imports this."""

    def __init__(self, fault: str | None = None) -> None:
        self.fault = fault
        self.run_as_calls = 0

    def canonical(self, path: Path) -> Path:
        if self.fault == "canonical_missing" and path == vss._FIXED_TRUST.script:
            raise FileNotFoundError(path)
        return path

    def has_reparse_in_chain(self, path: Path) -> bool:
        return (
            self.fault == "powershell_reparse"
            and path == vss._FIXED_TRUST.powershell
        ) or (
            self.fault == "journal_reparse"
            and path == vss._FIXED_TRUST.journal_root
        )

    def sha256(self, path: Path) -> str:
        expected = vss._FIXED_TRUST.helper_sha256[path.name]
        if self.fault in {"entry_hash", "module_hash"}:
            selected = (
                "Invoke-WeFlowVssHelper.ps1"
                if self.fault == "entry_hash"
                else "WeFlowVssHelper.psm1"
            )
            if path.name == selected:
                return "0" * 64
        return expected

    def current_user_sid(self) -> str:
        return "S-1-5-21-UNIT-TEST"

    def journal_acl(self, path: Path) -> vss._AclSnapshot:
        user = vss._AclAce(
            "S-1-5-21-UNIT-TEST", "Allow", vss._FULL_CONTROL,
            vss._CONTAINER_AND_OBJECT_INHERIT, 0, False)
        system = vss._AclAce(
            "S-1-5-18", "Allow", vss._FULL_CONTROL,
            vss._CONTAINER_AND_OBJECT_INHERIT, 0, False)
        if self.fault == "journal_acl_unprotected":
            return vss._AclSnapshot(False, (user, system))
        if self.fault == "journal_acl_duplicate":
            return vss._AclSnapshot(True, (user, user, system))
        if self.fault == "journal_acl_partial":
            partial = replace(user, rights=1)
            return vss._AclSnapshot(True, (user, partial, system))
        if self.fault == "journal_acl_flags":
            return vss._AclSnapshot(
                True, (replace(user, inheritance_flags=0), system))
        if self.fault == "journal_acl_propagation":
            return vss._AclSnapshot(
                True, (replace(user, propagation_flags=2), system))
        if self.fault == "journal_acl_inherited":
            return vss._AclSnapshot(
                True, (replace(user, inherited=True), system))
        if self.fault == "journal_acl_deny":
            return vss._AclSnapshot(
                True, (replace(user, access_type="Deny"), system))
        if self.fault == "journal_acl_unknown":
            return vss._AclSnapshot(
                True, (replace(user, sid="S-1-5-32-544"), system))
        return vss._AclSnapshot(True, (user, system))


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("canonical_missing", "trusted_path_missing"),
        ("powershell_reparse", "trusted_path_reparse"),
        ("entry_hash", "trusted_helper_hash_mismatch"),
        ("module_hash", "trusted_helper_hash_mismatch"),
        ("journal_reparse", "trusted_path_reparse"),
        ("journal_acl_unprotected", "journal_acl_invalid"),
        ("journal_acl_duplicate", "journal_acl_invalid"),
        ("journal_acl_partial", "journal_acl_invalid"),
        ("journal_acl_flags", "journal_acl_invalid"),
        ("journal_acl_propagation", "journal_acl_invalid"),
        ("journal_acl_inherited", "journal_acl_invalid"),
        ("journal_acl_deny", "journal_acl_invalid"),
        ("journal_acl_unknown", "journal_acl_invalid"),
    ],
)
def test_private_trust_adapter_rejects_every_pre_elevation_fault(
        fault: str, message: str) -> None:
    probe = _PrivateTestTrustProbe(fault)
    with pytest.raises(vss.VssTrustError, match=message):
        vss._validate_trust(vss._FIXED_TRUST, probe)
    assert probe.run_as_calls == 0


@pytest.mark.parametrize("fault", [
    "journal_acl_unprotected", "journal_acl_duplicate",
    "journal_acl_partial", "journal_acl_flags",
    "journal_acl_propagation", "journal_acl_inherited",
    "journal_acl_deny", "journal_acl_unknown",
])
def test_every_acl_tuple_drift_stops_before_process_adapter(
        fault: str, monkeypatch: pytest.MonkeyPatch) -> None:
    probe = _PrivateTestTrustProbe(fault)
    adapter_calls: list[object] = []
    monkeypatch.setattr(
        vss, "_validate_production_trust",
        lambda: vss._validate_trust(vss._FIXED_TRUST, probe))
    monkeypatch.setattr(
        vss, "_HelperProcessAdapter",
        lambda *args, **kwargs: adapter_calls.append((args, kwargs)))
    client = object.__new__(VssHelperClient)
    with pytest.raises(vss.VssTrustError, match="journal_acl_invalid"):
        client.inspect_owned(run_id=RUN_ID)
    assert adapter_calls == []


def test_private_trust_adapter_rejects_helper_outside_fixed_repo_root() -> None:
    outside = Path(r"C:\outside\vss-helper")
    fixed = replace(
        vss._FIXED_TRUST,
        helper_root=outside,
        script=outside / "Invoke-WeFlowVssHelper.ps1",
        module=outside / "WeFlowVssHelper.psm1",
    )
    probe = _PrivateTestTrustProbe()
    with pytest.raises(vss.VssTrustError, match="trusted_helper_root_mismatch"):
        vss._validate_trust(fixed, probe)
    assert probe.run_as_calls == 0


def test_public_invoke_stops_before_private_process_adapter_when_trust_fails(
        monkeypatch: pytest.MonkeyPatch) -> None:
    client = object.__new__(VssHelperClient)
    adapter_calls: list[object] = []

    def reject_trust() -> vss._TrustedRuntime:
        raise vss.VssTrustError("trusted_helper_hash_mismatch")

    monkeypatch.setattr(vss, "_validate_production_trust", reject_trust)
    monkeypatch.setattr(
        vss, "_HelperProcessAdapter",
        lambda *args, **kwargs: adapter_calls.append((args, kwargs)))
    with pytest.raises(vss.VssTrustError, match="trusted_helper_hash_mismatch"):
        client.inspect_owned(run_id=RUN_ID)
    assert adapter_calls == []


class FakeClient:
    def __init__(self, *, copy_fails: bool = False) -> None:
        self.state = "missing"
        self.calls: list[str] = []
        self.copy_fails = copy_fails

    def create(self, *, run_id: str, source_volume: str):
        self.calls.append("create")
        self.state = "created"
        return self.inspect_owned(run_id=run_id)

    def adopt(self, *, run_id: str, shadow_id: str):
        self.calls.append("adopt")
        self.state = "adopted"
        return self.inspect_owned(run_id=run_id)

    def inspect_owned(self, *, run_id: str):
        self.calls.append("inspect")
        return type("Journal", (), {
            "state": self.state, "shadow_id": SHADOW_ID,
            "device_object": DEVICE, "source_volume": "F:\\",
        })()

    def delete_exact(self, *, run_id: str, shadow_id: str):
        self.calls.append("delete")
        assert shadow_id == SHADOW_ID
        self.state = "deleted"
        return type("Journal", (), {
            "state": self.state, "shadow_id": SHADOW_ID,
            "device_object": DEVICE, "source_volume": "F:\\",
        })()


@pytest.mark.parametrize("failure_stage", [
    "create_return", "after_created", "after_adopted", "during_copy",
])
def test_stage_exit_always_inspects_and_deletes_owned_shadow(
        failure_stage: str, monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path) -> None:
    client = FakeClient()

    if failure_stage == "create_return":
        original = client.create

        def fail_after_create(**kwargs: object):
            original(**kwargs)
            raise RuntimeError("after_created_journal")

        client.create = fail_after_create
    elif failure_stage == "after_created":
        client.adopt = lambda **kwargs: (_ for _ in ()).throw(
            RuntimeError("before_adopt"))
    elif failure_stage == "after_adopted":
        original_adopt = client.adopt

        def fail_after_adopt(**kwargs: object):
            original_adopt(**kwargs)
            raise RuntimeError("after_adopted_journal")

        client.adopt = fail_after_adopt
    else:
        monkeypatch.setattr(
            "weflow_chat.vss.copy_owned_shadow_to_staging",
            lambda **kwargs: (_ for _ in ()).throw(
                RuntimeError("copy_failed")))

    with pytest.raises(RuntimeError):
        acquire_vss_staging(
            client=client, run_id=RUN_ID, source_volume="F:\\",
            live_path=r"F:\synthetic\wxid_test\db_storage",
            source_account_name=ACCOUNT_NAME,
            run_root=tmp_path / "E-run", snapshots_root=tmp_path)
    assert client.state == "deleted"
    assert client.calls[-1] == "inspect"


def test_creating_without_identity_is_inspected_but_never_deleted(
        tmp_path: Path) -> None:
    client = FakeClient()

    def fail_unknown(**kwargs: object):
        client.calls.append("create")
        client.state = "creating"
        raise RuntimeError("unknown_shadow_risk")

    def inspect_unknown(**kwargs: object):
        client.calls.append("inspect")
        return type("Journal", (), {
            "state": "creating", "shadow_id": None,
            "device_object": None, "source_volume": "F:\\",
        })()

    client.create = fail_unknown
    client.inspect_owned = inspect_unknown
    with pytest.raises(VssCleanupError, match="owned_shadow_cleanup_failed"):
        acquire_vss_staging(
            client=client, run_id=RUN_ID, source_volume="F:\\",
            live_path=r"F:\synthetic\wxid_test\db_storage",
            source_account_name=ACCOUNT_NAME,
            run_root=tmp_path / "E-run", snapshots_root=tmp_path)
    assert "inspect" in client.calls
    assert "delete" not in client.calls


def test_finally_inspects_and_deletes_after_copy_failure(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    client = FakeClient()

    def fail_copy(*args: object, **kwargs: object) -> StagingReceipt:
        raise OSError("synthetic_copy_failure")

    monkeypatch.setattr("weflow_chat.vss.copy_owned_shadow_to_staging",
                        fail_copy)
    with pytest.raises(OSError, match="synthetic_copy_failure"):
        acquire_vss_staging(
            client=client, run_id=RUN_ID, source_volume="F:\\",
            live_path=r"F:\synthetic\wxid_test\db_storage",
            source_account_name=ACCOUNT_NAME,
            run_root=tmp_path / "E-run", snapshots_root=tmp_path)
    assert client.state == "deleted"
    assert client.calls[-3:] == ["inspect", "delete", "inspect"]


def test_success_returns_only_after_deleted(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    client = FakeClient()
    staging = tmp_path / "E-run" / "vss-staging"
    relative_db = PureWindowsPath(ACCOUNT_NAME, "db_storage")
    receipt = StagingReceipt(
        staging, ACCOUNT_NAME, relative_db, 1, 9, "A" * 64)
    monkeypatch.setattr("weflow_chat.vss.copy_owned_shadow_to_staging",
                        lambda **kwargs: receipt)
    result = acquire_vss_staging(
        client=client, run_id=RUN_ID, source_volume="F:\\",
        live_path=r"F:\synthetic\wxid_test\db_storage",
        source_account_name=ACCOUNT_NAME,
        run_root=tmp_path / "E-run", snapshots_root=tmp_path)
    assert result == receipt
    assert client.state == "deleted"
    assert "GLOBALROOT" not in str(result.staging_path)
    assert result.source_account_name == ACCOUNT_NAME
    assert result.account_db_relative_path == relative_db


def test_wrong_source_owned_journal_never_triggers_delete(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class WrongSourceClient:
        def __init__(self) -> None:
            self.delete_calls = 0

        def create(self, **kwargs: object):
            return type("Journal", (), {
                "state": "created", "shadow_id": SHADOW_ID,
                "device_object": DEVICE, "source_volume": "F:\\",
            })()

        def adopt(self, **kwargs: object):
            return type("Journal", (), {
                "state": "adopted", "shadow_id": SHADOW_ID,
                "device_object": DEVICE, "source_volume": "F:\\",
            })()

        def inspect_owned(self, **kwargs: object):
            return type("Journal", (), {
                "state": "adopted", "shadow_id": SHADOW_ID,
                "device_object": DEVICE, "source_volume": "E:\\",
            })()

        def delete_exact(self, **kwargs: object):
            self.delete_calls += 1
            raise AssertionError("delete_must_not_run")

    client = WrongSourceClient()
    monkeypatch.setattr(
        vss, "copy_owned_shadow_to_staging",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("copy_must_not_run")))

    with pytest.raises(
            VssCleanupError, match="owned_shadow_cleanup_failed"):
        acquire_vss_staging(
            client=client, run_id=RUN_ID, source_volume="F:\\",
            live_path=r"F:\synthetic\wxid_test\db_storage",
            source_account_name=ACCOUNT_NAME,
            run_root=tmp_path / "E-run", snapshots_root=tmp_path)

    assert client.delete_calls == 0


def test_primary_and_cleanup_failures_are_both_preserved_without_outer_leak(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    primary = OSError("synthetic_primary_secret")
    cleanup = RuntimeError("synthetic_cleanup_secret")

    class DualFailureClient(FakeClient):
        def __init__(self) -> None:
            super().__init__()
            self.inspect_count = 0

        def inspect_owned(self, *, run_id: str):
            self.inspect_count += 1
            if self.inspect_count >= 4:
                raise cleanup
            return super().inspect_owned(run_id=run_id)

    client = DualFailureClient()
    monkeypatch.setattr(
        vss, "copy_owned_shadow_to_staging",
        lambda **kwargs: (_ for _ in ()).throw(primary))

    with pytest.raises(VssCleanupError) as caught:
        acquire_vss_staging(
            client=client, run_id=RUN_ID, source_volume="F:\\",
            live_path=r"F:\synthetic\wxid_test\db_storage",
            source_account_name=ACCOUNT_NAME,
            run_root=tmp_path / "E-run", snapshots_root=tmp_path)

    assert str(caught.value) == "owned_shadow_cleanup_failed"
    assert "secret" not in str(caught.value)
    assert isinstance(caught.value.__cause__, BaseExceptionGroup)
    assert caught.value.__cause__.exceptions == (primary, cleanup)


def test_cleanup_only_failure_uses_original_cleanup_as_cause(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cleanup = RuntimeError("synthetic_cleanup_secret")
    receipt = StagingReceipt(
        tmp_path / "E-run" / "vss-staging", ACCOUNT_NAME,
        PureWindowsPath(ACCOUNT_NAME, "db_storage"), 1, 9, "A" * 64)

    class CleanupFailureClient(FakeClient):
        def __init__(self) -> None:
            super().__init__()
            self.inspect_count = 0

        def inspect_owned(self, *, run_id: str):
            self.inspect_count += 1
            if self.inspect_count >= 4:
                raise cleanup
            return super().inspect_owned(run_id=run_id)

    client = CleanupFailureClient()
    monkeypatch.setattr(
        vss, "copy_owned_shadow_to_staging", lambda **kwargs: receipt)

    with pytest.raises(VssCleanupError) as caught:
        acquire_vss_staging(
            client=client, run_id=RUN_ID, source_volume="F:\\",
            live_path=r"F:\synthetic\wxid_test\db_storage",
            source_account_name=ACCOUNT_NAME,
            run_root=tmp_path / "E-run", snapshots_root=tmp_path)

    assert str(caught.value) == "owned_shadow_cleanup_failed"
    assert caught.value.__cause__ is cleanup


def test_synthetic_cleanup_requires_true_child_and_rejects_reparse(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "synthetic-root"
    child = root / "run-1"
    child.mkdir(parents=True)
    (child / "session.db").write_bytes(b"synthetic")
    with pytest.raises(VssPathError, match="cleanup_root_forbidden"):
        remove_synthetic_tree(root, allowed_root=root)
    monkeypatch.setattr("weflow_chat.vss._is_reparse_point",
                        lambda path: path.name == "session.db")
    with pytest.raises(VssPathError, match="cleanup_reparse_rejected"):
        remove_synthetic_tree(child, allowed_root=root)
    assert child.exists()


def test_staging_publication_uses_core_durable_gates(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "shadow-source"
    (source / "nested").mkdir(parents=True)
    (source / "session.db").write_bytes(b"database")
    (source / "nested" / "session.db-wal").write_bytes(b"wal")
    run_root = tmp_path / "run"
    run_root.mkdir()
    relative_db = PureWindowsPath(ACCOUNT_NAME, "db_storage")

    monkeypatch.setattr(
        vss, "_assert_shadow_account_db_source",
        lambda *args, **kwargs: relative_db)
    monkeypatch.setattr(
        vss, "_assert_fixed_run_root", lambda path, **_kwargs: path
    )

    flushed: list[Path] = []
    published: list[tuple[Path, Path]] = []
    verified: list[Path] = []
    real_flush = vss.flush_file_durable
    real_publish = vss.replace_write_through
    real_verify = vss.verify_published_directory_durable

    def flush(path: Path) -> None:
        flushed.append(path)
        real_flush(path)

    def publish(source_path: Path, destination_path: Path) -> None:
        published.append((source_path, destination_path))
        real_publish(source_path, destination_path)

    def verify(destination: Path, **kwargs: object):
        verified.append(destination)
        return real_verify(destination, **kwargs)

    monkeypatch.setattr(vss, "flush_file_durable", flush)
    monkeypatch.setattr(vss, "replace_write_through", publish)
    monkeypatch.setattr(
        vss, "verify_published_directory_durable", verify)

    receipt = copy_owned_shadow_to_staging(
        shadow_source=source, run_root=run_root,
        snapshots_root=run_root.parent,
        source_account_name=ACCOUNT_NAME)

    assert sorted(path.name for path in flushed) == [
        "session.db", "session.db-wal"]
    assert len(published) == 1
    assert published[0][1] == run_root / "vss-staging"
    assert verified == [run_root / "vss-staging"]
    assert receipt.staging_path == run_root / "vss-staging"
    assert receipt.file_count == 2


def test_staging_flush_failure_prevents_directory_publication(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "shadow-source"
    source.mkdir()
    (source / "session.db").write_bytes(b"database")
    run_root = tmp_path / "run"
    run_root.mkdir()
    relative_db = PureWindowsPath(ACCOUNT_NAME, "db_storage")
    monkeypatch.setattr(
        vss, "_assert_shadow_account_db_source",
        lambda *args, **kwargs: relative_db)
    monkeypatch.setattr(
        vss, "_assert_fixed_run_root", lambda path, **_kwargs: path
    )
    monkeypatch.setattr(
        vss, "flush_file_durable",
        lambda path: (_ for _ in ()).throw(
            OSError("synthetic_flush_failure")))
    publications: list[tuple[Path, Path]] = []
    monkeypatch.setattr(
        vss, "replace_write_through",
        lambda source_path, destination_path:
        publications.append((source_path, destination_path)))

    with pytest.raises(OSError, match="synthetic_flush_failure"):
        copy_owned_shadow_to_staging(
            shadow_source=source, run_root=run_root,
            snapshots_root=run_root.parent,
            source_account_name=ACCOUNT_NAME)

    assert publications == []
    assert not (run_root / "vss-staging").exists()


def test_staging_return_requires_post_publication_reenumeration_and_rehash(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "shadow-source"
    source.mkdir()
    (source / "session.db").write_bytes(b"database")
    run_root = tmp_path / "run"
    run_root.mkdir()
    relative_db = PureWindowsPath(ACCOUNT_NAME, "db_storage")
    monkeypatch.setattr(
        vss, "_assert_shadow_account_db_source",
        lambda *args, **kwargs: relative_db)
    monkeypatch.setattr(
        vss, "_assert_fixed_run_root", lambda path, **_kwargs: path
    )
    real_publish = vss.replace_write_through

    def publish_then_mutate(
            source_path: Path, destination_path: Path) -> None:
        real_publish(source_path, destination_path)
        published_file = (
            destination_path / Path(relative_db) / "session.db")
        published_file.write_bytes(b"changed-after-publication")

    monkeypatch.setattr(vss, "replace_write_through", publish_then_mutate)

    with pytest.raises(
            vss.CopyVerificationError,
            match="published_manifest_mismatch"):
        copy_owned_shadow_to_staging(
            shadow_source=source, run_root=run_root,
            snapshots_root=run_root.parent,
            source_account_name=ACCOUNT_NAME)
