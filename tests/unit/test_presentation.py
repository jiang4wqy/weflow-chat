from dataclasses import replace
import json
import os
import shutil
import stat
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from weflow_chat.media import import_media_staging
from weflow_chat.presentation import (
    PresentationError,
    build_presentation,
    read_presentation_receipt,
)


ACCOUNT = "wxid_synthetic"
SESSION_SHA256 = (
    "C0982ECB2A04CDD914AF70FA368E1A2FCD1F0C271F77B5844B39D2085A58C1C0"
)
MESSAGE_SHA256 = (
    "461119F91047311DC1B09ABF4AA89C0B4A2DCB8A9421CF13BAEC52C582692304"
)
ATTACH_SHA256 = (
    "646CF1E8C38A30439ABB10704CF4771456CE2D88708DBF5746C0EA38FA97B53C"
)
VIDEO_SHA256 = (
    "CB82221685A8FF6DB15AFFAD875F8753B4BD92A9587264AE00CD20B33FAB7D75"
)
CHANGED_ATTACH_SHA256 = (
    "C773779E7CFE91B29B5F4E3F7E332615CB88A287A959D5DADCD448ED9A3CA3E3"
)
DEEP_ATTACH_PARENT = "msg/attach/" + "a" * 32 + "/2026-07/Img"


def _active_tree(root: Path) -> Path:
    active = root / "active"
    account = active / ACCOUNT / "db_storage"
    session = account / "session" / "session.db"
    message = account / "message" / "message_0.db"
    session.parent.mkdir(parents=True)
    message.parent.mkdir(parents=True)
    session.write_bytes(b"session-db")
    message.write_bytes(b"message-db")
    return active


def _media_receipt(
        root: Path,
        *,
        attach_bytes: bytes = b"attach-media",
        attach_sha256: str = ATTACH_SHA256,
        attach_relative_path: str = "msg/attach/a.dat",
):
    staging = root / "media-staging"
    account = staging / ACCOUNT
    attach = account / Path(attach_relative_path)
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True, exist_ok=True)
    video.parent.mkdir(parents=True, exist_ok=True)
    attach.write_bytes(attach_bytes)
    video.write_bytes(b"video-media")
    files = (
        SimpleNamespace(
            relative_path=attach_relative_path,
            size=len(attach_bytes),
            sha256=attach_sha256,
        ),
        SimpleNamespace(
            relative_path="msg/video/b.jpg",
            size=11,
            sha256=VIDEO_SHA256,
        ),
    )
    staging_manifest = json.dumps(
        [
            {
                "relativePath": item.relative_path,
                "size": item.size,
                "sha256": item.sha256,
            }
            for item in files
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return import_media_staging(
        SimpleNamespace(
            staging_path=staging,
            source_account_name=ACCOUNT,
            files=files,
            file_count=2,
            byte_count=len(attach_bytes) + 11,
            manifest_sha256=sha256(staging_manifest).hexdigest().upper(),
        ),
        media_store_root=root / "media-store",
    )


def _identity(path: Path) -> tuple[int, int]:
    information = path.stat()
    return information.st_dev, information.st_ino


def _media_manifest_bytes(manifest) -> bytes:
    return json.dumps(
        {
            "schemaVersion": manifest.schema_version,
            "sourceAccountName": manifest.source_account_name,
            "fileCount": manifest.file_count,
            "byteCount": manifest.byte_count,
            "files": [
                {
                    "relativePath": item.relative_path,
                    "size": item.size,
                    "sha256": item.sha256,
                    "volumeSerial": item.volume_serial,
                    "fileId": item.file_id,
                }
                for item in manifest.files
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _assert_no_reparse(root: Path) -> None:
    for path in (root, *root.rglob("*")):
        information = path.lstat()
        assert not path.is_symlink()
        assert not (
            getattr(information, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        )


def _built_receipt(
        tmp_path: Path,
        *,
        run_name: str = "run",
):
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    run_root = tmp_path / run_name
    run_root.mkdir()
    destination = run_root / "presentation"
    receipt = build_presentation(
        active_root=active,
        media_receipt=media,
        destination_root=destination,
        account_name=ACCOUNT,
    )
    return receipt, destination


def _write_canonical_json(path: Path, value: object) -> None:
    path.write_bytes(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8"))


def _make_junction(link: Path, target: Path) -> None:
    powershell = Path(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "& { param($link,$target) $null=New-Item "
            "-ItemType Junction -Path $link -Target $target }",
            str(link),
            str(target),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip("junction creation unavailable")


def test_build_presentation_copies_database_and_media_with_independent_identity(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    run_root = tmp_path / "run"
    run_root.mkdir()
    destination = run_root / "presentation"

    receipt = build_presentation(
        active_root=active,
        media_receipt=media,
        destination_root=destination,
        account_name=ACCOUNT,
    )

    expected_files = (
        f"{ACCOUNT}/db_storage/message/message_0.db",
        f"{ACCOUNT}/db_storage/session/session.db",
        f"{ACCOUNT}/msg/attach/a.dat",
        f"{ACCOUNT}/msg/video/b.jpg",
    )
    assert tuple(
        path.relative_to(destination).as_posix()
        for path in sorted(destination.rglob("*"))
        if path.is_file()
    ) == expected_files
    assert receipt.schema_version == 1
    assert receipt.presentation_root == destination.resolve()
    assert receipt.manifest_path == (
        destination.parent / "presentation-manifest.json"
    ).resolve()
    assert receipt.file_count == 4
    assert receipt.byte_count == 43
    assert tuple(
        item.relative_path for item in receipt.manifest.files
    ) == expected_files
    assert tuple(item.sha256 for item in receipt.manifest.files) == (
        MESSAGE_SHA256,
        SESSION_SHA256,
        ATTACH_SHA256,
        VIDEO_SHA256,
    )

    for relative in expected_files[:2]:
        source = active / relative
        published = destination / relative
        assert published.read_bytes() == source.read_bytes()
        assert _identity(published) != _identity(source)
    media_root = media.manifest_path.parent / ACCOUNT
    for item in media.manifest.files:
        source = media_root / item.relative_path
        published = destination / ACCOUNT / item.relative_path
        assert published.read_bytes() == source.read_bytes()
        assert _identity(source) == (
            item.volume_serial,
            item.file_id,
        )
        assert _identity(published) != _identity(source)
    _assert_no_reparse(destination)

    canonical = {
        "schemaVersion": 1,
        "sourceAccountName": ACCOUNT,
        "mediaStoreManifestSha256": media.manifest_sha256,
        "fileCount": 4,
        "byteCount": 43,
        "files": [
            {
                "relativePath": item.relative_path,
                "kind": item.kind,
                "size": item.size,
                "sha256": item.sha256,
                "deviceId": item.device_id,
                "fileId": item.file_id,
            }
            for item in receipt.manifest.files
        ],
    }
    expected_hash = sha256(json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest().upper()
    assert receipt.manifest_sha256 == expected_hash
    assert read_presentation_receipt(
        receipt.manifest_path,
        expected_presentation_root=destination,
        account_name=ACCOUNT,
    ) == receipt


@pytest.mark.skipif(os.name != "nt", reason="Windows MAX_PATH regression")
def test_build_presentation_publishes_deep_media_below_legacy_max_path(
        tmp_path: Path) -> None:
    attach_relative = DEEP_ATTACH_PARENT + "/" + "b" * 32 + ".dat"
    active = _active_tree(tmp_path)
    media = _media_receipt(
        tmp_path,
        attach_relative_path=attach_relative,
    )
    unpadded = (
        tmp_path
        / "presentation"
        / ACCOUNT
        / Path(attach_relative)
    )
    padding = 231 - len(str(unpadded)) - 1
    assert 1 <= padding <= 200
    run_root = tmp_path / ("r" * padding)
    run_root.mkdir()
    destination = run_root / "presentation"
    published = destination / ACCOUNT / Path(attach_relative)
    legacy_partial = (
        run_root
        / (".presentation.partial." + "0" * 32)
        / ACCOUNT
        / Path(attach_relative)
    )
    assert len(str(published)) == 231
    assert len(str(legacy_partial)) >= 260

    receipt = build_presentation(
        active_root=active,
        media_receipt=media,
        destination_root=destination,
        account_name=ACCOUNT,
    )

    assert published.read_bytes() == b"attach-media"
    assert receipt.presentation_root == destination.resolve()
    assert read_presentation_receipt(
        receipt.manifest_path,
        expected_presentation_root=destination,
        account_name=ACCOUNT,
    ) == receipt


@pytest.mark.skipif(os.name != "nt", reason="Windows MAX_PATH regression")
@pytest.mark.parametrize(
    ("attach_name", "final_length", "failed_budget"),
    (
        ("b" * 32 + ".dat", 260, "file"),
        ("b.dat", 250, "directory"),
    ),
)
def test_build_presentation_rejects_legacy_windows_path_overflow_before_partial(
        tmp_path: Path,
        attach_name: str,
        final_length: int,
        failed_budget: str,
) -> None:
    attach_relative = DEEP_ATTACH_PARENT + "/" + attach_name
    active = _active_tree(tmp_path)
    media = _media_receipt(
        tmp_path,
        attach_relative_path=attach_relative,
    )
    unpadded = (
        tmp_path
        / "presentation"
        / ACCOUNT
        / Path(attach_relative)
    )
    padding = final_length - len(str(unpadded)) - 1
    assert 1 <= padding <= 200
    run_root = tmp_path / ("r" * padding)
    run_root.mkdir()
    destination = run_root / "presentation"
    published = destination / ACCOUNT / Path(attach_relative)
    partial = (
        run_root
        / (".p." + "0" * 16)
        / ACCOUNT
        / Path(attach_relative)
    )
    if failed_budget == "file":
        assert len(str(published)) == 260
    else:
        assert len(str(published)) <= 259
        assert len(str(partial)) <= 259
        assert len(str(partial.parent)) > 247

    with pytest.raises(
        PresentationError,
        match=r"^presentation_path_budget_exceeded$",
    ):
        build_presentation(
            active_root=active,
            media_receipt=media,
            destination_root=destination,
            account_name=ACCOUNT,
        )

    assert tuple(run_root.iterdir()) == ()


def test_mutating_presentation_media_does_not_mutate_media_store(
        tmp_path: Path) -> None:
    receipt, destination = _built_receipt(tmp_path)
    store_file = (
        tmp_path
        / "media-store"
        / ACCOUNT
        / "msg"
        / "attach"
        / "a.dat"
    )
    presentation_file = (
        destination
        / ACCOUNT
        / "msg"
        / "attach"
        / "a.dat"
    )
    store_before = store_file.read_bytes()
    store_identity = _identity(store_file)

    presentation_file.write_bytes(b"presentation-mutated")

    assert presentation_file.read_bytes() == b"presentation-mutated"
    assert _identity(presentation_file) != store_identity
    assert store_file.read_bytes() == store_before
    assert _identity(store_file) == store_identity
    published_item = next(
        item
        for item in receipt.manifest.files
        if item.relative_path.endswith("/msg/attach/a.dat")
    )
    assert (published_item.device_id, published_item.file_id) != store_identity


def test_media_copy_supports_cross_volume(tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    with tempfile.TemporaryDirectory(
            prefix="weflow-presentation-media-") as media_temp:
        media_root = Path(media_temp)
        media = _media_receipt(media_root)
        if media_root.stat().st_dev == tmp_path.stat().st_dev:
            pytest.skip("a second filesystem volume is unavailable")
        run_root = tmp_path / "run"
        run_root.mkdir()
        destination = run_root / "presentation"

        build_presentation(
            active_root=active,
            media_receipt=media,
            destination_root=destination,
            account_name=ACCOUNT,
        )

        source = (
            media.manifest_path.parent
            / ACCOUNT
            / "msg"
            / "attach"
            / "a.dat"
        )
        published = (
            destination
            / ACCOUNT
            / "msg"
            / "attach"
            / "a.dat"
        )
        assert published.read_bytes() == source.read_bytes()
        assert published.stat().st_dev != source.stat().st_dev
        assert _identity(published) != _identity(source)


def test_presentation_receipt_rejects_extra_key(
        tmp_path: Path) -> None:
    receipt, destination = _built_receipt(tmp_path)
    value = json.loads(receipt.manifest_path.read_bytes())
    value["unexpected"] = 1
    _write_canonical_json(receipt.manifest_path, value)

    with pytest.raises(
        PresentationError,
        match=r"^presentation_receipt_invalid$",
    ):
        read_presentation_receipt(
            receipt.manifest_path,
            expected_presentation_root=destination,
            account_name=ACCOUNT,
        )


def test_presentation_receipt_rejects_duplicate_key(
        tmp_path: Path) -> None:
    receipt, destination = _built_receipt(tmp_path)
    original = receipt.manifest_path.read_bytes()
    receipt.manifest_path.write_bytes(
        original[:-1] + b',"schemaVersion":1}'
    )

    with pytest.raises(
        PresentationError,
        match=r"^presentation_receipt_invalid$",
    ):
        read_presentation_receipt(
            receipt.manifest_path,
            expected_presentation_root=destination,
            account_name=ACCOUNT,
        )


def test_presentation_receipt_rejects_bool_as_integer(
        tmp_path: Path) -> None:
    receipt, destination = _built_receipt(tmp_path)
    value = json.loads(receipt.manifest_path.read_bytes())
    value["manifest"]["files"][0]["deviceId"] = True
    _write_canonical_json(receipt.manifest_path, value)

    with pytest.raises(
        PresentationError,
        match=r"^presentation_receipt_invalid$",
    ):
        read_presentation_receipt(
            receipt.manifest_path,
            expected_presentation_root=destination,
            account_name=ACCOUNT,
        )


def test_presentation_receipt_rejects_manifest_hash_drift(
        tmp_path: Path) -> None:
    receipt, destination = _built_receipt(tmp_path)
    value = json.loads(receipt.manifest_path.read_bytes())
    value["manifest"]["files"][0]["sha256"] = "0" * 64
    _write_canonical_json(receipt.manifest_path, value)

    with pytest.raises(
        PresentationError,
        match=r"^presentation_receipt_invalid$",
    ):
        read_presentation_receipt(
            receipt.manifest_path,
            expected_presentation_root=destination,
            account_name=ACCOUNT,
        )


def test_presentation_receipt_rejects_file_identity_drift(
        tmp_path: Path) -> None:
    receipt, destination = _built_receipt(tmp_path)
    media = destination / ACCOUNT / "msg" / "attach" / "a.dat"
    payload = media.read_bytes()
    media.unlink()
    media.write_bytes(payload)

    with pytest.raises(
        PresentationError,
        match=r"^presentation_publication_mismatch$",
    ):
        read_presentation_receipt(
            receipt.manifest_path,
            expected_presentation_root=destination,
            account_name=ACCOUNT,
        )


def test_presentation_receipt_rejects_tree_drift(
        tmp_path: Path) -> None:
    receipt, destination = _built_receipt(tmp_path)
    (destination / ACCOUNT / "unexpected.dat").write_bytes(b"unexpected")

    with pytest.raises(
        PresentationError,
        match=r"^presentation_publication_mismatch$",
    ):
        read_presentation_receipt(
            receipt.manifest_path,
            expected_presentation_root=destination,
            account_name=ACCOUNT,
        )


def test_presentation_receipt_rejects_reparse_ancestor(
        tmp_path: Path) -> None:
    receipt, destination = _built_receipt(
        tmp_path,
        run_name="junction-target",
    )
    junction = tmp_path / "junction"
    _make_junction(junction, destination.parent)
    try:
        with pytest.raises(
            PresentationError,
            match=r"^presentation_receipt_invalid$",
        ):
            read_presentation_receipt(
                junction / receipt.manifest_path.name,
                expected_presentation_root=(
                    junction / destination.name
                ),
                account_name=ACCOUNT,
            )
    finally:
        os.rmdir(junction)


def test_missing_media_manifest_fails_before_publication(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    media.manifest_path.unlink()
    run_root = tmp_path / "run"
    run_root.mkdir()
    destination = run_root / "presentation"

    try:
        build_presentation(
            active_root=active,
            media_receipt=media,
            destination_root=destination,
            account_name=ACCOUNT,
        )
    except PresentationError as error:
        assert str(error) == "media_store_manifest_invalid"
    else:
        raise AssertionError("missing media manifest must fail")

    assert not os.path.lexists(destination)


def test_changed_media_manifest_fails_before_publication(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    media.manifest_path.write_bytes(b"{}")
    run_root = tmp_path / "run"
    run_root.mkdir()
    destination = run_root / "presentation"

    with pytest.raises(
        PresentationError,
        match=r"^media_store_manifest_mismatch$",
    ):
        build_presentation(
            active_root=active,
            media_receipt=media,
            destination_root=destination,
            account_name=ACCOUNT,
        )

    assert not os.path.lexists(destination)


def test_receipt_identity_mismatch_fails_before_publication(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    changed_file = replace(
        media.manifest.files[0],
        file_id=media.manifest.files[0].file_id + 1,
    )
    changed_manifest = replace(
        media.manifest,
        files=(changed_file, *media.manifest.files[1:]),
    )
    changed_bytes = _media_manifest_bytes(changed_manifest)
    media.manifest_path.write_bytes(changed_bytes)
    changed_receipt = replace(
        media,
        manifest=changed_manifest,
        manifest_sha256=sha256(changed_bytes).hexdigest().upper(),
    )
    run_root = tmp_path / "run"
    run_root.mkdir()
    destination = run_root / "presentation"

    with pytest.raises(
        PresentationError,
        match=r"^media_store_file_mismatch$",
    ):
        build_presentation(
            active_root=active,
            media_receipt=changed_receipt,
            destination_root=destination,
            account_name=ACCOUNT,
        )

    assert not os.path.lexists(destination)


def test_publication_must_preserve_verified_file_identities(
        tmp_path: Path, monkeypatch) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    run_root = tmp_path / "run"
    run_root.mkdir()
    destination = run_root / "presentation"

    def copying_publication(source: Path, target: Path) -> None:
        shutil.copytree(source, target)
        shutil.rmtree(source)

    monkeypatch.setattr(
        "weflow_chat.presentation.replace_write_through",
        copying_publication,
    )

    with pytest.raises(
        PresentationError,
        match=r"^presentation_publication_mismatch$",
    ):
        build_presentation(
            active_root=active,
            media_receipt=media,
            destination_root=destination,
            account_name=ACCOUNT,
        )


def test_media_copy_failure_leaves_no_published_presentation(
        tmp_path: Path, monkeypatch) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    run_root = tmp_path / "run"
    run_root.mkdir()
    destination = run_root / "presentation"
    real_copyfile = shutil.copyfile

    def fail_media_copy(source: Path, target: Path) -> None:
        if "media-store" in Path(source).parts:
            raise OSError("synthetic media-copy failure")
        real_copyfile(source, target)

    monkeypatch.setattr(
        "weflow_chat.presentation.shutil.copyfile",
        fail_media_copy,
    )

    with pytest.raises(
        PresentationError,
        match=r"^presentation_media_copy_failed$",
    ):
        build_presentation(
            active_root=active,
            media_receipt=media,
            destination_root=destination,
            account_name=ACCOUNT,
        )

    assert not os.path.lexists(destination)


def test_source_change_during_media_copy_fails_before_publication(
        tmp_path: Path, monkeypatch) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    run_root = tmp_path / "run"
    run_root.mkdir()
    destination = run_root / "presentation"
    real_copyfile = shutil.copyfile

    def mutate_source_after_copy(source: Path, target: Path) -> None:
        real_copyfile(source, target)
        source = Path(source)
        if "media-store" in source.parts and source.name == "a.dat":
            source.write_bytes(b"tamper-media")

    monkeypatch.setattr(
        "weflow_chat.presentation.shutil.copyfile",
        mutate_source_after_copy,
    )

    with pytest.raises(
        PresentationError,
        match=r"^presentation_media_copy_mismatch$",
    ):
        build_presentation(
            active_root=active,
            media_receipt=media,
            destination_root=destination,
            account_name=ACCOUNT,
        )

    assert not os.path.lexists(destination)


def test_corrupt_media_copy_fails_before_publication(
        tmp_path: Path, monkeypatch) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    run_root = tmp_path / "run"
    run_root.mkdir()
    destination = run_root / "presentation"
    real_copyfile = shutil.copyfile

    def corrupt_media_target(source: Path, target: Path) -> None:
        real_copyfile(source, target)
        if "media-store" in Path(source).parts:
            Path(target).write_bytes(b"corrupt")

    monkeypatch.setattr(
        "weflow_chat.presentation.shutil.copyfile",
        corrupt_media_target,
    )

    with pytest.raises(
        PresentationError,
        match=r"^presentation_media_copy_mismatch$",
    ):
        build_presentation(
            active_root=active,
            media_receipt=media,
            destination_root=destination,
            account_name=ACCOUNT,
        )

    assert not os.path.lexists(destination)


def test_store_replacement_does_not_mutate_old_presentation(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    first_media = _media_receipt(tmp_path)
    first_run = tmp_path / "run-1"
    first_run.mkdir()
    first_destination = first_run / "presentation"
    build_presentation(
        active_root=active,
        media_receipt=first_media,
        destination_root=first_destination,
        account_name=ACCOUNT,
    )
    old_link = (
        first_destination
        / ACCOUNT
        / "msg"
        / "attach"
        / "a.dat"
    )
    old_identity = _identity(old_link)

    second_media = _media_receipt(
        tmp_path,
        attach_bytes=b"attach-media-v2",
        attach_sha256=CHANGED_ATTACH_SHA256,
    )
    current_store_file = (
        second_media.manifest_path.parent
        / ACCOUNT
        / "msg"
        / "attach"
        / "a.dat"
    )

    assert current_store_file.read_bytes() == b"attach-media-v2"
    assert _identity(current_store_file) != old_identity
    assert old_link.read_bytes() == b"attach-media"
    assert _identity(old_link) == old_identity


def test_repeated_construction_never_mutates_existing_presentation(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    run_root = tmp_path / "run"
    run_root.mkdir()
    destination = run_root / "presentation"
    build_presentation(
        active_root=active,
        media_receipt=media,
        destination_root=destination,
        account_name=ACCOUNT,
    )
    before = tuple(
        (
            path.relative_to(destination).as_posix(),
            path.read_bytes(),
            _identity(path),
        )
        for path in sorted(destination.rglob("*"))
        if path.is_file()
    )

    with pytest.raises(
        PresentationError,
        match=r"^presentation_destination_invalid$",
    ):
        build_presentation(
            active_root=active,
            media_receipt=media,
            destination_root=destination,
            account_name=ACCOUNT,
        )

    after = tuple(
        (
            path.relative_to(destination).as_posix(),
            path.read_bytes(),
            _identity(path),
        )
        for path in sorted(destination.rglob("*"))
        if path.is_file()
    )
    assert after == before


def test_unexpected_active_top_level_path_fails_before_publication(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    unexpected = active / "unexpected"
    unexpected.mkdir()
    (unexpected / "foreign.db").write_bytes(b"foreign")
    media = _media_receipt(tmp_path)
    run_root = tmp_path / "run"
    run_root.mkdir()
    destination = run_root / "presentation"

    with pytest.raises(
        PresentationError,
        match=r"^presentation_active_invalid$",
    ):
        build_presentation(
            active_root=active,
            media_receipt=media,
            destination_root=destination,
            account_name=ACCOUNT,
        )

    assert not os.path.lexists(destination)
