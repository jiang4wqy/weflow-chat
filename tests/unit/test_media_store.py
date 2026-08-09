from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

import weflow_chat.media as media

from weflow_chat.media import (
    MediaImportError,
    import_media_staging,
    read_media_store_receipt,
)


ACCOUNT = "wxid_synthetic"
ATTACH_SHA256 = (
    "646CF1E8C38A30439ABB10704CF4771456CE2D88708DBF5746C0EA38FA97B53C"
)
VIDEO_SHA256 = (
    "CB82221685A8FF6DB15AFFAD875F8753B4BD92A9587264AE00CD20B33FAB7D75"
)
CHANGED_ATTACH_SHA256 = (
    "C773779E7CFE91B29B5F4E3F7E332615CB88A287A959D5DADCD448ED9A3CA3E3"
)


def _receipt_for_files(staging: Path, files):
    encoded = json.dumps(
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
    return SimpleNamespace(
        staging_path=staging,
        source_account_name=ACCOUNT,
        files=tuple(files),
        file_count=len(files),
        byte_count=sum(item.size for item in files),
        manifest_sha256=sha256(encoded).hexdigest().upper(),
    )


def _staging_receipt(
        staging: Path, *, attach_size: int = 12,
        attach_sha256: str = ATTACH_SHA256):
    return _receipt_for_files(staging, (
        SimpleNamespace(
            relative_path="msg/attach/a.dat",
            size=attach_size,
            sha256=attach_sha256,
        ),
        SimpleNamespace(
            relative_path="msg/video/b.jpg",
            size=11,
            sha256=VIDEO_SHA256,
        ),
    ))


def _tree_snapshot(root: Path) -> tuple[tuple[str, bytes, int], ...]:
    return tuple(
        (
            path.relative_to(root).as_posix(),
            path.read_bytes(),
            path.stat().st_mtime_ns,
        )
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def _tree_metadata_snapshot(root: Path):
    if not root.exists():
        return None
    result = []
    for path in (root, *sorted(root.rglob("*"))):
        info = path.lstat()
        result.append((
            "." if path == root else path.relative_to(root).as_posix(),
            stat.S_IFMT(info.st_mode),
            info.st_size,
            info.st_mtime_ns,
            info.st_dev,
            info.st_ino,
            path.read_bytes() if stat.S_ISREG(info.st_mode) else None,
        ))
    return tuple(result)


def _make_junction(link: Path, target: Path) -> None:
    powershell = Path(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    result = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "& { param($link,$target) $null=New-Item -ItemType Junction "
            "-Path $link -Target $target }",
            str(link),
            str(target),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip("junction creation unavailable")


def test_import_publishes_fixed_media_and_durable_manifest(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    source_before = _tree_snapshot(staging)
    store = tmp_path / "media-store"

    receipt = import_media_staging(
        _staging_receipt(staging), media_store_root=store)

    assert receipt.schema_version == 1
    assert receipt.file_count == 2
    assert receipt.byte_count == 23
    assert receipt.published_count == 2
    assert receipt.manifest_path == store / "media-manifest.json"
    assert receipt.manifest_sha256 == sha256(
        receipt.manifest_path.read_bytes()).hexdigest().upper()
    assert tuple(item.relative_path for item in receipt.manifest.files) == (
        "msg/attach/a.dat",
        "msg/video/b.jpg",
    )
    assert tuple(item.sha256 for item in receipt.manifest.files) == (
        ATTACH_SHA256,
        VIDEO_SHA256,
    )
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    assert published_attach.read_bytes() == b"attach-media"
    assert (store / ACCOUNT / "msg" / "video" / "b.jpg").read_bytes() == (
        b"video-media")
    attach_stat = published_attach.stat()
    assert receipt.manifest.files[0].volume_serial == attach_stat.st_dev
    assert receipt.manifest.files[0].file_id == attach_stat.st_ino
    manifest_json = json.loads(receipt.manifest_path.read_text("utf-8"))
    assert manifest_json["schemaVersion"] == 1
    assert manifest_json["files"][0]["volumeSerial"] == attach_stat.st_dev
    assert manifest_json["files"][0]["fileId"] == attach_stat.st_ino
    assert _tree_snapshot(staging) == source_before


def test_read_media_store_receipt_revalidates_without_writes(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    first = import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    before = _tree_metadata_snapshot(store)

    receipt = read_media_store_receipt(store, ACCOUNT)

    assert receipt is not None
    assert receipt.manifest == first.manifest
    assert receipt.manifest_sha256 == first.manifest_sha256
    assert receipt.file_count == 2
    assert receipt.byte_count == 23
    assert receipt.published_count == 0
    assert receipt.skipped_count == 2
    assert _tree_metadata_snapshot(store) == before


@pytest.mark.parametrize("existing_root", [False, True])
def test_read_media_store_receipt_without_manifest_returns_none_without_writes(
        tmp_path: Path, existing_root: bool) -> None:
    store = tmp_path / "media-store"
    if existing_root:
        store.mkdir()
    before = _tree_metadata_snapshot(store)

    assert read_media_store_receipt(store, ACCOUNT) is None
    assert _tree_metadata_snapshot(store) == before


def test_read_empty_manifest_never_creates_missing_account(
        tmp_path: Path) -> None:
    store = tmp_path / "media-store"
    store.mkdir()
    manifest = store / "media-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "sourceAccountName": ACCOUNT,
                "fileCount": 0,
                "byteCount": 0,
                "files": [],
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    before = _tree_metadata_snapshot(store)

    with pytest.raises(
            MediaImportError, match="^media_store_manifest_mismatch$"):
        read_media_store_receipt(store, ACCOUNT)

    assert _tree_metadata_snapshot(store) == before
    assert not (store / ACCOUNT).exists()


def test_read_empty_manifest_with_empty_account_is_read_only(
        tmp_path: Path) -> None:
    store = tmp_path / "media-store"
    (store / ACCOUNT).mkdir(parents=True)
    manifest = store / "media-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "sourceAccountName": ACCOUNT,
                "fileCount": 0,
                "byteCount": 0,
                "files": [],
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    before = _tree_metadata_snapshot(store)

    receipt = read_media_store_receipt(store, ACCOUNT)

    assert receipt is not None
    assert receipt.file_count == 0
    assert receipt.published_count == 0
    assert receipt.skipped_count == 0
    assert _tree_metadata_snapshot(store) == before


def test_read_without_manifest_rejects_unexpected_entry_without_writes_or_leak(
        tmp_path: Path) -> None:
    store = tmp_path / "media-store"
    store.mkdir()
    secret_name = "private-contact-photo.dat"
    (store / secret_name).write_bytes(b"orphan")
    before = _tree_metadata_snapshot(store)

    with pytest.raises(MediaImportError) as caught:
        read_media_store_receipt(store, ACCOUNT)

    assert str(caught.value) == "media_store_manifest_mismatch"
    assert secret_name not in str(caught.value)
    assert _tree_metadata_snapshot(store) == before


def test_read_media_store_receipt_rejects_manifest_drift_during_verification(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    first = import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    attach_identity = published_attach.stat().st_ino
    original_manifest = first.manifest_path.read_bytes()
    original_read = media.os.read
    mutated = False

    def mutate_manifest_while_reading_file(
            descriptor: int, byte_count: int) -> bytes:
        nonlocal mutated
        if not mutated and os.fstat(descriptor).st_ino == attach_identity:
            first.manifest_path.write_bytes(original_manifest + b"\n")
            mutated = True
        return original_read(descriptor, byte_count)

    monkeypatch.setattr(media.os, "read", mutate_manifest_while_reading_file)

    with pytest.raises(
            MediaImportError, match="^media_store_manifest_mismatch$"):
        read_media_store_receipt(store, ACCOUNT)

    assert mutated is True


def test_read_media_store_receipt_rejects_boundary_drift_without_name_leak(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    import_media_staging(_staging_receipt(staging), media_store_root=store)
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    attach_identity = published_attach.stat().st_ino
    secret_name = "private-contact-photo.dat"
    unexpected = published_attach.with_name(secret_name)
    original_read = media.os.read
    mutated = False

    def add_unmanifested_file_while_reading(
            descriptor: int, byte_count: int) -> bytes:
        nonlocal mutated
        if not mutated and os.fstat(descriptor).st_ino == attach_identity:
            unexpected.write_bytes(b"not-in-manifest")
            mutated = True
        return original_read(descriptor, byte_count)

    monkeypatch.setattr(media.os, "read", add_unmanifested_file_while_reading)

    with pytest.raises(MediaImportError) as caught:
        read_media_store_receipt(store, ACCOUNT)

    assert str(caught.value) == "media_store_manifest_mismatch"
    assert secret_name not in str(caught.value)
    assert mutated is True


def test_identical_reimport_publishes_nothing(tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    first = import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    identity_before = published_attach.stat().st_ino

    second = import_media_staging(
        _staging_receipt(staging), media_store_root=store)

    assert second.published_count == 0
    assert second.skipped_count == 2
    assert second.manifest_sha256 == first.manifest_sha256
    assert published_attach.stat().st_ino == identity_before


def test_changed_path_atomically_replaces_store_entry(tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    import_media_staging(_staging_receipt(staging), media_store_root=store)
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    identity_before = published_attach.stat().st_ino
    old_presentation = tmp_path / "old-presentation.dat"
    os.link(published_attach, old_presentation)
    attach.write_bytes(b"attach-media-v2")

    receipt = import_media_staging(
        _staging_receipt(
            staging,
            attach_size=15,
            attach_sha256=CHANGED_ATTACH_SHA256,
        ),
        media_store_root=store,
    )

    assert receipt.published_count == 1
    assert receipt.skipped_count == 1
    assert published_attach.read_bytes() == b"attach-media-v2"
    assert published_attach.stat().st_ino != identity_before
    assert old_presentation.read_bytes() == b"attach-media"
    assert old_presentation.stat().st_ino == identity_before
    assert receipt.manifest.files[0].sha256 == CHANGED_ATTACH_SHA256


@pytest.mark.parametrize("unlisted", [
    "cache/c.dat",
    "temp/head_image/avatar",
])
def test_unlisted_staging_roots_fail_closed(
        tmp_path: Path, unlisted: str) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    extra = account / Path(unlisted)
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    extra.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    extra.write_bytes(b"not-whitelisted")
    store = tmp_path / "media-store"

    with pytest.raises(
            MediaImportError, match="^media_staging_tree_invalid$"):
        import_media_staging(
            _staging_receipt(staging), media_store_root=store)

    assert not (store / "media-manifest.json").exists()


def test_staging_receipt_manifest_hash_mismatch_fails_closed(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    receipt = _staging_receipt(staging)
    receipt.manifest_sha256 = "B" * 64
    store = tmp_path / "media-store"

    with pytest.raises(
            MediaImportError, match="^media_staging_receipt_invalid$"):
        import_media_staging(receipt, media_store_root=store)

    assert not (store / "media-manifest.json").exists()


def test_duplicate_key_in_prior_manifest_fails_closed(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    first = import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    payload = first.manifest_path.read_text("utf-8").replace(
        '"schemaVersion":1',
        '"schemaVersion":1,"schemaVersion":1',
        1,
    )
    first.manifest_path.write_text(payload, encoding="utf-8")

    with pytest.raises(
            MediaImportError, match="^media_store_manifest_invalid$"):
        import_media_staging(
            _staging_receipt(staging), media_store_root=store)


def test_existing_store_without_manifest_fails_closed_without_deletion(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    orphan = store / ACCOUNT / "msg" / "attach" / "orphan.dat"
    orphan.parent.mkdir(parents=True)
    orphan.write_bytes(b"existing")

    with pytest.raises(
            MediaImportError, match="^media_store_manifest_mismatch$"):
        import_media_staging(
            _staging_receipt(staging), media_store_root=store)

    assert orphan.read_bytes() == b"existing"
    assert not (store / "media-manifest.json").exists()


def test_hash_mismatch_retains_only_an_unpublished_partial(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"

    with pytest.raises(
            MediaImportError, match="^media_staging_file_mismatch$"):
        import_media_staging(
            _staging_receipt(staging, attach_sha256="D" * 64),
            media_store_root=store,
        )

    assert not (store / ACCOUNT / "msg" / "attach" / "a.dat").exists()
    assert not (store / "media-manifest.json").exists()
    assert len(tuple(store.rglob("*.partial"))) == 1


@pytest.mark.parametrize("relative_path", [
    "../msg/attach/a.dat",
    "/msg/attach/a.dat",
    r"msg\attach\a.dat",
    "msg/attach/a.dat:stream",
    "msg//attach/a.dat",
    "msg/attach/./a.dat",
    "cache/a.dat",
    "temp/head_image/avatar",
])
def test_unsafe_or_unlisted_receipt_path_fails_closed(
        tmp_path: Path, relative_path: str) -> None:
    item = SimpleNamespace(
        relative_path=relative_path,
        size=12,
        sha256=ATTACH_SHA256,
    )
    receipt = _receipt_for_files(
        tmp_path / "media-staging", (item,))

    with pytest.raises(
            MediaImportError, match="^media_relative_path_invalid$"):
        import_media_staging(
            receipt, media_store_root=tmp_path / "media-store")


def test_case_colliding_receipt_paths_fail_closed(tmp_path: Path) -> None:
    receipt = _receipt_for_files(tmp_path / "media-staging", (
        SimpleNamespace(
            relative_path="msg/attach/A.dat",
            size=1,
            sha256="A" * 64,
        ),
        SimpleNamespace(
            relative_path="msg/attach/a.dat",
            size=1,
            sha256="B" * 64,
        ),
    ))

    with pytest.raises(
            MediaImportError, match="^media_relative_path_collision$"):
        import_media_staging(
            receipt, media_store_root=tmp_path / "media-store")


def test_directory_instead_of_staged_file_fails_closed(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    (account / "msg" / "attach" / "a.dat").mkdir(parents=True)
    video = account / "msg" / "video" / "b.jpg"
    video.parent.mkdir(parents=True)
    video.write_bytes(b"video-media")

    with pytest.raises(
            MediaImportError, match="^media_staging_tree_invalid$"):
        import_media_staging(
            _staging_receipt(staging),
            media_store_root=tmp_path / "media-store",
        )


@pytest.mark.parametrize(("field", "invalid"), [
    ("volumeSerial", True),
    ("volumeSerial", -1),
    ("fileId", True),
    ("fileId", -1),
])
def test_prior_manifest_rejects_invalid_identity_fields(
        tmp_path: Path, field: str, invalid) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    first = import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    raw = json.loads(first.manifest_path.read_text("utf-8"))
    raw["files"][0][field] = invalid
    first.manifest_path.write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(
            MediaImportError, match="^media_store_manifest_invalid$"):
        import_media_staging(
            _staging_receipt(staging), media_store_root=store)


def test_prior_manifest_identity_mismatch_fails_closed(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    first = import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    raw = json.loads(first.manifest_path.read_text("utf-8"))
    raw["files"][0]["fileId"] += 1
    first.manifest_path.write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(
            MediaImportError, match="^media_store_manifest_mismatch$"):
        import_media_staging(
            _staging_receipt(staging), media_store_root=store)


def test_smaller_generation_never_deletes_published_media(
        tmp_path: Path) -> None:
    first_staging = tmp_path / "first" / "media-staging"
    first_account = first_staging / ACCOUNT
    attach = first_account / "msg" / "attach" / "a.dat"
    video = first_account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    import_media_staging(
        _staging_receipt(first_staging), media_store_root=store)
    published_video = store / ACCOUNT / "msg" / "video" / "b.jpg"
    video_identity = published_video.stat().st_ino
    second_staging = tmp_path / "second" / "media-staging"
    second_attach = (
        second_staging / ACCOUNT / "msg" / "attach" / "a.dat")
    second_attach.parent.mkdir(parents=True)
    second_attach.write_bytes(b"attach-media")
    second_receipt = _receipt_for_files(second_staging, (
        SimpleNamespace(
            relative_path="msg/attach/a.dat",
            size=12,
            sha256=ATTACH_SHA256,
        ),
    ))

    result = import_media_staging(
        second_receipt, media_store_root=store)

    assert result.file_count == 2
    assert published_video.read_bytes() == b"video-media"
    assert published_video.stat().st_ino == video_identity


def test_staging_symlink_fails_closed(tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    outside = tmp_path / "outside.dat"
    outside.write_bytes(b"attach-media")
    attach = account / "msg" / "attach" / "a.dat"
    attach.parent.mkdir(parents=True)
    try:
        attach.symlink_to(outside)
    except OSError as error:
        pytest.skip(f"symlink unavailable: {error.winerror}")
    video = account / "msg" / "video" / "b.jpg"
    video.parent.mkdir(parents=True)
    video.write_bytes(b"video-media")

    with pytest.raises(
            MediaImportError, match="^media_staging_tree_invalid$"):
        import_media_staging(
            _staging_receipt(staging),
            media_store_root=tmp_path / "media-store",
        )


def test_prior_store_content_mismatch_fails_closed(tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    published_attach.write_bytes(b"tampered-data")

    with pytest.raises(
            MediaImportError, match="^media_store_manifest_mismatch$"):
        import_media_staging(
            _staging_receipt(staging), media_store_root=store)


def test_media_store_ancestor_reparse_fails_before_write(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    target = tmp_path / "junction-target"
    target.mkdir()
    junction = tmp_path / "junction"
    _make_junction(junction, target)
    try:
        with pytest.raises(
                MediaImportError,
                match="^media_store_manifest_mismatch$"):
            import_media_staging(
                _staging_receipt(staging),
                media_store_root=junction / "media-store",
            )
        assert not (target / "media-store").exists()
    finally:
        os.rmdir(junction)


@pytest.mark.parametrize("position", ["root", "account"])
def test_existing_media_store_reparse_fails_before_write(
        tmp_path: Path, position: str) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    attach = account / "msg" / "attach" / "a.dat"
    video = account / "msg" / "video" / "b.jpg"
    attach.parent.mkdir(parents=True)
    video.parent.mkdir(parents=True)
    attach.write_bytes(b"attach-media")
    video.write_bytes(b"video-media")
    target = tmp_path / "junction-target"
    target.mkdir()
    if position == "root":
        store = tmp_path / "media-store"
        junction = store
    else:
        store = tmp_path / "media-store"
        store.mkdir()
        junction = store / ACCOUNT
    _make_junction(junction, target)
    try:
        with pytest.raises(
                MediaImportError,
                match="^media_store_manifest_mismatch$"):
            import_media_staging(
                _staging_receipt(staging),
                media_store_root=store,
            )
        assert tuple(target.iterdir()) == ()
    finally:
        os.rmdir(junction)


def test_next_import_reconciles_atomically_published_bytes_after_crash(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    staged_attach = account / "msg" / "attach" / "a.dat"
    staged_video = account / "msg" / "video" / "b.jpg"
    staged_attach.parent.mkdir(parents=True)
    staged_video.parent.mkdir(parents=True)
    staged_attach.write_bytes(b"attach-media")
    staged_video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    first = import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    old_identity = published_attach.stat().st_ino
    old_presentation = tmp_path / "old-presentation.dat"
    os.link(published_attach, old_presentation)
    old_manifest_bytes = first.manifest_path.read_bytes()
    staged_attach.write_bytes(b"attach-media-v2")
    replacement = published_attach.with_name(".a.dat.crash-published")
    replacement.write_bytes(b"attach-media-v2")
    os.replace(replacement, published_attach)
    crash_published_identity = published_attach.stat().st_ino
    assert crash_published_identity != old_identity
    assert first.manifest_path.read_bytes() == old_manifest_bytes

    recovered = import_media_staging(
        _staging_receipt(
            staging,
            attach_size=15,
            attach_sha256=CHANGED_ATTACH_SHA256,
        ),
        media_store_root=store,
    )

    assert recovered.published_count == 0
    assert recovered.skipped_count == 2
    assert recovered.manifest.files[0].sha256 == CHANGED_ATTACH_SHA256
    assert recovered.manifest.files[0].file_id == crash_published_identity
    assert recovered.manifest_path.read_bytes() != old_manifest_bytes
    assert published_attach.read_bytes() == b"attach-media-v2"
    assert published_attach.stat().st_ino == crash_published_identity
    assert old_presentation.read_bytes() == b"attach-media"
    assert old_presentation.stat().st_ino == old_identity


def test_crash_recovery_rejects_third_content_without_manifest_change(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    staged_attach = account / "msg" / "attach" / "a.dat"
    staged_video = account / "msg" / "video" / "b.jpg"
    staged_attach.parent.mkdir(parents=True)
    staged_video.parent.mkdir(parents=True)
    staged_attach.write_bytes(b"attach-media")
    staged_video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    first = import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    old_presentation = tmp_path / "old-presentation.dat"
    os.link(published_attach, old_presentation)
    old_manifest_bytes = first.manifest_path.read_bytes()
    staged_attach.write_bytes(b"attach-media-v2")
    replacement = published_attach.with_name(".a.dat.third-content")
    replacement.write_bytes(b"third-content!!")
    os.replace(replacement, published_attach)

    with pytest.raises(
            MediaImportError, match="^media_store_manifest_mismatch$"):
        import_media_staging(
            _staging_receipt(
                staging,
                attach_size=15,
                attach_sha256=CHANGED_ATTACH_SHA256,
            ),
            media_store_root=store,
        )

    assert first.manifest_path.read_bytes() == old_manifest_bytes
    assert published_attach.read_bytes() == b"third-content!!"
    assert old_presentation.read_bytes() == b"attach-media"


def test_crash_recovery_rejects_in_place_mutation_with_old_identity(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    staged_attach = account / "msg" / "attach" / "a.dat"
    staged_video = account / "msg" / "video" / "b.jpg"
    staged_attach.parent.mkdir(parents=True)
    staged_video.parent.mkdir(parents=True)
    staged_attach.write_bytes(b"attach-media")
    staged_video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    first = import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    old_identity = published_attach.stat().st_ino
    old_manifest_bytes = first.manifest_path.read_bytes()
    staged_attach.write_bytes(b"attach-media-v2")
    published_attach.write_bytes(b"attach-media-v2")
    assert published_attach.stat().st_ino == old_identity

    with pytest.raises(
            MediaImportError, match="^media_store_manifest_mismatch$"):
        import_media_staging(
            _staging_receipt(
                staging,
                attach_size=15,
                attach_sha256=CHANGED_ATTACH_SHA256,
            ),
            media_store_root=store,
        )

    assert first.manifest_path.read_bytes() == old_manifest_bytes
    assert published_attach.read_bytes() == b"attach-media-v2"
    assert published_attach.stat().st_ino == old_identity


def test_crash_recovery_rejects_staging_drift(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    staged_attach = account / "msg" / "attach" / "a.dat"
    staged_video = account / "msg" / "video" / "b.jpg"
    staged_attach.parent.mkdir(parents=True)
    staged_video.parent.mkdir(parents=True)
    staged_attach.write_bytes(b"attach-media")
    staged_video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    first = import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    old_presentation = tmp_path / "old-presentation.dat"
    os.link(published_attach, old_presentation)
    old_manifest_bytes = first.manifest_path.read_bytes()
    staged_attach.write_bytes(b"third-content!!")
    replacement = published_attach.with_name(".a.dat.crash-published")
    replacement.write_bytes(b"attach-media-v2")
    os.replace(replacement, published_attach)

    with pytest.raises(
            MediaImportError, match="^media_staging_file_mismatch$"):
        import_media_staging(
            _staging_receipt(
                staging,
                attach_size=15,
                attach_sha256=CHANGED_ATTACH_SHA256,
            ),
            media_store_root=store,
        )

    assert first.manifest_path.read_bytes() == old_manifest_bytes
    assert published_attach.read_bytes() == b"attach-media-v2"
    assert old_presentation.read_bytes() == b"attach-media"


@pytest.mark.skipif(os.name != "nt", reason="Windows file attributes")
def test_windows_readonly_attribute_blocks_atomic_media_update(
        tmp_path: Path) -> None:
    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    staged_attach = account / "msg" / "attach" / "a.dat"
    staged_video = account / "msg" / "video" / "b.jpg"
    staged_attach.parent.mkdir(parents=True)
    staged_video.parent.mkdir(parents=True)
    staged_attach.write_bytes(b"attach-media")
    staged_video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    first = import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    old_presentation = tmp_path / "old-presentation.dat"
    os.link(published_attach, old_presentation)
    old_identity = published_attach.stat().st_ino
    old_manifest_bytes = first.manifest_path.read_bytes()
    readonly = stat.FILE_ATTRIBUTE_READONLY
    os.chmod(published_attach, stat.S_IREAD)
    try:
        assert published_attach.stat().st_file_attributes & readonly
        assert old_presentation.stat().st_file_attributes & readonly
        staged_attach.write_bytes(b"attach-media-v2")

        with pytest.raises(OSError) as error:
            import_media_staging(
                _staging_receipt(
                    staging,
                    attach_size=15,
                    attach_sha256=CHANGED_ATTACH_SHA256,
                ),
                media_store_root=store,
            )
        assert error.value.winerror == 5

        assert first.manifest_path.read_bytes() == old_manifest_bytes
        assert published_attach.read_bytes() == b"attach-media"
        assert published_attach.stat().st_ino == old_identity
        assert old_presentation.read_bytes() == b"attach-media"
        assert old_presentation.stat().st_ino == old_identity
        os.chmod(published_attach, stat.S_IWRITE)
        assert not (
            published_attach.stat().st_file_attributes & readonly)
        assert not (old_presentation.stat().st_file_attributes & readonly)
    finally:
        os.chmod(published_attach, stat.S_IWRITE)


@pytest.mark.skipif(os.name != "nt", reason="Windows handle attributes")
def test_windows_held_handle_still_blocks_atomic_readonly_update(
        tmp_path: Path) -> None:
    # SHARE_DELETE does not make MoveFileEx replacement succeed while this
    # attribute handle is open. A process death could also bypass a later
    # restore, so production must not use this workaround.
    import ctypes
    from ctypes import wintypes

    class FileBasicInfo(ctypes.Structure):
        _fields_ = [
            ("creation_time", ctypes.c_longlong),
            ("last_access_time", ctypes.c_longlong),
            ("last_write_time", ctypes.c_longlong),
            ("change_time", ctypes.c_longlong),
            ("file_attributes", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    get_information = kernel32.GetFileInformationByHandleEx
    get_information.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
    ]
    get_information.restype = wintypes.BOOL
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    def basic_info(handle) -> FileBasicInfo:
        value = FileBasicInfo()
        if not get_information(
                handle, 0, ctypes.byref(value), ctypes.sizeof(value)):
            raise ctypes.WinError(ctypes.get_last_error())
        return value

    def set_attributes(handle, attributes: int) -> None:
        value = basic_info(handle)
        value.file_attributes = attributes or stat.FILE_ATTRIBUTE_NORMAL
        if not set_information(
                handle, 0, ctypes.byref(value), ctypes.sizeof(value)):
            raise ctypes.WinError(ctypes.get_last_error())

    staging = tmp_path / "media-staging"
    account = staging / ACCOUNT
    staged_attach = account / "msg" / "attach" / "a.dat"
    staged_video = account / "msg" / "video" / "b.jpg"
    staged_attach.parent.mkdir(parents=True)
    staged_video.parent.mkdir(parents=True)
    staged_attach.write_bytes(b"attach-media")
    staged_video.write_bytes(b"video-media")
    store = tmp_path / "media-store"
    import_media_staging(
        _staging_receipt(staging), media_store_root=store)
    published_attach = store / ACCOUNT / "msg" / "attach" / "a.dat"
    old_presentation = tmp_path / "old-presentation.dat"
    os.link(published_attach, old_presentation)
    old_identity = published_attach.stat().st_ino
    old_manifest_bytes = (
        store / "media-manifest.json").read_bytes()
    os.chmod(published_attach, stat.S_IREAD)
    handle = create_file(
        str(published_attach),
        0x0080 | 0x0100,
        0x0001 | 0x0002 | 0x0004,
        None,
        3,
        0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        os.chmod(published_attach, stat.S_IWRITE)
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        original_attributes = basic_info(handle).file_attributes
        set_attributes(
            handle, original_attributes & ~stat.FILE_ATTRIBUTE_READONLY)
        assert not (
            old_presentation.stat().st_file_attributes &
            stat.FILE_ATTRIBUTE_READONLY)
        staged_attach.write_bytes(b"attach-media-v2")

        with pytest.raises(OSError) as error:
            import_media_staging(
                _staging_receipt(
                    staging,
                    attach_size=15,
                    attach_sha256=CHANGED_ATTACH_SHA256,
                ),
                media_store_root=store,
            )
        assert error.value.winerror == 5
        assert (store / "media-manifest.json").read_bytes() == (
            old_manifest_bytes)
        assert published_attach.stat().st_ino == old_identity
        assert old_presentation.read_bytes() == b"attach-media"
        set_attributes(handle, original_attributes)
        assert (
            old_presentation.stat().st_file_attributes &
            stat.FILE_ATTRIBUTE_READONLY)
        assert (
            published_attach.stat().st_file_attributes &
            stat.FILE_ATTRIBUTE_READONLY)
    finally:
        close_handle(handle)
        os.chmod(old_presentation, stat.S_IWRITE)
        os.chmod(published_attach, stat.S_IWRITE)
