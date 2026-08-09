import ctypes
import json
from hashlib import sha256
import multiprocessing
import os
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

import weflow_chat.presentation_slots as presentation_slots
from weflow_chat.media import import_media_staging
from weflow_chat.presentation_slots import (
    PresentationSlotError,
    rebuild_inactive_slot,
)


ACCOUNT = "wxid_synthetic"


def _hold_native_slot_lock(
        lock_path_text: str,
        ready,
        release,
        crash: bool = False,
) -> None:
    lock_path = Path(lock_path_text)
    if os.name == "nt":
        create_file = ctypes.WinDLL(
            "kernel32",
            use_last_error=True,
        ).CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(
            str(lock_path),
            0xC0000000,
            0,
            None,
            4,
            0x00200000,
            None,
        )
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            ready.set()
            if crash:
                os._exit(0)
            release.wait(20)
        finally:
            ctypes.WinDLL(
                "kernel32",
                use_last_error=True,
            ).CloseHandle(handle)
        return

    import fcntl

    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT,
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        ready.set()
        if crash:
            os._exit(0)
        release.wait(20)
    finally:
        os.close(descriptor)


def _sha256(payload: bytes) -> str:
    return sha256(payload).hexdigest().upper()


def _active_tree(root: Path) -> Path:
    active = root / "active"
    session = (
        active
        / ACCOUNT
        / "db_storage"
        / "session"
        / "session.db"
    )
    message = (
        active
        / ACCOUNT
        / "db_storage"
        / "message"
        / "message_0.db"
    )
    session.parent.mkdir(parents=True)
    message.parent.mkdir(parents=True)
    session.write_bytes(b"session-db")
    message.write_bytes(b"message-db")
    return active


def _media_receipt(
        root: Path,
        *,
        attach: bytes = b"attach-media",
        video: bytes = b"video-media",
    ):
    staging = root / (
        "media-staging-"
        + _sha256(attach + b"\0" + video)[:12]
    )
    staging_account = staging / ACCOUNT
    attach_path = staging_account / "msg" / "attach" / "a.dat"
    video_path = staging_account / "msg" / "video" / "b.jpg"
    attach_path.parent.mkdir(parents=True)
    video_path.parent.mkdir(parents=True)
    attach_path.write_bytes(attach)
    video_path.write_bytes(video)
    files = (
        SimpleNamespace(
            relative_path="msg/attach/a.dat",
            size=len(attach),
            sha256=_sha256(attach),
        ),
        SimpleNamespace(
            relative_path="msg/video/b.jpg",
            size=len(video),
            sha256=_sha256(video),
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
            file_count=len(files),
            byte_count=sum(item.size for item in files),
            manifest_sha256=_sha256(staging_manifest),
        ),
        media_store_root=root / "media-store",
    )


def _identity(path: Path) -> tuple[int, int]:
    information = path.stat()
    return information.st_dev, information.st_ino


def _tree_snapshot(root: Path) -> tuple:
    values = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            values.append(("directory", relative))
        else:
            values.append((
                "file",
                relative,
                path.read_bytes(),
                _identity(path),
            ))
    return tuple(values)


def _slots_root_for_copy_temp_length(
        tmp_path: Path,
        slot_name: str,
        target_length: int,
) -> Path:
    relative_temp = (
        Path(slot_name)
        / "presentation"
        / ACCOUNT
        / "db_storage"
        / "message"
        / (".message_0.db." + "0" * 32 + ".partial")
    )
    one_character_root = tmp_path / "r"
    padding = (
        target_length
        - len(str(one_character_root / relative_temp))
        + 1
    )
    assert 1 <= padding <= 200
    slots_root = tmp_path / ("r" * padding)
    slots_root.mkdir()
    assert len(str(slots_root / relative_temp)) == target_length
    return slots_root


@pytest.mark.skipif(os.name != "nt", reason="Windows MAX_PATH regression")
@pytest.mark.parametrize("slot_name", ("A", "B"))
def test_copy_temp_path_overflow_is_rejected_before_slot_lock_or_write(
        tmp_path: Path,
        slot_name: str,
) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = _slots_root_for_copy_temp_length(
        tmp_path,
        slot_name,
        260,
    )
    before = _tree_snapshot(slots_root)

    with pytest.raises(
        PresentationSlotError,
        match=r"^slot_path_budget_exceeded$",
    ):
        rebuild_inactive_slot(
            active,
            media,
            slots_root,
            slot_name,
            ACCOUNT,
            "generation-overflow",
        )

    assert _tree_snapshot(slots_root) == before
    assert not os.path.lexists(slots_root / slot_name)


def test_active_overlap_is_rejected_before_any_slot_write(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    before = _tree_snapshot(active)

    with pytest.raises(
        PresentationSlotError,
        match=r"^slot_source_overlap$",
    ):
        rebuild_inactive_slot(
            active,
            media,
            active,
            "A",
            ACCOUNT,
            "generation-1",
        )

    assert _tree_snapshot(active) == before
    assert not os.path.lexists(active / "A")


def test_media_store_overlap_is_rejected_before_any_slot_write(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    media_root = media.manifest_path.parent
    before = _tree_snapshot(media_root)

    with pytest.raises(
        PresentationSlotError,
        match=r"^slot_source_overlap$",
    ):
        rebuild_inactive_slot(
            active,
            media,
            media_root,
            "A",
            ACCOUNT,
            "generation-1",
        )

    assert _tree_snapshot(media_root) == before
    assert not os.path.lexists(media_root / "A")


def test_source_ancestor_slots_root_is_rejected_before_any_write(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    before = _tree_snapshot(tmp_path)

    with pytest.raises(
        PresentationSlotError,
        match=r"^slot_source_overlap$",
    ):
        rebuild_inactive_slot(
            active,
            media,
            tmp_path,
            "A",
            ACCOUNT,
            "generation-1",
        )

    assert _tree_snapshot(tmp_path) == before
    assert not os.path.lexists(tmp_path / "A")


def test_same_slot_thread_is_rejected_before_ready_invalidation(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    entered_copy = threading.Event()
    release_copy = threading.Event()
    original_copy = (
        presentation_slots._copy_source_to_exclusive_temp
    )
    worker_errors = []

    def block_first_copy(*args, **kwargs):
        if not entered_copy.is_set():
            entered_copy.set()
            if not release_copy.wait(20):
                raise RuntimeError("copy_release_timeout")
        return original_copy(*args, **kwargs)

    def first_generation() -> None:
        try:
            rebuild_inactive_slot(
                active,
                media,
                slots_root,
                "A",
                ACCOUNT,
                "generation-thread-1",
            )
        except BaseException as error:
            worker_errors.append(error)

    monkeypatch.setattr(
        presentation_slots,
        "_copy_source_to_exclusive_temp",
        block_first_copy,
    )
    worker = threading.Thread(target=first_generation)
    worker.start()
    assert entered_copy.wait(20)
    try:
        with pytest.raises(
            PresentationSlotError,
            match=r"^slot_busy$",
        ):
            rebuild_inactive_slot(
                active,
                media,
                slots_root,
                "A",
                ACCOUNT,
                "generation-thread-2",
            )
    finally:
        release_copy.set()
        worker.join(20)

    assert not worker.is_alive()
    assert worker_errors == []
    ready = json.loads(
        (slots_root / "A" / "READY").read_bytes()
    )
    assert ready["generationId"] == "generation-thread-1"


def test_same_slot_process_lock_is_rejected_as_busy(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slot_root = slots_root / "A"
    slot_root.mkdir(parents=True)
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    release = context.Event()
    process = context.Process(
        target=_hold_native_slot_lock,
        args=(str(slot_root / ".slot.lock"), ready, release),
    )
    process.start()
    assert ready.wait(20)
    try:
        with pytest.raises(
            PresentationSlotError,
            match=r"^slot_busy$",
        ):
            rebuild_inactive_slot(
                active,
                media,
                slots_root,
                "A",
                ACCOUNT,
                "generation-process-1",
            )
    finally:
        release.set()
        process.join(20)

    assert process.exitcode == 0
    assert not os.path.lexists(slot_root / "READY")


def test_crashed_process_releases_slot_lock(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slot_root = slots_root / "A"
    slot_root.mkdir(parents=True)
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    unused_release = context.Event()
    process = context.Process(
        target=_hold_native_slot_lock,
        args=(
            str(slot_root / ".slot.lock"),
            ready,
            unused_release,
            True,
        ),
    )
    process.start()
    assert ready.wait(20)
    process.join(20)
    assert process.exitcode == 0

    receipt = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-after-crash",
    )

    assert receipt.ready_path.is_file()


def test_first_build_publishes_complete_ready_slot(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()

    receipt = rebuild_inactive_slot(
        active_root=active,
        media_receipt=media,
        slots_root=slots_root,
        slot_name="A",
        account_name=ACCOUNT,
        generation_id="generation-1",
    )

    slot_root = slots_root / "A"
    presentation = slot_root / "presentation"
    expected_files = (
        f"{ACCOUNT}/db_storage/message/message_0.db",
        f"{ACCOUNT}/db_storage/session/session.db",
        f"{ACCOUNT}/msg/attach/a.dat",
        f"{ACCOUNT}/msg/video/b.jpg",
    )
    assert tuple(
        path.relative_to(presentation).as_posix()
        for path in sorted(presentation.rglob("*"))
        if path.is_file()
    ) == expected_files
    assert receipt.slot_name == "A"
    assert receipt.generation_id == "generation-1"
    assert receipt.presentation_root == presentation.resolve()
    assert receipt.manifest_path == (slot_root / "slot-manifest.json").resolve()
    assert receipt.ready_path == (slot_root / "READY").resolve()
    assert receipt.media_store_manifest_sha256 == media.manifest_sha256
    assert receipt.file_count == 4
    assert receipt.bytes_written == len(b"attach-media") + len(b"video-media")
    assert receipt.ready_path.is_file()

    store_account = media.manifest_path.parent / ACCOUNT
    for item in media.manifest.files:
        source = store_account / item.relative_path
        published = presentation / ACCOUNT / item.relative_path
        assert published.read_bytes() == source.read_bytes()
        assert _identity(published) != _identity(source)


def test_unchanged_media_keeps_identity_and_writes_zero_bytes(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    media_paths = tuple(
        first.presentation_root
        / ACCOUNT
        / item.relative_path
        for item in media.manifest.files
    )
    before = tuple(_identity(path) for path in media_paths)

    second = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-2",
    )

    assert tuple(_identity(path) for path in media_paths) == before
    assert second.bytes_written == 0
    assert second.manifest.bytes_written == 0
    assert json.loads(second.ready_path.read_bytes())["bytesWritten"] == 0


def test_hardlinked_media_target_is_replaced_before_reuse(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    attach = (
        first.presentation_root
        / ACCOUNT
        / "msg"
        / "attach"
        / "a.dat"
    )
    outside_link = tmp_path / "outside-link.dat"
    try:
        os.link(attach, outside_link)
    except OSError:
        pytest.skip("hardlink creation unavailable")
    linked_identity = _identity(attach)
    assert _identity(outside_link) == linked_identity

    second = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-2",
    )

    assert _identity(attach) != linked_identity
    assert attach.stat().st_nlink == 1
    assert _identity(outside_link) == linked_identity
    assert outside_link.read_bytes() == b"attach-media"
    assert second.bytes_written == len(b"attach-media")


def test_media_source_hardlink_is_rejected_before_unlink_or_replace(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    source = (
        media.manifest_path.parent
        / ACCOUNT
        / "msg"
        / "attach"
        / "a.dat"
    )
    destination = (
        first.presentation_root
        / ACCOUNT
        / "msg"
        / "attach"
        / "a.dat"
    )
    destination.unlink()
    try:
        os.link(source, destination)
    except OSError:
        pytest.skip("hardlink creation unavailable")
    source_before = (
        _identity(source),
        source.stat().st_nlink,
        source.read_bytes(),
    )

    with pytest.raises(
        PresentationSlotError,
        match=r"^slot_media_source_hardlink$",
    ):
        rebuild_inactive_slot(
            active,
            media,
            slots_root,
            "A",
            ACCOUNT,
            "generation-2",
        )

    assert (
        _identity(source),
        source.stat().st_nlink,
        source.read_bytes(),
    ) == source_before
    assert _identity(destination) == _identity(source)
    assert not os.path.lexists(first.ready_path)


def test_one_changed_media_file_replaces_only_that_identity(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    first_media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        first_media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    attach = (
        first.presentation_root
        / ACCOUNT
        / "msg"
        / "attach"
        / "a.dat"
    )
    video = (
        first.presentation_root
        / ACCOUNT
        / "msg"
        / "video"
        / "b.jpg"
    )
    before_attach = _identity(attach)
    before_video = _identity(video)

    changed_payload = b"attach-media-v2"
    second_media = _media_receipt(
        tmp_path,
        attach=changed_payload,
    )
    second = rebuild_inactive_slot(
        active,
        second_media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-2",
    )

    assert attach.read_bytes() == changed_payload
    assert _identity(attach) != before_attach
    assert _identity(video) == before_video
    assert second.bytes_written == len(changed_payload)


def test_polluted_media_target_is_replaced_without_rewriting_others(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    attach = (
        first.presentation_root
        / ACCOUNT
        / "msg"
        / "attach"
        / "a.dat"
    )
    video = (
        first.presentation_root
        / ACCOUNT
        / "msg"
        / "video"
        / "b.jpg"
    )
    before_attach = _identity(attach)
    before_video = _identity(video)
    attach.write_bytes(b"x" * len(b"attach-media"))

    second = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-2",
    )

    assert attach.read_bytes() == b"attach-media"
    assert _identity(attach) != before_attach
    assert _identity(video) == before_video
    assert second.bytes_written == len(b"attach-media")


def test_removed_database_file_is_reconciled_from_reused_slot(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    active_message = (
        active
        / ACCOUNT
        / "db_storage"
        / "message"
        / "message_0.db"
    )
    active_message.unlink()
    active_message.parent.rmdir()

    second = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-2",
    )

    assert not os.path.lexists(
        first.presentation_root
        / ACCOUNT
        / "db_storage"
        / "message"
    )
    assert second.ready_path.is_file()


def test_unexpected_file_and_directories_are_removed_without_media_rewrite(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    media_paths = tuple(
        first.presentation_root
        / ACCOUNT
        / item.relative_path
        for item in media.manifest.files
    )
    before = tuple(_identity(path) for path in media_paths)
    pollution = (
        first.presentation_root
        / ACCOUNT
        / "msg"
        / "attach"
        / "polluted"
        / "nested"
        / "unexpected.bin"
    )
    pollution.parent.mkdir(parents=True)
    pollution.write_bytes(b"unexpected")

    second = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-2",
    )

    assert not os.path.lexists(
        first.presentation_root
        / ACCOUNT
        / "msg"
        / "attach"
        / "polluted"
    )
    assert tuple(_identity(path) for path in media_paths) == before
    assert second.bytes_written == 0


def test_owned_atomic_control_temps_are_removed_before_rebuild(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    manifest_temp = (
        first.slot_root / ".slot-manifest.json.abcdefgh"
    )
    ready_temp = first.slot_root / ".READY.1234abcd"
    manifest_temp.write_bytes(b"partial manifest")
    ready_temp.write_bytes(b"partial ready")

    second = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-2",
    )

    assert not os.path.lexists(manifest_temp)
    assert not os.path.lexists(ready_temp)
    assert second.ready_path.is_file()


def test_unknown_slot_file_is_rejected_without_ready_invalidation(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    unknown = first.slot_root / ".slot-manifest.json.abcdefghi"
    unknown.write_bytes(b"not an owned temp")
    ready_before = first.ready_path.read_bytes()

    with pytest.raises(
        PresentationSlotError,
        match=r"^slot_root_invalid$",
    ):
        rebuild_inactive_slot(
            active,
            media,
            slots_root,
            "A",
            ACCOUNT,
            "generation-2",
        )

    assert unknown.read_bytes() == b"not an owned temp"
    assert first.ready_path.read_bytes() == ready_before


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows share-deny directory pin test",
)
def test_copy_parent_is_pinned_across_check_and_use(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    original_copy = (
        presentation_slots._copy_source_to_exclusive_temp
    )
    race = {"attempted": False, "blocked": False}

    def attempt_parent_swap(source, temporary, **kwargs):
        if not race["attempted"]:
            race["attempted"] = True
            parent = Path(temporary).parent
            moved = parent.with_name(parent.name + "-race-moved")
            try:
                parent.rename(moved)
            except OSError:
                race["blocked"] = True
            else:
                moved.rename(parent)
        return original_copy(source, temporary, **kwargs)

    monkeypatch.setattr(
        presentation_slots,
        "_copy_source_to_exclusive_temp",
        attempt_parent_swap,
    )

    receipt = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )

    assert race == {"attempted": True, "blocked": True}
    assert receipt.ready_path.is_file()


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows share-deny directory pin test",
)
def test_reconciliation_parent_is_pinned_before_unlink(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    unexpected = (
        first.presentation_root
        / ACCOUNT
        / "msg"
        / "attach"
        / "unexpected.bin"
    )
    unexpected.write_bytes(b"unexpected")
    original_unlink = Path.unlink
    race = {"attempted": False, "blocked": False}

    def attempt_parent_swap(path: Path, *args, **kwargs):
        if path == unexpected and not race["attempted"]:
            race["attempted"] = True
            parent = path.parent
            moved = parent.with_name(parent.name + "-race-moved")
            try:
                parent.rename(moved)
            except OSError:
                race["blocked"] = True
            else:
                moved.rename(parent)
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", attempt_parent_swap)

    receipt = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-2",
    )

    assert race == {"attempted": True, "blocked": True}
    assert not os.path.lexists(unexpected)
    assert receipt.ready_path.is_file()


def test_hostile_temp_hardlink_cannot_truncate_active_source(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    source = (
        active
        / ACCOUNT
        / "db_storage"
        / "message"
        / "message_0.db"
    )
    source_before = (
        _identity(source),
        source.stat().st_nlink,
        source.read_bytes(),
    )
    original_create = (
        presentation_slots._exclusive_create_file_descriptor
    )
    race = {"attempted": False}

    def plant_source_hardlink(temporary: Path) -> int:
        if not race["attempted"]:
            race["attempted"] = True
            os.link(source, temporary)
        return original_create(temporary)

    monkeypatch.setattr(
        presentation_slots,
        "_exclusive_create_file_descriptor",
        plant_source_hardlink,
    )

    with pytest.raises(
        PresentationSlotError,
        match=r"^slot_copy_failed$",
    ):
        rebuild_inactive_slot(
            active,
            media,
            slots_root,
            "A",
            ACCOUNT,
            "generation-hostile-temp",
        )

    assert race["attempted"] is True
    assert (
        _identity(source),
        source.stat().st_nlink,
        source.read_bytes(),
    ) == source_before
    assert not os.path.lexists(slots_root / "A" / "READY")


@pytest.mark.parametrize("source_kind", ("active", "media"))
def test_post_close_source_hardlink_swap_is_rolled_back(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        source_kind: str,
) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    if source_kind == "active":
        relative_parts = (
            ACCOUNT,
            "db_storage",
            "message",
            "message_0.db",
        )
        source = active.joinpath(*relative_parts)
    else:
        relative_parts = (
            ACCOUNT,
            "msg",
            "attach",
            "a.dat",
        )
        source = media.manifest_path.parent.joinpath(
            *relative_parts
        )
    destination = (
        slots_root
        / "A"
        / "presentation"
    ).joinpath(*relative_parts)
    source_before = (
        _identity(source),
        source.stat().st_nlink,
        source.read_bytes(),
    )
    original_replace = presentation_slots.replace_write_through
    race = {"attempted": False}

    def swap_after_close(
            temporary: Path,
            target: Path,
    ) -> None:
        if Path(target) == destination and not race["attempted"]:
            race["attempted"] = True
            Path(temporary).unlink()
            os.link(source, temporary)
        original_replace(temporary, target)

    monkeypatch.setattr(
        presentation_slots,
        "replace_write_through",
        swap_after_close,
    )

    with pytest.raises(
        PresentationSlotError,
        match=r"^slot_publication_mismatch$",
    ):
        rebuild_inactive_slot(
            active,
            media,
            slots_root,
            "A",
            ACCOUNT,
            f"generation-post-close-{source_kind}",
        )

    assert race["attempted"] is True
    assert (
        _identity(source),
        source.stat().st_nlink,
        source.read_bytes(),
    ) == source_before
    assert not os.path.lexists(destination)
    assert not os.path.lexists(slots_root / "A" / "READY")


def test_rebuilding_b_does_not_touch_ready_a(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-a",
    )
    before = {
        path.relative_to(first.slot_root).as_posix(): (
            path.read_bytes(),
            _identity(path),
        )
        for path in first.slot_root.rglob("*")
        if path.is_file()
    }

    second = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "B",
        ACCOUNT,
        "generation-b",
    )

    after = {
        path.relative_to(first.slot_root).as_posix(): (
            path.read_bytes(),
            _identity(path),
        )
        for path in first.slot_root.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert second.slot_name == "B"
    assert second.ready_path.is_file()


def test_failure_after_invalidation_never_republishes_ready(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    assert first.ready_path.is_file()

    def fail_copy(*_args, **_kwargs):
        raise PresentationSlotError("synthetic_copy_failure")

    monkeypatch.setattr(
        presentation_slots,
        "_copy_and_replace",
        fail_copy,
    )
    with pytest.raises(
        PresentationSlotError,
        match=r"^synthetic_copy_failure$",
    ):
        rebuild_inactive_slot(
            active,
            media,
            slots_root,
            "A",
            ACCOUNT,
            "generation-2",
        )
    assert not os.path.lexists(first.ready_path)


def test_ready_is_published_only_after_final_tree_rescan(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    ready_path = (slots_root / "A" / "READY").absolute()
    original_rescan = presentation_slots._strict_rescan
    ready_states = []

    def observe_rescan(*args, **kwargs):
        ready_states.append(os.path.lexists(ready_path))
        return original_rescan(*args, **kwargs)

    monkeypatch.setattr(
        presentation_slots,
        "_strict_rescan",
        observe_rescan,
    )

    receipt = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )

    assert ready_states == [False, False]
    assert receipt.ready_path.is_file()


def test_ready_cleanup_failure_is_reported_explicitly(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    ready_path = (slots_root / "A" / "READY").absolute()
    original_atomic_write = presentation_slots.atomic_write_bytes
    original_unlink = Path.unlink

    def publish_then_fail(path: Path, payload: bytes) -> None:
        original_atomic_write(path, payload)
        if path == ready_path:
            raise OSError("synthetic_failure_after_ready_publication")

    def refuse_ready_cleanup(path: Path, *args, **kwargs) -> None:
        if path == ready_path:
            raise OSError("synthetic_ready_cleanup_failure")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(
        presentation_slots,
        "atomic_write_bytes",
        publish_then_fail,
    )
    monkeypatch.setattr(Path, "unlink", refuse_ready_cleanup)

    with pytest.raises(
        PresentationSlotError,
        match=r"^slot_ready_invalidation_failed$",
    ):
        rebuild_inactive_slot(
            active,
            media,
            slots_root,
            "A",
            ACCOUNT,
            "generation-1",
        )
    assert os.path.lexists(ready_path)


def test_nested_reparse_is_rejected_before_any_outside_write(
        tmp_path: Path) -> None:
    active = _active_tree(tmp_path)
    media = _media_receipt(tmp_path)
    slots_root = tmp_path / "slots"
    slots_root.mkdir()
    first = rebuild_inactive_slot(
        active,
        media,
        slots_root,
        "A",
        ACCOUNT,
        "generation-1",
    )
    attach_directory = (
        first.presentation_root
        / ACCOUNT
        / "msg"
        / "attach"
    )
    for child in attach_directory.iterdir():
        child.unlink()
    attach_directory.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.bin"
    sentinel.write_bytes(b"unchanged")
    try:
        os.symlink(
            outside,
            attach_directory,
            target_is_directory=True,
        )
    except OSError:
        pytest.skip("directory symlink creation unavailable")

    with pytest.raises(
        PresentationSlotError,
        match=r"^slot_tree_invalid$",
    ):
        rebuild_inactive_slot(
            active,
            media,
            slots_root,
            "A",
            ACCOUNT,
            "generation-2",
        )
    assert sentinel.read_bytes() == b"unchanged"
    assert tuple(outside.iterdir()) == (sentinel,)
    assert not os.path.lexists(first.ready_path)
