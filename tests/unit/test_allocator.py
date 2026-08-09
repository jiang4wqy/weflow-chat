import json
import os

import pytest

import weflow_chat.orchestrator as orchestrator
from weflow_chat.orchestrator import allocate_refresh_version
from weflow_chat.transaction import MirrorWriteError


RUN_ID = "33333333-3333-4333-8333-333333333333"


def test_exclusive_json_publisher_writes_canonical_payload(tmp_path):
    destination = tmp_path / "value.json"

    owned = orchestrator._publish_json_no_replace(
        destination, {"b": 2, "a": 1}
    )
    orchestrator._close_windows_handle(owned.handle)

    assert destination.read_bytes() == b'{"a":1,"b":2}'
    assert tuple(tmp_path.iterdir()) == (destination,)


def test_exclusive_json_publisher_flushes_after_rename(
    tmp_path, monkeypatch
):
    real_flush = orchestrator._flush_windows_handle
    flushes = []

    def record_flush(handle):
        flushes.append(handle)
        real_flush(handle)

    monkeypatch.setattr(
        orchestrator, "_flush_windows_handle", record_flush
    )
    owned = orchestrator._publish_json_no_replace(
        tmp_path / "value.json", {"value": 1}
    )
    orchestrator._close_windows_handle(owned.handle)

    assert len(flushes) == 1


def test_json_create_preserves_query_error_when_delete_fails(
    tmp_path, monkeypatch
):
    primary_error = RuntimeError("identity_query")
    real_delete = orchestrator._delete_windows_handle
    monkeypatch.setattr(
        orchestrator,
        "_query_file_identity",
        lambda _handle: (_ for _ in ()).throw(primary_error),
    )
    monkeypatch.setattr(
        orchestrator,
        "_delete_windows_handle",
        lambda _handle: (_ for _ in ()).throw(
            PermissionError("delete_failed")
        ),
    )

    with pytest.raises(RuntimeError, match="identity_query") as captured:
        orchestrator._create_owned_json(
            tmp_path / "value.json", {"value": 1}
        )

    assert captured.value is primary_error
    assert any(
        "json_create_delete_failed" in note
        for note in getattr(primary_error, "__notes__", ())
    )
    monkeypatch.setattr(
        orchestrator, "_delete_windows_handle", real_delete
    )
    (tmp_path / "value.json").unlink()


def _allocate(tmp_path, timestamp="20260721-140000"):
    (tmp_path / "E").mkdir(exist_ok=True)
    (tmp_path / "C").mkdir(exist_ok=True)
    return allocate_refresh_version(
        snapshots_root=tmp_path / "E",
        recovery_root=tmp_path / "C",
        timestamp_utc=timestamp,
        run_id=RUN_ID,
    )


def test_allocator_uses_timestamp_guid_and_writes_strict_locator(
    tmp_path,
):
    allocated = _allocate(tmp_path)

    assert allocated.layout.root == (
        tmp_path / "E" / f"20260721-140000-{RUN_ID}"
    )
    assert allocated.recovery_root == tmp_path / "C" / RUN_ID
    assert allocated.store.primary_path == (
        allocated.layout.root / "transaction.json"
    )
    assert allocated.store.recovery_path == (
        allocated.recovery_root / "transaction.json"
    )
    locator = json.loads(
        (
            allocated.recovery_root / "run-locator.json"
        ).read_text(encoding="utf-8")
    )
    assert locator == {
        "schemaVersion": 1,
        "runId": RUN_ID,
        "primaryTransactionPath": str(
            allocated.layout.root / "transaction.json"
        ),
    }
    assert allocated.store.read_equal().record.run_id == RUN_ID


def test_allocator_locator_failure_removes_only_fresh_empty_roots(
    tmp_path, monkeypatch
):
    real_write = orchestrator._write_locator_no_replace
    monkeypatch.setattr(
        orchestrator,
        "_write_locator_no_replace",
        lambda _path, _value: (_ for _ in ()).throw(
            OSError("locator_write")
        ),
    )

    with pytest.raises(OSError, match="locator_write"):
        _allocate(tmp_path, "20260721-140001")

    assert not (
        tmp_path / "E" / f"20260721-140001-{RUN_ID}"
    ).exists()
    assert not (tmp_path / "C" / RUN_ID).exists()
    monkeypatch.setattr(
        orchestrator, "_write_locator_no_replace", real_write
    )
    assert _allocate(
        tmp_path, "20260721-140001"
    ).store.read_equal()


def test_allocator_post_rename_open_failure_cleans_and_retries(
    tmp_path, monkeypatch
):
    real_open = orchestrator._open_owned_file
    failed = False

    def fail_first_final_open(
        path, *, for_delete=False, share_delete=False
    ):
        nonlocal failed
        if (
            not failed
            and not for_delete
            and not share_delete
            and path.name == "transaction.json"
        ):
            failed = True
            raise OSError("probe_open")
        return real_open(
            path,
            for_delete=for_delete,
            share_delete=share_delete,
        )

    monkeypatch.setattr(
        orchestrator,
        "_open_owned_file",
        fail_first_final_open,
    )

    with pytest.raises(
        MirrorWriteError,
        match="mirrored_transaction_create_failed",
    ):
        _allocate(tmp_path, "20260721-140016")

    assert failed
    assert not (
        tmp_path / "E" / f"20260721-140016-{RUN_ID}"
    ).exists()
    assert not (tmp_path / "C" / RUN_ID).exists()
    monkeypatch.setattr(
        orchestrator, "_open_owned_file", real_open
    )
    assert _allocate(
        tmp_path, "20260721-140016"
    ).store.read_equal()


def test_allocator_store_create_failure_removes_partial_files(
    tmp_path, monkeypatch
):
    real_create = (
        orchestrator.MirroredTransactionStore
        .create_with_exclusive_publisher
    )

    def fail_after_primary(self, _record, *, publish_json):
        publish_json(self.primary_path, {})
        raise OSError("store_create")

    monkeypatch.setattr(
        orchestrator.MirroredTransactionStore,
        "create_with_exclusive_publisher",
        fail_after_primary,
    )
    with pytest.raises(OSError, match="store_create"):
        _allocate(tmp_path, "20260721-140002")

    assert not (
        tmp_path / "E" / f"20260721-140002-{RUN_ID}"
    ).exists()
    assert not (tmp_path / "C" / RUN_ID).exists()
    monkeypatch.setattr(
        orchestrator.MirroredTransactionStore,
        "create_with_exclusive_publisher",
        real_create,
    )
    assert _allocate(
        tmp_path, "20260721-140002"
    ).store.read_equal()


@pytest.mark.parametrize(
    "failure_point", ["layout", "store_constructor"]
)
def test_allocator_constructor_failure_removes_fresh_roots(
    tmp_path, monkeypatch, failure_point
):
    with monkeypatch.context() as scoped:
        if failure_point == "layout":
            scoped.setattr(
                orchestrator.RunLayout,
                "from_existing_root",
                classmethod(
                    lambda _cls, _root: (
                        _ for _ in ()
                    ).throw(
                        RuntimeError("allocator_construction")
                    )
                ),
            )
        else:
            scoped.setattr(
                orchestrator,
                "MirroredTransactionStore",
                lambda **_kwargs: (
                    _ for _ in ()
                ).throw(
                    RuntimeError("allocator_construction")
                ),
            )
        with pytest.raises(
            RuntimeError, match="allocator_construction"
        ):
            _allocate(tmp_path, "20260721-140003")

    assert not (
        tmp_path / "E" / f"20260721-140003-{RUN_ID}"
    ).exists()
    assert not (tmp_path / "C" / RUN_ID).exists()
    assert _allocate(
        tmp_path, "20260721-140003"
    ).store.read_equal()


@pytest.mark.parametrize(
    "timestamp,run_id",
    [
        ("20260721-14000", RUN_ID),
        ("20260721-140000", "not-a-uuid"),
        ("20260230-140000", RUN_ID),
    ],
)
def test_allocator_rejects_invalid_identity_before_creation(
    tmp_path, timestamp, run_id
):
    with pytest.raises(ValueError):
        allocate_refresh_version(
            snapshots_root=tmp_path / "E",
            recovery_root=tmp_path / "C",
            timestamp_utc=timestamp,
            run_id=run_id,
        )

    assert not (tmp_path / "E").exists()
    assert not (tmp_path / "C").exists()


def test_allocator_collision_preserves_existing_root(tmp_path):
    existing = tmp_path / "E" / f"20260721-140004-{RUN_ID}"
    existing.mkdir(parents=True)
    sentinel = existing / "sentinel"
    sentinel.write_bytes(b"keep")

    with pytest.raises(
        FileExistsError, match="refresh_version_collision"
    ):
        _allocate(tmp_path, "20260721-140004")

    assert sentinel.read_bytes() == b"keep"


@pytest.mark.skipif(
    os.name != "nt", reason="Windows NtCreateFile semantics"
)
def test_atomic_directory_create_never_replaces_hidden_collision(
    tmp_path, monkeypatch
):
    (tmp_path / "E").mkdir()
    (tmp_path / "C").mkdir()
    existing = tmp_path / "E" / f"20260721-140015-{RUN_ID}"
    existing.mkdir()
    sentinel = existing / "sentinel"
    sentinel.write_bytes(b"keep")
    real_lexists = os.path.lexists

    def hide_target_from_precheck(path):
        if os.path.normcase(str(path)) == os.path.normcase(
            str(existing)
        ):
            return False
        return real_lexists(path)

    monkeypatch.setattr(
        orchestrator.os.path,
        "lexists",
        hide_target_from_precheck,
    )

    with pytest.raises(FileExistsError):
        allocate_refresh_version(
            snapshots_root=tmp_path / "E",
            recovery_root=tmp_path / "C",
            timestamp_utc="20260721-140015",
            run_id=RUN_ID,
        )

    assert sentinel.read_bytes() == b"keep"


def test_allocator_transaction_competitor_is_never_replaced(
    tmp_path, monkeypatch
):
    real_publish = orchestrator._publish_json_no_replace
    competitor = tmp_path / "C" / RUN_ID / "transaction.json"
    injected = False

    def publish_after_competitor(path, value):
        nonlocal injected
        if not injected:
            injected = True
            path.write_bytes(b"competitor")
        return real_publish(path, value)

    monkeypatch.setattr(
        orchestrator,
        "_publish_json_no_replace",
        publish_after_competitor,
    )

    with pytest.raises(
        MirrorWriteError,
        match="mirrored_transaction_create_failed",
    ):
        _allocate(tmp_path, "20260721-140005")

    assert competitor.read_bytes() == b"competitor"


def test_allocator_locator_competitor_is_never_replaced(
    tmp_path, monkeypatch
):
    real_write = orchestrator._write_locator_no_replace
    competitor = tmp_path / "C" / RUN_ID / "run-locator.json"

    def write_after_competitor(path, value):
        path.write_bytes(b"competitor")
        return real_write(path, value)

    monkeypatch.setattr(
        orchestrator,
        "_write_locator_no_replace",
        write_after_competitor,
    )

    with pytest.raises(FileExistsError):
        _allocate(tmp_path, "20260721-140006")

    assert competitor.read_bytes() == b"competitor"


def test_allocator_publishes_locator_after_equal_mirrors(
    tmp_path, monkeypatch
):
    real_write = orchestrator._write_locator_no_replace
    primary = (
        tmp_path
        / "E"
        / f"20260721-140007-{RUN_ID}"
        / "transaction.json"
    )
    recovery = tmp_path / "C" / RUN_ID / "transaction.json"

    def assert_mirrors_then_write(path, value):
        assert primary.read_bytes() == recovery.read_bytes()
        return real_write(path, value)

    monkeypatch.setattr(
        orchestrator,
        "_write_locator_no_replace",
        assert_mirrors_then_write,
    )

    _allocate(tmp_path, "20260721-140007")


def test_allocator_rejects_same_identity_locator_mutation(
    tmp_path, monkeypatch
):
    real_open = orchestrator._open_owned_file
    mutated = False

    def mutate_before_final_lock(
        path, *, for_delete=False, share_delete=False
    ):
        nonlocal mutated
        if (
            not mutated
            and not for_delete
            and not share_delete
            and path.name == "run-locator.json"
        ):
            mutated = True
            path.write_bytes(b"mutated")
        return real_open(
            path,
            for_delete=for_delete,
            share_delete=share_delete,
        )

    monkeypatch.setattr(
        orchestrator,
        "_open_owned_file",
        mutate_before_final_lock,
    )

    with pytest.raises(
        RuntimeError,
        match="allocator_publish_content_changed",
    ):
        _allocate(tmp_path, "20260721-140017")

    assert mutated
    assert not (
        tmp_path / "E" / f"20260721-140017-{RUN_ID}"
    ).exists()
    assert not (tmp_path / "C" / RUN_ID).exists()


def test_allocator_rejects_post_link_competitor_identity(
    tmp_path, monkeypatch
):
    real_open = orchestrator._open_owned_file
    competitor = tmp_path / "C" / RUN_ID / "transaction.json"
    injected = False

    def replace_published_link(
        path, *, for_delete=False, share_delete=False
    ):
        nonlocal injected
        if (
            not injected
            and not for_delete
            and not share_delete
            and path.name == "transaction.json"
        ):
            injected = True
            path.unlink()
            path.write_bytes(b"competitor")
        return real_open(
            path,
            for_delete=for_delete,
            share_delete=share_delete,
        )

    monkeypatch.setattr(
        orchestrator,
        "_open_owned_file",
        replace_published_link,
    )

    with pytest.raises(
        MirrorWriteError,
        match="mirrored_transaction_create_failed",
    ):
        _allocate(tmp_path, "20260721-140008")

    assert injected
    assert competitor.read_bytes() == b"competitor"


def test_allocator_cleanup_never_deletes_swapped_competitor(
    tmp_path, monkeypatch
):
    real_open = orchestrator._open_owned_file
    swapped_path = None

    def swap_before_delete_open(
        path, *, for_delete=False, share_delete=False
    ):
        nonlocal swapped_path
        if for_delete and swapped_path is None:
            path.unlink()
            path.write_bytes(b"competitor")
            swapped_path = path
        return real_open(
            path,
            for_delete=for_delete,
            share_delete=share_delete,
        )

    monkeypatch.setattr(
        orchestrator,
        "_open_owned_file",
        swap_before_delete_open,
    )
    monkeypatch.setattr(
        orchestrator,
        "_write_locator_no_replace",
        lambda _path, _value: (_ for _ in ()).throw(
            OSError("locator_write")
        ),
    )

    with pytest.raises(OSError, match="locator_write"):
        _allocate(tmp_path, "20260721-140009")

    assert swapped_path is not None
    assert swapped_path.read_bytes() == b"competitor"
    assert not (
        tmp_path / "E" / f"20260721-140009-{RUN_ID}"
    ).exists()


def test_allocator_preserves_primary_error_when_cleanup_close_fails(
    tmp_path, monkeypatch
):
    primary_error = OSError("locator_write")

    def fail_locator(_path, _value):
        monkeypatch.setattr(
            orchestrator,
            "_close_windows_handle",
            lambda _handle: (_ for _ in ()).throw(
                PermissionError("close_failed")
            ),
        )
        raise primary_error

    monkeypatch.setattr(
        orchestrator,
        "_write_locator_no_replace",
        fail_locator,
    )

    with pytest.raises(OSError, match="locator_write") as captured:
        _allocate(tmp_path, "20260721-140010")

    assert captured.value is primary_error
    assert isinstance(captured.value.__cause__, PermissionError)
    assert any(
        "owned_handle_close_failed" in note
        for note in getattr(captured.value, "__notes__", ())
    )


def test_allocator_requires_existing_parent_roots(tmp_path):
    snapshots_root = tmp_path / "E"
    snapshots_root.mkdir()

    with pytest.raises(FileNotFoundError):
        allocate_refresh_version(
            snapshots_root=snapshots_root,
            recovery_root=tmp_path / "C",
            timestamp_utc="20260721-140011",
            run_id=RUN_ID,
        )

    assert tuple(snapshots_root.iterdir()) == ()
    assert not (tmp_path / "C").exists()


@pytest.mark.skipif(
    os.name != "nt", reason="Windows directory handle semantics"
)
def test_allocator_rejects_parent_replaced_before_pin(
    tmp_path, monkeypatch
):
    (tmp_path / "E").mkdir()
    (tmp_path / "C").mkdir()
    real_pin = orchestrator._pin_directory
    snapshots_root = tmp_path / "E"
    displaced = tmp_path / "E.displaced"
    injected = False

    def replace_parent_then_pin(path):
        nonlocal injected
        if path == snapshots_root and not injected:
            injected = True
            path.rename(displaced)
            path.mkdir()
        return real_pin(path)

    monkeypatch.setattr(
        orchestrator,
        "_pin_directory",
        replace_parent_then_pin,
    )

    with pytest.raises(
        RuntimeError,
        match="fresh_allocator_parent_identity_changed",
    ):
        allocate_refresh_version(
            snapshots_root=snapshots_root,
            recovery_root=tmp_path / "C",
            timestamp_utc="20260721-140018",
            run_id=RUN_ID,
        )

    assert injected
    assert tuple(snapshots_root.iterdir()) == ()
    assert tuple(displaced.iterdir()) == ()


@pytest.mark.skipif(
    os.name != "nt", reason="Windows directory handle semantics"
)
def test_allocator_pins_run_root_until_locator_is_published(
    tmp_path, monkeypatch
):
    real_write = orchestrator._write_locator_no_replace
    run_root = (
        tmp_path
        / "E"
        / f"20260721-140012-{RUN_ID}"
    )

    def try_to_replace_root(path, value):
        with pytest.raises(OSError):
            run_root.rename(tmp_path / "replaced")
        return real_write(path, value)

    monkeypatch.setattr(
        orchestrator,
        "_write_locator_no_replace",
        try_to_replace_root,
    )

    _allocate(tmp_path, "20260721-140012")


@pytest.mark.skipif(
    os.name != "nt", reason="Windows directory handle semantics"
)
def test_allocator_pins_parent_roots_until_publication(
    tmp_path, monkeypatch
):
    real_write = orchestrator._write_locator_no_replace

    def try_to_replace_parent(path, value):
        with pytest.raises(OSError):
            (tmp_path / "E").rename(tmp_path / "replaced-parent")
        return real_write(path, value)

    monkeypatch.setattr(
        orchestrator,
        "_write_locator_no_replace",
        try_to_replace_parent,
    )

    _allocate(tmp_path, "20260721-140013")
