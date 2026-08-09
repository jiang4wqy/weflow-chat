from dataclasses import dataclass
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import stat
from types import SimpleNamespace

import pytest

import weflow_chat.manifest as manifest_module
from weflow_chat.copies import (
    CopyVerificationError, copy_tree_verified,
    flush_file_durable, import_vss_staging, materialize_role_copy,
)
from weflow_chat.manifest import (
    UnsafeTreeEntryError, build_manifest, file_set_receipt,
    read_run_manifest,
    staging_receipt_sha256, validate_scandir_entry,
    validate_account_role_tree,
)
from weflow_chat.atomic_io import replace_write_through
from weflow_chat.audit import AuditErrorCode
from weflow_chat.models import CopyRole
from weflow_chat.paths import PathBoundaryError, RunLayout


def test_manifest_includes_existing_sidecars(synthetic_db_storage):
    manifest = build_manifest(synthetic_db_storage, role=CopyRole.SOURCE)
    names = {entry.relative_path for entry in manifest.files}
    assert {"session.db", "session.db-wal", "session.db-shm"} <= names


def test_manifest_allows_absent_wal(synthetic_db_storage_without_wal):
    manifest = build_manifest(
        synthetic_db_storage_without_wal, role=CopyRole.SOURCE)
    assert all(not item.relative_path.endswith("-wal")
               for item in manifest.files)


def test_run_manifest_records_snapshot_provenance(tmp_path,
                                                   synthetic_db_storage):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    staging_db = layout.role_db_storage(CopyRole.VSS_STAGING, account)
    staging_db.parent.mkdir(parents=True)
    shutil.copytree(synthetic_db_storage, staging_db)
    staging_manifest = build_manifest(
        layout.vss_staging, role=CopyRole.VSS_STAGING)
    receipt = SimpleNamespace(
        staging_path=layout.vss_staging,
        source_account_name=account,
        account_db_relative_path=PureWindowsPath(account, "db_storage"),
        file_count=staging_manifest.total_files,
        byte_count=staging_manifest.total_bytes,
        manifest_sha256=staging_receipt_sha256(staging_manifest))
    run_manifest = import_vss_staging(
        layout, staging_receipt=receipt,
        source_account_name=account,
        run_id="11111111-1111-1111-1111-111111111111",
        captured_at_utc="2026-07-21T12:00:00+00:00",
        source_volume="F:\\",
        shadow_id="{22222222-2222-2222-2222-222222222222}")
    value = json.loads(layout.manifest_path.read_text(encoding="utf-8"))
    assert value["runId"] == "11111111-1111-1111-1111-111111111111"
    assert value["sourceAccountName"] == "wxid_synthetic_66a8"
    assert value["snapshotMethod"] == "vss-crash-consistent"
    assert value["shadowId"] == (
        "{22222222-2222-2222-2222-222222222222}")
    assert value["residualRisk"] == (
        "crash_consistent_no_cross_database_atomicity_proof")
    assert value["categoryCounts"]["wal"] == 1
    assert value["source"]["totalFiles"] == run_manifest.source.total_files
    source_db = layout.role_db_storage(
        CopyRole.SOURCE, "wxid_synthetic_66a8")
    assert Path(value["source"]["root"]) == layout.source
    assert all(item["relativePath"].startswith(
        account + "/db_storage/") for item in value["source"]["files"])
    assert (source_db / "session.db").is_file()
    assert not (layout.source / "session.db").exists()
    reread, receipt = read_run_manifest(
        layout, expected_run_id=run_manifest.run_id,
        expected_source_account_name="wxid_synthetic_66a8")
    assert reread == run_manifest
    assert receipt.manifest_path == str(layout.manifest_path)
    assert len(receipt.canonical_sha256) == 64
    original_manifest = layout.manifest_path.read_text(encoding="utf-8")
    first_size = value["source"]["files"][0]["size"]
    duplicate_payloads = (
        original_manifest.replace(
            f'"runId":"{run_manifest.run_id}"',
            (
                f'"runId":"{run_manifest.run_id}",'
                f'"runId":"{run_manifest.run_id}"'
            ),
            1,
        ),
        original_manifest.replace(
            '"role":"source"',
            '"role":"source","role":"source"',
            1,
        ),
        original_manifest.replace(
            f'"size":{first_size}',
            f'"size":{first_size},"size":{first_size}',
            1,
        ),
    )
    for payload in duplicate_payloads:
        layout.manifest_path.write_text(payload, encoding="utf-8")
        with pytest.raises(
            ValueError, match="run_manifest_schema_mismatch"
        ):
            read_run_manifest(
                layout,
                expected_run_id=run_manifest.run_id,
                expected_source_account_name="wxid_synthetic_66a8",
            )
    layout.manifest_path.write_text(original_manifest, encoding="utf-8")
    with pytest.raises(ValueError, match="run_manifest_schema_mismatch"):
        read_run_manifest(
            layout, expected_run_id=run_manifest.run_id,
            expected_source_account_name="wxid_other")

    validation = materialize_role_copy(
        layout, CopyRole.VALIDATION,
        source_account_name="wxid_synthetic_66a8")
    active = materialize_role_copy(
        layout, CopyRole.ACTIVE,
        source_account_name="wxid_synthetic_66a8")
    assert validation.root == str(layout.validation)
    assert active.root == str(layout.active)
    assert (file_set_receipt(validation).content_sha256 ==
            file_set_receipt(active).content_sha256 ==
            file_set_receipt(run_manifest.source).content_sha256)


def test_run_manifest_reader_rejects_extra_fields(tmp_path):
    root = tmp_path / "run"
    root.mkdir()
    layout = RunLayout.from_existing_root(root)
    layout.manifest_path.write_text(
        '{"schemaVersion":1,"extra":true}', encoding="utf-8")
    with pytest.raises(ValueError, match="run_manifest_schema_mismatch"):
        read_run_manifest(
            layout,
            expected_run_id="11111111-1111-1111-1111-111111111111",
            expected_source_account_name="wxid_synthetic_66a8")


def test_import_rejects_an_ordinary_but_non_staging_path(tmp_path):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    other = run_root / "other"
    other.mkdir()
    receipt = SimpleNamespace(
        staging_path=other, file_count=0, byte_count=0,
        source_account_name=account,
        account_db_relative_path=PureWindowsPath(account, "db_storage"),
        manifest_sha256="0" * 64)
    with pytest.raises(PathBoundaryError,
                       match="not_exact_run_vss_staging"):
        import_vss_staging(
            layout, staging_receipt=receipt,
            source_account_name=account,
            run_id="11111111-1111-1111-1111-111111111111",
            captured_at_utc="2026-07-21T12:00:00+00:00",
            source_volume="F:\\",
            shadow_id="{22222222-2222-2222-2222-222222222222}")


def test_import_rejects_staging_receipt_account_mismatch(
        tmp_path, synthetic_db_storage):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    staging_db = layout.role_db_storage(CopyRole.VSS_STAGING, account)
    staging_db.parent.mkdir(parents=True)
    shutil.copytree(synthetic_db_storage, staging_db)
    staging_manifest = build_manifest(
        layout.vss_staging, role=CopyRole.VSS_STAGING)
    receipt = SimpleNamespace(
        staging_path=layout.vss_staging,
        source_account_name="wxid_other",
        account_db_relative_path=PureWindowsPath(
            "wxid_other", "db_storage"),
        file_count=staging_manifest.total_files,
        byte_count=staging_manifest.total_bytes,
        manifest_sha256=staging_receipt_sha256(staging_manifest))
    with pytest.raises(CopyVerificationError,
                       match="staging_account_contract_mismatch"):
        import_vss_staging(
            layout, staging_receipt=receipt,
            source_account_name=account,
            run_id="11111111-1111-1111-1111-111111111111",
            captured_at_utc="2026-07-21T12:00:00+00:00",
            source_volume="F:\\",
            shadow_id="{22222222-2222-2222-2222-222222222222}")


@dataclass
class FakeDirEntry:
    name: str
    reparse: bool = False
    symlink: bool = False
    kind: str = "file"

    def is_symlink(self):
        return self.symlink

    def stat(self, *, follow_symlinks):
        assert follow_symlinks is False
        flags = (stat.FILE_ATTRIBUTE_REPARSE_POINT
                 if self.reparse else 0)
        return SimpleNamespace(st_file_attributes=flags)

    def is_file(self, *, follow_symlinks):
        return self.kind == "file"

    def is_dir(self, *, follow_symlinks):
        return self.kind == "dir"


@pytest.mark.parametrize("entry", [
    FakeDirEntry("session.db:secret"),
    FakeDirEntry("junction", reparse=True, kind="dir"),
    FakeDirEntry("link.db", symlink=True),
])
def test_scandir_entry_rejects_ads_reparse_and_symlink(entry):
    with pytest.raises(UnsafeTreeEntryError):
        validate_scandir_entry(entry)


def test_copy_rejects_source_mutation(tmp_path, synthetic_db_storage):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    staging_db = layout.role_db_storage(CopyRole.VSS_STAGING, account)
    staging_db.parent.mkdir(parents=True)
    shutil.copytree(synthetic_db_storage, staging_db)

    def mutating_copy(source, destination):
        destination.write_bytes(source.read_bytes())
        if source.name == "session.db":
            source.write_bytes(source.read_bytes() + b"x")

    with pytest.raises(CopyVerificationError):
        copy_tree_verified(
            layout, from_role=CopyRole.VSS_STAGING,
            to_role=CopyRole.SOURCE,
            source_account_name=account,
            copy_file=mutating_copy)
    assert not layout.role_db_storage(
        CopyRole.SOURCE, account).exists()


@pytest.mark.parametrize("extra_at", ["role", "account"])
def test_role_tree_rejects_extra_top_level_directory(
        tmp_path, synthetic_db_storage, extra_at):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    staging_db = layout.role_db_storage(CopyRole.VSS_STAGING, account)
    staging_db.parent.mkdir(parents=True)
    shutil.copytree(synthetic_db_storage, staging_db)
    parent = (layout.vss_staging if extra_at == "role"
              else staging_db.parent)
    (parent / "unexpected-empty-directory").mkdir()
    with pytest.raises(CopyVerificationError,
                       match="account_role_tree_mismatch"):
        validate_account_role_tree(
            layout.vss_staging, source_account_name=account)


def test_role_tree_rejects_empty_db_storage(tmp_path):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    layout.role_db_storage(
        CopyRole.VSS_STAGING, account).mkdir(parents=True)
    with pytest.raises(CopyVerificationError,
                       match="account_role_tree_empty"):
        validate_account_role_tree(
            layout.vss_staging, source_account_name=account)


def test_role_tree_rejects_nested_empty_directory(
        tmp_path, synthetic_db_storage):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    staging_db = layout.role_db_storage(CopyRole.VSS_STAGING, account)
    staging_db.parent.mkdir(parents=True)
    shutil.copytree(synthetic_db_storage, staging_db)
    (staging_db / "empty-nested").mkdir()
    with pytest.raises(CopyVerificationError,
                       match="account_role_tree_empty"):
        validate_account_role_tree(
            layout.vss_staging, source_account_name=account)


def test_copy_flushes_every_file_before_write_through_publish(
        tmp_path, synthetic_db_storage):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    staging_db = layout.role_db_storage(CopyRole.VSS_STAGING, account)
    staging_db.parent.mkdir(parents=True)
    shutil.copytree(synthetic_db_storage, staging_db)
    flushed = []
    published = []

    def recording_flush(path):
        flushed.append(path.relative_to(path.parents[2]).as_posix())
        flush_file_durable(path)

    def recording_publish(source, destination):
        assert len(flushed) == len(build_manifest(
            layout.vss_staging,
            role=CopyRole.VSS_STAGING).files)
        published.append(destination)
        replace_write_through(source, destination)

    copy_tree_verified(
        layout, from_role=CopyRole.VSS_STAGING,
        to_role=CopyRole.SOURCE, source_account_name=account,
        flush_file=recording_flush,
        publish_directory=recording_publish)
    assert published == [layout.source]
    assert len(flushed) == len(set(flushed))


def test_bounded_manifest_reader_rejects_identity_change_during_open(
        tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    replacement = tmp_path / "replacement.json"
    manifest.write_bytes(b"{}")
    replacement.write_bytes(b"{}")
    real_open = os.open

    def swapping_open(path, flags):
        replacement.replace(manifest)
        return real_open(path, flags)

    monkeypatch.setattr(manifest_module.os, "open", swapping_open)
    with pytest.raises(ValueError, match="run_manifest_path_changed"):
        manifest_module._read_bounded_ordinary_file(manifest)


def test_file_flush_failure_preserves_partial_and_never_publishes(
        tmp_path, synthetic_db_storage):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    staging_db = layout.role_db_storage(CopyRole.VSS_STAGING, account)
    staging_db.parent.mkdir(parents=True)
    shutil.copytree(synthetic_db_storage, staging_db)

    def fail_flush(_):
        raise OSError("synthetic_file_fsync_failure")

    with pytest.raises(OSError, match="synthetic_file_fsync_failure"):
        copy_tree_verified(
            layout, from_role=CopyRole.VSS_STAGING,
            to_role=CopyRole.SOURCE,
            source_account_name=account, flush_file=fail_flush)
    assert not layout.source.exists()
    assert list(layout.root.glob(".source.partial.*"))


def test_post_publish_durability_failure_quarantines_destination(
        tmp_path, synthetic_db_storage):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    staging_db = layout.role_db_storage(CopyRole.VSS_STAGING, account)
    staging_db.parent.mkdir(parents=True)
    shutil.copytree(synthetic_db_storage, staging_db)

    def fail_durability(*_args, **_kwargs):
        raise OSError("synthetic_directory_durability_failure")

    with pytest.raises(
            OSError, match="synthetic_directory_durability_failure"):
        copy_tree_verified(
            layout, from_role=CopyRole.VSS_STAGING,
            to_role=CopyRole.SOURCE,
            source_account_name=account,
            verify_published=fail_durability)
    assert not layout.source.exists()
    assert list(layout.root.glob(".source.rejected.*"))


def test_publish_that_moves_then_raises_is_also_quarantined(
        tmp_path, synthetic_db_storage):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    staging_db = layout.role_db_storage(CopyRole.VSS_STAGING, account)
    staging_db.parent.mkdir(parents=True)
    shutil.copytree(synthetic_db_storage, staging_db)
    failed = False

    def publish_then_fail(source, destination):
        nonlocal failed
        replace_write_through(source, destination)
        if not failed:
            failed = True
            raise OSError("synthetic_post_move_failure")

    with pytest.raises(OSError, match="synthetic_post_move_failure"):
        copy_tree_verified(
            layout, from_role=CopyRole.VSS_STAGING,
            to_role=CopyRole.SOURCE,
            source_account_name=account,
            publish_directory=publish_then_fail)
    assert not layout.source.exists()
    assert list(layout.root.glob(".source.rejected.*"))


def _published_manifest_layout(tmp_path, synthetic_db_storage):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    staging_db = layout.role_db_storage(CopyRole.VSS_STAGING, account)
    staging_db.parent.mkdir(parents=True)
    shutil.copytree(synthetic_db_storage, staging_db)
    staging_manifest = build_manifest(
        layout.vss_staging, role=CopyRole.VSS_STAGING)
    receipt = SimpleNamespace(
        staging_path=layout.vss_staging,
        source_account_name=account,
        account_db_relative_path=PureWindowsPath(account, "db_storage"),
        file_count=staging_manifest.total_files,
        byte_count=staging_manifest.total_bytes,
        manifest_sha256=staging_receipt_sha256(staging_manifest))
    run_manifest = import_vss_staging(
        layout, staging_receipt=receipt, source_account_name=account,
        run_id="11111111-1111-1111-1111-111111111111",
        captured_at_utc="2026-07-21T12:00:00+00:00",
        source_volume="F:\\",
        shadow_id="{22222222-2222-2222-2222-222222222222}")
    return layout, account, run_manifest


@pytest.mark.parametrize("field,value", [
    ("schemaVersion", True),
    ("toolVersion", ""),
    ("capturedAtUtc", "2026-07-21T12:00:00"),
    ("sourceVolume", "F:"),
    ("shadowId", "not-a-uuid"),
    ("stagingManifestSha256", "not-a-sha256"),
    ("snapshotMethod", "other"),
    ("residualRisk", "other"),
])
def test_run_manifest_reader_rejects_malformed_top_level_values(
        tmp_path, synthetic_db_storage, field, value):
    layout, account, manifest = _published_manifest_layout(
        tmp_path, synthetic_db_storage)
    raw = json.loads(layout.manifest_path.read_text(encoding="utf-8"))
    raw[field] = value
    layout.manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="run_manifest_schema_mismatch"):
        read_run_manifest(layout, expected_run_id=manifest.run_id,
                          expected_source_account_name=account)


@pytest.mark.parametrize("relative_path", [
    "session.db",
    "wxid_synthetic_66a8/db_storage/../session.db",
    "wxid_synthetic_66a8\\db_storage\\session.db",
    "wxid_synthetic_66a8/db_storage/session.db:secret",
    "C:/wxid_synthetic_66a8/db_storage/session.db",
    "/wxid_synthetic_66a8/db_storage/session.db",
])
def test_run_manifest_reader_rejects_noncanonical_or_outside_file_path(
        tmp_path, synthetic_db_storage, relative_path):
    layout, account, manifest = _published_manifest_layout(
        tmp_path, synthetic_db_storage)
    raw = json.loads(layout.manifest_path.read_text(encoding="utf-8"))
    raw["source"]["files"][0]["relativePath"] = relative_path
    layout.manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="run_manifest_schema_mismatch"):
        read_run_manifest(layout, expected_run_id=manifest.run_id,
                          expected_source_account_name=account)


@pytest.mark.parametrize("failure,expected_code", [
    ("edge", AuditErrorCode.PATH_REJECTED),
    ("destination", AuditErrorCode.PATH_REJECTED),
    ("source_tree", AuditErrorCode.PATH_REJECTED),
    ("copy", AuditErrorCode.IO_FAILURE),
    ("publish", AuditErrorCode.IO_FAILURE),
])
def test_copy_failure_always_records_fixed_sanitized_audit_reason(
        tmp_path, synthetic_db_storage, failure, expected_code):
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    account = "wxid_synthetic_66a8"
    staging_db = layout.role_db_storage(CopyRole.VSS_STAGING, account)
    staging_db.parent.mkdir(parents=True)
    shutil.copytree(synthetic_db_storage, staging_db)
    kwargs = {}
    if failure == "edge":
        from_role, to_role = CopyRole.ACTIVE, CopyRole.SOURCE
    else:
        from_role, to_role = CopyRole.VSS_STAGING, CopyRole.SOURCE
    if failure == "destination":
        layout.source.mkdir()
    if failure == "copy":
        def fail_copy(_source, _destination):
            raise OSError("wxid_synthetic_66a8 C:/secret synthetic_failure")
        kwargs["copy_file"] = fail_copy
    if failure == "source_tree":
        (layout.vss_staging / "unexpected").mkdir()
    if failure == "publish":
        def fail_publish(_source, _destination):
            raise OSError("wxid_synthetic_66a8 C:/secret synthetic_failure")
        kwargs["publish_directory"] = fail_publish
    with pytest.raises((CopyVerificationError, OSError)):
        copy_tree_verified(layout, from_role=from_role, to_role=to_role,
                           source_account_name=account, **kwargs)
    records = [json.loads(line) for line in
               layout.audit_path.read_text(encoding="utf-8").splitlines()]
    assert records[-1]["status"] == "failed"
    assert records[-1]["errorCode"] == expected_code.value
    assert records[-1]["normalizedPaths"] == [from_role.value, to_role.value]
    assert "wxid_synthetic_66a8" not in layout.audit_path.read_text(
        encoding="utf-8")
    assert "synthetic_failure" not in layout.audit_path.read_text(
        encoding="utf-8")


def test_source_is_read_only_and_materialized_roles_are_writable(
        tmp_path, synthetic_db_storage):
    layout, account, _ = _published_manifest_layout(tmp_path,
                                                     synthetic_db_storage)
    source_files = list(iter((layout.role_db_storage(
        CopyRole.SOURCE, account)).rglob("*")))
    assert all(not (path.stat().st_mode & stat.S_IWRITE)
               for path in source_files if path.is_file())
    for role in (CopyRole.VALIDATION, CopyRole.ACTIVE):
        materialize_role_copy(layout, role, source_account_name=account)
        files = list(layout.role_db_storage(role, account).rglob("*"))
        assert all(path.stat().st_mode & stat.S_IWRITE
                   for path in files if path.is_file())
