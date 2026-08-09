from pathlib import Path
import json

import pytest

from weflow_chat.audit import (
    AuditErrorCode, AuditEvent, AuditStage, AuditStatus, AuditWriter,
    InvalidAuditEventError, SensitiveAuditValueError,
)
from weflow_chat.atomic_io import atomic_write_bytes
from weflow_chat.models import CopyRole, PlannedFile
import weflow_chat.paths as paths_module
from weflow_chat.paths import (
    PathBoundaryError, assert_descendant, canonical_existing,
)


def test_rejects_destination_outside_run_root(tmp_path: Path) -> None:
    (tmp_path / "run").mkdir()
    with pytest.raises(PathBoundaryError):
        assert_descendant(tmp_path / "outside", tmp_path / "run")


def test_run_layout_derives_every_fixed_run_artifact(tmp_path: Path) -> None:
    root = tmp_path / "run"
    root.mkdir()
    layout = paths_module.RunLayout.from_existing_root(root)
    assert layout.manifest_path == root / "manifest.json"
    assert layout.compatibility_path == root / "compatibility.json"
    assert layout.transaction_path == root / "transaction.json"
    assert layout.audit_path == root / "audit.jsonl"
    assert layout.config_backup == root / "config-backup"
    account = "wxid_synthetic_66a8"
    assert layout.role_account_root(
        CopyRole.SOURCE, account) == root / "source" / account
    assert layout.role_db_storage(
        CopyRole.SOURCE, account) == (
            root / "source" / account / "db_storage")
    assert layout.role_db_storage(
        CopyRole.VSS_STAGING, account) == (
            root / "vss-staging" / account / "db_storage")
    assert layout.role_db_storage(
        CopyRole.VALIDATION, account) == (
            root / "validation" / account / "db_storage")
    assert layout.role_db_storage(
        CopyRole.ACTIVE, account) == (
            root / "active" / account / "db_storage")


@pytest.mark.parametrize("account", [
    "", ".", "..", r"parent\child", "parent/child", "name:stream",
    "generic", "wxid_bad-name", "wxid_bad.name", "WXID_upper",
])
def test_run_layout_rejects_unsafe_source_account_name(
        tmp_path: Path, account: str) -> None:
    root = tmp_path / "run"
    root.mkdir()
    layout = paths_module.RunLayout.from_existing_root(root)
    with pytest.raises(PathBoundaryError,
                       match="source_account_name_rejected"):
        layout.role_db_storage(CopyRole.SOURCE, account)


def test_audit_rejects_safe_envelope(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    with pytest.raises(SensitiveAuditValueError):
        writer.append(AuditEvent(stage=AuditStage.COPY,
                                 status=AuditStatus.FAILED,
                                 error_code=AuditErrorCode.IO_FAILURE,
                                 normalized_paths=("safe:ZmFrZQ==",)))


def test_audit_rejects_account_id_and_non_enum_fields(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    with pytest.raises(SensitiveAuditValueError):
        writer.append(AuditEvent(
            stage=AuditStage.COPY, status=AuditStatus.FAILED,
            error_code=AuditErrorCode.PATH_REJECTED,
            normalized_paths=("role/source/" + "wxid_" + "not_loggable",)))
    with pytest.raises(InvalidAuditEventError):
        writer.append(AuditEvent(stage="copy", status=AuditStatus.OK))


@pytest.mark.parametrize("status", [AuditStatus.BLOCKED, AuditStatus.FAILED])
def test_audit_requires_fixed_error_code_for_unsuccessful_statuses(
        status: AuditStatus) -> None:
    with pytest.raises(InvalidAuditEventError,
                       match="missing_audit_error_code"):
        AuditEvent(stage=AuditStage.COPY, status=status)


@pytest.mark.parametrize("role", list(CopyRole))
def test_audit_accepts_known_role_alias_path_shape(
        tmp_path: Path, role: CopyRole) -> None:
    path = tmp_path / "audit.jsonl"
    AuditWriter(path).append(AuditEvent(
        stage=AuditStage.COPY, status=AuditStatus.OK,
        normalized_paths=(role.value, f"{role.value}/session.db")))
    assert json.loads(path.read_text(encoding="utf-8"))[
        "normalizedPaths"] == [role.value, f"{role.value}/session.db"]


def test_audit_rejects_extra_account_directory_in_normalized_path(
        tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    with pytest.raises(SensitiveAuditValueError,
                       match="audit_path_rejected"):
        writer.append(AuditEvent(
            stage=AuditStage.COPY, status=AuditStatus.OK,
            normalized_paths=("source/account-42/session.db",)))


@pytest.mark.parametrize("field", [
    "file_count", "byte_count", "pid", "candidate_count",
])
@pytest.mark.parametrize("value", [-1, True, "1", 1.0])
def test_audit_rejects_invalid_quantitative_fields(
        field: str, value: object) -> None:
    with pytest.raises(InvalidAuditEventError, match="invalid_audit_quantity"):
        AuditEvent(stage=AuditStage.COPY, status=AuditStatus.OK,
                   **{field: value})


def test_audit_requires_immutable_normalized_path_and_hash_tuples() -> None:
    with pytest.raises(InvalidAuditEventError, match="invalid_audit_paths"):
        AuditEvent(stage=AuditStage.COPY, status=AuditStatus.OK,
                   normalized_paths=["source"])  # type: ignore[arg-type]
    with pytest.raises(InvalidAuditEventError, match="invalid_audit_hashes"):
        AuditEvent(stage=AuditStage.COPY, status=AuditStatus.OK,
                   sha256_values=["a" * 64])  # type: ignore[arg-type]


def test_audit_normalizes_and_validates_sha256_values() -> None:
    event = AuditEvent(stage=AuditStage.COPY, status=AuditStatus.OK,
                       sha256_values=("A" * 64,))
    assert event.sha256_values == ("a" * 64,)
    for invalid in ("safe:ZmFrZQ==", "a" * 63, "g" * 64):
        with pytest.raises(InvalidAuditEventError, match="invalid_audit_sha256"):
            AuditEvent(stage=AuditStage.COPY, status=AuditStatus.OK,
                       sha256_values=(invalid,))


def test_audit_requires_utc_iso8601_timestamp() -> None:
    event = AuditEvent(stage=AuditStage.COPY, status=AuditStatus.OK,
                       at_utc="2026-07-22T12:34:56+00:00")
    assert event.at_utc == "2026-07-22T12:34:56+00:00"
    for invalid in ("free text", "2026-07-22T12:34:56",
                    "2026-07-22T12:34:56+08:00"):
        with pytest.raises(InvalidAuditEventError, match="invalid_audit_at_utc"):
            AuditEvent(stage=AuditStage.COPY, status=AuditStatus.OK,
                       at_utc=invalid)


def test_rejects_ads_device_and_reparse_paths(tmp_path: Path,
                                               monkeypatch) -> None:
    with pytest.raises(PathBoundaryError, match="alternate_stream"):
        canonical_existing(tmp_path / "config.json:secret")
    with pytest.raises(PathBoundaryError, match="special_path"):
        canonical_existing(Path(
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy99"))
    junction = tmp_path / "junction"
    junction.mkdir()
    monkeypatch.setattr(
        paths_module, "_is_reparse",
        lambda path: path == junction.absolute())
    with pytest.raises(PathBoundaryError, match="reparse_component"):
        canonical_existing(junction)


def test_rejects_native_device_path_case_insensitively() -> None:
    with pytest.raises(PathBoundaryError, match="special_path"):
        canonical_existing(Path(
            r"\dEvIcE\HarddiskVolumeShadowCopy99\synthetic.db"))


def test_existing_and_future_paths_reject_reparse_in_any_ancestor(
        tmp_path: Path, monkeypatch) -> None:
    ancestor = tmp_path / "ancestor"
    ancestor.mkdir()
    child = ancestor / "child.json"
    child.write_bytes(b"synthetic")
    monkeypatch.setattr(
        paths_module, "_is_reparse",
        lambda path: path == ancestor.absolute())
    with pytest.raises(PathBoundaryError, match="reparse_component"):
        canonical_existing(child)
    with pytest.raises(PathBoundaryError, match="reparse_component"):
        paths_module.canonical_future(
            ancestor / "not-yet-created" / "future.json")


def test_audit_has_fixed_fields(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditWriter(path).append(AuditEvent(stage=AuditStage.COPY,
                                        status=AuditStatus.OK,
                                        file_count=3, byte_count=12))
    record = json.loads(path.read_text(encoding="utf-8"))
    assert set(record) == {
        "atUtc", "stage", "status", "errorCode", "normalizedPaths",
        "fileCount", "byteCount", "sha256Values", "pid", "candidateCount"
    }


def test_atomic_write_replaces_and_rereads_exact_bytes(tmp_path: Path):
    target = tmp_path / "transaction.json"
    atomic_write_bytes(target, b"old")
    atomic_write_bytes(target, b"new")
    assert target.read_bytes() == b"new"


def test_planned_file_is_a_task1_shared_contract() -> None:
    value = PlannedFile(
        live_path=r"C:\synthetic\WeFlow-config.json",
        action="replace", existed_before=True,
        expected_old_sha256="A" * 64,
        expected_new_sha256="B" * 64)
    assert value.action == "replace"
