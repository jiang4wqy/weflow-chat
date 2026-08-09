import os
from pathlib import Path, PureWindowsPath
import shutil
import stat
import uuid

from weflow_chat import __version__
from weflow_chat.atomic_io import replace_write_through
from weflow_chat.audit import (
    AuditErrorCode, AuditEvent, AuditStage, AuditStatus, AuditWriter,
)
from weflow_chat.manifest import (
    CopyVerificationError, FileSetManifest, ResidualRisk, RunManifest,
    SnapshotMethod, StagingReceiptLike, build_manifest,
    content_signature, iter_ordinary_files, publish_run_manifest,
    staging_receipt_sha256, validate_account_role_manifest,
    validate_account_role_tree, validate_scandir_entry, UnsafeTreeEntryError,
)
from weflow_chat.models import CopyRole
from weflow_chat.paths import (
    PathBoundaryError, RunLayout, assert_descendant, canonical_existing,
)


_ALLOWED_EDGES = {
    (CopyRole.VSS_STAGING, CopyRole.SOURCE),
    (CopyRole.SOURCE, CopyRole.VALIDATION),
    (CopyRole.SOURCE, CopyRole.ACTIVE),
}
_PATH_FAILURES = {
    "copy_edge_rejected", "destination_exists",
    "copied_file_identity_changed", "account_role_layout_mismatch",
    "account_role_tree_mismatch", "account_role_tree_empty",
    "account_role_name_collision", "unsafe_tree_entry",
    "non_ordinary_tree_entry", "published_directory_not_observable",
}
_HASH_FAILURES = {
    "copy_manifest_mismatch", "published_manifest_mismatch",
}


def _audit_error_code(error: BaseException) -> AuditErrorCode:
    if isinstance(error, PathBoundaryError):
        return AuditErrorCode.PATH_REJECTED
    if isinstance(error, UnsafeTreeEntryError):
        return AuditErrorCode.PATH_REJECTED
    if isinstance(error, OSError):
        return AuditErrorCode.IO_FAILURE
    if isinstance(error, CopyVerificationError):
        if str(error) in _PATH_FAILURES:
            return AuditErrorCode.PATH_REJECTED
        if str(error) in _HASH_FAILURES:
            return AuditErrorCode.HASH_MISMATCH
    return AuditErrorCode.IO_FAILURE


def _role_path(layout: RunLayout, role: CopyRole,
               source_account_name: str) -> Path:
    layout.role_db_storage(role, source_account_name)
    return layout.role_root(role)


def flush_file_durable(path: Path) -> None:
    with path.open("r+b") as stream:
        stream.flush()
        os.fsync(stream.fileno())


def verify_published_directory_durable(
        destination: Path, *, role: CopyRole,
        source_account_name: str,
        expected_signature: tuple) -> FileSetManifest:
    parent = canonical_existing(destination.parent)
    with os.scandir(parent) as iterator:
        matches = [entry for entry in iterator
                   if entry.name == destination.name]
    if (len(matches) != 1 or
            validate_scandir_entry(matches[0]) != "directory" or
            canonical_existing(Path(matches[0].path)) != destination):
        raise CopyVerificationError("published_directory_not_observable")
    validate_account_role_tree(
        destination, source_account_name=source_account_name)
    final = build_manifest(destination, role=role)
    validate_account_role_manifest(
        final, source_account_name=source_account_name)
    if content_signature(final) != expected_signature:
        raise CopyVerificationError("published_manifest_mismatch")
    return final


def copy_tree_verified(layout: RunLayout, *, from_role: CopyRole,
                       to_role: CopyRole,
                       source_account_name: str,
                       copy_file=shutil.copyfile,
                       flush_file=flush_file_durable,
                       publish_directory=replace_write_through,
                       verify_published=verify_published_directory_durable,
                       ) -> FileSetManifest:
    audit = AuditWriter(layout.audit_path)
    aliases = (from_role.value, to_role.value)
    audit.append(AuditEvent(
        stage=AuditStage.COPY, status=AuditStatus.STARTED,
        normalized_paths=aliases))
    try:
        if (from_role, to_role) not in _ALLOWED_EDGES:
            raise CopyVerificationError("copy_edge_rejected")
        source = _role_path(layout, from_role, source_account_name)
        destination = _role_path(layout, to_role, source_account_name)
        if from_role is CopyRole.VSS_STAGING:
            source = layout.require_exact_staging(source)
        else:
            source = canonical_existing(source)
        assert_descendant(source, layout.root)
        assert_descendant(destination, layout.root)
        if destination.exists():
            raise CopyVerificationError("destination_exists")
        partial = destination.with_name(
            f".{destination.name}.partial.{uuid.uuid4().hex}")
        partial.mkdir()
        validate_account_role_tree(
            source, source_account_name=source_account_name)
        before = build_manifest(source, role=from_role)
        validate_account_role_manifest(
            before, source_account_name=source_account_name)
        for item in before.files:
            source_file = source / Path(item.relative_path)
            target_file = partial / Path(item.relative_path)
            assert_descendant(source_file, source)
            assert_descendant(target_file, partial)
            target_file.parent.mkdir(parents=True, exist_ok=True)
            copy_file(source_file, target_file)
            copied_target = canonical_existing(target_file)
            if copied_target != target_file:
                raise CopyVerificationError("copied_file_identity_changed")
            flush_file(copied_target)
        validate_account_role_tree(
            source, source_account_name=source_account_name)
        after = build_manifest(source, role=from_role)
        validate_account_role_tree(
            partial, source_account_name=source_account_name)
        copied = build_manifest(partial, role=to_role)
        validate_account_role_manifest(
            copied, source_account_name=source_account_name)
        if not (content_signature(before) == content_signature(after) ==
                content_signature(copied)):
            raise CopyVerificationError("copy_manifest_mismatch")
        try:
            publish_directory(partial, destination)
            final = verify_published(
                destination, role=to_role,
                source_account_name=source_account_name,
                expected_signature=content_signature(before))
        except BaseException:
            rejected = destination.with_name(
                f".{destination.name}.rejected.{uuid.uuid4().hex}")
            if destination.exists():
                publish_directory(destination, rejected)
            raise
        audit.append(AuditEvent(
            stage=AuditStage.COPY, status=AuditStatus.OK,
            normalized_paths=aliases,
            file_count=final.total_files, byte_count=final.total_bytes))
        return final
    except BaseException as error:
        audit.append(AuditEvent(
            stage=AuditStage.COPY, status=AuditStatus.FAILED,
            error_code=_audit_error_code(error),
            normalized_paths=aliases))
        raise


def import_vss_staging(
        layout: RunLayout, *, staging_receipt: StagingReceiptLike,
        source_account_name: str, run_id: str, shadow_id: str,
        source_volume: str,
        captured_at_utc: str) -> RunManifest:
    uuid.UUID(run_id)
    uuid.UUID(shadow_id.strip("{}"))
    staging_path = layout.require_exact_staging(staging_receipt.staging_path)
    expected_relative = PureWindowsPath(source_account_name, "db_storage")
    if (staging_receipt.source_account_name != source_account_name or
            staging_receipt.account_db_relative_path != expected_relative):
        raise CopyVerificationError("staging_account_contract_mismatch")
    staging_manifest = build_manifest(
        staging_path, role=CopyRole.VSS_STAGING)
    validate_account_role_tree(
        staging_path, source_account_name=source_account_name)
    if (staging_manifest.total_files != staging_receipt.file_count or
            staging_manifest.total_bytes != staging_receipt.byte_count or
            staging_receipt_sha256(staging_manifest) !=
            staging_receipt.manifest_sha256):
        raise CopyVerificationError("staging_receipt_mismatch")
    source = copy_tree_verified(
        layout, from_role=CopyRole.VSS_STAGING,
        to_role=CopyRole.SOURCE,
        source_account_name=source_account_name)
    set_tree_read_only(layout.source)
    sealed = build_manifest(layout.source, role=CopyRole.SOURCE)
    if content_signature(sealed) != content_signature(source):
        raise CopyVerificationError("source_changed_while_sealing")
    value = RunManifest(
        schema_version=1, tool_version=__version__,
        run_id=run_id, source_account_name=source_account_name,
        captured_at_utc=captured_at_utc,
        source_volume=source_volume, shadow_id=shadow_id,
        staging_manifest_sha256=staging_receipt.manifest_sha256,
        snapshot_method=SnapshotMethod.VSS_CRASH_CONSISTENT,
        residual_risk=ResidualRisk.NO_CROSS_DATABASE_ATOMICITY_PROOF,
        source=sealed,
    )
    publish_run_manifest(layout, value)
    return value


def set_tree_read_only(root: Path) -> None:
    for path in iter_ordinary_files(root):
        path.chmod(path.stat().st_mode & ~stat.S_IWRITE)


def clear_tree_read_only(root: Path) -> None:
    for path in iter_ordinary_files(root):
        path.chmod(path.stat().st_mode | stat.S_IWRITE)


def materialize_role_copy(layout: RunLayout,
                          role: CopyRole, *,
                          source_account_name: str) -> FileSetManifest:
    if role not in (CopyRole.VALIDATION, CopyRole.ACTIVE):
        raise CopyVerificationError("writable_role_rejected")
    result = copy_tree_verified(
        layout, from_role=CopyRole.SOURCE, to_role=role,
        source_account_name=source_account_name)
    clear_tree_read_only(_role_path(layout, role, source_account_name))
    return result
