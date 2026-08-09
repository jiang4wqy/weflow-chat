from dataclasses import dataclass
from enum import StrEnum
import hashlib
import os
from pathlib import Path
from typing import Callable, Protocol

from weflow_chat.atomic_io import atomic_write_bytes
from weflow_chat.audit import (
    AuditErrorCode, AuditEvent, AuditStage, AuditStatus, AuditWriter,
)
from weflow_chat.config import PreparedChange
from weflow_chat.models import PlannedFile, TxState
from weflow_chat.paths import assert_descendant, canonical_existing, canonical_future
from weflow_chat.security import BackupBundle, BackupItem, SecurityAdapter, SecurityMetadata
from weflow_chat.transaction import ConservativeTransactionView, MirroredTransactionStore, TransactionRecord


class LiveHashState(StrEnum):
    ALL_OLD = "all_old"
    ALL_NEW = "all_new"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class RecoveryAction(StrEnum):
    NO_WRITE_ROLLBACK_MARKER = "no_write_rollback_marker"
    FULL_ROLLBACK = "full_rollback"
    REVALIDATE_ACCEPTED = "revalidate_accepted"


class CutoverCheckpoint(StrEnum):
    AFTER_REPLACING = "after_replacing"
    AFTER_CACHE_REPLACE = "after_cache_replace"
    AFTER_ANALYTICS_DELETE = "after_analytics_delete"
    AFTER_CONFIG_REPLACE = "after_config_replace"
    AFTER_CONFIG_REPLACED_STATE = "after_config_replaced_state"


class ExactDeleteError(RuntimeError):
    pass


class RestorePlanError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class RestoreOperation:
    backup_item: BackupItem
    planned_file: PlannedFile
    live_path: Path
    selected_backup_path: Path | None
    validated_current_sha256: str | None
    restore_payload: bytes | None
    delete_created: bool
    security: SecurityMetadata | None


@dataclass(frozen=True, slots=True)
class RestorePlan:
    run_id: str
    known_live_paths: frozenset[str]
    operations: tuple[RestoreOperation, ...]
    bundle: BackupBundle


class ProcessGate(Protocol):
    def request_normal_close_and_wait(self, timeout_seconds: float) -> bool:
        """Return True only after the injected process/handle check is clear."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def is_sha256(value: object) -> bool:
    return (type(value) is str and len(value) == 64 and
            not (set(value) - set("0123456789ABCDEF")))


def classify_live_hashes(planned_files: tuple[PlannedFile, ...],
                         current_hashes: dict[str, str | None]) -> LiveHashState:
    old_matches, new_matches = [], []
    for item in planned_files:
        current = current_hashes.get(item.live_path)
        old_matches.append(current == item.expected_old_sha256)
        new_matches.append(current == item.expected_new_sha256)
    if all(old_matches):
        return LiveHashState.ALL_OLD
    if all(new_matches):
        return LiveHashState.ALL_NEW
    if all(old or new for old, new in zip(old_matches, new_matches)):
        return LiveHashState.MIXED
    return LiveHashState.UNKNOWN


def choose_recovery_action(view: ConservativeTransactionView,
                           hashes: LiveHashState) -> RecoveryAction:
    if view.mirrors_diverged or view.requires_full_rollback:
        return RecoveryAction.FULL_ROLLBACK
    if view.record.state is TxState.PREPARED and hashes is LiveHashState.ALL_OLD:
        return RecoveryAction.NO_WRITE_ROLLBACK_MARKER
    if view.record.state is TxState.ACCEPTED and hashes is LiveHashState.ALL_NEW:
        return RecoveryAction.REVALIDATE_ACCEPTED
    return RecoveryAction.FULL_ROLLBACK


def _formal_new_state_is_complete(record: TransactionRecord,
                                  current_hashes: dict[str, str | None]) -> bool:
    if not record.planned_files:
        return False
    for item in record.planned_files:
        if item.action == "replace":
            valid = is_sha256(item.expected_new_sha256)
        elif item.action == "delete":
            valid = item.expected_new_sha256 is None
        elif item.action == "delete_if_created":
            valid = item.expected_new_sha256 is None or is_sha256(item.expected_new_sha256)
        else:
            valid = False
        if not valid or current_hashes.get(item.live_path) != item.expected_new_sha256:
            return False
    return True


def _audit_writer(store: MirroredTransactionStore, audit_path: Path | None) -> AuditWriter:
    return AuditWriter(audit_path or store.primary_path.parent / "audit.jsonl")


class _RecoveryAudit:
    def __init__(self, store: MirroredTransactionStore, preferred_path: Path | None):
        preferred = preferred_path or store.primary_path.parent / "audit.jsonl"
        self.preferred = AuditWriter(preferred)
        self.preferred_available = store._storage_available(preferred.parent)
        self.store = store

    def _fallback(self) -> AuditWriter:
        # Resolve the C-side fallback only when it is actually needed.  This
        # keeps minimal injected seams valid while ensuring an offline primary
        # is never recreated by recovery audit writes.
        return AuditWriter(
            self.store.recovery_path.parent / "recovery-audit.jsonl")

    def append(self, event: AuditEvent) -> None:
        if not self.preferred_available:
            self._fallback().append(event)
            return
        try:
            self.preferred.append(event)
        except OSError:
            self._fallback().append(event)


def remove_new_file_exact(planned: PlannedFile, current_path: Path, *,
                          known_live_paths: frozenset[str]) -> None:
    canonical = str(canonical_existing(current_path))
    if canonical != planned.live_path or canonical not in known_live_paths:
        raise ExactDeleteError("exact_delete_unplanned_path")
    if planned.existed_before or planned.action != "delete_if_created":
        raise ExactDeleteError("exact_delete_action_rejected")
    if sha256_path(current_path) != planned.expected_new_sha256:
        raise ExactDeleteError("exact_delete_hash_mismatch")
    current_path.unlink()


def read_current_hashes(planned_files: tuple[PlannedFile, ...]) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for item in planned_files:
        path = Path(item.live_path)
        if not os.path.lexists(path):
            result[item.live_path] = None
            continue
        if not path.exists():
            raise ExactDeleteError("live_path_reparse_or_dangling")
        if (not path.is_file() or path.is_symlink() or
                str(canonical_existing(path)) != item.live_path):
            raise ExactDeleteError("live_path_identity_changed")
        result[item.live_path] = sha256_path(path)
    return result


def apply_prepared_change_exact(change: PreparedChange,
                                security_adapter: SecurityAdapter) -> None:
    path = Path(change.live_path)
    if str(canonical_existing(path)) != change.live_path:
        raise ValueError("prepared_change_path_changed")
    if sha256_path(path) != change.expected_old_sha256:
        raise ValueError("prepared_change_old_hash_mismatch")
    security = security_adapter.capture(path)
    if change.action == "replace":
        if change.payload is None or sha256_bytes(change.payload) != change.expected_new_sha256:
            raise ValueError("prepared_change_payload_mismatch")
        atomic_write_bytes(path, change.payload)
        security_adapter.restore(path, security)
    elif change.action == "delete":
        if change.payload is not None or change.expected_new_sha256 is not None:
            raise ValueError("prepared_delete_contract_invalid")
        path.unlink()
    else:
        raise ValueError("prepared_change_action_invalid")


def _validate_change_set(changes: tuple[PreparedChange, ...],
                         record: TransactionRecord, bundle: BackupBundle) -> None:
    writable = tuple(item for item in record.planned_files
                     if item.action != "delete_if_created")
    supplied = tuple(item.live_path for item in changes)
    receipt = bundle.receipt
    bindings_match = (
        len(changes) == len(writable) and
        all((change.live_path, change.action,
             change.expected_old_sha256, change.expected_new_sha256) ==
            (planned.live_path, planned.action,
             planned.expected_old_sha256, planned.expected_new_sha256)
            for change, planned in zip(changes, writable)))
    if (not bindings_match or
            supplied != tuple(item.live_path for item in writable) or
            {item.live_path for item in record.planned_files} != {item.live_path for item in bundle.items} or
            record.backup_manifest_sha256 != receipt.canonical_sha256 or
            record.backup_primary_manifest_path != receipt.primary_manifest_path or
            record.backup_recovery_manifest_path != receipt.recovery_manifest_path or
            record.source_manifest_sha256 is None or
            record.source_manifest_sha256 != record.active_manifest_sha256):
        raise ValueError("cutover_change_set_mismatch")


def execute_cutover(changes: tuple[PreparedChange, ...], *, bundle: BackupBundle,
                    store: MirroredTransactionStore, security_adapter: SecurityAdapter,
                    checkpoint: Callable[[CutoverCheckpoint], None] = lambda _: None,
                    audit_path: Path | None = None) -> TransactionRecord:
    audit = _audit_writer(store, audit_path)
    audit.append(AuditEvent(AuditStage.CUTOVER, AuditStatus.STARTED,
                            normalized_paths=("active",), file_count=len(changes)))
    current = store.read_equal().record
    _validate_change_set(changes, current, bundle)
    bundle.verify_both_copies_and_old_hashes(security_adapter)
    current = store.transition(TxState.PREPARED, TxState.REPLACING)
    checkpoint(CutoverCheckpoint.AFTER_REPLACING)
    checkpoints = {
        "WeFlow-cache-maps.json": CutoverCheckpoint.AFTER_CACHE_REPLACE,
        "analytics_cache.json": CutoverCheckpoint.AFTER_ANALYTICS_DELETE,
        "WeFlow-config.json": CutoverCheckpoint.AFTER_CONFIG_REPLACE,
    }
    for change in changes:
        apply_prepared_change_exact(change, security_adapter)
        current = store.record_applied_file(change.live_path)
        point = checkpoints.get(Path(change.live_path).name)
        if point is not None:
            checkpoint(point)
    current = store.transition(TxState.REPLACING, TxState.CONFIG_REPLACED)
    checkpoint(CutoverCheckpoint.AFTER_CONFIG_REPLACED_STATE)
    audit.append(AuditEvent(AuditStage.CUTOVER, AuditStatus.OK,
                            normalized_paths=("active",), file_count=len(changes)))
    return current


def _backup_receipt_matches(record: TransactionRecord, bundle: BackupBundle) -> bool:
    receipt = bundle.receipt
    return (record.run_id == bundle.run_id == receipt.run_id and
            record.backup_manifest_sha256 == receipt.canonical_sha256 and
            record.backup_primary_manifest_path == receipt.primary_manifest_path and
            record.backup_recovery_manifest_path == receipt.recovery_manifest_path and
            Path(receipt.primary_manifest_path).parent == Path(bundle.primary_root) and
            Path(receipt.recovery_manifest_path).parent == Path(bundle.recovery_root) and
            Path(receipt.primary_manifest_path).name == "backup-manifest.json" and
            Path(receipt.recovery_manifest_path).name == "backup-manifest.json" and
            len(record.planned_files) == receipt.item_count and
            record.source_manifest_sha256 is not None and
            record.source_manifest_sha256 == record.active_manifest_sha256)


def _canonical_live_identity(stored: str) -> tuple[Path, str | None]:
    path = Path(stored)
    canonical = canonical_existing(path) if path.exists() else canonical_future(path)
    if str(canonical) != stored:
        raise RestorePlanError("restore_live_path_identity_changed")
    return canonical, sha256_path(canonical) if canonical.exists() else None


def _verified_backup_payload(item: BackupItem, bundle: BackupBundle,
                             security_adapter: SecurityAdapter) -> tuple[Path, bytes]:
    selected = canonical_existing(item.resolve_verified_restore_copy())
    if str(selected) == item.recovery_backup_path:
        root, stored_root = canonical_existing(Path(bundle.recovery_root)), bundle.recovery_root
    elif str(selected) == item.primary_backup_path:
        root, stored_root = canonical_existing(Path(bundle.primary_root)), bundle.primary_root
    else:
        raise RestorePlanError("restore_backup_identity_mismatch")
    if str(root) != stored_root:
        raise RestorePlanError("restore_backup_root_identity_mismatch")
    assert_descendant(selected, root)
    if selected.name != Path(item.live_path).name:
        raise RestorePlanError("restore_backup_name_mismatch")
    security_adapter.verify_restricted_backup_tree(root)
    payload = selected.read_bytes()
    if sha256_bytes(payload) != item.expected_old_sha256:
        raise RestorePlanError("restore_backup_hash_mismatch")
    return selected, payload


def build_restore_plan(record: TransactionRecord, bundle: BackupBundle,
                       security_adapter: SecurityAdapter) -> RestorePlan:
    """Materialize every verified old payload before the first live write."""
    try:
        if not _backup_receipt_matches(record, bundle):
            raise RestorePlanError("restore_receipt_mismatch")
        item_keys = [item.live_path.casefold() for item in bundle.items]
        plan_keys = [item.live_path.casefold() for item in record.planned_files]
        if (len(item_keys) != len(set(item_keys)) or len(plan_keys) != len(set(plan_keys)) or
                set(item_keys) != set(plan_keys)):
            raise RestorePlanError("restore_path_set_mismatch")
        by_path = {item.live_path.casefold(): item for item in bundle.items}
        operations: list[RestoreOperation] = []
        for planned in record.planned_files:
            item = by_path[planned.live_path.casefold()]
            if (item.live_path != planned.live_path or
                    type(item.existed_before) is not bool or
                    item.existed_before != planned.existed_before or
                    item.expected_old_sha256 != planned.expected_old_sha256):
                raise RestorePlanError("restore_item_plan_mismatch")
            live, current_hash = _canonical_live_identity(planned.live_path)
            if item.existed_before:
                security = item.security
                if (planned.action not in {"replace", "delete"} or type(security) is not SecurityMetadata or
                        type(security.file_attributes) is not int or
                        not all(type(value) is str and value for value in (security.owner_sid, security.group_sid, security.dacl_sddl)) or
                        type(item.primary_backup_path) is not str or type(item.recovery_backup_path) is not str or
                        Path(item.primary_backup_path).parent != Path(bundle.primary_root) or
                        Path(item.recovery_backup_path).parent != Path(bundle.recovery_root) or
                        Path(item.primary_backup_path).name != live.name or Path(item.recovery_backup_path).name != live.name or
                        not is_sha256(planned.expected_old_sha256) or
                        (planned.action == "replace" and not is_sha256(planned.expected_new_sha256)) or
                        (planned.action == "delete" and planned.expected_new_sha256 is not None)):
                    raise RestorePlanError("restore_present_item_contract_mismatch")
                selected, old_payload = _verified_backup_payload(item, bundle, security_adapter)
                if current_hash == item.expected_old_sha256:
                    payload = None
                elif ((planned.action == "replace" and current_hash == planned.expected_new_sha256) or
                      (planned.action == "delete" and current_hash is None)):
                    payload = old_payload
                else:
                    raise RestorePlanError("restore_live_hash_not_old_or_planned_new")
                operations.append(RestoreOperation(item, planned, live, selected, current_hash,
                                                   payload, False, security))
            else:
                if (planned.action != "delete_if_created" or planned.expected_old_sha256 is not None or
                        (planned.expected_new_sha256 is not None and not is_sha256(planned.expected_new_sha256)) or
                        any(value is not None for value in (item.primary_backup_path, item.recovery_backup_path, item.expected_old_sha256, item.security))):
                    raise RestorePlanError("restore_absent_item_contract_mismatch")
                if current_hash is None:
                    delete_created = False
                elif planned.expected_new_sha256 is not None and current_hash == planned.expected_new_sha256:
                    delete_created = True
                else:
                    raise RestorePlanError("restore_created_hash_not_recorded")
                operations.append(RestoreOperation(item, planned, live, None, current_hash,
                                                   None, delete_created, None))
        return RestorePlan(record.run_id, frozenset(item.live_path for item in record.planned_files),
                           tuple(operations), bundle)
    except RestorePlanError:
        raise
    except Exception as error:
        raise RestorePlanError("restore_plan_preflight_failed") from error


def _execute_restore_plan(plan: RestorePlan, security_adapter: SecurityAdapter, *,
                          restore_bytes: Callable[[Path, bytes], None] = atomic_write_bytes) -> None:
    for operation in plan.operations:
        path = operation.live_path
        current = sha256_path(path) if path.exists() else None
        if current != operation.validated_current_sha256:
            raise OSError("live_state_changed_after_restore_preflight")
        if operation.restore_payload is not None:
            restore_bytes(path, operation.restore_payload)
        if operation.security is not None:
            security_adapter.restore(path, operation.security)
            security_adapter.verify(path, operation.security)
        elif operation.delete_created:
            remove_new_file_exact(operation.planned_file, path,
                                  known_live_paths=plan.known_live_paths)
    plan.bundle.verify_restored_old_set(security_adapter)


def recover_transaction(*, store: MirroredTransactionStore, bundle: BackupBundle,
                        process_gate: ProcessGate, security_adapter: SecurityAdapter,
                        accepted_revalidator: Callable[[TransactionRecord, dict[str, str | None]], bool],
                        timeout_seconds: float, audit_path: Path | None = None,
                        restore_bytes: Callable[[Path, bytes], None] = atomic_write_bytes) -> TransactionRecord:
    audit = _RecoveryAudit(store, audit_path)
    audit.append(AuditEvent(AuditStage.RECOVERY, AuditStatus.STARTED,
                            normalized_paths=("active",)))
    view = store.inspect_conservative()
    try:
        processes_stopped = process_gate.request_normal_close_and_wait(
            timeout_seconds)
    except Exception:
        processes_stopped = False
    if not processes_stopped:
        audit.append(AuditEvent(AuditStage.RECOVERY, AuditStatus.BLOCKED,
                                AuditErrorCode.PROCESS_RUNNING, normalized_paths=("active",)))
        return store.force_conservative_state(TxState.RECOVERY_PENDING)
    if not _backup_receipt_matches(view.record, bundle):
        audit.append(AuditEvent(AuditStage.RECOVERY, AuditStatus.BLOCKED,
                                AuditErrorCode.HASH_MISMATCH, normalized_paths=("active",)))
        return store.force_conservative_state(TxState.RECOVERY_PENDING)
    try:
        current_hashes = read_current_hashes(view.record.planned_files)
    except Exception:
        audit.append(AuditEvent(AuditStage.RECOVERY, AuditStatus.BLOCKED,
                                AuditErrorCode.HASH_MISMATCH, normalized_paths=("active",)))
        return store.force_conservative_state(TxState.RECOVERY_PENDING)
    action = choose_recovery_action(view, classify_live_hashes(view.record.planned_files, current_hashes))
    if action is RecoveryAction.NO_WRITE_ROLLBACK_MARKER:
        result = store.transition(TxState.PREPARED, TxState.ROLLED_BACK)
        audit.append(AuditEvent(AuditStage.RECOVERY, AuditStatus.OK, normalized_paths=("active",)))
        return result
    if action is RecoveryAction.REVALIDATE_ACCEPTED and _formal_new_state_is_complete(view.record, current_hashes):
        try:
            accepted_now = accepted_revalidator(view.record, current_hashes)
        except Exception:
            accepted_now = False
        if accepted_now:
            result = store.commit_revalidated_accepted(current_hashes=current_hashes,
                                                       accepted_revalidated=True)
            audit.append(AuditEvent(AuditStage.RECOVERY, AuditStatus.OK, normalized_paths=("active",)))
            return result
    try:
        plan = build_restore_plan(view.record, bundle, security_adapter)
    except RestorePlanError:
        audit.append(AuditEvent(AuditStage.RECOVERY, AuditStatus.BLOCKED,
                                AuditErrorCode.HASH_MISMATCH, normalized_paths=("active",)))
        return store.force_conservative_state(TxState.RECOVERY_PENDING)
    pending = store.force_conservative_state(TxState.RECOVERY_PENDING)
    if (not _backup_receipt_matches(pending, bundle) or
            pending.planned_files != tuple(operation.planned_file for operation in plan.operations)):
        audit.append(AuditEvent(AuditStage.RECOVERY, AuditStatus.BLOCKED,
                                AuditErrorCode.HASH_MISMATCH, normalized_paths=("active",)))
        return pending
    try:
        _execute_restore_plan(plan, security_adapter, restore_bytes=restore_bytes)
    except Exception:
        audit.append(AuditEvent(AuditStage.RECOVERY, AuditStatus.BLOCKED,
                                AuditErrorCode.IO_FAILURE, normalized_paths=("active",)))
        return pending
    result = store.force_conservative_state(TxState.ROLLED_BACK)
    audit.append(AuditEvent(AuditStage.RECOVERY, AuditStatus.OK, normalized_paths=("active",)))
    return result
