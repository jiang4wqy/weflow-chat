from dataclasses import asdict, dataclass, replace
import hashlib
import json
import re
import uuid
from pathlib import PureWindowsPath

from weflow_chat.atomic_io import atomic_write_json
from weflow_chat.models import CopyRole, PlannedFile, TxState

@dataclass(frozen=True, slots=True)
class TransactionRecord:
    schema_version: int
    run_id: str
    sequence: int
    state: TxState
    shadow_id: str | None
    shadow_source_volume: str | None
    planned_files: tuple[PlannedFile, ...]
    applied_files: tuple[str, ...] = ()
    backup_manifest_sha256: str | None = None
    backup_primary_manifest_path: str | None = None
    backup_recovery_manifest_path: str | None = None
    source_manifest_sha256: str | None = None
    active_manifest_sha256: str | None = None
    presentation_manifest_sha256: str | None = None
    media_store_manifest_sha256: str | None = None
    acceptance_sha256: str | None = None
    mirror_degraded: bool = False

@dataclass(frozen=True, slots=True)
class MirrorView:
    record: TransactionRecord
    canonical_sha256: str

@dataclass(frozen=True, slots=True)
class ConservativeTransactionView:
    record: TransactionRecord
    mirrors_diverged: bool
    requires_full_rollback: bool

class MirrorWriteError(RuntimeError):
    pass

class MirrorDivergenceError(RuntimeError):
    pass

class InvalidTransitionError(RuntimeError):
    pass

_EDGES = {
    TxState.DISCOVERED: {TxState.SNAPSHOT_READY,
                         TxState.RECOVERY_PENDING, TxState.ROLLED_BACK},
    TxState.SNAPSHOT_READY: {TxState.VALIDATED,
                             TxState.RECOVERY_PENDING, TxState.ROLLED_BACK},
    TxState.VALIDATED: {TxState.PREPARED,
                        TxState.RECOVERY_PENDING, TxState.ROLLED_BACK},
    TxState.PREPARED: {TxState.REPLACING,
                       TxState.RECOVERY_PENDING, TxState.ROLLED_BACK},
    TxState.REPLACING: {TxState.CONFIG_REPLACED,
                        TxState.RECOVERY_PENDING, TxState.ROLLED_BACK},
    TxState.CONFIG_REPLACED: {TxState.ACCEPTED,
                              TxState.RECOVERY_PENDING, TxState.ROLLED_BACK},
    TxState.ACCEPTED: {TxState.RECOVERY_PENDING, TxState.ROLLED_BACK},
    TxState.RECOVERY_PENDING: {TxState.ROLLED_BACK},
    TxState.COMMITTED: set(),
    TxState.ROLLED_BACK: set(),
}

def _record_json(record: TransactionRecord) -> dict[str, object]:
    return {
        "schemaVersion": record.schema_version,
        "runId": record.run_id,
        "sequence": record.sequence,
        "state": record.state.value,
        "shadowId": record.shadow_id,
        "shadowSourceVolume": record.shadow_source_volume,
        "plannedFiles": [asdict(item) for item in record.planned_files],
        "appliedFiles": list(record.applied_files),
        "backupManifestSha256": record.backup_manifest_sha256,
        "backupPrimaryManifestPath": record.backup_primary_manifest_path,
        "backupRecoveryManifestPath": record.backup_recovery_manifest_path,
        "sourceManifestSha256": record.source_manifest_sha256,
        "activeManifestSha256": record.active_manifest_sha256,
        "presentationManifestSha256":
            record.presentation_manifest_sha256,
        "mediaStoreManifestSha256":
            record.media_store_manifest_sha256,
        "acceptanceSha256": record.acceptance_sha256,
        "mirrorDegraded": record.mirror_degraded,
    }

def _canonical_hash(value: dict[str, object]) -> str:
    payload = json.dumps(value, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest().upper()

def _is_sha256(value: object) -> bool:
    return (type(value) is str and len(value) == 64 and
            not (set(value) - set("0123456789ABCDEF")))

_TRANSACTION_KEYS = {
    "schemaVersion", "runId", "sequence", "state", "shadowId",
    "shadowSourceVolume", "plannedFiles", "appliedFiles",
    "backupManifestSha256", "backupPrimaryManifestPath",
    "backupRecoveryManifestPath", "sourceManifestSha256",
    "activeManifestSha256", "presentationManifestSha256",
    "mediaStoreManifestSha256", "acceptanceSha256",
    "mirrorDegraded",
}
_LEGACY_TRANSACTION_KEYS = _TRANSACTION_KEYS - {
    "presentationManifestSha256",
    "mediaStoreManifestSha256",
    "acceptanceSha256",
}
_PLANNED_FILE_KEYS = {
    "live_path", "action", "existed_before",
    "expected_old_sha256", "expected_new_sha256",
}
_PLAN_REQUIRED_STATES = {
    TxState.PREPARED, TxState.REPLACING, TxState.CONFIG_REPLACED,
    TxState.ACCEPTED, TxState.COMMITTED,
}
_SHADOW_REQUIRED_STATES = {
    TxState.SNAPSHOT_READY, TxState.VALIDATED, TxState.PREPARED,
    TxState.REPLACING, TxState.CONFIG_REPLACED, TxState.ACCEPTED,
    TxState.COMMITTED,
}
_MIN_SEQUENCE = {
    TxState.SNAPSHOT_READY: 2,
    TxState.VALIDATED: 3,
    TxState.PREPARED: 5,
    TxState.REPLACING: 6,
    TxState.CONFIG_REPLACED: 7,
    TxState.ACCEPTED: 8,
    TxState.COMMITTED: 9,
}

def _is_exact_windows_file_path(value: object) -> bool:
    if type(value) is not str or not value or "\0" in value:
        return False
    path = PureWindowsPath(value)
    return (
        path.is_absolute() and
        re.fullmatch(r"[A-Z]:", path.drive) is not None and
        path.root == "\\" and str(path) == value and bool(path.name) and
        all(part not in {".", ".."} and ":" not in part
            for part in path.parts[1:])
    )

def _optional_exact_path(value: object) -> bool:
    return value is None or _is_exact_windows_file_path(value)

def _reject_duplicate_json_keys(pairs):
    value = {}
    for key, item in pairs:
        if type(key) is not str or key in value:
            raise ValueError("duplicate_transaction_json_key")
        value[key] = item
    return value

def _parse_planned_file(value: object) -> PlannedFile:
    if type(value) is not dict or set(value) != _PLANNED_FILE_KEYS:
        raise ValueError("invalid_planned_file_schema")
    live_path = value["live_path"]
    action = value["action"]
    existed = value["existed_before"]
    old_hash = value["expected_old_sha256"]
    new_hash = value["expected_new_sha256"]
    if (not _is_exact_windows_file_path(live_path) or
            type(existed) is not bool or
            action not in {"replace", "delete", "delete_if_created"}):
        raise ValueError("invalid_planned_file_identity")
    if action == "replace":
        valid = existed and _is_sha256(old_hash) and _is_sha256(new_hash)
    elif action == "delete":
        valid = existed and _is_sha256(old_hash) and new_hash is None
    else:
        valid = (not existed and old_hash is None and
                 (new_hash is None or _is_sha256(new_hash)))
    if not valid:
        raise ValueError("invalid_planned_file_semantics")
    return PlannedFile(
        live_path=live_path, action=action, existed_before=existed,
        expected_old_sha256=old_hash,
        expected_new_sha256=new_hash)

def _validate_transaction_semantics(
        record: TransactionRecord,
        *,
        legacy_terminal: bool = False,
) -> None:
    if legacy_terminal:
        if (
            record.schema_version != 0
            or record.state not in {
                TxState.COMMITTED,
                TxState.ROLLED_BACK,
            }
            or any(
                value is not None
                for value in (
                    record.presentation_manifest_sha256,
                    record.media_store_manifest_sha256,
                    record.acceptance_sha256,
                )
            )
        ):
            raise ValueError("invalid_legacy_terminal_record")
    if record.state is TxState.DISCOVERED:
        if record.sequence not in {0, 1}:
            raise ValueError("invalid_discovered_sequence")
        if ((record.sequence == 0) != (record.shadow_id is None)):
            raise ValueError("invalid_discovered_shadow_sequence")
    minimum = _MIN_SEQUENCE.get(record.state)
    if minimum is not None and record.sequence < minimum:
        raise ValueError("invalid_state_sequence")
    if (record.state in _SHADOW_REQUIRED_STATES and
            record.shadow_id is None):
        raise ValueError("state_requires_shadow")
    legacy_receipts = (
        record.backup_manifest_sha256,
        record.backup_primary_manifest_path,
        record.backup_recovery_manifest_path,
        record.source_manifest_sha256,
        record.active_manifest_sha256,
    )
    legacy_receipt_count = sum(
        value is not None for value in legacy_receipts
    )
    presentation_receipts = (
        record.presentation_manifest_sha256,
        record.media_store_manifest_sha256,
    )
    presentation_receipt_count = sum(
        value is not None for value in presentation_receipts
    )
    if (
        legacy_receipt_count not in {0, len(legacy_receipts)}
        or (
            not legacy_terminal
            and presentation_receipt_count not in {
                0,
                len(presentation_receipts),
            }
        )
        or (
            presentation_receipt_count
            and legacy_receipt_count != len(legacy_receipts)
        )
    ):
        raise ValueError("partial_cutover_receipts")
    if legacy_receipt_count:
        if (not _is_sha256(record.backup_manifest_sha256) or
                not _is_exact_windows_file_path(
                    record.backup_primary_manifest_path) or
                not _is_exact_windows_file_path(
                    record.backup_recovery_manifest_path) or
                not _is_sha256(record.source_manifest_sha256) or
                record.source_manifest_sha256 !=
                    record.active_manifest_sha256):
            raise ValueError("invalid_cutover_receipts")
    if record.state in _PLAN_REQUIRED_STATES:
        if (
            not record.planned_files
            or legacy_receipt_count != len(legacy_receipts)
        ):
            raise ValueError("state_requires_complete_cutover_plan")
    elif (
        record.planned_files
        and legacy_receipt_count != len(legacy_receipts)
    ):
        raise ValueError("plan_requires_complete_receipts")
    if legacy_receipt_count and not record.planned_files:
        raise ValueError("receipts_require_cutover_plan")
    if (
        record.state in {TxState.ACCEPTED, TxState.COMMITTED}
        and not legacy_terminal
    ):
        if not _is_sha256(record.acceptance_sha256):
            raise ValueError("state_requires_acceptance_receipt")
    elif record.state in {
            TxState.RECOVERY_PENDING, TxState.ROLLED_BACK}:
        if (record.acceptance_sha256 is not None and
                (not _is_sha256(record.acceptance_sha256) or
                 legacy_receipt_count != len(legacy_receipts) or
                 not record.planned_files)):
            raise ValueError("invalid_preserved_acceptance_receipt")
    elif record.acceptance_sha256 is not None:
        raise ValueError("early_state_rejects_acceptance_receipt")
    if (record.planned_files and
            (record.state not in {
                TxState.VALIDATED, TxState.PREPARED,
                TxState.REPLACING, TxState.CONFIG_REPLACED,
                TxState.ACCEPTED, TxState.COMMITTED,
                TxState.RECOVERY_PENDING, TxState.ROLLED_BACK} or
             record.shadow_id is None)):
        raise ValueError("cutover_plan_invalid_for_state")
    planned_by_path = {
        item.live_path.casefold(): item for item in record.planned_files}
    if len(planned_by_path) != len(record.planned_files):
        raise ValueError("duplicate_planned_path")
    if len(set(path.casefold() for path in record.applied_files)) != len(
            record.applied_files):
        raise ValueError("duplicate_applied_path")
    actual_order = []
    for path in record.applied_files:
        if type(path) is not str:
            raise TypeError("applied_path_must_be_string")
        planned = planned_by_path.get(path.casefold())
        if (planned is None or planned.live_path != path or
                planned.action == "delete_if_created"):
            raise ValueError("invalid_applied_path")
        actual_order.append(path)
    writable_order = [
        item.live_path for item in record.planned_files
        if item.action != "delete_if_created"]
    if actual_order != writable_order[:len(actual_order)]:
        raise ValueError("applied_path_order_mismatch")
    if (record.state in {
            TxState.CONFIG_REPLACED, TxState.ACCEPTED,
            TxState.COMMITTED} and actual_order != writable_order):
        raise ValueError("final_state_requires_all_applied_paths")
    sequence_floor = _MIN_SEQUENCE.get(record.state, 0)
    if record.state in {
            TxState.REPLACING, TxState.CONFIG_REPLACED,
            TxState.ACCEPTED, TxState.COMMITTED}:
        sequence_floor += len(actual_order)
    if record.sequence < sequence_floor:
        raise ValueError("state_sequence_missing_applied_writes")
    if (record.applied_files and record.state not in {
            TxState.REPLACING, TxState.CONFIG_REPLACED,
            TxState.ACCEPTED, TxState.COMMITTED,
            TxState.RECOVERY_PENDING, TxState.ROLLED_BACK}):
        raise ValueError("applied_paths_invalid_for_state")
    if (record.mirror_degraded and record.state not in {
            TxState.RECOVERY_PENDING, TxState.ROLLED_BACK}):
        raise ValueError("mirror_degraded_state_rejected")

def _validate_record_for_write(record: TransactionRecord) -> None:
    if (type(record) is not TransactionRecord or
            type(record.schema_version) is not int or
            record.schema_version != 1 or
            type(record.run_id) is not str or
            str(uuid.UUID(record.run_id)) != record.run_id or
            type(record.sequence) is not int or
            not 0 <= record.sequence <= 2**63 - 1 or
            type(record.state) is not TxState or
            type(record.planned_files) is not tuple or
            type(record.applied_files) is not tuple or
            type(record.mirror_degraded) is not bool):
        raise ValueError("invalid_transaction_record_write")
    if record.shadow_id is None:
        if record.shadow_source_volume is not None:
            raise ValueError("invalid_shadow_record_write")
    elif (type(record.shadow_id) is not str or
          record.shadow_id != "{" + str(uuid.UUID(
              record.shadow_id.strip("{}"))).upper() + "}" or
          type(record.shadow_source_volume) is not str or
          re.fullmatch(
              r"[A-Z]:\\", record.shadow_source_volume) is None):
        raise ValueError("invalid_shadow_record_write")
    if (not all(type(item) is PlannedFile and
                _parse_planned_file(asdict(item)) == item
                for item in record.planned_files) or
            not all(type(item) is str for item in record.applied_files)):
        raise ValueError("invalid_nested_transaction_record_write")
    if not all(item is None or _is_sha256(item) for item in (
            record.backup_manifest_sha256,
            record.source_manifest_sha256,
            record.active_manifest_sha256,
            record.presentation_manifest_sha256,
            record.media_store_manifest_sha256,
            record.acceptance_sha256)):
        raise ValueError("invalid_hash_record_write")
    if not all(_optional_exact_path(item) for item in (
            record.backup_primary_manifest_path,
            record.backup_recovery_manifest_path)):
        raise ValueError("invalid_path_record_write")
    _validate_transaction_semantics(record)

class MirroredTransactionStore:
    def __init__(self, *, primary_path, recovery_path,
                 write_json=atomic_write_json,
                 storage_available=lambda path: path.exists()):
        self.primary_path = primary_path
        self.recovery_path = recovery_path
        self._write_json = write_json
        self._storage_available = storage_available

    def _read_one(self, path) -> MirrorView:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            # Unavailable/missing storage is not malformed content and is
            # deliberately handled by inspect_conservative().
            raise
        except UnicodeError as error:
            raise MirrorDivergenceError(
                "invalid_transaction_record") from error
        try:
            value = json.loads(
                text, object_pairs_hook=_reject_duplicate_json_keys)
            keys = (
                frozenset(value)
                if type(value) is dict
                else frozenset()
            )
            legacy_terminal = keys == _LEGACY_TRANSACTION_KEYS
            if (type(value) is not dict or
                    keys not in {
                        frozenset(_TRANSACTION_KEYS),
                        frozenset(_LEGACY_TRANSACTION_KEYS),
                    } or
                    type(value["schemaVersion"]) is not int or
                    value["schemaVersion"] != 1 or
                    type(value["runId"]) is not str or
                    str(uuid.UUID(value["runId"])) != value["runId"] or
                    type(value["sequence"]) is not int or
                    not 0 <= value["sequence"] <= 2**63 - 1 or
                    type(value["state"]) is not str or
                    type(value["plannedFiles"]) is not list or
                    type(value["appliedFiles"]) is not list or
                    type(value["mirrorDegraded"]) is not bool):
                raise ValueError("invalid_top_level_transaction_schema")
            state = TxState(value["state"])
            if legacy_terminal and state not in {
                    TxState.COMMITTED, TxState.ROLLED_BACK}:
                raise ValueError("legacy_nonterminal_rejected")
            shadow_id = value["shadowId"]
            shadow_volume = value["shadowSourceVolume"]
            if shadow_id is None:
                if shadow_volume is not None:
                    raise ValueError("shadow_volume_without_shadow")
            else:
                if (type(shadow_id) is not str or
                        shadow_id != "{" + str(uuid.UUID(
                            shadow_id.strip("{}"))).upper() + "}" or
                        type(shadow_volume) is not str or
                        re.fullmatch(
                            r"[A-Z]:\\", shadow_volume) is None):
                    raise ValueError("invalid_shadow_identity")
            planned_files = tuple(
                _parse_planned_file(item)
                for item in value["plannedFiles"])
            if not all(type(item) is str
                       for item in value["appliedFiles"]):
                raise TypeError("invalid_applied_files_type")
            optional_hashes = (
                value["backupManifestSha256"],
                value["sourceManifestSha256"],
                value["activeManifestSha256"],
                value.get("presentationManifestSha256"),
                value.get("mediaStoreManifestSha256"),
                value.get("acceptanceSha256"),
            )
            if not all(item is None or _is_sha256(item)
                       for item in optional_hashes):
                raise ValueError("invalid_transaction_hash")
            if not all(_optional_exact_path(item) for item in (
                    value["backupPrimaryManifestPath"],
                    value["backupRecoveryManifestPath"])):
                raise ValueError("invalid_transaction_path")
            record = TransactionRecord(
                schema_version=0 if legacy_terminal else 1,
                run_id=value["runId"],
                sequence=value["sequence"], state=state,
                shadow_id=shadow_id,
                shadow_source_volume=shadow_volume,
                planned_files=planned_files,
                applied_files=tuple(value["appliedFiles"]),
                backup_manifest_sha256=value["backupManifestSha256"],
                backup_primary_manifest_path=
                    value["backupPrimaryManifestPath"],
                backup_recovery_manifest_path=
                    value["backupRecoveryManifestPath"],
                source_manifest_sha256=value["sourceManifestSha256"],
                active_manifest_sha256=value["activeManifestSha256"],
                presentation_manifest_sha256=
                    value.get("presentationManifestSha256"),
                media_store_manifest_sha256=
                    value.get("mediaStoreManifestSha256"),
                acceptance_sha256=value.get("acceptanceSha256"),
                mirror_degraded=value["mirrorDegraded"],
            )
            _validate_transaction_semantics(
                record,
                legacy_terminal=legacy_terminal,
            )
            return MirrorView(record, _canonical_hash(value))
        except MirrorDivergenceError:
            raise
        except (json.JSONDecodeError, TypeError, KeyError, ValueError,
                AttributeError, OverflowError, RecursionError) as error:
            raise MirrorDivergenceError(
                "invalid_transaction_record") from error

    def read_equal(self) -> MirrorView:
        recovery = self._read_one(self.recovery_path)
        primary = self._read_one(self.primary_path)
        if recovery != primary:
            raise MirrorDivergenceError("transaction_mirrors_diverged")
        return recovery

    def _write_both(self, record: TransactionRecord) -> TransactionRecord:
        try:
            _validate_record_for_write(record)
            payload = _record_json(record)
        except Exception as error:
            raise MirrorWriteError(
                "invalid_transaction_record_write") from error
        try:
            self._write_json(self.recovery_path, payload)
            recovery = self._read_one(self.recovery_path)
            if recovery.record != record:
                raise MirrorWriteError("recovery_mirror_reread_mismatch")
            self._write_json(self.primary_path, payload)
            equal = self.read_equal()
        except Exception as error:
            raise MirrorWriteError("mirrored_transaction_write_failed") from error
        return equal.record

    def create(self, record: TransactionRecord) -> TransactionRecord:
        if record.sequence != 0 or record.state is not TxState.DISCOVERED:
            raise InvalidTransitionError("invalid_initial_transaction")
        if self.recovery_path.exists() or self.primary_path.exists():
            raise InvalidTransitionError("transaction_already_exists")
        return self._write_both(record)

    def create_with_exclusive_publisher(
        self,
        record: TransactionRecord,
        *,
        publish_json,
    ) -> TransactionRecord:
        if record.sequence != 0 or record.state is not TxState.DISCOVERED:
            raise InvalidTransitionError("invalid_initial_transaction")
        try:
            _validate_record_for_write(record)
            payload = _record_json(record)
            publish_json(self.recovery_path, payload)
            if self._read_one(self.recovery_path).record != record:
                raise MirrorWriteError(
                    "recovery_mirror_reread_mismatch"
                )
            publish_json(self.primary_path, payload)
            return self.read_equal().record
        except Exception as error:
            raise MirrorWriteError(
                "mirrored_transaction_create_failed"
            ) from error

    def record_shadow(self, *, expected: TxState, shadow_id: str,
                      source_volume: str) -> TransactionRecord:
        current = self.read_equal().record
        if (expected is not TxState.DISCOVERED or
                current.state is not expected or
                current.shadow_id is not None):
            raise InvalidTransitionError("shadow_already_recorded")
        if re.fullmatch(r"[A-Z]:\\", source_volume) is None:
            raise InvalidTransitionError("invalid_shadow_source_volume")
        normalized = "{" + str(uuid.UUID(shadow_id.strip("{}"))).upper() + "}"
        return self._write_both(replace(
            current, sequence=current.sequence + 1,
            shadow_id=normalized, shadow_source_volume=source_volume))

    def late_bind_created_shadow_for_cleanup(
            self, *, shadow_id: str, source_volume: str,
            expected_source_volume: str, journal_run_id: str,
            journal_state: str) -> TransactionRecord:
        current = self.read_equal().record
        receipts = (
            current.backup_manifest_sha256,
            current.backup_primary_manifest_path,
            current.backup_recovery_manifest_path,
            current.source_manifest_sha256,
            current.active_manifest_sha256,
            current.presentation_manifest_sha256,
            current.media_store_manifest_sha256,
            current.acceptance_sha256,
        )
        if (current.state is not TxState.RECOVERY_PENDING or
                current.mirror_degraded or
                current.shadow_id is not None or
                current.shadow_source_volume is not None or
                current.planned_files or current.applied_files or
                any(value is not None for value in receipts) or
                journal_run_id != current.run_id or
                journal_state != "created" or
                re.fullmatch(r"[A-Z]:\\", expected_source_volume) is None or
                source_volume != expected_source_volume):
            raise InvalidTransitionError("late_shadow_bind_rejected")
        try:
            normalized = (
                "{" + str(uuid.UUID(shadow_id.strip("{}"))).upper() + "}")
        except (ValueError, AttributeError) as error:
            raise InvalidTransitionError(
                "late_shadow_bind_rejected") from error
        return self._write_both(replace(
            current, sequence=current.sequence + 1,
            shadow_id=normalized, shadow_source_volume=source_volume))

    def transition(self, expected: TxState,
                   target: TxState) -> TransactionRecord:
        current = self.read_equal().record
        if current.mirror_degraded:
            raise InvalidTransitionError("degraded_mirror_recovery_only")
        if expected is TxState.ACCEPTED and target is TxState.COMMITTED:
            raise InvalidTransitionError(
                "accepted_commit_requires_revalidation")
        if (expected is TxState.CONFIG_REPLACED and
                target is TxState.ACCEPTED):
            raise InvalidTransitionError(
                "ui_acceptance_receipt_required")
        if current.state is not expected or target not in _EDGES[expected]:
            raise InvalidTransitionError("invalid_transaction_transition")
        if (expected is TxState.DISCOVERED and
                target is TxState.SNAPSHOT_READY and
                current.shadow_id is None):
            raise InvalidTransitionError("snapshot_shadow_not_recorded")
        if expected is TxState.VALIDATED and target is TxState.PREPARED:
            if not current.planned_files:
                raise InvalidTransitionError("cutover_plan_not_recorded")
            required_receipts = (
                current.backup_manifest_sha256,
                current.backup_primary_manifest_path,
                current.backup_recovery_manifest_path,
                current.source_manifest_sha256,
                current.active_manifest_sha256,
            )
            presentation_receipts = (
                current.presentation_manifest_sha256,
                current.media_store_manifest_sha256,
            )
            if (any(value is None for value in required_receipts) or
                    sum(
                        value is not None
                        for value in presentation_receipts
                    ) not in {0, len(presentation_receipts)} or
                    current.source_manifest_sha256 !=
                    current.active_manifest_sha256):
                raise InvalidTransitionError(
                    "cutover_receipts_not_recorded")
        return self._write_both(replace(
            current, sequence=current.sequence + 1, state=target))

    def record_cutover_plan(
            self, *, expected: TxState,
            planned_files: tuple[PlannedFile, ...], backup_receipt,
            source_receipt, active_receipt,
            presentation_receipt) -> TransactionRecord:
        current = self.read_equal().record
        paths = [item.live_path for item in planned_files]
        if (expected is not TxState.VALIDATED or
                current.state is not expected or current.planned_files or
                not planned_files or len(paths) != len(set(paths)) or
                backup_receipt.run_id != current.run_id or
                backup_receipt.item_count != len(planned_files) or
                not isinstance(backup_receipt.primary_manifest_path, str) or
                not backup_receipt.primary_manifest_path or
                not isinstance(backup_receipt.recovery_manifest_path, str) or
                not backup_receipt.recovery_manifest_path or
                source_receipt.role is not CopyRole.SOURCE or
                active_receipt.role is not CopyRole.ACTIVE or
                source_receipt.content_sha256 !=
                active_receipt.content_sha256 or
                source_receipt.total_files != active_receipt.total_files or
                source_receipt.total_bytes != active_receipt.total_bytes):
            raise InvalidTransitionError("invalid_cutover_plan")
        presentation_hash = getattr(
            presentation_receipt, "manifest_sha256", None)
        media_store_hash = getattr(
            getattr(presentation_receipt, "manifest", None),
            "media_store_manifest_sha256", None)
        hashes = [
            backup_receipt.canonical_sha256,
            source_receipt.content_sha256,
            active_receipt.content_sha256,
        ]
        if presentation_receipt is not None:
            hashes.extend((presentation_hash, media_store_hash))
        if any(not _is_sha256(value) for value in hashes):
            raise InvalidTransitionError("invalid_cutover_receipt")
        return self._write_both(replace(
            current, sequence=current.sequence + 1,
            planned_files=planned_files,
            backup_manifest_sha256=backup_receipt.canonical_sha256,
            backup_primary_manifest_path=
                backup_receipt.primary_manifest_path,
            backup_recovery_manifest_path=
                backup_receipt.recovery_manifest_path,
            source_manifest_sha256=source_receipt.content_sha256,
            active_manifest_sha256=active_receipt.content_sha256,
            presentation_manifest_sha256=
                presentation_hash,
            media_store_manifest_sha256=
                media_store_hash))

    def record_ui_acceptance(
            self, *, expected: TxState = TxState.CONFIG_REPLACED,
            acceptance_sha256: str) -> TransactionRecord:
        current = self.read_equal().record
        required_receipts = (
            current.backup_manifest_sha256,
            current.backup_primary_manifest_path,
            current.backup_recovery_manifest_path,
            current.source_manifest_sha256,
            current.active_manifest_sha256,
        )
        presentation_receipts = (
            current.presentation_manifest_sha256,
            current.media_store_manifest_sha256,
        )
        if (expected is not TxState.CONFIG_REPLACED or
                current.state is not expected or
                current.acceptance_sha256 is not None or
                not current.planned_files or
                any(value is None for value in required_receipts) or
                sum(
                    value is not None
                    for value in presentation_receipts
                ) not in {0, len(presentation_receipts)} or
                current.source_manifest_sha256 !=
                    current.active_manifest_sha256 or
                not _is_sha256(acceptance_sha256)):
            raise InvalidTransitionError("ui_acceptance_rejected")
        return self._write_both(replace(
            current,
            sequence=current.sequence + 1,
            state=TxState.ACCEPTED,
            acceptance_sha256=acceptance_sha256,
        ))

    def commit_revalidated_accepted(
            self, *, current_hashes: dict[str, str | None],
            accepted_revalidated: bool) -> TransactionRecord:
        current = self.read_equal().record
        if current.state is not TxState.ACCEPTED or not accepted_revalidated:
            raise InvalidTransitionError(
                "accepted_commit_revalidation_failed")
        if current.mirror_degraded:
            raise InvalidTransitionError("degraded_commit_rejected")
        required_receipts = (
            current.backup_manifest_sha256,
            current.backup_primary_manifest_path,
            current.backup_recovery_manifest_path,
            current.source_manifest_sha256,
            current.active_manifest_sha256,
        )
        presentation_receipts = (
            current.presentation_manifest_sha256,
            current.media_store_manifest_sha256,
        )
        if (any(value is None for value in required_receipts) or
                sum(
                    value is not None
                    for value in presentation_receipts
                ) not in {0, len(presentation_receipts)} or
                current.source_manifest_sha256 !=
                current.active_manifest_sha256):
            raise InvalidTransitionError(
                "accepted_commit_receipts_incomplete")
        if not _is_sha256(current.acceptance_sha256):
            raise InvalidTransitionError(
                "accepted_commit_acceptance_incomplete")
        if set(current_hashes) != {
                item.live_path for item in current.planned_files}:
            raise InvalidTransitionError("accepted_hash_set_incomplete")
        for item in current.planned_files:
            expected = item.expected_new_sha256
            if item.action == "replace":
                complete = _is_sha256(expected)
            elif item.action == "delete":
                complete = expected is None
            elif item.action == "delete_if_created":
                complete = expected is None or _is_sha256(expected)
            else:
                complete = False
            if (not complete or
                    current_hashes[item.live_path] != expected):
                raise InvalidTransitionError(
                    "accepted_formal_hash_mismatch")
        return self._write_both(replace(
            current, sequence=current.sequence + 1,
            state=TxState.COMMITTED))

    def record_applied_file(self, live_path: str) -> TransactionRecord:
        current = self.read_equal().record
        writable_order = tuple(
            item.live_path for item in current.planned_files
            if item.action != "delete_if_created")
        next_offset = len(current.applied_files)
        if (current.state is not TxState.REPLACING or
                next_offset >= len(writable_order) or
                live_path != writable_order[next_offset]):
            raise InvalidTransitionError("unplanned_applied_file")
        return self._write_both(replace(
            current, sequence=current.sequence + 1,
            applied_files=current.applied_files + (live_path,)))

    def record_created_file_hash(self, live_path: str,
                                 sha256: str) -> TransactionRecord:
        current = self.read_equal().record
        if (current.state not in {TxState.CONFIG_REPLACED,
                                  TxState.ACCEPTED} or
                not _is_sha256(sha256)):
            raise InvalidTransitionError("derived_hash_state_rejected")
        updated = []
        found = False
        for item in current.planned_files:
            if item.live_path == live_path:
                if item.existed_before or item.action != "delete_if_created":
                    raise InvalidTransitionError(
                        "derived_hash_action_rejected")
                item = replace(item, expected_new_sha256=sha256)
                found = True
            updated.append(item)
        if not found:
            raise InvalidTransitionError("unplanned_derived_file")
        return self._write_both(replace(
            current, sequence=current.sequence + 1,
            planned_files=tuple(updated)))

    def record_formal_file_hashes(
            self, current_hashes: dict[str, str | None]) -> TransactionRecord:
        """Atomically bind the complete file set observed after formal UI close."""
        current = self.read_equal().record
        if current.state not in {
                TxState.CONFIG_REPLACED,
                TxState.ACCEPTED,
                TxState.RECOVERY_PENDING}:
            raise InvalidTransitionError(
                "formal_hash_state_rejected")
        if set(current_hashes) != {
                item.live_path for item in current.planned_files}:
            raise InvalidTransitionError(
                "formal_hash_set_incomplete")
        updated = []
        for item in current.planned_files:
            observed = current_hashes[item.live_path]
            if item.action == "replace":
                valid = _is_sha256(observed)
            elif item.action == "delete":
                valid = observed is None
            elif item.action == "delete_if_created":
                valid = observed is None or _is_sha256(observed)
            else:
                valid = False
            if not valid:
                raise InvalidTransitionError(
                    "formal_hash_semantics_rejected")
            updated.append(replace(
                item,
                expected_new_sha256=observed,
            ))
        planned_files = tuple(updated)
        if planned_files == current.planned_files:
            return current
        return self._write_both(replace(
            current,
            sequence=current.sequence + 1,
            planned_files=planned_files,
        ))

    def inspect_conservative(self) -> ConservativeTransactionView:
        views = []
        for path in (self.recovery_path, self.primary_path):
            try:
                views.append(self._read_one(path))
            except (OSError, MirrorDivergenceError):
                pass
        if not views:
            raise MirrorDivergenceError("no_valid_transaction_mirror")
        if (len(views) == 2 and
                views[0].record.sequence == views[1].record.sequence and
                views[0] != views[1]):
            raise MirrorDivergenceError("equal_sequence_mirror_divergence")
        selected = max(views, key=lambda item: item.record.sequence).record
        diverged = len(views) != 2 or views[0] != views[1]
        destructive = selected.state in {
            TxState.REPLACING, TxState.CONFIG_REPLACED,
            TxState.RECOVERY_PENDING,
        }
        return ConservativeTransactionView(
            selected, diverged, diverged or destructive)

    def force_conservative_state(self,
                                 target: TxState) -> TransactionRecord:
        if target not in {TxState.RECOVERY_PENDING,
                          TxState.ROLLED_BACK}:
            raise InvalidTransitionError("unsafe_recovery_target")
        current = self.inspect_conservative().record
        if current.state in {TxState.COMMITTED, TxState.ROLLED_BACK}:
            raise InvalidTransitionError("terminal_recovery_rejected")
        updated = replace(
            current, sequence=current.sequence + 1, state=target)
        if self._storage_available(self.primary_path.parent):
            return self._write_both(updated)
        recovery = self._read_one(self.recovery_path)
        if recovery.record != current:
            raise MirrorDivergenceError(
                "degraded_recovery_mirror_not_authoritative")
        degraded = replace(updated, mirror_degraded=True)
        _validate_record_for_write(degraded)
        self._write_json(self.recovery_path, _record_json(degraded))
        reread = self._read_one(self.recovery_path)
        if reread.record != degraded:
            raise MirrorWriteError(
                "degraded_recovery_mirror_reread_mismatch")
        return reread.record

    def assert_ready_for_new_run(self) -> None:
        view = self.inspect_conservative()
        if (view.mirrors_diverged or view.record.mirror_degraded or
                view.record.state not in {
                    TxState.COMMITTED, TxState.ROLLED_BACK}):
            raise InvalidTransitionError("prior_run_not_reconciled")

    def reconcile_degraded_mirror(
            self, *, old_set_revalidated: bool) -> TransactionRecord:
        if not old_set_revalidated:
            raise InvalidTransitionError(
                "old_set_revalidation_required")
        view = self.inspect_conservative()
        current = view.record
        if current.schema_version != 1:
            raise InvalidTransitionError(
                "legacy_transaction_write_rejected"
            )
        if (not current.mirror_degraded or
                current.state is not TxState.ROLLED_BACK or
                not self._storage_available(self.primary_path.parent)):
            raise InvalidTransitionError(
                "degraded_mirror_reconciliation_rejected")
        # Recreate and reread the E mirror while the degraded marker is
        # still true. Only then may the ordinary C-then-E write clear it.
        self._write_json(self.primary_path, _record_json(current))
        if self.read_equal().record != current:
            raise MirrorWriteError(
                "degraded_primary_recreation_mismatch")
        return self._write_both(replace(
            current, sequence=current.sequence + 1,
            mirror_degraded=False))
