from __future__ import annotations

from contextlib import ExitStack
import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
import json
import os
from pathlib import Path, PureWindowsPath
import re
from typing import Callable, Protocol
import uuid

from weflow_chat.acceptance import AcceptanceRecord
from weflow_chat.atomic_io import atomic_write_json
from weflow_chat.compatibility import (
    CompatibilityReport,
    RuntimeContract,
    probe_compatibility,
    write_compatibility_report,
)
from weflow_chat.config import (
    PreparedChange,
    build_planned_files,
    create_dual_config_backup,
    prepare_stored_key_cutover,
    read_backup_bundle,
)
from weflow_chat.copies import (
    import_vss_staging,
    materialize_role_copy,
)
from weflow_chat.manifest import (
    RunManifest,
    build_manifest,
    content_signature,
    file_set_receipt,
    read_run_manifest,
    sha256_file,
)
from weflow_chat.media import (
    MediaStoreReceipt,
    import_media_staging,
    read_media_store_receipt,
)
from weflow_chat.media_budget import (
    calculate_media_post_staging_budget,
)
from weflow_chat.models import CopyRole, TxState
from weflow_chat.paths import (
    RunLayout,
    canonical_existing,
    canonical_future,
)
from weflow_chat.presentation import (
    PresentationReceipt,
    build_presentation,
    read_presentation_receipt,
)
from weflow_chat.preflight import (
    HostAdapters,
    HostContract,
    run_preflight,
)
from weflow_chat.recovery import (
    execute_cutover,
    read_current_hashes,
    recover_transaction,
)
from weflow_chat.security import (
    BackupBundle,
    SecurityAdapter,
)
from weflow_chat.transaction import (
    MirroredTransactionStore,
    TransactionRecord,
)
from weflow_chat.validator.profile import (
    _close_windows_handle,
    _create_windows_temp,
    _delete_windows_handle,
    _read_windows_handle,
    _rename_windows_handle,
    _write_windows_handle,
)
from weflow_chat.validator.security import _pin_directory
from weflow_chat.validator.security import (
    _windows_directory_handle,
)
from weflow_chat.validator.contracts import (
    FingerprintSet,
    ValidationReceipt,
)
from weflow_chat.validator.launcher import ValidatorBlockedError
from weflow_chat.vss import (
    JOURNAL_ROOT,
    MediaStagingFile,
    MediaStagingReceipt,
    ShadowState,
    StagingReceipt,
    VssHelperClient,
    copy_owned_shadow_media_to_staging,
    copy_owned_shadow_to_staging,
    map_volume_path,
    remove_synthetic_tree as remove_owned_staging_tree,
)
from weflow_chat.weixin_trust import (
    STORED_ENVELOPE_REFRESH,
    LocalTrustEvidence,
    LocalTrustReceipt,
    RuntimeWeixinDllIdentity,
    TrustState,
    local_trust_evidence_sha256,
    write_local_trust_evidence_pair,
    write_local_trust_pair,
)


@dataclass(frozen=True, slots=True)
class AllocatedRefresh:
    layout: RunLayout
    recovery_root: Path
    store: MirroredTransactionStore


@dataclass(slots=True)
class _OwnedFile:
    handle: int | None
    identity: tuple[int, int, int]


_ACCEPTANCE_KEYS = {
    "schemaVersion",
    "runId",
    "uiConfirmed",
    "validationFingerprints",
    "presentationManifestSha256",
    "mediaStoreManifestSha256",
}


def _reject_duplicate_json_keys(
        pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def _read_anchored_acceptance(
        path: Path,
        *,
        record: TransactionRecord,
) -> dict[str, object]:
    canonical = canonical_existing(path)
    if (
        canonical != path.absolute()
        or not canonical.is_file()
        or canonical.is_symlink()
        or record.acceptance_sha256 is None
    ):
        raise ValueError("acceptance_receipt_invalid")
    before = sha256_file(canonical)
    value = json.loads(
        canonical.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=lambda _value: (
            _ for _ in ()
        ).throw(ValueError("invalid_json_constant")),
    )
    after = sha256_file(canonical)
    if (
        before != after
        or after != record.acceptance_sha256
        or type(value) is not dict
        or set(value) != _ACCEPTANCE_KEYS
        or value["schemaVersion"] != 1
        or value["runId"] != record.run_id
        or value["uiConfirmed"] is not True
        or type(value["validationFingerprints"]) is not dict
        or not value["validationFingerprints"]
        or value["presentationManifestSha256"]
        != record.presentation_manifest_sha256
        or value["mediaStoreManifestSha256"]
        != record.media_store_manifest_sha256
    ):
        raise ValueError("acceptance_receipt_invalid")
    return value


def _ensure_dedicated_cache(path: Path) -> Path:
    expected = canonical_future(path)
    if expected != path.absolute():
        raise RuntimeError(
            "dedicated_cache_boundary_mismatch"
        )
    path.mkdir(parents=True, exist_ok=True)
    actual = canonical_existing(path)
    if (
        actual != expected
        or not actual.is_dir()
        or actual.is_symlink()
    ):
        raise RuntimeError(
            "dedicated_cache_boundary_mismatch"
        )
    return actual


def _backup_config_value(
    bundle: BackupBundle,
    config_path: Path,
) -> dict:
    expected = os.path.normcase(
        os.path.normpath(str(canonical_existing(config_path)))
    )
    for item in bundle.items:
        if os.path.normcase(
            os.path.normpath(item.live_path)
        ) != expected:
            continue
        value = json.loads(
            item.resolve_verified_restore_copy().read_text(
                encoding="utf-8"
            )
        )
        if type(value) is not dict:
            break
        return value
    raise ValueError("backup_config_missing")


def _identity(path: Path) -> tuple[int, int, int]:
    information = path.lstat()
    return (
        information.st_dev,
        information.st_ino,
        information.st_ctime_ns,
    )


def _pin_identity(pin) -> tuple[int, ...]:
    identity = getattr(pin, "identity", None)
    if isinstance(identity, tuple):
        return tuple(int(part) for part in identity)
    if identity is None:
        raise RuntimeError("fresh_allocator_root_not_pinned")
    return (
        int(identity.volume_serial_number),
        int(identity.file_index_high),
        int(identity.file_index_low),
    )


def _open_movable_directory(path: Path):
    information = path.lstat()
    return None, (information.st_dev, information.st_ino)


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.USHORT),
        ("maximum_length", wintypes.USHORT),
        ("buffer", wintypes.LPWSTR),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.ULONG),
        ("root_directory", wintypes.HANDLE),
        ("object_name", ctypes.POINTER(_UnicodeString)),
        ("attributes", wintypes.ULONG),
        ("security_descriptor", wintypes.LPVOID),
        ("security_quality_of_service", wintypes.LPVOID),
    ]


class _IoStatusValue(ctypes.Union):
    _fields_ = [
        ("status", wintypes.LONG),
        ("pointer", wintypes.LPVOID),
    ]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [
        ("value", _IoStatusValue),
        ("information", ctypes.c_size_t),
    ]


class _OwnedWindowsDirectoryPin:
    def __init__(
        self,
        path: Path,
        handle: int,
        identity: tuple[int, int, int],
    ) -> None:
        self.path = path
        self.handle = handle
        self.identity = identity

    def __enter__(self):
        return self

    def verify(self) -> None:
        if self.handle is None:
            raise RuntimeError("fresh_allocator_root_not_pinned")
        current_handle, current_identity = (
            _windows_directory_handle(
                self.path, lock_rename=False
            )
        )
        try:
            current = (
                int(current_identity.volume_serial_number),
                int(current_identity.file_index_high),
                int(current_identity.file_index_low),
            )
            if current != self.identity:
                raise RuntimeError(
                    "fresh_allocator_root_identity_changed"
                )
        except BaseException as primary:
            try:
                _close_windows_handle(current_handle)
            except BaseException as close_error:
                primary.add_note(
                    f"directory_verify_close_failed: "
                    f"{close_error!r}"
                )
            raise
        else:
            _close_windows_handle(current_handle)

    def __exit__(self, *_args: object) -> bool:
        if self.handle is not None:
            _close_windows_handle(self.handle)
            self.handle = None
        return False


def _query_directory_identity(
    handle: int,
) -> tuple[int, int, int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    get_information.restype = wintypes.BOOL
    information = _ByHandleFileInformation()
    if not get_information(handle, ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    if (
        information.file_attributes & 0x400
        or not information.file_attributes & 0x10
    ):
        raise RuntimeError("fresh_allocator_root_not_ordinary")
    return (
        information.volume_serial_number,
        information.file_index_high,
        information.file_index_low,
    )


def _create_atomic_windows_directory(
    *,
    parent_pin,
    final_path: Path,
    stack: ExitStack,
):
    parent_handle = getattr(parent_pin, "handle", None)
    if parent_handle is None:
        raise RuntimeError("fresh_allocator_parent_not_pinned")
    name_buffer = ctypes.create_unicode_buffer(final_path.name)
    name = _UnicodeString(
        len(final_path.name) * ctypes.sizeof(ctypes.c_wchar),
        (len(final_path.name) + 1)
        * ctypes.sizeof(ctypes.c_wchar),
        ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes),
        parent_handle,
        ctypes.pointer(name),
        0x40,
        None,
        None,
    )
    status_block = _IoStatusBlock()
    created_handle = wintypes.HANDLE()
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    create_file = ntdll.NtCreateFile
    create_file.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.ULONG,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatusBlock),
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    ]
    create_file.restype = wintypes.LONG
    status = create_file(
        ctypes.byref(created_handle),
        0x80 | 0x10000 | 0x100000,
        ctypes.byref(attributes),
        ctypes.byref(status_block),
        None,
        0,
        0x1 | 0x2,
        2,
        0x1 | 0x20 | 0x00200000,
        None,
        0,
    )
    if status < 0:
        rtl_error = ntdll.RtlNtStatusToDosError
        rtl_error.argtypes = [wintypes.LONG]
        rtl_error.restype = wintypes.ULONG
        raise ctypes.WinError(rtl_error(status))
    handle = int(created_handle.value)
    try:
        identity = _query_directory_identity(handle)
        pin = _OwnedWindowsDirectoryPin(
            final_path, handle, identity
        )
        pin.verify()
        parent_pin.verify()
        stack.enter_context(pin)
        return pin
    except BaseException as primary:
        try:
            _delete_windows_handle(handle)
        except BaseException as delete_error:
            primary.add_note(
                f"directory_create_delete_failed: {delete_error!r}"
            )
        try:
            _close_windows_handle(handle)
        except BaseException as close_error:
            primary.add_note(
                f"directory_create_close_failed: {close_error!r}"
            )
        raise


def _create_and_pin_root(
    *,
    parent: Path,
    parent_pin,
    final_path: Path,
    stack: ExitStack,
):
    if os.name == "nt":
        parent_pin.verify()
        pin = _create_atomic_windows_directory(
            parent_pin=parent_pin,
            final_path=final_path,
            stack=stack,
        )
        return pin
    temporary = parent / (
        f".{final_path.name}.{uuid.uuid4()}.tmp"
    )
    temporary.mkdir()
    movable_handle = None
    try:
        movable_handle, created_identity = (
            _open_movable_directory(temporary)
        )
        parent_pin.verify()
        os.rename(temporary, final_path)
        parent_pin.verify()
        pin = stack.enter_context(_pin_directory(final_path))
        pin.verify()
        if _pin_identity(pin) != created_identity:
            raise RuntimeError(
                "fresh_allocator_root_identity_changed"
            )
        return pin
    finally:
        if movable_handle is not None:
            _close_windows_handle(movable_handle)


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("file_attributes", wintypes.DWORD),
        ("reparse_tag", wintypes.DWORD),
    ]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", wintypes.DWORD),
        ("creation_time", wintypes.FILETIME),
        ("last_access_time", wintypes.FILETIME),
        ("last_write_time", wintypes.FILETIME),
        ("volume_serial_number", wintypes.DWORD),
        ("file_size_high", wintypes.DWORD),
        ("file_size_low", wintypes.DWORD),
        ("number_of_links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    ]


def _query_file_identity(
    handle: int,
) -> tuple[int, int, int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_information = kernel32.GetFileInformationByHandleEx
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    get_information.restype = wintypes.BOOL
    information = _FileAttributeTagInfo()
    if not get_information(
        handle,
        9,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    if (
        information.file_attributes & 0x400
        or information.file_attributes & 0x10
    ):
        raise RuntimeError("fresh_allocator_cleanup_refused")
    get_handle_information = kernel32.GetFileInformationByHandle
    get_handle_information.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    get_handle_information.restype = wintypes.BOOL
    handle_information = _ByHandleFileInformation()
    if not get_handle_information(
        handle, ctypes.byref(handle_information)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return (
        handle_information.volume_serial_number,
        handle_information.file_index_high,
        handle_information.file_index_low,
    )


def _open_owned_file(
    path: Path,
    *,
    for_delete: bool = False,
    share_delete: bool = False,
) -> tuple[int, tuple[int, int, int]]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x80000000 | (0x10000 if for_delete else 0),
        (
            0
            if for_delete
            else 0x1 | (0x2 | 0x4 if share_delete else 0)
        ),
        None,
        3,
        0x00200000,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return handle, _query_file_identity(handle)
    except BaseException as primary:
        try:
            _close_windows_handle(handle)
        except BaseException as close_error:
            primary.add_note(
                f"file_query_close_failed: {close_error!r}"
            )
        raise


def _flush_windows_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    flush = kernel32.FlushFileBuffers
    flush.argtypes = [wintypes.HANDLE]
    flush.restype = wintypes.BOOL
    if not flush(handle):
        raise ctypes.WinError(ctypes.get_last_error())


def _create_owned_json(
    path: Path, value: dict
) -> tuple[int, tuple[int, int, int]]:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    handle = _create_windows_temp(path)
    try:
        identity = _query_file_identity(handle)
        _write_windows_handle(handle, payload)
        return handle, identity
    except BaseException as primary:
        try:
            _delete_windows_handle(handle)
        except BaseException as delete_error:
            primary.add_note(
                f"json_create_delete_failed: {delete_error!r}"
            )
        try:
            _close_windows_handle(handle)
        except BaseException as close_error:
            primary.add_note(
                f"json_create_close_failed: {close_error!r}"
            )
        raise


def _cleanup_pinned_allocator_roots(roots, owned_files) -> None:
    root_policies = {
        root: allowed_names
        for root, _pin, allowed_names, _identity_value in roots
    }
    if any(
        path.parent not in root_policies
        or path.name not in root_policies[path.parent]
        for path in owned_files
    ):
        raise RuntimeError("fresh_allocator_cleanup_refused")
    for root, pin, _allowed_names, expected_identity in roots:
        pin.verify()
        if _identity(root) != expected_identity:
            raise RuntimeError("fresh_allocator_root_not_ordinary")
    cleanup_blocked = False
    for owned in owned_files.values():
        if owned.handle is not None:
            try:
                _close_windows_handle(owned.handle)
            except BaseException:
                cleanup_blocked = True
            else:
                owned.handle = None
    for path, owned in owned_files.items():
        if owned.handle is not None:
            continue
        handle = None
        try:
            handle, identity = _open_owned_file(
                path, for_delete=True
            )
            if identity != owned.identity:
                cleanup_blocked = True
                continue
            _delete_windows_handle(handle)
        except BaseException:
            cleanup_blocked = True
        finally:
            if handle is not None:
                try:
                    _close_windows_handle(handle)
                except BaseException:
                    cleanup_blocked = True
    for root, pin, _allowed, _expected in roots:
        pin.verify()
        if tuple(root.iterdir()):
            cleanup_blocked = True
            continue
        handle = getattr(pin, "handle", None)
        if handle is None:
            raise RuntimeError("fresh_allocator_root_not_pinned")
        _delete_windows_handle(handle)
    if cleanup_blocked:
        raise RuntimeError("fresh_allocator_cleanup_refused")
    owned_files.clear()


def _close_owned_best_effort(
    owned_files, *, note_target: BaseException | None
) -> None:
    for owned in owned_files.values():
        if owned.handle is None:
            continue
        try:
            _close_windows_handle(owned.handle)
        except BaseException as close_error:
            if note_target is not None:
                note_target.add_note(
                    f"owned_handle_close_failed: {close_error!r}"
                )
        owned.handle = None
    owned_files.clear()


def _publish_json_no_replace(path: Path, value: dict) -> _OwnedFile:
    temporary = path.with_name(
        f".{path.name}.{uuid.uuid4()}.tmp"
    )
    expected = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    temporary_handle = None
    target_handle = None
    renamed = False
    try:
        temporary_handle, temporary_identity = _create_owned_json(
            temporary, value
        )
        _rename_windows_handle(temporary_handle, path)
        renamed = True
        _flush_windows_handle(temporary_handle)
        if _read_windows_handle(
            temporary_handle, len(expected)
        ) != expected:
            raise RuntimeError("allocator_publish_content_changed")
        _close_windows_handle(temporary_handle)
        temporary_handle = None
        target_handle, target_identity = _open_owned_file(path)
        if target_identity != temporary_identity:
            raise RuntimeError("allocator_publish_identity_changed")
        if path.read_bytes() != expected:
            raise RuntimeError("allocator_publish_content_changed")
        owned = _OwnedFile(target_handle, target_identity)
        target_handle = None
        return owned
    except BaseException as primary:
        if target_handle is not None:
            try:
                _close_windows_handle(target_handle)
            except BaseException as close_error:
                primary.add_note(
                    f"target_handle_close_failed: {close_error!r}"
                )
            target_handle = None
        if temporary_handle is not None:
            try:
                if not renamed:
                    _delete_windows_handle(temporary_handle)
            except BaseException as delete_error:
                primary.add_note(
                    f"temporary_delete_failed: {delete_error!r}"
                )
            try:
                _close_windows_handle(temporary_handle)
            except BaseException as close_error:
                primary.add_note(
                    f"temporary_handle_close_failed: {close_error!r}"
                )
            temporary_handle = None
        if renamed and os.path.lexists(path):
            cleanup_handle = None
            try:
                cleanup_handle, cleanup_identity = (
                    _open_owned_file(path, for_delete=True)
                )
                if cleanup_identity == temporary_identity:
                    _delete_windows_handle(cleanup_handle)
            except BaseException as cleanup_error:
                primary.add_note(
                    f"published_target_cleanup_failed: "
                    f"{cleanup_error!r}"
                )
            finally:
                if cleanup_handle is not None:
                    try:
                        _close_windows_handle(cleanup_handle)
                    except BaseException as close_error:
                        primary.add_note(
                            "published_target_close_failed: "
                            f"{close_error!r}"
                        )
        raise


def _write_locator_no_replace(
    path: Path, value: dict
) -> _OwnedFile:
    return _publish_json_no_replace(path, value)


def allocate_refresh_version(
    *,
    snapshots_root: Path,
    recovery_root: Path,
    timestamp_utc: str,
    run_id: str,
) -> AllocatedRefresh:
    if (
        not isinstance(run_id, str)
        or str(uuid.UUID(run_id)) != run_id
    ):
        raise ValueError("refresh_run_id_invalid")
    if (
        not isinstance(timestamp_utc, str)
        or re.fullmatch(r"[0-9]{8}-[0-9]{6}", timestamp_utc)
        is None
    ):
        raise ValueError("refresh_timestamp_invalid")
    try:
        parsed = datetime.strptime(
            timestamp_utc, "%Y%m%d-%H%M%S"
        )
    except ValueError as error:
        raise ValueError("refresh_timestamp_invalid") from error
    if parsed.strftime("%Y%m%d-%H%M%S") != timestamp_utc:
        raise ValueError("refresh_timestamp_invalid")
    expected_snapshots = canonical_existing(snapshots_root)
    expected_recovery = canonical_existing(recovery_root)
    if expected_snapshots == expected_recovery:
        raise ValueError("refresh_roots_must_differ")
    snapshots_identity = _identity(expected_snapshots)
    recovery_identity = _identity(expected_recovery)
    name = f"{timestamp_utc}-{run_id}"
    run_root = expected_snapshots / name
    mirror_root = expected_recovery / run_id
    stack = ExitStack()
    roots = []
    owned_files = {}
    result = None
    pending_error = None
    pending_cause = None
    try:
        snapshots_pin = stack.enter_context(
            _pin_directory(expected_snapshots)
        )
        recovery_pin = stack.enter_context(
            _pin_directory(expected_recovery)
        )
        snapshots_pin.verify()
        recovery_pin.verify()
        if (
            canonical_existing(expected_snapshots)
            != expected_snapshots
            or canonical_existing(expected_recovery)
            != expected_recovery
            or _identity(expected_snapshots)
            != snapshots_identity
            or _identity(expected_recovery)
            != recovery_identity
        ):
            raise RuntimeError(
                "fresh_allocator_parent_identity_changed"
            )
        if (
            os.path.lexists(run_root)
            or os.path.lexists(mirror_root)
        ):
            raise FileExistsError("refresh_version_collision")
        run_pin = _create_and_pin_root(
            parent=expected_snapshots,
            parent_pin=snapshots_pin,
            final_path=run_root,
            stack=stack,
        )
        roots.append(
            (
                run_root,
                run_pin,
                {"transaction.json"},
                _identity(run_root),
            )
        )
        mirror_pin = _create_and_pin_root(
            parent=expected_recovery,
            parent_pin=recovery_pin,
            final_path=mirror_root,
            stack=stack,
        )
        roots.append(
            (
                mirror_root,
                mirror_pin,
                {"run-locator.json", "transaction.json"},
                _identity(mirror_root),
            )
        )
        layout = RunLayout.from_existing_root(run_root)
        store = MirroredTransactionStore(
            primary_path=layout.transaction_path,
            recovery_path=mirror_root / "transaction.json",
            storage_available=lambda path: path.exists(),
        )

        def publish_owned(path, value):
            owned_files[path] = _publish_json_no_replace(
                path, value
            )

        store.create_with_exclusive_publisher(
            TransactionRecord(
                schema_version=1,
                run_id=run_id,
                sequence=0,
                state=TxState.DISCOVERED,
                shadow_id=None,
                shadow_source_volume=None,
                planned_files=(),
                applied_files=(),
            ),
            publish_json=publish_owned,
        )
        store.read_equal()
        locator = mirror_root / "run-locator.json"
        owned_files[locator] = _write_locator_no_replace(
            locator,
            {
                "schemaVersion": 1,
                "runId": run_id,
                "primaryTransactionPath": str(
                    layout.transaction_path
                ),
            },
        )
        snapshots_pin.verify()
        recovery_pin.verify()
        result = AllocatedRefresh(layout, mirror_root, store)
        _close_owned_best_effort(
            owned_files, note_target=None
        )
    except BaseException as primary:
        pending_error = primary
        try:
            _cleanup_pinned_allocator_roots(
                roots, owned_files
            )
        except BaseException as cleanup:
            pending_cause = cleanup
            _close_owned_best_effort(
                owned_files, note_target=primary
            )
    finally:
        try:
            stack.close()
        except BaseException as close_error:
            if pending_error is None:
                pending_error = close_error
            else:
                pending_error.add_note(
                    f"allocator_pin_close_failed: {close_error!r}"
                )
    if pending_error is not None:
        if pending_cause is not None:
            raise pending_error from pending_cause
        raise pending_error
    if result is None:
        raise RuntimeError("refresh_allocation_incomplete")
    return result


class RefreshMode(StrEnum):
    FULL = "full"
    DATABASE_ONLY = "database-only"
    PRIOR_MEDIA = "prior-media"


class RefreshStage(StrEnum):
    DISCOVERED = "discovered"
    SNAPSHOT_READY = "snapshot_ready"
    VALIDATED = "validated"
    PREPARED = "prepared"
    CONFIG_REPLACED = "config_replaced"
    UI_CONFIRMED = "ui_confirmed"
    ACTIVE_CONFIRMED = "active_confirmed"
    ACCEPTED = "accepted"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    RECOVERY_PENDING = "recovery_pending"
    COMPATIBILITY_BLOCKED = "compatibility_blocked"


class ShadowResumeResolution(StrEnum):
    CREATE_NOT_ENTERED = "create_not_entered"
    EXACT_SHADOW_DELETED = "exact_shadow_deleted"


@dataclass(frozen=True, slots=True)
class RunRecord:
    runId: str
    stage: RefreshStage
    productionWriteCount: int
    runRoot: Path
    activeParent: Path
    compatibility: CompatibilityReport | None
    runManifest: RunManifest | None
    acceptance: AcceptanceRecord
    trustStatus: str


class ValidatorBackend(Protocol):
    def validate(
        self,
        *,
        area: str,
        layout: RunLayout,
        run_id: str,
    ) -> ValidationReceipt:
        raise NotImplementedError

    def media_openability(
        self,
        *,
        area: str,
        layout: RunLayout,
        run_id: str,
    ) -> dict:
        raise NotImplementedError


class FormalUiBackend(Protocol):
    def launch_and_require_account_open(
        self,
        active_parent: Path,
    ) -> bool:
        raise NotImplementedError

    def relaunch_after_commit(self) -> None:
        raise NotImplementedError


class ProcessGate(Protocol):
    def request_normal_close_and_wait(
        self,
        timeout_seconds: float,
    ) -> bool:
        raise NotImplementedError


@dataclass(slots=True)
class RefreshDependencies:
    contract: HostContract
    layout: RunLayout
    store: MirroredTransactionStore
    vss: VssHelperClient
    validator: ValidatorBackend
    formal_ui: FormalUiBackend
    process_gate: ProcessGate
    security: SecurityAdapter
    preflight_adapters: HostAdapters
    runtime_contract: RuntimeContract | None
    primary_backup_root: Path
    recovery_backup_root: Path
    refresh_mode: RefreshMode = RefreshMode.FULL
    validation_only: bool = False
    weixin_trust_state: TrustState = TrustState.BUILTIN_TRUSTED
    weixin_runtime_identity: RuntimeWeixinDllIdentity | None = None
    trial_identity_revalidator: (
        Callable[[], RuntimeWeixinDllIdentity] | None
    ) = None
    trust_security: object | None = None
    now_utc: Callable[[], str] = (
        lambda: datetime.now(timezone.utc).isoformat()
    )
    journal_exists: Callable[[str], bool] = (
        lambda run_id: (
            JOURNAL_ROOT / f"{str(uuid.UUID(run_id))}.json"
        ).is_file()
    )


class RefreshOrchestrator:
    def __init__(
        self,
        dependencies: RefreshDependencies,
        run_id: str,
    ) -> None:
        self.dependencies = dependencies
        self.run_id = run_id
        self.stage = RefreshStage.DISCOVERED
        self.compatibility: CompatibilityReport | None = None
        self.run_manifest: RunManifest | None = None
        self.media_receipt: MediaStoreReceipt | None = None
        self.presentation_receipt: PresentationReceipt | None = None
        self.preflight_config_sha256: str | None = None
        self.validation_fingerprints: FingerprintSet | None = None
        self.media_openability_counts: dict | None = None
        self.active_fingerprints: FingerprintSet | None = None
        self.bundle: BackupBundle | None = None
        self.prepared_changes: tuple[PreparedChange, ...] = ()
        self.ui_confirmed = False
        self.production_write_count = 0
        self.trust_status = (
            "trial_required"
            if dependencies.weixin_trust_state
            is TrustState.TRIAL_REQUIRED
            else "not_required"
        )
        self.audit_events: list[tuple[str, object]] = []

    @property
    def layout(self) -> RunLayout:
        return self.dependencies.layout

    @property
    def refresh_mode(self) -> RefreshMode:
        return self.dependencies.refresh_mode

    @property
    def cutover_parent(self) -> Path:
        if self.refresh_mode is RefreshMode.DATABASE_ONLY:
            return self.layout.active
        return self.layout.root / "presentation"

    @property
    def transaction(self):
        return self.dependencies.store.read_equal().record

    @property
    def record(self) -> RunRecord:
        return RunRecord(
            runId=self.run_id,
            stage=self.stage,
            productionWriteCount=self.production_write_count,
            runRoot=self.layout.root,
            activeParent=(
                self.cutover_parent
            ),
            compatibility=self.compatibility,
            runManifest=self.run_manifest,
            acceptance=AcceptanceRecord(
                self.ui_confirmed,
                self.validation_fingerprints,
                self.active_fingerprints,
            ),
            trustStatus=self.trust_status,
        )

    def record_from_transaction(self) -> RunRecord:
        view = (
            self.dependencies.store
            .inspect_conservative()
        )
        value = view.record.state.value
        self.stage = (
            RefreshStage.RECOVERY_PENDING
            if (
                view.mirrors_diverged
                or view.record.mirror_degraded
            )
            else (
                RefreshStage(value)
                if value
                in {
                    item.value
                    for item in RefreshStage
                }
                else RefreshStage.RECOVERY_PENDING
            )
        )
        return self.record

    def manifest(self, role: str):
        return build_manifest(
            getattr(self.layout, role),
            role=CopyRole(role),
        )

    def audit_text(self) -> str:
        return json.dumps(
            self.audit_events,
            separators=(",", ":"),
        )

    def _record_created_derived_files_after_close(self) -> None:
        """Bind only file states that the completed UI phase can authorize."""
        current = (
            self.dependencies.store
            .inspect_conservative()
            .record
        )
        try:
            _read_anchored_acceptance(
                self.layout.root / "acceptance.json",
                record=current,
            )
            confirmed = True
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ):
            confirmed = False
        try:
            if confirmed:
                observed = read_current_hashes(
                    current.planned_files
                )
                self.dependencies.store.record_formal_file_hashes(
                    observed
                )
                return
            for item in current.planned_files:
                if (
                    item.action == "delete_if_created"
                    and not item.existed_before
                    and item.expected_new_sha256 is None
                    and Path(item.live_path).exists()
                ):
                    observed = read_current_hashes(
                        (item,)
                    )[item.live_path]
                    if observed is None:
                        raise RuntimeError(
                            "created_derived_file_disappeared"
                        )
                    self.dependencies.store.record_created_file_hash(
                        item.live_path,
                        observed,
                    )
        except BaseException:
            self.dependencies.store.force_conservative_state(
                TxState.RECOVERY_PENDING
            )
            self.stage = RefreshStage.RECOVERY_PENDING
            raise

    def prepare_snapshot(self) -> RunRecord:
        deps = self.dependencies
        if deps.runtime_contract is None:
            raise RuntimeError(
                "runtime_contract_required_for_new_snapshot"
            )
        report = run_preflight(
            deps.contract,
            deps.preflight_adapters,
        )
        if not report.ok:
            deps.store.force_conservative_state(
                TxState.ROLLED_BACK
            )
            self.stage = RefreshStage.COMPATIBILITY_BLOCKED
            return self.record
        self.preflight_config_sha256 = report.configSha256
        self.compatibility = probe_compatibility(
            run_id=self.run_id,
            runtime=deps.runtime_contract,
            config_path=deps.contract.config_path,
        )
        path = write_compatibility_report(
            self.layout.root,
            self.compatibility,
        )
        persisted = json.loads(
            path.read_text(encoding="utf-8")
        )
        if persisted["status"] != "compatible":
            deps.store.force_conservative_state(
                TxState.ROLLED_BACK
            )
            self.stage = RefreshStage.COMPATIBILITY_BLOCKED
            return self.record

        stages_media = self.refresh_mode is RefreshMode.FULL
        needs_media_receipt = (
            self.refresh_mode is not RefreshMode.DATABASE_ONLY
        )
        prior_media_receipt = (
            read_media_store_receipt(
                deps.contract.media_store_root,
                deps.contract.account_id,
            )
            if needs_media_receipt
            else None
        )
        if (
            self.refresh_mode is RefreshMode.PRIOR_MEDIA
            and prior_media_receipt is None
        ):
            deps.store.force_conservative_state(
                TxState.ROLLED_BACK
            )
            self.stage = RefreshStage.COMPATIBILITY_BLOCKED
            self.audit_events.append(
                ("prior_media_store_missing", False)
            )
            return self.record
        prior_media_inventory = (
            None
            if prior_media_receipt is None
            else tuple(
                MediaStagingFile(
                    relative_path=item.relative_path,
                    size=item.size,
                    sha256=item.sha256,
                )
                for item in (
                    prior_media_receipt.manifest.files
                )
            )
        )
        created = None
        staging: StagingReceipt | None = None
        media_staging: MediaStagingReceipt | None = None
        primary_error: BaseException | None = None
        create_entered = False
        create_returned = False
        source_volume = deps.contract.source_volume
        try:
            create_entered = True
            created = deps.vss.create(
                run_id=self.run_id,
                source_volume=source_volume,
            )
            create_returned = True
            if (
                created.run_id != self.run_id
                or created.source_volume != source_volume
                or created.shadow_id is None
            ):
                raise RuntimeError("created_shadow_id_missing")
            deps.store.record_shadow(
                expected=TxState.DISCOVERED,
                shadow_id=created.shadow_id,
                source_volume=source_volume,
            )
            deps.vss.adopt(
                run_id=self.run_id,
                shadow_id=created.shadow_id,
            )
            owned = deps.vss.inspect_owned(
                run_id=self.run_id
            )
            if (
                owned.run_id != self.run_id
                or owned.source_volume != source_volume
                or owned.state is not ShadowState.ADOPTED
                or owned.shadow_id != created.shadow_id
                or owned.device_object is None
            ):
                raise RuntimeError("owned_shadow_not_adopted")
            shadow_source = map_volume_path(
                owned.device_object,
                source_volume=source_volume,
                live_path=deps.contract.db_storage,
            )
            staging = copy_owned_shadow_to_staging(
                shadow_source=shadow_source,
                run_root=self.layout.root,
                snapshots_root=deps.contract.snapshots_root,
                source_account_name=deps.contract.account_id,
            )
            if stages_media:
                shadow_account = map_volume_path(
                    owned.device_object,
                    source_volume=source_volume,
                    live_path=deps.contract.source_account,
                )
                media_staging = copy_owned_shadow_media_to_staging(
                    shadow_account=shadow_account,
                    run_root=self.layout.root,
                    snapshots_root=deps.contract.snapshots_root,
                    source_account_name=deps.contract.account_id,
                    prior_inventory=prior_media_inventory,
                )
        except BaseException as error:
            primary_error = error
            if create_entered and not create_returned:
                deps.store.force_conservative_state(
                    TxState.RECOVERY_PENDING
                )
                self.stage = RefreshStage.RECOVERY_PENDING
        finally:
            cleanup_error: BaseException | None = None
            try:
                view = deps.store.inspect_conservative()
                if (
                    view.mirrors_diverged
                    or view.record.mirror_degraded
                ):
                    raise RuntimeError(
                        "shadow_transaction_not_joint"
                    )
                current = view.record
                recorded = current.shadow_id
                journal_exists = deps.journal_exists(
                    self.run_id
                )
                if recorded is not None and not journal_exists:
                    raise RuntimeError(
                        "recorded_shadow_journal_missing"
                    )
                if recorded is not None or journal_exists:
                    inspected = deps.vss.inspect_owned(
                        run_id=self.run_id
                    )
                    if inspected.state in {
                        ShadowState.CREATED,
                        ShadowState.ADOPTED,
                    }:
                        reread = deps.store.read_equal().record
                        if (
                            reread != current
                            or recorded is None
                            or inspected.run_id != current.run_id
                            or current.shadow_source_volume != source_volume
                            or (
                                inspected.source_volume
                                != current.shadow_source_volume
                            )
                            or inspected.shadow_id != recorded
                        ):
                            raise RuntimeError(
                                "shadow_identity_not_exactly_recorded"
                            )
                        deps.vss.delete_exact(
                            run_id=self.run_id,
                            shadow_id=recorded,
                        )
                        inspected = deps.vss.inspect_owned(
                            run_id=self.run_id
                        )
                    elif inspected.state is ShadowState.CREATING:
                        raise RuntimeError(
                            "shadow_ownership_unknown_creating"
                        )
                    if (
                        inspected.state is not ShadowState.DELETED
                        or inspected.run_id != current.run_id
                        or inspected.source_volume != source_volume
                        or (
                            recorded is not None
                            and inspected.shadow_id != recorded
                        )
                    ):
                        raise RuntimeError(
                            "owned_shadow_not_exactly_deleted"
                        )
            except BaseException as error:
                cleanup_error = error
            if cleanup_error is not None:
                deps.store.force_conservative_state(
                    TxState.RECOVERY_PENDING
                )
                self.stage = RefreshStage.RECOVERY_PENDING
                raise RuntimeError(
                    "shadow_cleanup_recovery_pending"
                ) from cleanup_error

        if primary_error is not None:
            raise primary_error
        if (
            staging is None
            or created is None
            or created.shadow_id is None
            or (stages_media and media_staging is None)
        ):
            raise RuntimeError("staging_receipt_missing")
        expected_relative = PureWindowsPath(
            deps.contract.account_id,
            "db_storage",
        )
        if (
            staging.staging_path != self.layout.vss_staging
            or (
                staging.source_account_name
                != deps.contract.account_id
            )
            or (
                staging.account_db_relative_path
                != expected_relative
            )
        ):
            raise RuntimeError(
                "staging_receipt_identity_mismatch"
            )
        if stages_media:
            assert media_staging is not None
            if (
                media_staging.staging_path
                != self.layout.root / "media-staging"
                or (
                    media_staging.source_account_name
                    != deps.contract.account_id
                )
            ):
                raise RuntimeError(
                    "media_staging_receipt_identity_mismatch"
                )
            calculate_media_post_staging_budget(
                prior_inventory=prior_media_inventory,
                delta_receipt=media_staging,
                source_db_bytes=staging.byte_count,
                validation_db_bytes=staging.byte_count,
                active_db_bytes=staging.byte_count,
                presentation_db_bytes=staging.byte_count,
                existing_destination_volume_root=(
                    deps.contract.media_store_root.parent
                ),
            )
        elif self.refresh_mode is RefreshMode.PRIOR_MEDIA:
            calculate_media_post_staging_budget(
                prior_inventory=prior_media_inventory,
                delta_receipt=MediaStagingReceipt(
                    staging_path=self.layout.root,
                    source_account_name=deps.contract.account_id,
                    files=(),
                    file_count=0,
                    byte_count=0,
                    manifest_sha256=(
                        sha256(b"[]").hexdigest().upper()
                    ),
                ),
                source_db_bytes=staging.byte_count,
                validation_db_bytes=staging.byte_count,
                active_db_bytes=staging.byte_count,
                presentation_db_bytes=staging.byte_count,
                existing_destination_volume_root=(
                    deps.contract.media_store_root.parent
                ),
            )
        self.run_manifest = import_vss_staging(
            self.layout,
            staging_receipt=staging,
            source_account_name=deps.contract.account_id,
            run_id=self.run_id,
            shadow_id=created.shadow_id,
            source_volume=source_volume,
            captured_at_utc=created.created_at_utc,
        )
        if stages_media:
            assert media_staging is not None
            self.media_receipt = import_media_staging(
                media_staging,
                media_store_root=deps.contract.media_store_root,
            )
            remove_owned_staging_tree(
                media_staging.staging_path,
                allowed_root=self.layout.root,
            )
        elif self.refresh_mode is RefreshMode.PRIOR_MEDIA:
            self.media_receipt = prior_media_receipt
        materialize_role_copy(
            self.layout,
            CopyRole.VALIDATION,
            source_account_name=deps.contract.account_id,
        )
        deps.store.transition(
            TxState.DISCOVERED,
            TxState.SNAPSHOT_READY,
        )
        self.stage = RefreshStage.SNAPSHOT_READY
        return self.record

    def validate_copies(self) -> ValidationReceipt:
        if self.stage is not RefreshStage.SNAPSHOT_READY:
            raise RuntimeError("snapshot_required")
        source_before = content_signature(
            self.manifest("source")
        )
        validation_before = content_signature(
            self.manifest("validation")
        )
        if validation_before != source_before:
            return self._block_incompatible_validation(
                "validation_source_manifest_mismatch"
            )
        receipt = self.dependencies.validator.validate(
            area="validation",
            layout=self.layout,
            run_id=self.run_id,
        )
        if (
            receipt.status != "ok"
            or receipt.fingerprints is None
        ):
            return self._block_incompatible_validation(
                receipt.reasonCode
            )
        if content_signature(
            self.manifest("source")
        ) != source_before:
            return self._block_incompatible_validation(
                "validation_source_manifest_mismatch"
            )
        materialize_role_copy(
            self.layout,
            CopyRole.ACTIVE,
            source_account_name=(
                self.dependencies.contract.account_id
            ),
        )
        source_after = content_signature(
            self.manifest("source")
        )
        active = content_signature(
            self.manifest("active")
        )
        if (
            source_before != source_after
            or source_before != active
        ):
            return self._block_incompatible_validation(
                "active_source_manifest_mismatch"
            )
        if self.refresh_mode is RefreshMode.DATABASE_ONLY:
            self.validation_fingerprints = receipt.fingerprints
            self.dependencies.store.transition(
                TxState.SNAPSHOT_READY,
                TxState.VALIDATED,
            )
            self.stage = RefreshStage.VALIDATED
            return receipt
        if self.media_receipt is None:
            return self._block_incompatible_validation(
                "media_store_receipt_missing"
            )
        self.presentation_receipt = build_presentation(
            active_root=self.layout.active,
            media_receipt=self.media_receipt,
            destination_root=(
                self.layout.root / "presentation"
            ),
            account_name=(
                self.dependencies.contract.account_id
            ),
        )
        if self.refresh_mode is RefreshMode.FULL:
            try:
                media_openability = (
                    self.dependencies.validator.media_openability(
                        area="presentation",
                        layout=self.layout,
                        run_id=self.run_id,
                    )
                )
            except ValidatorBlockedError as error:
                return self._block_incompatible_validation(
                    str(error)
                )
            self.media_openability_counts = dict(media_openability)
            self.audit_events.append(
                ("mediaOpenability", dict(media_openability))
            )
        self.validation_fingerprints = receipt.fingerprints
        self.dependencies.store.transition(
            TxState.SNAPSHOT_READY,
            TxState.VALIDATED,
        )
        self.stage = RefreshStage.VALIDATED
        return receipt

    def _block_incompatible_validation(
        self,
        reason_code: str | None,
    ) -> ValidationReceipt:
        self.dependencies.store.transition(
            TxState.SNAPSHOT_READY,
            TxState.ROLLED_BACK,
        )
        self.stage = RefreshStage.COMPATIBILITY_BLOCKED
        return ValidationReceipt(
            "compatibility_blocked",
            reason_code,
            None,
        )

    def complete_validation_only(self) -> RunRecord:
        deps = self.dependencies
        if not deps.validation_only:
            raise RuntimeError("validation_only_flow_required")
        if self.refresh_mode is not RefreshMode.FULL:
            raise RuntimeError("full_validation_mode_required")
        if self.stage is not RefreshStage.VALIDATED:
            raise RuntimeError("validation_required")
        if (
            self.production_write_count != 0
            or self.preflight_config_sha256 is None
            or sha256_file(deps.contract.config_path)
            != self.preflight_config_sha256
            or self.compatibility is None
            or self.compatibility.status != "compatible"
            or self.run_manifest is None
            or self.validation_fingerprints is None
            or self.media_openability_counts is None
            or self.presentation_receipt is None
        ):
            return self.rollback(
                "validation_only_evidence_incomplete"
            )
        media_counts = self.media_openability_counts
        if (
            media_counts.get("version") != 1
            or media_counts.get("unreadableLocalCount") != 0
        ):
            return self.rollback(
                "validation_only_media_evidence_invalid"
            )
        identity = None
        if deps.weixin_trust_state is TrustState.TRIAL_REQUIRED:
            try:
                if (
                    deps.weixin_runtime_identity is None
                    or deps.trial_identity_revalidator is None
                ):
                    raise RuntimeError(
                        "trial_identity_revalidator_missing"
                    )
                identity = deps.trial_identity_revalidator()
                if identity != deps.weixin_runtime_identity:
                    raise RuntimeError(
                        "trial_weixin_identity_changed"
                    )
            except BaseException:
                return self.rollback(
                    "trial_weixin_identity_revalidation_failed"
                )
        deps.store.transition(
            TxState.VALIDATED,
            TxState.ROLLED_BACK,
        )
        self.stage = RefreshStage.ROLLED_BACK
        if deps.weixin_trust_state is not TrustState.TRIAL_REQUIRED:
            return self.record
        try:
            if identity is None or deps.trust_security is None:
                raise RuntimeError("local_trust_writer_missing")
            restrict = getattr(
                deps.trust_security,
                "restrict_local_trust_artifact",
            )
            verify = getattr(
                deps.trust_security,
                "verify_local_trust_artifact",
            )
            transaction = deps.store.read_equal()
            fingerprints = self.validation_fingerprints
            presentation = self.presentation_receipt
            evidence = LocalTrustEvidence(
                schema_version=1,
                run_id=self.run_id,
                version=identity.version,
                architecture=identity.architecture,
                dll_size=identity.dll_size,
                dll_sha256=identity.dll_sha256,
                signer_certificate_sha256=(
                    identity.signer_certificate_sha256
                ),
                transaction_sha256=(
                    transaction.canonical_sha256
                ),
                compatibility_sha256=sha256_file(
                    self.layout.compatibility_path
                ),
                run_manifest_sha256=sha256_file(
                    self.layout.manifest_path
                ),
                validation_schema_fingerprint=(
                    fingerprints.schemaFingerprint
                ),
                validation_aggregate_fingerprint=(
                    fingerprints.aggregateFingerprint
                ),
                validation_database_coverage_fingerprint=(
                    fingerprints.databaseCoverageFingerprint
                ),
                media_openability=tuple(
                    sorted(
                        (name, count)
                        for name, count in media_counts.items()
                        if name != "version"
                    )
                ),
                presentation_manifest_sha256=(
                    presentation.manifest_sha256
                ),
                media_store_manifest_sha256=(
                    presentation.manifest
                    .media_store_manifest_sha256
                ),
                formal_config_sha256_before=(
                    self.preflight_config_sha256
                ),
                formal_config_sha256_after=sha256_file(
                    deps.contract.config_path
                ),
                production_write_count=(
                    self.production_write_count
                ),
                final_state="ROLLED_BACK",
            )
            evidence_sha256 = local_trust_evidence_sha256(
                evidence
            )
            created = datetime.fromisoformat(
                deps.now_utc().replace("Z", "+00:00")
            )
            if (
                created.tzinfo is None
                or created.utcoffset()
                != timezone.utc.utcoffset(created)
            ):
                raise ValueError("local_trust_time_invalid")
            receipt = LocalTrustReceipt(
                schema_version=1,
                run_id=self.run_id,
                version=identity.version,
                architecture=identity.architecture,
                dll_size=identity.dll_size,
                dll_sha256=identity.dll_sha256,
                signer_certificate_sha256=(
                    identity.signer_certificate_sha256
                ),
                capabilities=frozenset(
                    {STORED_ENVELOPE_REFRESH}
                ),
                evidence_sha256=evidence_sha256,
                created_at_utc=created.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            )
            recovery_root = deps.recovery_backup_root.parent
            write_local_trust_evidence_pair(
                primary_root=self.layout.root,
                recovery_root=recovery_root,
                evidence=evidence,
                restrict=restrict,
                verify=verify,
            )
            write_local_trust_pair(
                primary_root=self.layout.root,
                recovery_root=recovery_root,
                receipt=receipt,
                restrict=restrict,
                verify=verify,
            )
        except BaseException:
            self.audit_events.append(
                ("localTrustEnrolled", False)
            )
            self.trust_status = "local_trust_not_enrolled"
            return self.record
        self.audit_events.append(("localTrustEnrolled", True))
        self.trust_status = "local_trust_enrolled"
        return self.record

    def prepare_cutover(self) -> RunRecord:
        if self.dependencies.validation_only:
            raise RuntimeError("validation_only_cutover_forbidden")
        if self.stage is not RefreshStage.VALIDATED:
            raise RuntimeError("validation_required")
        deps = self.dependencies
        cutover_parent = self.cutover_parent
        if self.refresh_mode is not RefreshMode.DATABASE_ONLY and (
            self.presentation_receipt is None
            or (
                self.presentation_receipt.presentation_root
                != cutover_parent
            )
        ):
            raise RuntimeError(
                "presentation_receipt_required"
            )
        if self.preflight_config_sha256 is None:
            deps.store.force_conservative_state(
                TxState.RECOVERY_PENDING
            )
            self.stage = RefreshStage.RECOVERY_PENDING
            return self.record
        if not deps.process_gate.request_normal_close_and_wait(
            30.0
        ):
            deps.store.force_conservative_state(
                TxState.RECOVERY_PENDING
            )
            self.stage = RefreshStage.RECOVERY_PENDING
            return self.record
        if (
            sha256_file(deps.contract.config_path)
            != self.preflight_config_sha256
        ):
            deps.store.force_conservative_state(
                TxState.RECOVERY_PENDING
            )
            self.stage = RefreshStage.RECOVERY_PENDING
            return self.record
        weflow_cache_path = (
            _ensure_dedicated_cache(
                deps.contract.weflow_cache_root
            )
            if self.refresh_mode is not RefreshMode.DATABASE_ONLY
            else None
        )
        self.prepared_changes = prepare_stored_key_cutover(
            config_path=deps.contract.config_path,
            cache_path=deps.contract.cache_maps_path,
            analytics_path=deps.contract.analytics_cache_path,
            active_parent=cutover_parent,
            account_id=deps.contract.account_id,
            weflow_cache_path=weflow_cache_path,
        )
        self.bundle = create_dual_config_backup(
            (
                deps.contract.config_path,
                deps.contract.cache_maps_path,
                deps.contract.analytics_cache_path,
            ),
            primary_root=deps.primary_backup_root,
            recovery_root=deps.recovery_backup_root,
            run_id=self.run_id,
            security_adapter=deps.security,
        )
        planned = build_planned_files(
            self.prepared_changes,
            self.bundle,
        )
        source_receipt = file_set_receipt(
            self.manifest("source")
        )
        active_receipt = file_set_receipt(
            self.manifest("active")
        )
        deps.store.record_cutover_plan(
            expected=TxState.VALIDATED,
            planned_files=planned,
            backup_receipt=self.bundle.receipt,
            source_receipt=source_receipt,
            active_receipt=active_receipt,
            presentation_receipt=self.presentation_receipt,
        )
        deps.store.transition(
            TxState.VALIDATED,
            TxState.PREPARED,
        )
        execute_cutover(
            self.prepared_changes,
            bundle=self.bundle,
            store=deps.store,
            security_adapter=deps.security,
        )
        self.production_write_count += len(
            self.prepared_changes
        )
        self.stage = RefreshStage.CONFIG_REPLACED
        return self.record

    def launch_formal_for_ui(self) -> None:
        if self.stage is not RefreshStage.CONFIG_REPLACED:
            raise RuntimeError("config_replaced_required")
        if not (
            self.dependencies.formal_ui
            .launch_and_require_account_open(
                self.cutover_parent
            )
        ):
            self.rollback("formal_account_open_failed")
            raise RuntimeError("formal_account_open_failed")

    def record_ui_confirmation(
        self,
        response: str,
    ) -> RunRecord:
        expected = f"CONFIRM {self.run_id}"
        if (
            self.stage is not RefreshStage.CONFIG_REPLACED
            or response != expected
        ):
            return self.rollback(
                "ui_confirmation_rejected"
            )
        self.ui_confirmed = True
        self.audit_events.append(("uiConfirmed", True))
        current = (
            self.dependencies.store
            .inspect_conservative()
            .record
        )
        presentation_matches = (
            current.presentation_manifest_sha256 is None
            and current.media_store_manifest_sha256 is None
            and self.presentation_receipt is None
            if self.refresh_mode is RefreshMode.DATABASE_ONLY
            else (
                self.presentation_receipt is not None
                and current.presentation_manifest_sha256
                == self.presentation_receipt.manifest_sha256
                and current.media_store_manifest_sha256
                == (
                    self.presentation_receipt.manifest
                    .media_store_manifest_sha256
                )
            )
        )
        if (
            current.state is not TxState.CONFIG_REPLACED
            or not presentation_matches
        ):
            return self.rollback(
                "presentation_receipt_mismatch"
            )
        acceptance_path = (
            self.layout.root / "acceptance.json"
        )
        atomic_write_json(
            acceptance_path,
            {
                "schemaVersion": 1,
                "runId": self.run_id,
                "uiConfirmed": True,
                "validationFingerprints": asdict(
                    self.validation_fingerprints
                ),
                "presentationManifestSha256": (
                    current.presentation_manifest_sha256
                ),
                "mediaStoreManifestSha256": (
                    current.media_store_manifest_sha256
                ),
            },
        )
        self.dependencies.store.record_ui_acceptance(
            expected=TxState.CONFIG_REPLACED,
            acceptance_sha256=sha256_file(
                acceptance_path
            ),
        )
        self.stage = RefreshStage.UI_CONFIRMED
        return self.record

    def finalize(self) -> RunRecord:
        if self.stage is not RefreshStage.UI_CONFIRMED:
            raise RuntimeError("ui_confirmation_required")
        deps = self.dependencies
        if not deps.process_gate.request_normal_close_and_wait(
            30.0
        ):
            deps.store.force_conservative_state(
                TxState.RECOVERY_PENDING
            )
            self.stage = RefreshStage.RECOVERY_PENDING
            return self.record
        self._record_created_derived_files_after_close()
        current = deps.store.inspect_conservative().record
        try:
            acceptance = _read_anchored_acceptance(
                self.layout.root / "acceptance.json",
                record=current,
            )
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ):
            return self.rollback(
                "acceptance_receipt_mismatch"
            )
        if (
            current.state is not TxState.ACCEPTED
            or acceptance["validationFingerprints"]
            != asdict(self.validation_fingerprints)
        ):
            return self.rollback(
                "acceptance_receipt_mismatch"
            )
        source_before = content_signature(
            self.manifest("source")
        )
        uses_presentation = (
            self.refresh_mode is not RefreshMode.DATABASE_ONLY
        )
        if uses_presentation:
            try:
                self.presentation_receipt = (
                    read_presentation_receipt(
                        (
                            self.layout.root
                            / "presentation-manifest.json"
                        ),
                        expected_presentation_root=(
                            self.layout.root / "presentation"
                        ),
                        account_name=deps.contract.account_id,
                    )
                )
            except (OSError, ValueError, RuntimeError):
                return self.rollback(
                    "presentation_receipt_mismatch"
                )
            if (
                self.presentation_receipt.manifest_sha256
                != current.presentation_manifest_sha256
                or (
                    self.presentation_receipt.manifest
                    .media_store_manifest_sha256
                )
                != current.media_store_manifest_sha256
            ):
                return self.rollback(
                    "presentation_receipt_mismatch"
                )
        elif (
            current.presentation_manifest_sha256 is not None
            or current.media_store_manifest_sha256 is not None
        ):
            return self.rollback("database_only_receipt_mismatch")
        receipt = deps.validator.validate(
            area=("presentation" if uses_presentation else "active"),
            layout=self.layout,
            run_id=self.run_id,
        )
        if (
            receipt.status != "ok"
            or receipt.fingerprints is None
            or (
                receipt.fingerprints
                != self.validation_fingerprints
            )
        ):
            return self.rollback(
                "active_fingerprint_mismatch"
            )
        source_after = content_signature(
            self.manifest("source")
        )
        if source_after != source_before:
            return self.rollback("source_changed_after_ui")
        if (
            self.bundle is None
            or current.backup_primary_manifest_path is None
            or current.backup_recovery_manifest_path is None
            or current.backup_manifest_sha256 is None
        ):
            return self.rollback("backup_bundle_missing")
        fresh_bundle = read_backup_bundle(
            primary_manifest_path=(
                current.backup_primary_manifest_path
            ),
            recovery_manifest_path=(
                current.backup_recovery_manifest_path
            ),
            expected_run_id=current.run_id,
            expected_sha256=current.backup_manifest_sha256,
            security_adapter=deps.security,
        )
        strict_manifest, _ = read_run_manifest(
            self.layout,
            expected_run_id=self.run_id,
            expected_source_account_name=(
                deps.contract.account_id
            ),
        )
        fresh_source = file_set_receipt(
            strict_manifest.source
        )
        fresh_active = (
            file_set_receipt(self.manifest("active"))
            if not uses_presentation
            else None
        )
        active_db = self.layout.role_db_storage(
            CopyRole.ACTIVE,
            deps.contract.account_id,
        )
        presentation_db = (
            self.layout.root
            / "presentation"
            / deps.contract.account_id
            / "db_storage"
        )
        if (
            fresh_source.content_sha256
            != current.source_manifest_sha256
            or not active_db.is_dir()
            or active_db.is_symlink()
            or canonical_existing(active_db) != active_db
            or (
                fresh_active is not None
                and fresh_active.content_sha256
                != current.active_manifest_sha256
            )
            or (
                uses_presentation
                and (
                    not presentation_db.is_dir()
                    or presentation_db.is_symlink()
                    or canonical_existing(presentation_db)
                    != presentation_db
                )
            )
        ):
            return self.rollback(
                "final_source_or_active_boundary_mismatch"
            )
        try:
            fresh_bundle.verify_backup_copies()
            deps.security.verify_restricted_backup_tree(
                Path(fresh_bundle.primary_root)
            )
            deps.security.verify_restricted_backup_tree(
                Path(fresh_bundle.recovery_root)
            )
        except (OSError, ValueError, RuntimeError):
            return self.rollback(
                "backup_reread_or_acl_mismatch"
            )
        production = json.loads(
            deps.contract.config_path.read_text(
                encoding="utf-8"
            )
        )
        try:
            backup_config = _backup_config_value(
                fresh_bundle,
                deps.contract.config_path,
            )
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ):
            return self.rollback("backup_config_mismatch")
        source_db = deps.contract.session_db
        expected_parent = self.cutover_parent
        cache_matches = (
            production.get("cachePath")
            == str(
                canonical_existing(
                    deps.contract.weflow_cache_root
                )
            )
            if uses_presentation
            else (
                ("cachePath" in production)
                == ("cachePath" in backup_config)
                and production.get("cachePath")
                == backup_config.get("cachePath")
            )
        )
        if (
            production.get("dbPath")
            != str(expected_parent)
            or not cache_matches
            or not source_db.is_file()
            or source_db.is_symlink()
            or canonical_existing(source_db) != source_db
        ):
            return self.rollback(
                "final_host_invariant_failed"
            )
        self.active_fingerprints = receipt.fingerprints
        self.stage = RefreshStage.ACCEPTED
        accepted = deps.store.inspect_conservative().record
        current_hashes = read_current_hashes(
            accepted.planned_files
        )
        deps.store.commit_revalidated_accepted(
            current_hashes=current_hashes,
            accepted_revalidated=True,
        )
        self.stage = RefreshStage.COMMITTED
        deps.formal_ui.relaunch_after_commit()
        return self.record

    def rollback(self, reason_code: str) -> RunRecord:
        self.audit_events.append((reason_code, False))
        if self.bundle is None:
            return self.resume(force_rollback=True)
        if not (
            self.dependencies.process_gate
            .request_normal_close_and_wait(30.0)
        ):
            self.dependencies.store.force_conservative_state(
                TxState.RECOVERY_PENDING
            )
            self.stage = RefreshStage.RECOVERY_PENDING
            return self.record
        self._record_created_derived_files_after_close()
        recovered = recover_transaction(
            store=self.dependencies.store,
            bundle=self.bundle,
            process_gate=self.dependencies.process_gate,
            security_adapter=self.dependencies.security,
            accepted_revalidator=(
                lambda record, current_hashes: False
            ),
            timeout_seconds=30.0,
        )
        self.stage = (
            RefreshStage.RECOVERY_PENDING
            if recovered.state is TxState.RECOVERY_PENDING
            else RefreshStage.ROLLED_BACK
        )
        return self.record

    def _cleanup_recorded_shadow_for_resume(
        self,
    ) -> ShadowResumeResolution:
        view = (
            self.dependencies.store
            .inspect_conservative()
        )
        if (
            view.mirrors_diverged
            or view.record.mirror_degraded
        ):
            raise RuntimeError(
                "resume_shadow_transaction_not_joint"
            )
        current = view.record
        journal_exists = self.dependencies.journal_exists(
            self.run_id
        )
        if current.shadow_id is None and not journal_exists:
            if current.state is TxState.DISCOVERED:
                return (
                    ShadowResumeResolution.CREATE_NOT_ENTERED
                )
            raise RuntimeError(
                "resume_unbound_pending_journal_absent"
            )
        if not journal_exists:
            raise RuntimeError(
                "resume_shadow_record_journal_mismatch"
            )
        inspected = self.dependencies.vss.inspect_owned(
            run_id=self.run_id
        )
        source_volume = self.dependencies.contract.source_volume
        if inspected.state is ShadowState.CREATING:
            raise RuntimeError(
                "resume_shadow_operation_in_flight"
            )
        if current.shadow_id is None:
            if (
                inspected.state is not ShadowState.CREATED
                or inspected.shadow_id is None
                or inspected.source_volume != source_volume
            ):
                raise RuntimeError(
                    "resume_unbound_shadow_not_late_bindable"
                )
            current = (
                self.dependencies.store
                .late_bind_created_shadow_for_cleanup(
                    shadow_id=inspected.shadow_id,
                    source_volume=inspected.source_volume,
                    expected_source_volume=source_volume,
                    journal_run_id=inspected.run_id,
                    journal_state=inspected.state.value,
                )
            )
        reread = self.dependencies.store.read_equal().record
        if (
            reread != current
            or inspected.run_id != current.run_id
            or current.shadow_source_volume != source_volume
            or (
                inspected.source_volume
                != current.shadow_source_volume
            )
            or inspected.shadow_id != current.shadow_id
        ):
            raise RuntimeError(
                "resume_shadow_identity_mismatch"
            )
        if inspected.state in {
            ShadowState.CREATED,
            ShadowState.ADOPTED,
        }:
            self.dependencies.vss.delete_exact(
                run_id=self.run_id,
                shadow_id=current.shadow_id,
            )
            inspected = self.dependencies.vss.inspect_owned(
                run_id=self.run_id
            )
        if (
            inspected.state is not ShadowState.DELETED
            or inspected.run_id != current.run_id
            or (
                inspected.source_volume
                != current.shadow_source_volume
            )
            or inspected.shadow_id != current.shadow_id
        ):
            raise RuntimeError(
                "resume_shadow_not_exactly_deleted"
            )
        return ShadowResumeResolution.EXACT_SHADOW_DELETED

    def resume(
        self,
        *,
        force_rollback: bool = False,
    ) -> RunRecord:
        try:
            view = (
                self.dependencies.store
                .inspect_conservative()
            )
        except BaseException:
            self.stage = RefreshStage.RECOVERY_PENDING
            return self.record
        if (
            view.mirrors_diverged
            or view.record.mirror_degraded
        ):
            self.stage = RefreshStage.RECOVERY_PENDING
            return self.record
        current = view.record
        if current.state in {
            TxState.COMMITTED,
            TxState.ROLLED_BACK,
        }:
            self.stage = RefreshStage(current.state.value)
            return self.record
        try:
            shadow_resolution = (
                self._cleanup_recorded_shadow_for_resume()
            )
        except BaseException:
            self.dependencies.store.force_conservative_state(
                TxState.RECOVERY_PENDING
            )
            self.stage = RefreshStage.RECOVERY_PENDING
            return self.record
        current = (
            self.dependencies.store
            .inspect_conservative()
            .record
        )
        terminal_resolution = (
            (
                shadow_resolution
                is ShadowResumeResolution.CREATE_NOT_ENTERED
                and current.state is TxState.DISCOVERED
            )
            or (
                shadow_resolution
                is ShadowResumeResolution.EXACT_SHADOW_DELETED
                and current.state in {
                    TxState.DISCOVERED,
                    TxState.SNAPSHOT_READY,
                    TxState.VALIDATED,
                    TxState.RECOVERY_PENDING,
                }
            )
        )
        no_write_terminal = (
            terminal_resolution
            and not current.planned_files
            and not current.applied_files
            and current.backup_primary_manifest_path is None
            and current.backup_recovery_manifest_path is None
            and current.backup_manifest_sha256 is None
            and current.source_manifest_sha256 is None
            and current.active_manifest_sha256 is None
        )
        if no_write_terminal:
            self.dependencies.store.force_conservative_state(
                TxState.ROLLED_BACK
            )
            self.stage = RefreshStage.ROLLED_BACK
            return self.record
        try:
            self.bundle = read_backup_bundle(
                primary_manifest_path=(
                    current.backup_primary_manifest_path
                ),
                recovery_manifest_path=(
                    current.backup_recovery_manifest_path
                ),
                expected_run_id=current.run_id,
                expected_sha256=(
                    current.backup_manifest_sha256
                ),
                security_adapter=(
                    self.dependencies.security
                ),
            )
        except BaseException:
            self.dependencies.store.force_conservative_state(
                TxState.RECOVERY_PENDING
            )
            self.stage = RefreshStage.RECOVERY_PENDING
            return self.record
        if not (
            self.dependencies.process_gate
            .request_normal_close_and_wait(30.0)
        ):
            self.dependencies.store.force_conservative_state(
                TxState.RECOVERY_PENDING
            )
            self.stage = RefreshStage.RECOVERY_PENDING
            return self.record
        self._record_created_derived_files_after_close()
        recovered = recover_transaction(
            store=self.dependencies.store,
            bundle=self.bundle,
            process_gate=self.dependencies.process_gate,
            security_adapter=self.dependencies.security,
            accepted_revalidator=(
                (
                    lambda record, current_hashes: False
                )
                if force_rollback
                else self._accepted_revalidator
            ),
            timeout_seconds=30.0,
        )
        self.stage = RefreshStage(recovered.state.value)
        return self.record

    def rollback_existing(self) -> RunRecord:
        return self.resume(force_rollback=True)

    def recover_after_exception(
        self,
        error: BaseException,
    ) -> RunRecord:
        self.audit_events.append(
            ("unhandled_refresh_exception", False)
        )
        try:
            return self.resume()
        except BaseException:
            try:
                self.dependencies.store.force_conservative_state(
                    TxState.RECOVERY_PENDING
                )
            except BaseException:
                pass
            self.stage = RefreshStage.RECOVERY_PENDING
            return self.record

    def _accepted_revalidator(
        self,
        record,
        current_hashes,
    ) -> bool:
        try:
            acceptance = _read_anchored_acceptance(
                self.layout.root / "acceptance.json",
                record=record,
            )
            uses_presentation = (
                record.presentation_manifest_sha256 is not None
            )
            if uses_presentation != (
                record.media_store_manifest_sha256 is not None
            ):
                return False
            active = self.dependencies.validator.validate(
                area=(
                    "presentation"
                    if uses_presentation
                    else "active"
                ),
                layout=self.layout,
                run_id=self.run_id,
            )
            if (
                active.status != "ok"
                or active.fingerprints is None
                or asdict(active.fingerprints)
                != acceptance["validationFingerprints"]
            ):
                return False
            if uses_presentation:
                presentation_receipt = read_presentation_receipt(
                    (
                        self.layout.root
                        / "presentation-manifest.json"
                    ),
                    expected_presentation_root=(
                        self.layout.root / "presentation"
                    ),
                    account_name=(
                        self.dependencies.contract.account_id
                    ),
                )
                if (
                    presentation_receipt.manifest_sha256
                    != record.presentation_manifest_sha256
                    or (
                        presentation_receipt.manifest
                        .media_store_manifest_sha256
                    )
                    != record.media_store_manifest_sha256
                ):
                    return False
            strict_manifest, _ = read_run_manifest(
                self.layout,
                expected_run_id=record.run_id,
                expected_source_account_name=(
                    self.dependencies.contract.account_id
                ),
            )
            source_receipt = file_set_receipt(
                strict_manifest.source
            )
            if (
                source_receipt.content_sha256
                != record.source_manifest_sha256
            ):
                return False
            if self.bundle is None:
                return False
            self.bundle.verify_backup_copies()
            (
                self.dependencies.security
                .verify_restricted_backup_tree(
                    Path(self.bundle.primary_root)
                )
            )
            (
                self.dependencies.security
                .verify_restricted_backup_tree(
                    Path(self.bundle.recovery_root)
                )
            )
            source_db = self.dependencies.contract.session_db
            if (
                not source_db.is_file()
                or source_db.is_symlink()
                or canonical_existing(source_db) != source_db
            ):
                return False
            active_db = self.layout.role_db_storage(
                CopyRole.ACTIVE,
                self.dependencies.contract.account_id,
            )
            if (
                not active_db.is_dir()
                or active_db.is_symlink()
                or canonical_existing(active_db) != active_db
            ):
                return False
            production = json.loads(
                (
                    self.dependencies.contract.config_path
                ).read_text(encoding="utf-8")
            )
            backup_config = _backup_config_value(
                self.bundle,
                self.dependencies.contract.config_path,
            )
            cache_matches = (
                production.get("cachePath")
                == str(
                    canonical_existing(
                        self.dependencies.contract
                        .weflow_cache_root
                    )
                )
                if uses_presentation
                else (
                    ("cachePath" in production)
                    == ("cachePath" in backup_config)
                    and production.get("cachePath")
                    == backup_config.get("cachePath")
                )
            )
            expected_parent = (
                self.layout.root / "presentation"
                if uses_presentation
                else self.layout.active
            )
            return (
                production.get("dbPath")
                == str(expected_parent)
                and cache_matches
                and set(current_hashes)
                == {
                    item.live_path
                    for item in record.planned_files
                }
            )
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            RuntimeError,
        ):
            return False
