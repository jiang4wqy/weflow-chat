from __future__ import annotations

import base64
import binascii
import copy
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
from typing import Callable

from weflow_chat.paths import (
    RunLayout,
    assert_descendant,
    canonical_existing,
)
from weflow_chat.validator.contracts import ValidatorLayout
from weflow_chat.validator.security import (
    _DirectoryPin,
    _close_windows_handle,
    _pin_directory,
    ensure_private_directory,
)


_ACCOUNT_PATTERN = re.compile(r"wxid_[A-Za-z0-9_]{1,128}")
_SECRET_FIELDS = ("decryptKey", "imageAesKey", "imageXorKey")
_PATH_KEYED_CACHE_FIELDS = (
    "contactsAvatarCacheMap",
    "contactsListCacheMap",
    "exportSessionMutualFriendsCacheMap",
    "exportSnsUserPostCountsCacheMap",
)
_MOVEFILE_WRITE_THROUGH = 0x8
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE = 0x10000
_CREATE_NEW = 1
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_WRITE_THROUGH = 0x80000000
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_FILE_BEGIN = 0
_FILE_RENAME_INFO_CLASS = 3
_FILE_DISPOSITION_INFO_CLASS = 4
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class ProfileCompatibilityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ConfigCopyReceipt:
    source_sha256: str
    destination_sha256: str
    changed_fields: tuple[str, ...]
    effective_db_path: str
    effective_cache_path: str
    source_path_absent: bool


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def _iter_json_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _iter_json_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_json_strings(item)


def _contains_windows_path(value: str, forbidden: str) -> bool:
    haystack = value.replace("/", "\\").casefold()
    needle = forbidden.replace("/", "\\").casefold()
    if len(needle) > 3:
        needle = needle.rstrip("\\")
    start = 0
    before_boundaries = " \t\r\n\"'=,:;([{<>|"
    after_boundaries = " \t\r\n\"'=,:;)]}<>|"
    while True:
        index = haystack.find(needle, start)
        if index < 0:
            return False
        before_ok = index == 0 or haystack[index - 1] in before_boundaries
        end = index + len(needle)
        after_ok = (
            end == len(haystack)
            or haystack[end] == "\\"
            or haystack[end] in after_boundaries
        )
        if before_ok and after_ok:
            return True
        start = index + 1


def _source_paths_absent(
    copied: dict[str, object],
    *,
    effective_db_path: str,
    effective_cache_path: str,
    forbidden_paths: tuple[str, str],
) -> bool:
    if (
        copied.get("dbPath") != effective_db_path
        or copied.get("cachePath") != effective_cache_path
    ):
        return False
    for key, value in copied.items():
        if key in {"dbPath", "cachePath"}:
            continue
        for text in (key, *_iter_json_strings(value)):
            if any(
                _contains_windows_path(text, forbidden)
                for forbidden in forbidden_paths
            ):
                return False
    return True


def _drop_source_path_keyed_cache_entries(
    copied: dict[str, object],
    source_db_path: str,
) -> tuple[str, ...]:
    changed = []
    for field in _PATH_KEYED_CACHE_FIELDS:
        value = copied.get(field)
        if value is None:
            continue
        if not isinstance(value, dict):
            raise ProfileCompatibilityError("config_schema_mismatch")
        filtered = {
            key: item
            for key, item in value.items()
            if not _contains_windows_path(key, source_db_path)
        }
        if len(filtered) != len(value):
            copied[field] = filtered
            changed.append(field)
    return tuple(changed)


def _safe_envelope(value: object) -> bool:
    return isinstance(value, str) and value.startswith("safe:") and len(value) > 5


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileCompatibilityError("config_duplicate_key")
        result[key] = value
    return result


def _strict_json(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ProfileCompatibilityError("config_schema_mismatch")
            ),
        )
    except ProfileCompatibilityError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProfileCompatibilityError("config_schema_mismatch") from error
    if not isinstance(value, dict):
        raise ProfileCompatibilityError("config_schema_mismatch")
    return value


def _strict_local_state(payload: bytes) -> dict[str, object]:
    value = _strict_json(payload)
    os_crypt = value.get("os_crypt")
    encrypted_key = (
        os_crypt.get("encrypted_key")
        if isinstance(os_crypt, dict)
        else None
    )
    try:
        decoded = base64.b64decode(
            encrypted_key, validate=True
        )
    except (TypeError, ValueError, binascii.Error) as error:
        raise ProfileCompatibilityError(
            "safe_storage_state_contract"
        ) from error
    if not decoded.startswith(b"DPAPI") or len(decoded) <= 5:
        raise ProfileCompatibilityError(
            "safe_storage_state_contract"
        )
    return value


def _secret_envelopes_are_safe(
    original: dict[str, object],
    current: str,
    nested: dict[str, object],
) -> bool:
    current_value = nested.get(current)
    if (
        not isinstance(current_value, dict)
        or not _safe_envelope(original.get("decryptKey"))
        or not _safe_envelope(current_value.get("decryptKey"))
    ):
        return False
    for account_name, container in nested.items():
        if (
            not isinstance(account_name, str)
            or _ACCOUNT_PATTERN.fullmatch(account_name) is None
            or not isinstance(container, dict)
        ):
            return False
    for container in (original, *nested.values()):
        if not isinstance(container, dict):
            return False
        for field in _SECRET_FIELDS:
            if field in container and not _safe_envelope(container[field]):
                return False
    return True


def _validate_config_schema(original: dict[str, object]) -> tuple[str, dict]:
    if (
        not isinstance(original.get("dbPath"), str)
        or not original["dbPath"]
        or not isinstance(original.get("cachePath"), str)
    ):
        raise ProfileCompatibilityError("config_schema_mismatch")
    current = original.get("myWxid")
    nested = original.get("wxidConfigs")
    if (
        not isinstance(current, str)
        or _ACCOUNT_PATTERN.fullmatch(current) is None
        or not isinstance(nested, dict)
        or not _secret_envelopes_are_safe(original, current, nested)
    ):
        raise ProfileCompatibilityError("safe_envelope_contract")
    return current, nested


def _reject_absolute_reparse(
    target: Path, *, require_target: bool = True
) -> None:
    absolute = Path(os.path.abspath(target))
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor = cursor / part
        if not os.path.lexists(cursor):
            continue
        info = cursor.lstat()
        if cursor.is_symlink() or (
            getattr(info, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ProfileCompatibilityError("profile_reparse_rejected")
    if require_target and not os.path.lexists(absolute):
        raise ProfileCompatibilityError("profile_path_missing")


def _reject_reparse(
    root: Path, target: Path, *, require_target: bool = True
) -> None:
    lexical_root = Path(os.path.abspath(root))
    lexical_target = Path(os.path.abspath(target))
    try:
        lexical_target.relative_to(lexical_root)
    except ValueError as error:
        raise ProfileCompatibilityError("profile_path_rejected") from error
    _reject_absolute_reparse(
        lexical_target, require_target=require_target
    )


def _move_file_no_replace(source: Path, destination: Path) -> None:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move = kernel32.MoveFileExW
        move.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        move.restype = ctypes.c_int
        if not move(
            str(source), str(destination), _MOVEFILE_WRITE_THROUGH
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return
    os.link(source, destination)
    os.unlink(source)
    directory = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("file_attributes", wintypes.DWORD),
        ("reparse_tag", wintypes.DWORD),
    ]


class _FileRenameInfo(ctypes.Structure):
    _fields_ = [
        ("replace_or_flags", wintypes.DWORD),
        ("root_directory", wintypes.HANDLE),
        ("file_name_length", wintypes.DWORD),
        ("file_name", wintypes.WCHAR * 1),
    ]


class _FileDispositionInfo(ctypes.Structure):
    _fields_ = [("delete_file", ctypes.c_ubyte)]


def _create_windows_temp(path: Path) -> int:
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
        _GENERIC_READ | _GENERIC_WRITE | _DELETE,
        0,
        None,
        _CREATE_NEW,
        _FILE_ATTRIBUTE_NORMAL
        | _FILE_FLAG_OPEN_REPARSE_POINT
        | _FILE_FLAG_WRITE_THROUGH,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
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
        _FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        error = ctypes.WinError(ctypes.get_last_error())
        _close_windows_handle(handle)
        raise error
    if (
        information.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        or information.file_attributes & _FILE_ATTRIBUTE_DIRECTORY
    ):
        _close_windows_handle(handle)
        raise ProfileCompatibilityError("profile_reparse_rejected")
    return handle


def _write_windows_handle(handle: int, payload: bytes) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    write_file = kernel32.WriteFile
    write_file.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    write_file.restype = wintypes.BOOL
    written = wintypes.DWORD()
    buffer = ctypes.create_string_buffer(payload)
    if not write_file(
        handle,
        buffer,
        len(payload),
        ctypes.byref(written),
        None,
    ) or written.value != len(payload):
        raise ctypes.WinError(ctypes.get_last_error())
    flush = kernel32.FlushFileBuffers
    flush.argtypes = [wintypes.HANDLE]
    flush.restype = wintypes.BOOL
    if not flush(handle):
        raise ctypes.WinError(ctypes.get_last_error())


def _read_windows_handle(handle: int, size: int) -> bytes:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_pointer = kernel32.SetFilePointerEx
    set_pointer.argtypes = [
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    ]
    set_pointer.restype = wintypes.BOOL
    if not set_pointer(handle, 0, None, _FILE_BEGIN):
        raise ctypes.WinError(ctypes.get_last_error())
    read_file = kernel32.ReadFile
    read_file.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    read_file.restype = wintypes.BOOL
    buffer = ctypes.create_string_buffer(size + 1)
    read = wintypes.DWORD()
    if not read_file(
        handle,
        buffer,
        size + 1,
        ctypes.byref(read),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return bytes(buffer.raw[: read.value])


def _rename_windows_handle(handle: int, destination: Path) -> None:
    if not destination.is_absolute() or destination.name in {"", ".", ".."}:
        raise ProfileCompatibilityError("profile_path_rejected")
    encoded_name = str(destination).encode("utf-16-le")
    name_offset = _FileRenameInfo.file_name.offset
    buffer = ctypes.create_string_buffer(
        ctypes.sizeof(_FileRenameInfo) + len(encoded_name)
    )
    information = _FileRenameInfo.from_buffer(buffer)
    information.replace_or_flags = 0
    information.root_directory = None
    information.file_name_length = len(encoded_name)
    ctypes.memmove(
        ctypes.addressof(buffer) + name_offset,
        encoded_name,
        len(encoded_name),
    )
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    if not set_information(
        handle,
        _FILE_RENAME_INFO_CLASS,
        buffer,
        len(buffer),
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _delete_windows_handle(handle: int) -> None:
    information = _FileDispositionInfo(1)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    if not set_information(
        handle,
        _FILE_DISPOSITION_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _publish_windows_bound(
    path: Path,
    encoded: bytes,
    *,
    pinned: _DirectoryPin,
    before_publish: Callable[[], None],
    after_temp_open: Callable[[Path], None],
    before_rename: Callable[[], None],
) -> tuple[bytes, bytes]:
    temporary: Path | None = None
    handle: int | None = None
    for _attempt in range(16):
        candidate = path.parent / (
            f".config-{secrets.token_hex(16)}.tmp"
        )
        try:
            handle = _create_windows_temp(candidate)
            temporary = candidate
            break
        except FileExistsError:
            continue
    if handle is None or temporary is None:
        raise ProfileCompatibilityError("config_write_failed")
    succeeded = False
    try:
        _write_windows_handle(handle, encoded)
        after_temp_open(temporary)
        before_publish()
        pinned.verify()
        if os.path.lexists(path):
            raise ProfileCompatibilityError(
                "profile_destination_exists"
            )
        before_rename()
        try:
            _rename_windows_handle(handle, path)
        except OSError as error:
            if getattr(error, "winerror", None) in {80, 183}:
                raise ProfileCompatibilityError(
                    "profile_destination_exists"
                ) from error
            raise ProfileCompatibilityError(
                "config_write_failed"
            ) from error
        pinned.verify()
        reread = _read_windows_handle(handle, len(encoded))
        pinned.verify()
        if reread != encoded:
            raise ProfileCompatibilityError("config_reread_mismatch")
        succeeded = True
        return encoded, reread
    finally:
        cleanup_error: OSError | None = None
        if not succeeded:
            try:
                _delete_windows_handle(handle)
            except OSError as error:
                cleanup_error = error
        try:
            _close_windows_handle(handle)
        except PermissionError as error:
            if cleanup_error is None:
                cleanup_error = error
        if cleanup_error is not None:
            raise ProfileCompatibilityError(
                "config_cleanup_failed"
            ) from cleanup_error


def _publish_json_for_test(
    path: Path,
    value: dict[str, object],
    *,
    before_publish: Callable[[], None] = lambda: None,
    after_temp_open: Callable[[Path], None] = lambda _path: None,
    before_rename: Callable[[], None] = lambda: None,
    pin_directory: Callable[[Path], _DirectoryPin] = _pin_directory,
    move_file: Callable[[Path, Path], None] = _move_file_no_replace,
) -> tuple[bytes, bytes]:
    encoded = json.dumps(
        value, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    temporary: Path | None = None
    parent_trusted = False
    moved = False
    try:
        try:
            pin_context = pin_directory(path.parent)
            with pin_context as pinned:
                pinned.verify()
                if (
                    os.name == "nt"
                    and pin_directory is _pin_directory
                    and move_file is _move_file_no_replace
                ):
                    return _publish_windows_bound(
                        path,
                        encoded,
                        pinned=pinned,
                        before_publish=before_publish,
                        after_temp_open=after_temp_open,
                        before_rename=before_rename,
                    )
                parent_trusted = True
                if os.path.lexists(path):
                    raise ProfileCompatibilityError(
                        "profile_destination_exists"
                    )
                descriptor, temporary_name = tempfile.mkstemp(
                    dir=path.parent,
                    prefix=".config-",
                    suffix=".tmp",
                )
                temporary = Path(temporary_name)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                after_temp_open(temporary)
                before_publish()
                try:
                    pinned.verify()
                except PermissionError as error:
                    parent_trusted = False
                    raise ProfileCompatibilityError(
                        "profile_parent_identity_changed"
                    ) from error
                if os.path.lexists(path):
                    raise ProfileCompatibilityError(
                        "profile_destination_exists"
                    )
                before_rename()
                try:
                    move_file(temporary, path)
                except OSError as error:
                    if os.path.lexists(path):
                        raise ProfileCompatibilityError(
                            "profile_destination_exists"
                        ) from error
                    raise ProfileCompatibilityError(
                        "config_write_failed"
                    ) from error
                moved = True
                pinned.verify()
                reread = path.read_bytes()
                pinned.verify()
                if reread != encoded:
                    raise ProfileCompatibilityError(
                        "config_reread_mismatch"
                    )
                return encoded, reread
        except PermissionError as error:
            raise ProfileCompatibilityError(
                "profile_parent_identity_changed"
            ) from error
    finally:
        if (
            temporary is not None
            and not moved
            and parent_trusted
            and os.path.lexists(temporary)
        ):
            temporary.unlink()


def _require_role_account_layout(
    role_root: Path,
    source_account_name: str,
    *,
    presentation: bool = False,
) -> Path:
    if (
        not isinstance(source_account_name, str)
        or _ACCOUNT_PATTERN.fullmatch(source_account_name) is None
    ):
        raise ProfileCompatibilityError("source_account_name_invalid")
    account_root = role_root / source_account_name
    db_storage = account_root / "db_storage"
    if not os.path.lexists(account_root) or not os.path.lexists(db_storage):
        raise ProfileCompatibilityError("role_account_layout_mismatch")
    _reject_reparse(role_root.parent, db_storage)
    expected_account_entries = {"db_storage"}
    if presentation:
        msg = account_root / "msg"
        attach = msg / "attach"
        video = msg / "video"
        for directory in (msg, attach, video):
            if not os.path.lexists(directory):
                raise ProfileCompatibilityError(
                    "role_account_layout_mismatch"
                )
            _reject_reparse(role_root.parent, directory)
        if (
            not msg.is_dir()
            or not attach.is_dir()
            or not video.is_dir()
            or {item.name for item in msg.iterdir()}
            != {"attach", "video"}
        ):
            raise ProfileCompatibilityError("role_account_layout_mismatch")
        expected_account_entries.add("msg")
    if (
        not account_root.is_dir()
        or not db_storage.is_dir()
        or {item.name for item in role_root.iterdir()} != {source_account_name}
        or {item.name for item in account_root.iterdir()}
        != expected_account_entries
    ):
        raise ProfileCompatibilityError("role_account_layout_mismatch")
    return db_storage


def _build_envelope_profile_for_test(
    *,
    source_config_path: Path,
    source_local_state_path: Path | None = None,
    run_layout: RunLayout,
    validator_layout: ValidatorLayout,
    area: str,
    secure: Callable[[Path], object] = ensure_private_directory,
    before_write: Callable[[], None] = lambda: None,
    reparse_check: Callable[..., None] = _reject_reparse,
    publish_json: Callable[..., tuple[bytes, bytes]] =
        _publish_json_for_test,
) -> ConfigCopyReceipt:
    if area not in {"validation", "active", "presentation"}:
        raise ProfileCompatibilityError("request_area_rejected")
    target_path = (
        run_layout.root / "presentation"
        if area == "presentation"
        else getattr(run_layout, area)
    )
    reparse_check(run_layout.root, target_path, require_target=True)
    target_role = canonical_existing(target_path)
    assert_descendant(target_role, run_layout.root)
    for directory in (
        validator_layout.attempt_root,
        validator_layout.user_data_dir,
        validator_layout.documents_dir,
        validator_layout.cache_dir,
        validator_layout.request_path.parent,
        validator_layout.result_path.parent,
    ):
        assert_descendant(directory, run_layout.root)
        reparse_check(run_layout.root, directory, require_target=False)
        secure(directory)
        reparse_check(run_layout.root, directory, require_target=True)

    _reject_absolute_reparse(source_config_path)
    source = canonical_existing(source_config_path)
    source_bytes = source.read_bytes()
    original = _strict_json(source_bytes)
    local_state_source: Path | None = None
    local_state_bytes: bytes | None = None
    local_state: dict[str, object] | None = None
    if source_local_state_path is not None:
        _reject_absolute_reparse(source_local_state_path)
        local_state_source = canonical_existing(
            source_local_state_path
        )
        local_state_bytes = local_state_source.read_bytes()
        local_state = _strict_local_state(local_state_bytes)
    current, _nested = _validate_config_schema(original)
    _require_role_account_layout(
        target_role,
        current,
        presentation=area == "presentation",
    )

    copied = copy.deepcopy(original)
    effective_db_path = str(target_role)
    effective_cache_path = str(
        canonical_existing(validator_layout.cache_dir)
    )
    copied["dbPath"] = effective_db_path
    copied["cachePath"] = effective_cache_path
    sanitized_cache_fields = (
        _drop_source_path_keyed_cache_entries(
            copied,
            original["dbPath"],
        )
    )
    source_path_absent = _source_paths_absent(
        copied,
        effective_db_path=effective_db_path,
        effective_cache_path=effective_cache_path,
        forbidden_paths=(str(run_layout.source), original["dbPath"]),
    )
    if not source_path_absent:
        raise ProfileCompatibilityError("profile_source_path_leak")
    destination = validator_layout.user_data_dir / "WeFlow-config.json"
    reparse_check(
        run_layout.root, destination.parent, require_target=True
    )
    reparse_check(run_layout.root, destination, require_target=False)
    if os.path.lexists(destination):
        raise ProfileCompatibilityError("profile_destination_exists")
    local_state_destination = (
        validator_layout.user_data_dir / "Local State"
    )
    if local_state is not None:
        reparse_check(
            run_layout.root,
            local_state_destination,
            require_target=False,
        )
        if os.path.lexists(local_state_destination):
            raise ProfileCompatibilityError(
                "profile_destination_exists"
            )

    def assert_sources_unchanged() -> None:
        if source.read_bytes() != source_bytes:
            raise ProfileCompatibilityError(
                "source_config_changed"
            )
        if (
            local_state_source is not None
            and local_state_source.read_bytes()
            != local_state_bytes
        ):
            raise ProfileCompatibilityError(
                "source_local_state_changed"
            )

    def before_publish() -> None:
        before_write()
        reparse_check(
            run_layout.root, destination.parent, require_target=True
        )
        reparse_check(
            run_layout.root, destination, require_target=False
        )
        assert_sources_unchanged()

    def before_local_state_publish() -> None:
        reparse_check(
            run_layout.root,
            local_state_destination.parent,
            require_target=True,
        )
        reparse_check(
            run_layout.root,
            local_state_destination,
            require_target=False,
        )
        assert_sources_unchanged()

    try:
        encoded, reread = publish_json(
            destination,
            copied,
            before_publish=before_publish,
        )
        reparse_check(run_layout.root, destination, require_target=True)
        if local_state is not None:
            local_encoded, local_reread = publish_json(
                local_state_destination,
                local_state,
                before_publish=before_local_state_publish,
            )
            reparse_check(
                run_layout.root,
                local_state_destination,
                require_target=True,
            )
            if (
                local_reread != local_encoded
                or _strict_local_state(local_reread)
                != local_state
            ):
                raise ProfileCompatibilityError(
                    "config_reread_mismatch"
                )
        source_after = source.read_bytes()
        local_state_after = (
            local_state_source.read_bytes()
            if local_state_source is not None
            else None
        )
    except ProfileCompatibilityError:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise ProfileCompatibilityError("config_write_failed") from error
    if source_after != source_bytes:
        raise ProfileCompatibilityError("source_config_changed")
    if local_state_after != local_state_bytes:
        raise ProfileCompatibilityError("source_config_changed")
    if (
        reread != encoded
        or _strict_json(reread) != copied
        or _digest(source_after) != _digest(source_bytes)
    ):
        raise ProfileCompatibilityError("config_reread_mismatch")
    return ConfigCopyReceipt(
        _digest(source_bytes),
        _digest(reread),
        (
            "dbPath",
            "cachePath",
            *sanitized_cache_fields,
        ),
        effective_db_path,
        effective_cache_path,
        source_path_absent,
    )


def build_envelope_profile(
    *,
    source_config_path: Path,
    run_layout: RunLayout,
    validator_layout: ValidatorLayout,
    area: str,
) -> ConfigCopyReceipt:
    return _build_envelope_profile_for_test(
        source_config_path=source_config_path,
        source_local_state_path=source_config_path.parent / "Local State",
        run_layout=run_layout,
        validator_layout=validator_layout,
        area=area,
    )


def build_synthetic_profile(
    *, layout: ValidatorLayout, area: str, source_account_name: str
) -> ConfigCopyReceipt:
    if area not in {"validation", "active", "presentation"}:
        raise ProfileCompatibilityError("request_area_rejected")
    if source_account_name != "wxid_test":
        raise ProfileCompatibilityError("synthetic_account_rejected")
    for directory in (
        layout.attempt_root,
        layout.user_data_dir,
        layout.documents_dir,
        layout.cache_dir,
        layout.request_path.parent,
        layout.result_path.parent,
    ):
        _reject_reparse(layout.run_root, directory, require_target=False)
        ensure_private_directory(directory)
        _reject_reparse(layout.run_root, directory, require_target=True)
    role_root = layout.run_root / area
    db_storage = role_root / source_account_name / "db_storage"
    _reject_reparse(layout.run_root, db_storage, require_target=False)
    db_storage.mkdir(parents=True, exist_ok=True)
    _reject_reparse(layout.run_root, db_storage, require_target=True)
    if area == "presentation":
        for directory in (
            role_root / source_account_name / "msg" / "attach",
            role_root / source_account_name / "msg" / "video",
        ):
            _reject_reparse(
                layout.run_root, directory, require_target=False
            )
            directory.mkdir(parents=True, exist_ok=True)
            _reject_reparse(
                layout.run_root, directory, require_target=True
            )
    _require_role_account_layout(
        role_root,
        source_account_name,
        presentation=area == "presentation",
    )
    synthetic_envelope = "safe:" + ("QUJDREVGR0g=" * 6)
    value = {
        "dbPath": str(role_root),
        "cachePath": str(layout.cache_dir),
        "myWxid": source_account_name,
        "decryptKey": synthetic_envelope,
        "wxidConfigs": {
            source_account_name: {"decryptKey": synthetic_envelope}
        },
    }
    destination = layout.user_data_dir / "WeFlow-config.json"
    _reject_reparse(
        layout.run_root, destination, require_target=False
    )
    if os.path.lexists(destination):
        raise ProfileCompatibilityError("profile_destination_exists")
    encoded, reread = _publish_json_for_test(destination, value)
    _reject_reparse(
        layout.run_root, destination, require_target=True
    )
    if reread != encoded or destination.read_bytes() != encoded:
        raise ProfileCompatibilityError("config_reread_mismatch")
    digest = _digest(encoded)
    return ConfigCopyReceipt(
        digest,
        digest,
        ("dbPath", "cachePath"),
        str(role_root),
        str(layout.cache_dir),
        True,
    )
