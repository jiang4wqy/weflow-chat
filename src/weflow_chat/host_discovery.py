from __future__ import annotations

from collections.abc import Callable, Iterable
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import sys

from weflow_chat.paths import canonical_existing, canonical_future
from weflow_chat.preflight import HostContract
from weflow_chat.settings import (
    HostSettings,
    read_settings,
    settings_path,
    write_settings,
)


_ACCOUNT_RE = re.compile(r"wxid_[A-Za-z0-9_]{1,128}")
_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_MIN_STORAGE_MARGIN = 1024**3
_COPY_MULTIPLIER = 3


@dataclass(frozen=True, slots=True)
class KnownFolders:
    local_app_data: Path
    roaming_app_data: Path
    documents: Path
    desktop: Path
    program_files: Path
    program_files_x86: Path


@dataclass(frozen=True, slots=True)
class VolumeCandidate:
    root: Path
    free_bytes: int
    is_fixed: bool
    file_system: str


class _Guid(ctypes.Structure):
    _fields_ = (
        ("data1", wintypes.DWORD),
        ("data2", wintypes.WORD),
        ("data3", wintypes.WORD),
        ("data4", ctypes.c_ubyte * 8),
    )

    @classmethod
    def parse(cls, value: str) -> "_Guid":
        import uuid

        raw = uuid.UUID(value).bytes_le
        return cls.from_buffer_copy(raw)


_KNOWN_FOLDER_IDS = {
    "local_app_data": "f1b32785-6fba-4fcf-9d55-7b8e7f157091",
    "roaming_app_data": "3eb685db-65f9-4cf6-a03a-e3ef65729f3d",
    "documents": "fdd39ad0-238f-46af-adb4-6c85480369c7",
    "desktop": "b4bfcc3a-db2c-424c-b029-7fe99a87c641",
    "program_files": "905e63b6-c1bf-494e-b29c-65b732d3d21a",
    "program_files_x86": "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e",
}


def _known_folder(identifier: str) -> Path:
    if sys.platform != "win32":
        raise RuntimeError("windows_required")
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    function = shell32.SHGetKnownFolderPath
    function.argtypes = (
        ctypes.POINTER(_Guid),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_wchar_p),
    )
    function.restype = ctypes.c_long
    pointer = ctypes.c_wchar_p()
    guid = _Guid.parse(identifier)
    result = function(ctypes.byref(guid), 0, None, ctypes.byref(pointer))
    if result != 0 or not pointer.value:
        raise RuntimeError("known_folder_unavailable")
    try:
        return canonical_existing(Path(pointer.value))
    finally:
        ole32.CoTaskMemFree(pointer)


def windows_known_folders() -> KnownFolders:
    values = {
        name: _known_folder(identifier)
        for name, identifier in _KNOWN_FOLDER_IDS.items()
    }
    return KnownFolders(**values)


def _read_weflow_account(config_path: Path) -> str:
    target = canonical_existing(config_path)
    information = target.lstat()
    if (
        not target.is_file()
        or target.is_symlink()
        or not 0 < information.st_size <= _MAX_CONFIG_BYTES
    ):
        raise RuntimeError("weflow_config_invalid")
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("weflow_config_invalid") from error
    selected = raw.get("myWxid") if isinstance(raw, dict) else None
    accounts = raw.get("wxidConfigs") if isinstance(raw, dict) else None
    selected_config = (
        accounts.get(selected)
        if isinstance(accounts, dict) and isinstance(selected, str)
        else None
    )
    top_envelope = raw.get("decryptKey") if isinstance(raw, dict) else None
    nested_envelope = (
        selected_config.get("decryptKey")
        if isinstance(selected_config, dict)
        else None
    )
    if (
        not isinstance(selected, str)
        or _ACCOUNT_RE.fullmatch(selected) is None
        or not isinstance(selected_config, dict)
        or not isinstance(top_envelope, str)
        or not top_envelope.startswith("safe:")
        or not isinstance(nested_envelope, str)
        or nested_envelope != top_envelope
    ):
        raise RuntimeError("weflow_not_initialized")
    return selected


def _ordinary_executable(path: Path, expected_name: str) -> Path | None:
    try:
        target = canonical_existing(path)
        if (
            target.name.casefold() != expected_name.casefold()
            or not target.is_file()
            or target.is_symlink()
        ):
            return None
        return target
    except (OSError, ValueError):
        return None


def _unique_executable(
    candidates: Iterable[Path], expected_name: str, reason: str
) -> Path:
    resolved = {
        item
        for candidate in candidates
        if (item := _ordinary_executable(candidate, expected_name))
        is not None
    }
    if len(resolved) != 1:
        raise RuntimeError(reason)
    return resolved.pop()


def _candidate_data_roots(
    folders: KnownFolders,
    volume_roots: Iterable[Path],
) -> tuple[Path, ...]:
    candidates = {folders.documents / "xwechat_files"}
    for raw_root in volume_roots:
        try:
            root = canonical_existing(raw_root)
            candidates.add(root / "xwechat_files")
            with os.scandir(root) as iterator:
                for entry in iterator:
                    if entry.is_dir(follow_symlinks=False):
                        candidates.add(Path(entry.path) / "xwechat_files")
        except (OSError, ValueError):
            continue
    return tuple(sorted(candidates, key=lambda item: str(item).casefold()))


def discover_source_accounts(
    *,
    account_id: str,
    data_roots: Iterable[Path],
) -> tuple[Path, ...]:
    if _ACCOUNT_RE.fullmatch(account_id) is None:
        raise RuntimeError("account_selector_invalid")
    matches: set[Path] = set()
    for data_root in data_roots:
        try:
            root = canonical_existing(data_root)
            if not root.is_dir() or root.is_symlink():
                continue
            with os.scandir(root) as iterator:
                entries = tuple(iterator)
        except (OSError, ValueError):
            continue
        for entry in entries:
            if (
                not entry.is_dir(follow_symlinks=False)
                or not (
                    entry.name == account_id
                    or entry.name.startswith(account_id + "_")
                )
            ):
                continue
            candidate = Path(entry.path)
            session = candidate / "db_storage" / "session" / "session.db"
            try:
                canonical = canonical_existing(candidate)
                session = canonical_existing(session)
            except (OSError, ValueError):
                continue
            if session.is_file() and not session.is_symlink():
                matches.add(canonical)
    return tuple(sorted(matches, key=lambda item: str(item).casefold()))


def _source_size(source_account: Path) -> int:
    root = canonical_existing(source_account / "db_storage")
    total = 0
    pending = [root]
    while pending:
        current = pending.pop()
        with os.scandir(current) as iterator:
            for entry in iterator:
                if entry.is_symlink():
                    raise RuntimeError("source_reparse_rejected")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
                else:
                    raise RuntimeError("source_entry_rejected")
    if total <= 0:
        raise RuntimeError("source_empty")
    return total


def required_storage_bytes(source_account: Path) -> int:
    return _source_size(source_account) * _COPY_MULTIPLIER + _MIN_STORAGE_MARGIN


def recommend_volumes(
    volumes: Iterable[VolumeCandidate], *, required_bytes: int
) -> tuple[VolumeCandidate, ...]:
    if type(required_bytes) is not int or required_bytes <= 0:
        raise ValueError("required_storage_invalid")
    eligible = tuple(
        item
        for item in volumes
        if (
            isinstance(item, VolumeCandidate)
            and item.is_fixed
            and item.file_system.casefold() == "ntfs"
            and item.free_bytes >= required_bytes
        )
    )
    return tuple(
        sorted(
            eligible,
            key=lambda item: (-item.free_bytes, str(item.root).casefold()),
        )
    )


def windows_volumes() -> tuple[VolumeCandidate, ...]:
    if sys.platform != "win32":
        raise RuntimeError("windows_required")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    mask = kernel32.GetLogicalDrives()
    if mask == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    results = []
    for index in range(26):
        if not mask & (1 << index):
            continue
        root = Path(f"{chr(65 + index)}:\\")
        drive_type = kernel32.GetDriveTypeW(str(root))
        file_system = ctypes.create_unicode_buffer(32)
        if not kernel32.GetVolumeInformationW(
            str(root), None, 0, None, None, None, file_system, len(file_system)
        ):
            continue
        try:
            free_bytes = shutil.disk_usage(root).free
        except OSError:
            continue
        results.append(
            VolumeCandidate(
                root=root,
                free_bytes=free_bytes,
                is_fixed=drive_type == 3,
                file_system=file_system.value,
            )
        )
    return tuple(results)


def _choose_numbered(
    values: tuple[Path, ...],
    *,
    input_fn: Callable[[str], str],
    output_fn: Callable[[str], None],
    label: str,
) -> Path:
    if not values:
        raise RuntimeError(f"{label}_not_found")
    if len(values) == 1:
        return values[0]
    output_fn(f"检测到 {len(values)} 个{label}候选。")
    for index, value in enumerate(values, start=1):
        output_fn(f"{index}. 驱动器 {value.drive or '未知'}")
    answer = input_fn(f"输入 SELECT <编号> 选择{label}: ")
    match = re.fullmatch(r"SELECT ([1-9][0-9]*)", answer)
    if match is None:
        raise RuntimeError(f"{label}_selection_cancelled")
    index = int(match.group(1)) - 1
    if not 0 <= index < len(values):
        raise RuntimeError(f"{label}_selection_invalid")
    return values[index]


def _choose_storage(
    volumes: tuple[VolumeCandidate, ...],
    *,
    folders: KnownFolders,
    input_fn: Callable[[str], str],
    output_fn: Callable[[str], None],
) -> Path:
    if not volumes:
        raise RuntimeError("storage_volume_not_found")
    output_fn("已按可用空间排序合格的 NTFS 存储卷。")
    for index, volume in enumerate(volumes, start=1):
        output_fn(
            f"{index}. 驱动器 {volume.root.drive}，"
            f"可用 {volume.free_bytes // (1024**3)} GiB"
        )
    answer = input_fn("输入 USE 使用推荐卷，或 SELECT <编号>: ")
    if answer == "USE":
        chosen = volumes[0]
    else:
        match = re.fullmatch(r"SELECT ([1-9][0-9]*)", answer)
        if match is None:
            raise RuntimeError("storage_selection_cancelled")
        index = int(match.group(1)) - 1
        if not 0 <= index < len(volumes):
            raise RuntimeError("storage_selection_invalid")
        chosen = volumes[index]
    if chosen.root.drive.casefold() == folders.local_app_data.drive.casefold():
        return folders.local_app_data / "WeFlowChat" / "Data"
    return chosen.root / "WeFlowChatData"


def _contract(
    *,
    folders: KnownFolders,
    settings: HostSettings,
    account_id: str,
    formal_weflow: Path,
    weixin_executable: Path,
) -> HostContract:
    source = canonical_existing(settings.source_account)
    data_root = canonical_future(settings.data_root)
    if source.name != account_id:
        raise RuntimeError("source_account_name_mismatch")
    return HostContract.discovered(
        source_account=source,
        data_root=data_root,
        formal_weflow=formal_weflow,
        weixin_install_root=weixin_executable.parent,
        config_path=folders.roaming_app_data / "weflow" / "WeFlow-config.json",
        cache_maps_path=(
            folders.roaming_app_data / "weflow" / "WeFlow-cache-maps.json"
        ),
        analytics_cache_path=(
            folders.documents / "WeFlow" / "analytics_cache.json"
        ),
        same_volume_recovery_root=(
            folders.roaming_app_data / "WeFlowChat" / "Recovery"
        ),
        account_id=account_id,
    )


def _runtime_candidates(folders: KnownFolders) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    weflow = (
        folders.local_app_data / "Programs" / "WeFlow" / "WeFlow.exe",
    )
    weixin = (
        folders.program_files / "Tencent" / "Weixin" / "Weixin.exe",
        folders.program_files_x86 / "Tencent" / "Weixin" / "Weixin.exe",
    )
    return weflow, weixin


def load_host_contract(
    *, folders: KnownFolders | None = None
) -> HostContract:
    known = windows_known_folders() if folders is None else folders
    config_path = known.roaming_app_data / "weflow" / "WeFlow-config.json"
    account_id = _read_weflow_account(config_path)
    weflow_candidates, weixin_candidates = _runtime_candidates(known)
    formal_weflow = _unique_executable(
        weflow_candidates, "WeFlow.exe", "weflow_install_not_unique"
    )
    weixin_executable = _unique_executable(
        weixin_candidates, "Weixin.exe", "weixin_install_not_unique"
    )
    stored = read_settings(settings_path(known.local_app_data))
    return _contract(
        folders=known,
        settings=stored,
        account_id=account_id,
        formal_weflow=formal_weflow,
        weixin_executable=weixin_executable,
    )


def initialize_host_contract(
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    folders: KnownFolders | None = None,
    volumes: tuple[VolumeCandidate, ...] | None = None,
) -> HostContract:
    known = windows_known_folders() if folders is None else folders
    path = settings_path(known.local_app_data)
    if path.exists():
        return load_host_contract(folders=known)
    config_path = known.roaming_app_data / "weflow" / "WeFlow-config.json"
    account_id = _read_weflow_account(config_path)
    discovered_volumes = windows_volumes() if volumes is None else volumes
    roots = tuple(item.root for item in discovered_volumes if item.is_fixed)
    source = _choose_numbered(
        discover_source_accounts(
            account_id=account_id,
            data_roots=_candidate_data_roots(known, roots),
        ),
        input_fn=input_fn,
        output_fn=output_fn,
        label="微信数据目录",
    )
    required = required_storage_bytes(source)
    eligible = recommend_volumes(discovered_volumes, required_bytes=required)
    data_root = _choose_storage(
        eligible,
        folders=known,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    canonical_future(data_root).mkdir(parents=True, exist_ok=False)
    stored = write_settings(
        path,
        HostSettings(source_account=source, data_root=data_root),
    )
    weflow_candidates, weixin_candidates = _runtime_candidates(known)
    return _contract(
        folders=known,
        settings=stored,
        account_id=account_id,
        formal_weflow=_unique_executable(
            weflow_candidates, "WeFlow.exe", "weflow_install_not_unique"
        ),
        weixin_executable=_unique_executable(
            weixin_candidates, "Weixin.exe", "weixin_install_not_unique"
        ),
    )
