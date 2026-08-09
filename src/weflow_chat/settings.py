from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from weflow_chat.atomic_io import atomic_write_json
from weflow_chat.paths import canonical_existing, canonical_future


_SCHEMA_VERSION = 1
_MAX_SETTINGS_BYTES = 16 * 1024


@dataclass(frozen=True, slots=True)
class HostSettings:
    source_account: Path
    data_root: Path


def settings_path(local_app_data: Path) -> Path:
    root = canonical_existing(local_app_data)
    return root / "WeFlowChat" / "settings.json"


def _validated(settings: HostSettings) -> HostSettings:
    if not isinstance(settings, HostSettings):
        raise TypeError("settings_contract_invalid")
    source = canonical_existing(settings.source_account)
    data_root = canonical_future(settings.data_root)
    if (
        not source.is_dir()
        or source.is_symlink()
        or not (source / "db_storage").is_dir()
        or data_root == source
        or data_root.is_relative_to(source)
        or source.is_relative_to(data_root)
    ):
        raise RuntimeError("settings_contract_invalid")
    return HostSettings(source, data_root)


def write_settings(path: Path, settings: HostSettings) -> HostSettings:
    target = canonical_future(path)
    if target.name.casefold() != "settings.json":
        raise RuntimeError("settings_path_invalid")
    validated = _validated(settings)
    atomic_write_json(
        target,
        {
            "schemaVersion": _SCHEMA_VERSION,
            "sourceAccount": str(validated.source_account),
            "dataRoot": str(validated.data_root),
        },
    )
    return read_settings(target)


def read_settings(path: Path) -> HostSettings:
    target = canonical_existing(path)
    information = target.lstat()
    if (
        not target.is_file()
        or target.is_symlink()
        or not 0 < information.st_size <= _MAX_SETTINGS_BYTES
    ):
        raise RuntimeError("settings_file_invalid")
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("settings_file_invalid") from error
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schemaVersion", "sourceAccount", "dataRoot"}
        or raw["schemaVersion"] != _SCHEMA_VERSION
        or not isinstance(raw["sourceAccount"], str)
        or not isinstance(raw["dataRoot"], str)
    ):
        raise RuntimeError("settings_file_invalid")
    return _validated(
        HostSettings(
            source_account=Path(raw["sourceAccount"]),
            data_root=Path(raw["dataRoot"]),
        )
    )
