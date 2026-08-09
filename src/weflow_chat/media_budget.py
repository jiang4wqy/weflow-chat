from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil

from weflow_chat.paths import canonical_existing
from weflow_chat.vss import MediaStagingFile, MediaStagingReceipt


_FIXED_FREE_SPACE_RESERVE_BYTES = 2**30
_ACCOUNT_RE = re.compile(r"[A-Za-z0-9_]{1,128}")
_SHA256_RE = re.compile(r"[0-9A-F]{64}")
_MEDIA_ROOTS = {
    ("msg", "attach"),
    ("msg", "video"),
}


class MediaBudgetError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class MediaPostStagingBudget:
    mergedMediaBytes: int
    deltaBytes: int
    requiredFreeBytes: int
    observedFreeBytes: int


def _validate_files(
    value: object,
) -> tuple[MediaStagingFile, ...]:
    if type(value) is not tuple:
        raise MediaBudgetError("media_budget_input_invalid")
    paths: list[str] = []
    for item in value:
        if (
            type(item) is not MediaStagingFile
            or type(item.relative_path) is not str
        ):
            raise MediaBudgetError("media_budget_input_invalid")
        relative = PurePosixPath(item.relative_path)
        if (
            relative.is_absolute()
            or relative.as_posix() != item.relative_path
            or "\\" in item.relative_path
            or ":" in item.relative_path
            or len(relative.parts) < 3
            or tuple(relative.parts[:2]) not in _MEDIA_ROOTS
            or any(part in {"", ".", ".."} for part in relative.parts)
            or type(item.size) is not int
            or item.size < 0
            or type(item.sha256) is not str
            or _SHA256_RE.fullmatch(item.sha256) is None
        ):
            raise MediaBudgetError("media_budget_input_invalid")
        paths.append(item.relative_path)
    if (
        paths != sorted(paths)
        or len({path.casefold() for path in paths}) != len(paths)
    ):
        raise MediaBudgetError("media_budget_input_invalid")
    return value


def _manifest_sha256(
    files: tuple[MediaStagingFile, ...],
) -> str:
    encoded = json.dumps(
        [
            {
                "relativePath": item.relative_path,
                "size": item.size,
                "sha256": item.sha256,
            }
            for item in files
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest().upper()


def calculate_media_post_staging_budget(
    *,
    prior_inventory: tuple[MediaStagingFile, ...] | None,
    delta_receipt: MediaStagingReceipt,
    source_db_bytes: int,
    validation_db_bytes: int,
    active_db_bytes: int,
    presentation_db_bytes: int,
    existing_destination_volume_root: Path,
) -> MediaPostStagingBudget:
    if (
        prior_inventory is not None
        and type(prior_inventory) is not tuple
    ):
        raise MediaBudgetError("media_budget_input_invalid")
    prior = _validate_files(
        () if prior_inventory is None else prior_inventory
    )
    if (
        type(delta_receipt) is not MediaStagingReceipt
        or type(delta_receipt.source_account_name) is not str
        or _ACCOUNT_RE.fullmatch(
            delta_receipt.source_account_name
        ) is None
        or type(delta_receipt.file_count) is not int
        or type(delta_receipt.byte_count) is not int
        or delta_receipt.file_count < 0
        or delta_receipt.byte_count < 0
        or type(delta_receipt.manifest_sha256) is not str
        or _SHA256_RE.fullmatch(
            delta_receipt.manifest_sha256
        ) is None
        or any(
            type(value) is not int or value < 0
            for value in (
                source_db_bytes,
                validation_db_bytes,
                active_db_bytes,
                presentation_db_bytes,
            )
        )
    ):
        raise MediaBudgetError("media_budget_input_invalid")
    delta_files = _validate_files(delta_receipt.files)
    if (
        delta_receipt.file_count != len(delta_files)
        or delta_receipt.byte_count
        != sum(item.size for item in delta_files)
        or delta_receipt.manifest_sha256
        != _manifest_sha256(delta_files)
    ):
        raise MediaBudgetError("media_budget_input_invalid")
    try:
        staging_root = canonical_existing(
            Path(delta_receipt.staging_path)
        )
        destination_root = canonical_existing(
            Path(existing_destination_volume_root)
        )
        if (
            not staging_root.is_dir()
            or not destination_root.is_dir()
            or staging_root.stat().st_dev
            != destination_root.stat().st_dev
        ):
            raise ValueError("media_budget_volume_mismatch")
    except (OSError, TypeError, ValueError) as error:
        raise MediaBudgetError(
            "media_budget_input_invalid"
        ) from error
    prior_by_path = {item.relative_path: item for item in prior}
    merged_by_path = dict(prior_by_path)
    for item in delta_files:
        merged_by_path[item.relative_path] = item

    final_store_growth = sum(
        item.size
        if (old := prior_by_path.get(item.relative_path)) is None
        else max(item.size - old.size, 0)
        for item in delta_files
    )
    merged_media_bytes = sum(item.size for item in merged_by_path.values())
    delta_bytes = sum(item.size for item in delta_files)
    database_bytes = (
        source_db_bytes
        + validation_db_bytes
        + active_db_bytes
        + presentation_db_bytes
    )
    import_peak_bytes = source_db_bytes + delta_bytes
    final_tree_peak_bytes = (
        database_bytes
        + final_store_growth
        + merged_media_bytes
        - delta_bytes
    )
    required = (
        max(import_peak_bytes, final_tree_peak_bytes)
        + _FIXED_FREE_SPACE_RESERVE_BYTES
    )
    try:
        observed = shutil.disk_usage(destination_root).free
    except OSError as error:
        raise MediaBudgetError(
            "media_budget_space_probe_invalid"
        ) from error
    if type(observed) is not int or observed < 0:
        raise MediaBudgetError("media_budget_space_probe_invalid")
    if observed < required:
        raise MediaBudgetError("media_post_staging_space_insufficient")
    return MediaPostStagingBudget(
        mergedMediaBytes=merged_media_bytes,
        deltaBytes=delta_bytes,
        requiredFreeBytes=required,
        observedFreeBytes=observed,
    )
