from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path, PureWindowsPath
from typing import Protocol

from weflow_chat.atomic_io import atomic_write_json
from weflow_chat.models import CopyRole, FileEntry
from weflow_chat.paths import (
    RunLayout, assert_descendant, canonical_existing,
)


class SnapshotMethod(StrEnum):
    VSS_CRASH_CONSISTENT = "vss-crash-consistent"


class ResidualRisk(StrEnum):
    NO_CROSS_DATABASE_ATOMICITY_PROOF = (
        "crash_consistent_no_cross_database_atomicity_proof")


class FileCategory(StrEnum):
    DATABASE = "database"
    WAL = "wal"
    SHM = "shm"
    OTHER = "other"


class UnsafeTreeEntryError(ValueError):
    pass


class CopyVerificationError(RuntimeError):
    pass


class StagingReceiptLike(Protocol):
    staging_path: Path
    source_account_name: str
    account_db_relative_path: PureWindowsPath
    file_count: int
    byte_count: int
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class FileSetManifest:
    role: CopyRole
    root: str
    files: tuple[FileEntry, ...]
    total_files: int
    total_bytes: int
    category_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class RunManifest:
    schema_version: int
    tool_version: str
    run_id: str
    source_account_name: str
    captured_at_utc: str
    source_volume: str
    shadow_id: str
    staging_manifest_sha256: str
    snapshot_method: SnapshotMethod
    residual_risk: ResidualRisk
    source: FileSetManifest


@dataclass(frozen=True, slots=True)
class FileSetReceipt:
    role: CopyRole
    content_sha256: str
    total_files: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class RunManifestReceipt:
    manifest_path: str
    canonical_sha256: str
    source_content_sha256: str


def _canonical_json_sha256(value: dict[str, object]) -> str:
    payload = json.dumps(value, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest().upper()


def file_set_receipt(value: FileSetManifest) -> FileSetReceipt:
    payload = json.dumps(
        content_signature(value), separators=(",", ":")).encode("utf-8")
    return FileSetReceipt(
        role=value.role,
        content_sha256=hashlib.sha256(payload).hexdigest().upper(),
        total_files=value.total_files,
        total_bytes=value.total_bytes,
    )


def validate_account_role_manifest(
        value: FileSetManifest, *, source_account_name: str) -> None:
    expected_prefix = (
        PureWindowsPath(source_account_name, "db_storage").as_posix() +
        "/")
    if (not value.files or any(
            not item.relative_path.startswith(expected_prefix)
            for item in value.files)):
        raise CopyVerificationError("account_role_layout_mismatch")


def _require_only_directory(parent: Path, expected_name: str) -> Path:
    with os.scandir(parent) as iterator:
        entries = list(iterator)
    if (len(entries) != 1 or entries[0].name != expected_name or
            validate_scandir_entry(entries[0]) != "directory"):
        raise CopyVerificationError("account_role_tree_mismatch")
    return canonical_existing(Path(entries[0].path))


def validate_account_role_tree(
        root: Path, *, source_account_name: str) -> None:
    """Require exactly root/account/db_storage and a nonempty DB tree."""
    root = canonical_existing(root)
    account_root = _require_only_directory(root, source_account_name)
    database_root = _require_only_directory(account_root, "db_storage")
    pending = [database_root]
    file_count = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            entries = list(iterator)
        if not entries:
            raise CopyVerificationError("account_role_tree_empty")
        if len({entry.name.casefold() for entry in entries}) != len(entries):
            raise CopyVerificationError("account_role_name_collision")
        for entry in entries:
            kind = validate_scandir_entry(entry)
            path = Path(entry.path)
            assert_descendant(path, database_root)
            if kind == "directory":
                pending.append(path)
            else:
                file_count += 1
    if file_count == 0:
        raise CopyVerificationError("account_role_tree_empty")


def validate_scandir_entry(entry) -> str:
    if ":" in entry.name or entry.is_symlink():
        raise UnsafeTreeEntryError("unsafe_tree_entry")
    info = entry.stat(follow_symlinks=False)
    if (getattr(info, "st_file_attributes", 0) &
            stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise UnsafeTreeEntryError("unsafe_tree_entry")
    if entry.is_file(follow_symlinks=False):
        return "file"
    if entry.is_dir(follow_symlinks=False):
        return "directory"
    raise UnsafeTreeEntryError("non_ordinary_tree_entry")


def iter_ordinary_files(root: Path):
    root = canonical_existing(root)
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            ordered = sorted(entries, key=lambda item: item.name.casefold())
        for entry in ordered:
            kind = validate_scandir_entry(entry)
            path = Path(entry.path)
            assert_descendant(path, root)
            if kind == "directory":
                pending.append(path)
            else:
                yield path


def classify_file(path: Path) -> FileCategory:
    lower = path.name.lower()
    if lower.endswith("-wal"):
        return FileCategory.WAL
    if lower.endswith("-shm"):
        return FileCategory.SHM
    if lower.endswith((".db", ".sqlite", ".sqlite3")):
        return FileCategory.DATABASE
    return FileCategory.OTHER


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def build_manifest(root: Path, *, role: CopyRole) -> FileSetManifest:
    root = canonical_existing(root)
    files = []
    counts = {category.value: 0 for category in FileCategory}
    for path in iter_ordinary_files(root):
        path_stat = path.stat()
        category = classify_file(path)
        counts[category.value] += 1
        files.append(FileEntry(path.relative_to(root).as_posix(),
                               category.value, path_stat.st_size,
                               path_stat.st_mtime_ns, sha256_file(path)))
    files.sort(key=lambda item: item.relative_path)
    return FileSetManifest(role, str(root), tuple(files), len(files),
                           sum(item.size for item in files), counts)


def content_signature(manifest: FileSetManifest) -> tuple:
    return tuple((item.relative_path, item.size, item.sha256)
                 for item in manifest.files)


def _manifest_json(value: RunManifest) -> dict[str, object]:
    return {
        "schemaVersion": value.schema_version,
        "toolVersion": value.tool_version,
        "runId": value.run_id,
        "sourceAccountName": value.source_account_name,
        "capturedAtUtc": value.captured_at_utc,
        "sourceVolume": value.source_volume,
        "shadowId": value.shadow_id,
        "stagingManifestSha256": value.staging_manifest_sha256,
        "snapshotMethod": value.snapshot_method.value,
        "residualRisk": value.residual_risk.value,
        "categoryCounts": value.source.category_counts,
        "source": {
            "role": value.source.role.value,
            "root": value.source.root,
            "totalFiles": value.source.total_files,
            "totalBytes": value.source.total_bytes,
            "files": [{
                "relativePath": item.relative_path,
                "category": item.category,
                "size": item.size,
                "mtimeNs": item.mtime_ns,
                "sha256": item.sha256,
            } for item in value.source.files],
        },
    }


_RUN_KEYS = {
    "schemaVersion", "toolVersion", "runId", "capturedAtUtc",
    "sourceVolume", "shadowId", "stagingManifestSha256",
    "snapshotMethod", "residualRisk", "categoryCounts", "source",
    "sourceAccountName",
}
_SOURCE_KEYS = {"role", "root", "totalFiles", "totalBytes", "files"}
_FILE_KEYS = {"relativePath", "category", "size", "mtimeNs", "sha256"}
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_TOOL_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,127}")
_WINDOWS_VOLUME_RE = re.compile(r"[A-Za-z]:\\")
_MAX_RUN_MANIFEST_BYTES = 64 * 1024 * 1024


def _same_file(*values) -> bool:
    identities = {
        (item.st_dev, item.st_ino, item.st_size)
        for item in values
    }
    return len(identities) == 1


def _read_bounded_ordinary_file(path: Path) -> bytes:
    descriptor = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("run_manifest_path_invalid")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
                not stat.S_ISREG(opened.st_mode) or
                not _same_file(before, opened)):
            raise ValueError("run_manifest_path_changed")
        chunks = []
        remaining = _MAX_RUN_MANIFEST_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_RUN_MANIFEST_BYTES:
            raise ValueError("run_manifest_too_large")
        after = os.fstat(descriptor)
        named = path.lstat()
        if (
                not stat.S_ISREG(named.st_mode) or
                not _same_file(before, opened, after, named) or
                after.st_size != len(payload)):
            raise ValueError("run_manifest_path_changed")
        return payload
    except ValueError:
        raise
    except OSError as error:
        raise ValueError("run_manifest_path_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("run_manifest_duplicate_key")
        result[key] = value
    return result


def _receipt_for(layout: RunLayout,
                 value: RunManifest) -> RunManifestReceipt:
    encoded = _manifest_json(value)
    return RunManifestReceipt(
        manifest_path=str(layout.manifest_path),
        canonical_sha256=_canonical_json_sha256(encoded),
        source_content_sha256=file_set_receipt(
            value.source).content_sha256,
    )


def publish_run_manifest(layout: RunLayout,
                         value: RunManifest) -> RunManifestReceipt:
    encoded = _manifest_json(value)
    atomic_write_json(layout.manifest_path, encoded)
    reread, receipt = read_run_manifest(
        layout, expected_run_id=value.run_id,
        expected_source_account_name=value.source_account_name)
    if reread != value:
        raise ValueError("run_manifest_reread_mismatch")
    return receipt


def read_run_manifest(
        layout: RunLayout, *, expected_run_id: str,
        expected_source_account_name: str,
        ) -> tuple[RunManifest, RunManifestReceipt]:
    try:
        if (type(expected_run_id) is not str or
                str(uuid.UUID(expected_run_id)) != expected_run_id.lower()):
            raise ValueError
        layout.role_db_storage(CopyRole.SOURCE, expected_source_account_name)
        payload = _read_bounded_ordinary_file(layout.manifest_path)
        raw = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("run_manifest_nonfinite_number")
            ),
        )
        if (not isinstance(raw, dict) or set(raw) != _RUN_KEYS or
                type(raw["schemaVersion"]) is not int or
                raw["schemaVersion"] != 1 or
                raw["runId"] != expected_run_id or
                raw["sourceAccountName"] != expected_source_account_name or
                not isinstance(raw["toolVersion"], str) or
                _TOOL_VERSION_RE.fullmatch(raw["toolVersion"]) is None or
                not isinstance(raw["capturedAtUtc"], str) or
                not isinstance(raw["sourceVolume"], str) or
                _WINDOWS_VOLUME_RE.fullmatch(raw["sourceVolume"]) is None or
                not isinstance(raw["shadowId"], str) or
                not isinstance(raw["stagingManifestSha256"], str) or
                _SHA256_RE.fullmatch(raw["stagingManifestSha256"]) is None or
                raw["snapshotMethod"] != SnapshotMethod.VSS_CRASH_CONSISTENT.value or
                raw["residualRisk"] !=
                ResidualRisk.NO_CROSS_DATABASE_ATOMICITY_PROOF.value):
            raise ValueError
        captured_at = datetime.fromisoformat(raw["capturedAtUtc"])
        if (captured_at.tzinfo is None or
                captured_at.utcoffset() != timedelta(0)):
            raise ValueError
        shadow_id = raw["shadowId"].strip("{}")
        if str(uuid.UUID(shadow_id)) != shadow_id.lower():
            raise ValueError
        source = raw["source"]
        if (not isinstance(source, dict) or set(source) != _SOURCE_KEYS or
                source["role"] != CopyRole.SOURCE.value or
                not isinstance(source["root"], str) or
                canonical_existing(Path(source["root"])) != layout.source or
                not isinstance(source["files"], list) or
                type(source["totalFiles"]) is not int or
                source["totalFiles"] < 0 or
                type(source["totalBytes"]) is not int or
                source["totalBytes"] < 0):
            raise ValueError
        expected_prefix = f"{expected_source_account_name}/db_storage/"
        entries = []
        for item in source["files"]:
            relative_path = item.get("relativePath") if isinstance(item, dict) else None
            valid_relative_path = (
                isinstance(relative_path, str) and
                relative_path.startswith(expected_prefix) and
                "\\" not in relative_path and ":" not in relative_path and
                all(component not in ("", ".", "..")
                    for component in relative_path.split("/")))
            if (not isinstance(item, dict) or set(item) != _FILE_KEYS or
                    not valid_relative_path or
                    not isinstance(item["category"], str) or
                    item["category"] not in {
                        category.value for category in FileCategory} or
                    type(item["size"]) is not int or item["size"] < 0 or
                    type(item["mtimeNs"]) is not int or item["mtimeNs"] < 0 or
                    not isinstance(item["sha256"], str) or
                    _SHA256_RE.fullmatch(item["sha256"]) is None):
                raise ValueError
            entries.append(FileEntry(
                relative_path=relative_path, category=item["category"],
                size=item["size"], mtime_ns=item["mtimeNs"],
                sha256=item["sha256"]))
        if (entries != sorted(entries, key=lambda item: item.relative_path) or
                len({item.relative_path for item in entries}) != len(entries)):
            raise ValueError
        computed_counts = {category.value: 0 for category in FileCategory}
        for entry in entries:
            computed_counts[entry.category] += 1
        if (not isinstance(raw["categoryCounts"], dict) or
                set(raw["categoryCounts"]) != set(computed_counts) or
                any(type(value) is not int or value < 0
                    for value in raw["categoryCounts"].values()) or
                raw["categoryCounts"] != computed_counts):
            raise ValueError
        manifest = RunManifest(
            schema_version=1,
            tool_version=raw["toolVersion"], run_id=raw["runId"],
            source_account_name=raw["sourceAccountName"],
            captured_at_utc=raw["capturedAtUtc"],
            source_volume=raw["sourceVolume"], shadow_id=raw["shadowId"],
            staging_manifest_sha256=raw["stagingManifestSha256"],
            snapshot_method=SnapshotMethod(raw["snapshotMethod"]),
            residual_risk=ResidualRisk(raw["residualRisk"]),
            source=FileSetManifest(
                role=CopyRole.SOURCE, root=source["root"],
                files=tuple(entries), total_files=source["totalFiles"],
                total_bytes=source["totalBytes"],
                category_counts=raw["categoryCounts"]),
        )
        if (manifest.source.total_files != len(entries) or
                manifest.source.total_bytes !=
                sum(item.size for item in entries)):
            raise ValueError
        validate_account_role_manifest(
            manifest.source,
            source_account_name=expected_source_account_name)
        validate_account_role_tree(
            layout.source, source_account_name=expected_source_account_name)
        return manifest, _receipt_for(layout, manifest)
    except (CopyVerificationError, OSError, TypeError, ValueError,
            UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("run_manifest_schema_mismatch") from error


def staging_receipt_sha256(manifest: FileSetManifest) -> str:
    value = tuple((item.relative_path, item.size, item.sha256)
                  for item in manifest.files)
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest().upper()


def import_vss_staging(*args, **kwargs):
    from weflow_chat.copies import import_vss_staging as implementation
    return implementation(*args, **kwargs)


def materialize_role_copy(*args, **kwargs):
    from weflow_chat.copies import materialize_role_copy as implementation
    return implementation(*args, **kwargs)
