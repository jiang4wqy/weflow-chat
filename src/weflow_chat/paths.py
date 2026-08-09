from dataclasses import dataclass
import os
import re
import stat
from pathlib import Path

from weflow_chat.models import CopyRole


class PathBoundaryError(ValueError):
    pass


def _reject_text(path: Path) -> None:
    raw = str(path)
    if (raw.startswith(("\\\\", "\\\\?\\", "\\\\.\\")) or
            raw.casefold().startswith("\\device\\")):
        raise PathBoundaryError("special_path_rejected")
    if any(part == ".." for part in path.parts):
        raise PathBoundaryError("parent_escape_rejected")
    drive, tail = os.path.splitdrive(raw)
    if ":" in tail or (not drive and ":" in raw):
        raise PathBoundaryError("alternate_stream_rejected")


def _is_reparse(path: Path) -> bool:
    info = path.stat(follow_symlinks=False)
    flags = getattr(info, "st_file_attributes", 0)
    return path.is_symlink() or bool(
        flags & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _reject_reparse_chain(path: Path) -> None:
    current = path
    while True:
        if os.path.lexists(current):
            if _is_reparse(current):
                raise PathBoundaryError("reparse_component_rejected")
        if current.parent == current:
            return
        current = current.parent


def canonical_existing(path: Path) -> Path:
    _reject_text(path)
    absolute = path.absolute()
    _reject_reparse_chain(absolute)
    return absolute.resolve(strict=True)


def canonical_future(path: Path) -> Path:
    _reject_text(path)
    absolute = path.absolute()
    suffix = []
    cursor = absolute
    while not os.path.lexists(cursor):
        if cursor.parent == cursor:
            raise PathBoundaryError("no_existing_ancestor")
        suffix.append(cursor.name)
        cursor = cursor.parent
    base = canonical_existing(cursor)
    return base.joinpath(*reversed(suffix))


def assert_descendant(child: Path, root: Path,
                      *, allow_equal: bool = False) -> None:
    child_value = os.path.normcase(str(canonical_future(child)))
    root_value = os.path.normcase(str(canonical_existing(root)))
    common = os.path.commonpath((child_value, root_value))
    if common != root_value or (not allow_equal and child_value == root_value):
        raise PathBoundaryError("outside_allowed_root")


@dataclass(frozen=True, slots=True)
class RunLayout:
    root: Path
    vss_staging: Path
    source: Path
    validation: Path
    active: Path
    manifest_path: Path
    compatibility_path: Path
    transaction_path: Path
    audit_path: Path
    config_backup: Path

    @classmethod
    def from_existing_root(cls, root: Path) -> "RunLayout":
        canonical_root = canonical_existing(root)
        return cls(
            root=canonical_root,
            vss_staging=canonical_root / "vss-staging",
            source=canonical_root / "source",
            validation=canonical_root / "validation",
            active=canonical_root / "active",
            manifest_path=canonical_root / "manifest.json",
            compatibility_path=canonical_root / "compatibility.json",
            transaction_path=canonical_root / "transaction.json",
            audit_path=canonical_root / "audit.jsonl",
            config_backup=canonical_root / "config-backup",
        )

    def require_exact_staging(self, supplied: Path) -> Path:
        expected = canonical_future(self.vss_staging)
        actual = canonical_existing(supplied)
        if actual != expected:
            raise PathBoundaryError("not_exact_run_vss_staging")
        return actual

    def role_root(self, role: CopyRole) -> Path:
        try:
            return {
                CopyRole.VSS_STAGING: self.vss_staging,
                CopyRole.SOURCE: self.source,
                CopyRole.VALIDATION: self.validation,
                CopyRole.ACTIVE: self.active,
            }[role]
        except KeyError as error:
            raise PathBoundaryError("account_role_rejected") from error

    def role_account_root(self, role: CopyRole,
                          source_account_name: str) -> Path:
        if (not isinstance(source_account_name, str) or
                re.fullmatch(
                    r"wxid_[A-Za-z0-9_]{1,128}",
                    source_account_name) is None):
            raise PathBoundaryError("source_account_name_rejected")
        return self.role_root(role) / source_account_name

    def role_db_storage(self, role: CopyRole,
                        source_account_name: str) -> Path:
        return self.role_account_root(
            role, source_account_name) / "db_storage"
