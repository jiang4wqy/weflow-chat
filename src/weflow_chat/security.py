from dataclasses import dataclass
import os
from pathlib import Path
from typing import Protocol

from weflow_chat.manifest import sha256_file
from weflow_chat.paths import canonical_existing


@dataclass(frozen=True, slots=True)
class SecurityMetadata:
    file_attributes: int
    owner_sid: str
    group_sid: str
    dacl_sddl: str


class SecurityAdapter(Protocol):
    def capture(self, path: Path) -> SecurityMetadata:
        raise NotImplementedError

    def restrict_backup_tree(self, path: Path) -> None:
        raise NotImplementedError

    def verify_restricted_backup_tree(self, path: Path) -> None:
        raise NotImplementedError

    def restore(self, path: Path, value: SecurityMetadata) -> None:
        raise NotImplementedError

    def verify(self, path: Path, value: SecurityMetadata) -> None:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class BackupItem:
    live_path: str
    existed_before: bool
    primary_backup_path: str | None
    recovery_backup_path: str | None
    expected_old_sha256: str | None
    security: SecurityMetadata | None

    def resolve_verified_restore_copy(self) -> Path:
        if not self.existed_before:
            raise ValueError("backup_item_was_absent")
        for stored in (self.recovery_backup_path, self.primary_backup_path):
            if stored is None:
                continue
            candidate = Path(stored)
            try:
                canonical = canonical_existing(candidate)
                if str(canonical) != stored:
                    raise ValueError("backup_copy_identity_changed")
                if sha256_file(canonical) == self.expected_old_sha256:
                    return canonical
            except OSError:
                continue
        raise ValueError("no_verified_backup_copy_available")


@dataclass(frozen=True, slots=True)
class BackupReceipt:
    run_id: str
    primary_manifest_path: str
    recovery_manifest_path: str
    canonical_sha256: str
    item_count: int


@dataclass(frozen=True, slots=True)
class BackupBundle:
    run_id: str
    items: tuple[BackupItem, ...]
    primary_root: str
    recovery_root: str
    receipt: BackupReceipt

    def verify_recovery_copy(self) -> None:
        for item in self.items:
            if item.existed_before:
                candidate = canonical_existing(Path(item.recovery_backup_path))
                if (str(candidate) != item.recovery_backup_path or
                        sha256_file(candidate) != item.expected_old_sha256):
                    raise ValueError("recovery_backup_hash_mismatch")

    def verify_at_least_one_backup_copy(self) -> None:
        for item in self.items:
            if item.existed_before:
                item.resolve_verified_restore_copy()

    def verify_backup_copies(self) -> None:
        self.verify_recovery_copy()
        for item in self.items:
            if item.existed_before:
                candidate = canonical_existing(Path(item.primary_backup_path))
                if (str(candidate) != item.primary_backup_path or
                        sha256_file(candidate) != item.expected_old_sha256):
                    raise ValueError("primary_backup_hash_mismatch")

    def verify_both_copies_and_old_hashes(
            self, security_adapter: SecurityAdapter) -> None:
        self.verify_backup_copies()
        for item in self.items:
            if item.existed_before:
                if sha256_file(Path(item.live_path)) != item.expected_old_sha256:
                    raise ValueError("live_old_hash_mismatch")
            elif os.path.lexists(item.live_path):
                raise ValueError("live_absence_changed_before_cutover")
        security_adapter.verify_restricted_backup_tree(Path(self.primary_root))
        security_adapter.verify_restricted_backup_tree(Path(self.recovery_root))

    def verify_restored_old_set(self, security_adapter: SecurityAdapter) -> None:
        for item in self.items:
            path = Path(item.live_path)
            if item.existed_before:
                if sha256_file(path) != item.expected_old_sha256:
                    raise ValueError("restored_hash_mismatch")
                security_adapter.verify(path, item.security)
            elif os.path.lexists(path):
                raise ValueError("restored_absence_mismatch")
