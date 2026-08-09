from dataclasses import dataclass
from enum import StrEnum


class TxState(StrEnum):
    DISCOVERED = "discovered"
    SNAPSHOT_READY = "snapshot_ready"
    VALIDATED = "validated"
    PREPARED = "prepared"
    REPLACING = "replacing"
    CONFIG_REPLACED = "config_replaced"
    ACCEPTED = "accepted"
    COMMITTED = "committed"
    RECOVERY_PENDING = "recovery_pending"
    ROLLED_BACK = "rolled_back"


class CopyRole(StrEnum):
    VSS_STAGING = "vss-staging"
    SOURCE = "source"
    VALIDATION = "validation"
    ACTIVE = "active"


@dataclass(frozen=True, slots=True)
class FileEntry:
    relative_path: str
    category: str
    size: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True, slots=True)
class PlannedFile:
    live_path: str
    action: str
    existed_before: bool
    expected_old_sha256: str | None
    expected_new_sha256: str | None
