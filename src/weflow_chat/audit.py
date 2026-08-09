from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import json
import re

from weflow_chat.models import CopyRole


class AuditStage(StrEnum):
    PREFLIGHT = "preflight"
    COPY = "copy"
    BACKUP = "backup"
    CUTOVER = "cutover"
    RECOVERY = "recovery"


class AuditStatus(StrEnum):
    STARTED = "started"
    OK = "ok"
    BLOCKED = "blocked"
    FAILED = "failed"


class AuditErrorCode(StrEnum):
    PATH_REJECTED = "path_rejected"
    HASH_MISMATCH = "hash_mismatch"
    PROCESS_RUNNING = "process_running"
    COMPATIBILITY_BLOCKED = "compatibility_blocked"
    IO_FAILURE = "io_failure"


class SensitiveAuditValueError(ValueError):
    pass


class InvalidAuditEventError(TypeError):
    pass


_SENSITIVE = (
    re.compile(r"(?:safe|lock):", re.I),
    re.compile(r"\b(?:decryptKey|imageAesKey|imageXorKey)\b", re.I),
    re.compile(r"\bwxid_[A-Za-z0-9_]+\b", re.I),
    re.compile(r"\b[0-9a-fA-F]{32,64}\b"),
    re.compile(r"\b[A-Za-z0-9+/]{48,}={0,2}\b"),
)
_ROLE_ALIASES = frozenset(role.value for role in CopyRole)
_SAFE_PATH_LEAF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")


def _validate_normalized_path(value: str) -> None:
    if not isinstance(value, str):
        raise InvalidAuditEventError("invalid_audit_path")
    components = value.split("/")
    if (components[0] not in _ROLE_ALIASES or
            (len(components) == 2 and
             _SAFE_PATH_LEAF.fullmatch(components[1]) is None) or
            len(components) not in (1, 2)):
        raise SensitiveAuditValueError("audit_path_rejected")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    stage: AuditStage
    status: AuditStatus
    error_code: AuditErrorCode | None = None
    normalized_paths: tuple[str, ...] = field(default_factory=tuple)
    file_count: int | None = None
    byte_count: int | None = None
    sha256_values: tuple[str, ...] = field(default_factory=tuple)
    pid: int | None = None
    candidate_count: int | None = None
    at_utc: str = field(default_factory=lambda:
        datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if not isinstance(self.stage, AuditStage):
            raise InvalidAuditEventError("invalid_audit_stage")
        if not isinstance(self.status, AuditStatus):
            raise InvalidAuditEventError("invalid_audit_status")
        if (self.error_code is not None and
                not isinstance(self.error_code, AuditErrorCode)):
            raise InvalidAuditEventError("invalid_audit_error_code")
        if (self.status in (AuditStatus.BLOCKED, AuditStatus.FAILED) and
                self.error_code is None):
            raise InvalidAuditEventError("missing_audit_error_code")
        if not isinstance(self.normalized_paths, tuple):
            raise InvalidAuditEventError("invalid_audit_paths")
        if not isinstance(self.sha256_values, tuple):
            raise InvalidAuditEventError("invalid_audit_hashes")
        for value in (self.file_count, self.byte_count, self.pid,
                      self.candidate_count):
            if value is not None and (type(value) is not int or value < 0):
                raise InvalidAuditEventError("invalid_audit_quantity")
        if any(not isinstance(value, str) or _SHA256.fullmatch(value) is None
               for value in self.sha256_values):
            raise InvalidAuditEventError("invalid_audit_sha256")
        object.__setattr__(self, "sha256_values", tuple(
            value.lower() for value in self.sha256_values))
        if not isinstance(self.at_utc, str):
            raise InvalidAuditEventError("invalid_audit_at_utc")
        try:
            parsed_at_utc = datetime.fromisoformat(self.at_utc)
        except ValueError as error:
            raise InvalidAuditEventError("invalid_audit_at_utc") from error
        if (parsed_at_utc.tzinfo is None or
                parsed_at_utc.utcoffset() != timedelta(0)):
            raise InvalidAuditEventError("invalid_audit_at_utc")


def _record(event: AuditEvent) -> dict[str, object]:
    values = [event.stage.value, event.status.value]
    for path in event.normalized_paths:
        _validate_normalized_path(path)
        values.append(path)
    if event.error_code is not None:
        values.append(event.error_code.value)
    for value in values:
        if any(pattern.search(value) for pattern in _SENSITIVE):
            raise SensitiveAuditValueError("audit_value_rejected")
    return {
        "atUtc": event.at_utc, "stage": event.stage.value,
        "status": event.status.value,
        "errorCode": (event.error_code.value
                      if event.error_code is not None else None),
        "normalizedPaths": list(event.normalized_paths),
        "fileCount": event.file_count, "byteCount": event.byte_count,
        "sha256Values": list(event.sha256_values),
        "pid": event.pid, "candidateCount": event.candidate_count,
    }


class AuditWriter:
    def __init__(self, path):
        self.path = path

    def append(self, event: AuditEvent) -> None:
        payload = json.dumps(_record(event), ensure_ascii=False,
                             separators=(",", ":")) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            import os
            os.fsync(stream.fileno())
