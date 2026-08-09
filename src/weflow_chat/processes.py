from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Callable

from weflow_chat.paths import canonical_existing


_UTC_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|\+00:00)"
)
@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    executable: Path
    parent_pid: int
    command_line: str
    architecture: str
    authenticode_status: str
    signer_subject: str
    dll_authenticode_status: str
    dll_signer_subject: str
    dll_version: str
    dll_sha256: str
    dll_path: Path
    dll_size: int
    dll_signer_certificate_sha256: str
    isolated_user_data: Path | None
    creation_time_utc: str

    @property
    def dllVersion(self) -> str:
        return self.dll_version


def relevant_formal_weflow_processes(
    source,
    *,
    expected: Path,
    canonicalize: Callable[[Path], Path] = canonical_existing,
) -> tuple[ProcessIdentity, ...]:
    try:
        canonical_expected = canonicalize(expected)
    except (OSError, ValueError) as error:
        raise RuntimeError(
            "formal_weflow_identity_unreadable"
        ) from error
    matched = []
    for item in source.list_processes():
        if not isinstance(item, ProcessIdentity):
            raise RuntimeError("process_identity_schema_invalid")
        if item.executable.name.casefold() != "weflow.exe":
            continue
        try:
            executable = canonicalize(item.executable)
        except (OSError, ValueError) as error:
            raise RuntimeError(
                "formal_weflow_identity_unreadable"
            ) from error
        if executable == canonical_expected:
            if item.isolated_user_data is not None:
                raise RuntimeError(
                    "formal_weflow_identity_invalid"
                )
            process_identity_token(item)
            matched.append(item)
    tokens = {}
    for item in matched:
        token = process_identity_token(item)
        if item.pid in tokens:
            raise RuntimeError("formal_weflow_pid_duplicate")
        tokens[item.pid] = token
    return tuple(matched)


def process_identity_token(
    identity: ProcessIdentity,
) -> tuple[int, Path, datetime]:
    try:
        if _UTC_TIMESTAMP_RE.fullmatch(
            identity.creation_time_utc
        ) is None:
            raise ValueError
        created = datetime.fromisoformat(
            identity.creation_time_utc.replace("Z", "+00:00")
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise RuntimeError("process_identity_token_invalid") from error
    if (
        type(identity.pid) is not int
        or identity.pid <= 0
        or type(identity.parent_pid) is not int
        or identity.parent_pid < 0
        or not isinstance(identity.executable, Path)
        or not isinstance(identity.command_line, str)
        or created.tzinfo is None
        or created.utcoffset() != timezone.utc.utcoffset(created)
    ):
        raise RuntimeError("process_identity_token_invalid")
    try:
        executable = canonical_existing(identity.executable)
    except (OSError, ValueError) as error:
        raise RuntimeError("process_identity_token_invalid") from error
    return identity.pid, executable, created
