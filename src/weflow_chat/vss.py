from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib
import json
import locale
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import stat
import subprocess
from types import MappingProxyType
from typing import Callable, Mapping, Protocol
from uuid import UUID

from ._vss_helper_trust import ALLOWED_HELPER_ROOT, HELPER_SHA256
from .atomic_io import replace_write_through
from .copies import (
    flush_file_durable,
    verify_published_directory_durable,
)
from .manifest import CopyVerificationError, staging_receipt_sha256
from .models import CopyRole


class VssError(RuntimeError):
    pass


class VssJournalError(VssError):
    pass


class VssPathError(VssError):
    pass


class VssCleanupError(VssError):
    pass


class VssTrustError(VssError):
    pass


class ShadowState(StrEnum):
    CREATING = "creating"
    CREATED = "created"
    ADOPTED = "adopted"
    DELETED = "deleted"


_JOURNAL_KEYS = {
    "version", "runId", "sourceVolume", "volumeDeviceId", "state",
    "shadowId", "deviceObject", "createdAtUtc", "updatedAtUtc",
}
_DEVICE_RE = re.compile(
    r"^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[1-9][0-9]*$")
_VOLUME_DEVICE_RE = re.compile(
    r"^\\\\\?\\Volume\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\\$")
_SHADOW_RE = re.compile(
    r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")
_ACCOUNT_RE = re.compile(r"^wxid_[A-Za-z0-9_]{1,128}$")
_HASH_RE = re.compile(r"^[0-9A-F]{64}$")
_UTC_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$")
_JOURNAL_PROPERTY_RE = re.compile(
    r'(?<!\\)"(?P<key>(?:\\.|[^"\\])*)"\s*:')
_FULL_CONTROL = 0x1F01FF
_CONTAINER_AND_OBJECT_INHERIT = 0x3
_ACL_PROBE_TIMEOUT_SECONDS = 15
_RUNAS_TIMEOUT_MILLISECONDS = 120_000
_RUNAS_TIMEOUT_EXIT_CODE = 124
_HELPER_OUTER_TIMEOUT_SECONDS = 180
_EXPECTED_HELPER_FILES = frozenset({
    "Invoke-WeFlowVssHelper.ps1", "WeFlowVssHelper.psm1",
})
SYSTEM_POWERSHELL = Path(
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
JOURNAL_ROOT = Path(r"C:\ProgramData\WeFlowRecovery\shadows")
_REPOSITORY_ROOT = Path(os.path.abspath(__file__)).parents[2]


@dataclass(frozen=True, slots=True)
class _FixedTrust:
    powershell: Path
    repository_root: Path
    allowed_helper_root: str
    helper_root: Path
    script: Path
    module: Path
    journal_root: Path
    helper_sha256: Mapping[str, str]


_HELPER_ROOT = _REPOSITORY_ROOT / ALLOWED_HELPER_ROOT
_FIXED_TRUST = _FixedTrust(
    powershell=SYSTEM_POWERSHELL,
    repository_root=_REPOSITORY_ROOT,
    allowed_helper_root=ALLOWED_HELPER_ROOT,
    helper_root=_HELPER_ROOT,
    script=_HELPER_ROOT / "Invoke-WeFlowVssHelper.ps1",
    module=_HELPER_ROOT / "WeFlowVssHelper.psm1",
    journal_root=JOURNAL_ROOT,
    helper_sha256=MappingProxyType(dict(HELPER_SHA256)),
)


@dataclass(frozen=True, slots=True)
class _AclAce:
    sid: str
    access_type: str
    rights: int
    inheritance_flags: int
    propagation_flags: int
    inherited: bool


@dataclass(frozen=True, slots=True)
class _AclSnapshot:
    protected: bool
    aces: tuple[_AclAce, ...]


@dataclass(frozen=True, slots=True)
class _TrustedRuntime:
    powershell: Path
    script: Path
    journal_root: Path


class _TrustProbe(Protocol):
    def canonical(self, path: Path) -> Path:
        raise NotImplementedError

    def has_reparse_in_chain(self, path: Path) -> bool:
        raise NotImplementedError

    def sha256(self, path: Path) -> str:
        raise NotImplementedError

    def current_user_sid(self) -> str:
        raise NotImplementedError

    def journal_acl(self, path: Path) -> _AclSnapshot:
        raise NotImplementedError


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.normpath(left)) == os.path.normcase(
        os.path.normpath(right))


def _validate_trust(fixed: _FixedTrust,
                    probe: _TrustProbe) -> _TrustedRuntime:
    if fixed.allowed_helper_root != "vss-helper":
        raise VssTrustError("trusted_helper_root_mismatch")
    if set(fixed.helper_sha256) != _EXPECTED_HELPER_FILES or any(
            not _HASH_RE.fullmatch(value)
            for value in fixed.helper_sha256.values()):
        raise VssTrustError("trusted_helper_allowlist_invalid")

    paths = (
        fixed.powershell, fixed.repository_root, fixed.helper_root,
        fixed.script, fixed.module, fixed.journal_root,
    )
    if any(probe.has_reparse_in_chain(path) for path in paths):
        raise VssTrustError("trusted_path_reparse")
    try:
        canonical = {path: probe.canonical(path) for path in paths}
        expected_root = probe.canonical(
            fixed.repository_root / fixed.allowed_helper_root)
    except OSError as error:
        raise VssTrustError("trusted_path_missing") from error

    if not _same_path(canonical[fixed.helper_root], expected_root):
        raise VssTrustError("trusted_helper_root_mismatch")
    if (
        not _same_path(canonical[fixed.script].parent, expected_root)
        or not _same_path(canonical[fixed.module].parent, expected_root)
        or canonical[fixed.script].name != "Invoke-WeFlowVssHelper.ps1"
        or canonical[fixed.module].name != "WeFlowVssHelper.psm1"
    ):
        raise VssTrustError("trusted_helper_path_mismatch")
    for path in (fixed.script, fixed.module):
        if probe.sha256(canonical[path]) != fixed.helper_sha256[path.name]:
            raise VssTrustError("trusted_helper_hash_mismatch")

    acl = probe.journal_acl(canonical[fixed.journal_root])
    expected_aces = tuple(sorted((
        _AclAce(probe.current_user_sid(), "Allow", _FULL_CONTROL,
                _CONTAINER_AND_OBJECT_INHERIT, 0, False),
        _AclAce("S-1-5-18", "Allow", _FULL_CONTROL,
                _CONTAINER_AND_OBJECT_INHERIT, 0, False),
    ), key=lambda ace: ace.sid))
    actual_aces = tuple(sorted(acl.aces, key=lambda ace: (
        ace.sid, ace.access_type, ace.rights, ace.inheritance_flags,
        ace.propagation_flags, ace.inherited)))
    if not acl.protected or actual_aces != expected_aces:
        raise VssTrustError("journal_acl_invalid")
    return _TrustedRuntime(
        canonical[fixed.powershell], canonical[fixed.script],
        canonical[fixed.journal_root])


@dataclass(frozen=True, slots=True)
class _AclEvidence:
    current_user_sid: str
    acl: _AclSnapshot


def _read_fixed_acl_evidence() -> _AclEvidence:
    # This is a fixed, non-elevated query executed only after SYSTEM_POWERSHELL
    # itself has passed canonical and reparse validation.
    query = (
        "$i=[Security.Principal.WindowsIdentity]::GetCurrent();"
        f"$a=Get-Acl -LiteralPath {_ps_literal(str(JOURNAL_ROOT))};"
        "$r=@($a.GetAccessRules($true,$true,"
        "[Security.Principal.SecurityIdentifier])|%{"
        "[pscustomobject]@{sid=$_.IdentityReference.Value;"
        "type=$_.AccessControlType.ToString();inherited=$_.IsInherited;"
        "rights=[int64]$_.FileSystemRights;"
        "inheritanceFlags=[int]$_.InheritanceFlags;"
        "propagationFlags=[int]$_.PropagationFlags}});"
        "[pscustomobject]@{currentUserSid=$i.User.Value;"
        "protected=$a.AreAccessRulesProtected;rules=$r}|"
        "ConvertTo-Json -Compress -Depth 4")
    command = [str(SYSTEM_POWERSHELL), "-NoProfile", "-NonInteractive",
               "-Command", query]
    try:
        result = subprocess.run(
            command, check=False, text=True, capture_output=True,
            encoding=locale.getencoding(), errors="replace",
            timeout=_ACL_PROBE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise VssTrustError("journal_acl_probe_timeout") from error
    if result.returncode != 0:
        raise VssTrustError("journal_acl_unreadable")
    try:
        value = json.loads(result.stdout)
        if set(value) != {"currentUserSid", "protected", "rules"}:
            raise ValueError
        if (not isinstance(value["currentUserSid"], str) or
                not isinstance(value["protected"], bool)):
            raise ValueError
        rules = value["rules"]
        if not isinstance(rules, list) or any(
                set(rule) != {
                    "sid", "type", "rights", "inheritanceFlags",
                    "propagationFlags", "inherited",
                }
                for rule in rules):
            raise ValueError
        if any(
                not isinstance(rule["sid"], str)
                or rule["type"] not in {"Allow", "Deny"}
                or type(rule["rights"]) is not int
                or type(rule["inheritanceFlags"]) is not int
                or type(rule["propagationFlags"]) is not int
                or not isinstance(rule["inherited"], bool)
                for rule in rules):
            raise ValueError
        return _AclEvidence(
            current_user_sid=value["currentUserSid"],
            acl=_AclSnapshot(
                protected=value["protected"],
                aces=tuple(_AclAce(
                    sid=rule["sid"], access_type=rule["type"],
                    rights=rule["rights"],
                    inheritance_flags=rule["inheritanceFlags"],
                    propagation_flags=rule["propagationFlags"],
                    inherited=rule["inherited"],
                ) for rule in rules),
            ),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise VssTrustError("journal_acl_schema_invalid") from error


class _WindowsTrustProbe:
    """Production-only filesystem and Win32 ACL evidence collector."""

    def __init__(self) -> None:
        self._acl_evidence: _AclEvidence | None = None

    def _fixed_acl_evidence(self) -> _AclEvidence:
        if self._acl_evidence is None:
            self._acl_evidence = _read_fixed_acl_evidence()
        return self._acl_evidence

    def canonical(self, path: Path) -> Path:
        return path.resolve(strict=True)

    def has_reparse_in_chain(self, path: Path) -> bool:
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current /= part
            try:
                if _is_reparse_point(current):
                    return True
            except OSError:
                return True
        return False

    def sha256(self, path: Path) -> str:
        return _sha256_file(path)

    def current_user_sid(self) -> str:
        return self._fixed_acl_evidence().current_user_sid

    def journal_acl(self, path: Path) -> _AclSnapshot:
        evidence = self._fixed_acl_evidence()
        if not _same_path(path, JOURNAL_ROOT):
            raise VssTrustError("journal_root_mismatch")
        return evidence.acl


def _validate_production_trust() -> _TrustedRuntime:
    return _validate_trust(_FIXED_TRUST, _WindowsTrustProbe())


@dataclass(frozen=True, slots=True)
class VssJournal:
    version: int
    run_id: str
    source_volume: str
    volume_device_id: str | None
    state: ShadowState
    shadow_id: str | None
    device_object: str | None
    created_at_utc: str
    updated_at_utc: str


@dataclass(frozen=True, slots=True)
class StagingReceipt:
    staging_path: Path
    source_account_name: str
    account_db_relative_path: PureWindowsPath
    file_count: int
    byte_count: int
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class MediaStagingFile:
    relative_path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class MediaStagingReceipt:
    staging_path: Path
    source_account_name: str
    files: tuple[MediaStagingFile, ...]
    file_count: int
    byte_count: int
    manifest_sha256: str


def _guid(value: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise VssJournalError("invalid_run_id") from error
    canonical = str(parsed)
    if value != canonical:
        raise VssJournalError("invalid_run_id")
    return canonical


def assert_device_object(value: str) -> str:
    if not isinstance(value, str) or not _DEVICE_RE.fullmatch(value):
        raise VssPathError("invalid_device_object")
    return value


def account_db_relative_path(source_account_name: str) -> PureWindowsPath:
    if (not isinstance(source_account_name, str)
            or not _ACCOUNT_RE.fullmatch(source_account_name)):
        raise VssPathError("source_account_name_invalid")
    return PureWindowsPath(source_account_name, "db_storage")


def _shadow_id(value: str) -> str:
    if not isinstance(value, str) or not _SHADOW_RE.fullmatch(value):
        raise VssJournalError("invalid_shadow_id")
    return "{" + str(UUID(value.strip("{}"))).upper() + "}"


def _utc_timestamp(value: object) -> str:
    if not isinstance(value, str) or not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise VssJournalError("journal_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise VssJournalError("journal_timestamp_invalid") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise VssJournalError("journal_timestamp_invalid")
    return value


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise VssJournalError("journal_duplicate_key")
        value[key] = item
    return value


def _relative_volume_path(value: str | PureWindowsPath) -> PureWindowsPath:
    path = PureWindowsPath(value)
    if path.is_absolute() or path.drive or path.root or not path.parts:
        raise VssPathError("shadow_relative_path_required")
    if any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        raise VssPathError("shadow_relative_path_rejected")
    return path


def map_shadow_path(device_object: str,
                    volume_relative_path: str | PureWindowsPath) -> Path:
    device = assert_device_object(device_object)
    relative = _relative_volume_path(volume_relative_path)
    return Path(device + "\\" + str(relative))


def map_volume_path(device_object: str, *, source_volume: str,
                    live_path: str | PureWindowsPath) -> Path:
    if not re.fullmatch(r"[A-Za-z]:\\", source_volume):
        raise VssPathError("invalid_source_volume")
    live = PureWindowsPath(live_path)
    if not live.is_absolute() or live.drive.casefold() != source_volume[:2].casefold():
        raise VssPathError("live_path_outside_source_volume")
    relative = PureWindowsPath(*live.parts[1:])
    return map_shadow_path(device_object, relative)


def read_vss_journal(path: Path, *, expected_run_id: str) -> VssJournal:
    expected = _guid(expected_run_id)
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(
            raw,
            object_pairs_hook=_strict_json_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VssJournalError("journal_unreadable") from error
    if not isinstance(value, dict) or set(value) != _JOURNAL_KEYS:
        raise VssJournalError("journal_schema_invalid")
    raw_keys = [match.group("key")
                for match in _JOURNAL_PROPERTY_RE.finditer(raw)]
    if len(raw_keys) != len(_JOURNAL_KEYS) or set(raw_keys) != _JOURNAL_KEYS:
        raise VssJournalError("journal_json_keys_invalid")
    if (type(value["version"]) is not int or value["version"] != 1 or
            not isinstance(value["runId"], str) or
            value["runId"] != expected):
        raise VssJournalError("journal_identity_invalid")
    try:
        state = ShadowState(value["state"])
    except (TypeError, ValueError) as error:
        raise VssJournalError("journal_state_invalid") from error
    if (not isinstance(value["sourceVolume"], str) or
            not re.fullmatch(r"[A-Za-z]:\\", value["sourceVolume"])):
        raise VssJournalError("journal_source_volume_invalid")
    if state is ShadowState.CREATING:
        if any(value[name] is not None for name in
               ("volumeDeviceId", "shadowId", "deviceObject")):
            raise VssJournalError("creating_journal_has_identity")
    else:
        normalized_shadow_id = _shadow_id(value["shadowId"])
        try:
            assert_device_object(value["deviceObject"])
        except VssPathError as error:
            raise VssJournalError("journal_device_object_invalid") from error
        if (not isinstance(value["volumeDeviceId"], str) or
                not _VOLUME_DEVICE_RE.fullmatch(value["volumeDeviceId"])):
            raise VssJournalError("invalid_volume_device_id")
    created_at_utc = _utc_timestamp(value["createdAtUtc"])
    updated_at_utc = _utc_timestamp(value["updatedAtUtc"])
    if updated_at_utc < created_at_utc:
        raise VssJournalError("journal_timestamp_order_invalid")
    return VssJournal(
        version=1, run_id=expected, source_volume=value["sourceVolume"],
        volume_device_id=value["volumeDeviceId"], state=state,
        shadow_id=(None if state is ShadowState.CREATING
                   else normalized_shadow_id),
        device_object=value["deviceObject"],
        created_at_utc=created_at_utc,
        updated_at_utc=updated_at_utc,
    )


def _ps_literal(value: str) -> str:
    if "\x00" in value or "\r" in value or "\n" in value:
        raise VssError("powershell_argument_rejected")
    return "'" + value.replace("'", "''") + "'"


def _build_helper_command(
    runtime: _TrustedRuntime, *, action: str, run_id: str,
    source_volume: str | None = None,
    expected_shadow_id: str | None = None,
) -> list[str]:
    """Private pure builder; production receives runtime only from trust validation."""
    if action not in {
        "PrepareCreate", "Create", "Adopt", "DeleteExact", "InspectOwned",
    }:
        raise VssError("helper_action_rejected")
    run_id = _guid(run_id)
    if action in {"PrepareCreate", "Create"}:
        if source_volume is None or expected_shadow_id is not None:
            raise VssError("create_arguments_invalid")
        if not re.fullmatch(r"[A-Za-z]:\\", source_volume):
            raise VssError("invalid_source_volume")
    elif action in {"Adopt", "DeleteExact"}:
        if source_volume is not None or expected_shadow_id is None:
            raise VssError("shadow_action_arguments_invalid")
        expected_shadow_id = _shadow_id(expected_shadow_id)
    elif source_volume is not None or expected_shadow_id is not None:
        raise VssError("inspect_arguments_invalid")
    helper_args = ["-NoProfile", "-NonInteractive", "-File",
                   str(runtime.script), "-Action", action,
                   "-RunId", run_id]
    if source_volume is not None:
        helper_args += ["-SourceVolume", source_volume]
    if expected_shadow_id is not None:
        helper_args += ["-ExpectedShadowId", expected_shadow_id]
    if action in {"PrepareCreate", "Adopt", "InspectOwned"}:
        return [str(runtime.powershell), *helper_args]
    array = ",".join(_ps_literal(item) for item in helper_args)
    elevated = (
        f"$a=@({array});"
        f"$p=Start-Process -FilePath {_ps_literal(str(runtime.powershell))} "
        "-ArgumentList $a -Verb RunAs -WindowStyle Hidden -PassThru;"
        f"if(-not $p.WaitForExit({_RUNAS_TIMEOUT_MILLISECONDS})){{"
        f"exit {_RUNAS_TIMEOUT_EXIT_CODE}}};"
        "exit $p.ExitCode")
    return [str(runtime.powershell), "-NoProfile", "-NonInteractive",
            "-Command", elevated]


class _HelperProcessAdapter:
    """Private runner seam. Only tests may supply a runner to this class."""

    def __init__(
        self, runtime: _TrustedRuntime,
        runner: Callable[..., subprocess.CompletedProcess[str]],
    ) -> None:
        self._runtime = runtime
        self._runner = runner

    def invoke(self, **arguments: str | None) -> VssJournal:
        command = _build_helper_command(self._runtime, **arguments)
        run_id = str(arguments["run_id"])
        try:
            result = self._runner(
                command, check=False, text=True, capture_output=True,
                encoding=locale.getencoding(), errors="replace",
                timeout=_HELPER_OUTER_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            if arguments["action"] == "PrepareCreate":
                raise VssError("prepare_create_timeout_unconfirmed") from error
            journal = self._read_durable_timeout_state(run_id)
        else:
            if (result.returncode == _RUNAS_TIMEOUT_EXIT_CODE and
                    arguments["action"] in {"Create", "DeleteExact"}):
                journal = self._read_durable_timeout_state(run_id)
            elif result.returncode != 0:
                raise VssError("helper_failed")
            else:
                journal = read_vss_journal(
                    self._runtime.journal_root / f"{run_id}.json",
                    expected_run_id=run_id)
        return _validate_action_journal_identity(journal, arguments)

    def _read_durable_timeout_state(self, run_id: str) -> VssJournal:
        try:
            return read_vss_journal(
                self._runtime.journal_root / f"{run_id}.json",
                expected_run_id=run_id)
        except VssJournalError as error:
            raise VssError("helper_timeout_journal_unreadable") from error


def _validate_action_journal_identity(
    journal: VssJournal, arguments: Mapping[str, str | None],
) -> VssJournal:
    action = arguments["action"]
    if action in {"PrepareCreate", "Create"}:
        if journal.source_volume != arguments["source_volume"]:
            raise VssJournalError("helper_source_volume_mismatch")
    elif action in {"Adopt", "DeleteExact"}:
        expected = _shadow_id(str(arguments["expected_shadow_id"]))
        if journal.shadow_id != expected:
            raise VssJournalError("helper_shadow_id_mismatch")
    return journal


def _assert_live_source_journal(
    journal: object, *, source_volume: str
) -> None:
    if getattr(journal, "source_volume", None) != source_volume:
        raise VssJournalError("helper_source_volume_mismatch")


class VssHelperClient:
    __slots__ = ("_source_volume",)

    def __init__(self, *, source_volume: str) -> None:
        if re.fullmatch(r"[A-Z]:\\", source_volume) is None:
            raise VssError("production_source_volume_invalid")
        self._source_volume = source_volume
        # All canonical/hash/reparse/ACL checks finish before any method can RunAs.
        _validate_production_trust()

    def _invoke(self, **arguments: str | None) -> VssJournal:
        # Revalidate immediately before every helper invocation to close the
        # constructor-to-invocation replacement window.
        runtime = _validate_production_trust()
        return _HelperProcessAdapter(runtime, subprocess.run).invoke(**arguments)

    def create(self, *, run_id: str, source_volume: str) -> VssJournal:
        if source_volume != self._source_volume:
            raise VssError("production_source_volume_invalid")
        prepared = self._invoke(
            action="PrepareCreate", run_id=run_id,
            source_volume=source_volume)
        _assert_live_source_journal(
            prepared, source_volume=self._source_volume
        )
        if prepared.state is not ShadowState.CREATING:
            raise VssJournalError("prepare_create_state_invalid")
        result = self._invoke(action="Create", run_id=run_id,
                              source_volume=source_volume)
        _assert_live_source_journal(
            result, source_volume=self._source_volume
        )
        if result.state is not ShadowState.CREATED:
            raise VssJournalError("create_state_invalid")
        return result

    def adopt(self, *, run_id: str, shadow_id: str) -> VssJournal:
        result = self._invoke(action="Adopt", run_id=run_id,
                              expected_shadow_id=shadow_id)
        _assert_live_source_journal(
            result, source_volume=self._source_volume
        )
        if result.state is not ShadowState.ADOPTED:
            raise VssJournalError("adopt_state_invalid")
        return result

    def delete_exact(self, *, run_id: str, shadow_id: str) -> VssJournal:
        result = self._invoke(action="DeleteExact", run_id=run_id,
                              expected_shadow_id=shadow_id)
        _assert_live_source_journal(
            result, source_volume=self._source_volume
        )
        if result.state is not ShadowState.DELETED:
            raise VssJournalError("delete_state_invalid")
        return result

    def inspect_owned(self, *, run_id: str) -> VssJournal:
        result = self._invoke(action="InspectOwned", run_id=run_id)
        _assert_live_source_journal(
            result, source_volume=self._source_volume
        )
        return result


def _is_reparse_point(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _assert_tree_has_no_reparse(root: Path) -> None:
    if _is_reparse_point(root):
        raise VssPathError("tree_reparse_rejected")
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in [*names, *files]:
            if _is_reparse_point(base / name):
                raise VssPathError("tree_reparse_rejected")


def _assert_fixed_run_root(
    run_root: Path, *, snapshots_root: Path
) -> Path:
    lexical = Path(os.path.abspath(run_root))
    snapshots = Path(os.path.abspath(snapshots_root))
    if not _same_path(lexical.parent, snapshots):
        raise VssPathError("staging_run_root_not_fixed")
    if not lexical.is_dir():
        raise VssPathError("staging_run_root_missing")
    current = Path(lexical.anchor)
    for part in lexical.parts[1:]:
        current /= part
        try:
            if _is_reparse_point(current):
                raise VssPathError("staging_run_root_reparse")
        except OSError as error:
            raise VssPathError("staging_run_root_unreadable") from error
    try:
        canonical = lexical.resolve(strict=True)
        canonical_parent = snapshots.resolve(strict=True)
    except OSError as error:
        raise VssPathError("staging_run_root_unreadable") from error
    if not _same_path(canonical.parent, canonical_parent):
        raise VssPathError("staging_run_root_not_fixed")
    return canonical


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _tree_manifest(root: Path) -> tuple[tuple[str, int, str], ...]:
    _assert_tree_has_no_reparse(root)
    result: list[tuple[str, int, str]] = []
    for path in sorted((item for item in root.rglob("*") if item.is_file()),
                       key=lambda item: item.relative_to(root).as_posix()):
        result.append((path.relative_to(root).as_posix(),
                       path.stat().st_size, _sha256_file(path)))
    return tuple(result)


def _assert_shadow_account_db_source(
    shadow_source: Path, *, source_account_name: str,
) -> PureWindowsPath:
    shadow_text = str(shadow_source)
    match = re.fullmatch(
        r"(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[1-9][0-9]*)\\(.+)",
        shadow_text)
    if match is None:
        raise VssPathError("shadow_source_path_invalid")
    assert_device_object(match.group(1))
    expected = account_db_relative_path(source_account_name)
    try:
        relative = _relative_volume_path(match.group(2))
    except VssPathError as error:
        raise VssPathError("shadow_account_db_path_invalid") from error
    if (len(relative.parts) < 2
            or tuple(relative.parts[-2:]) != tuple(expected.parts)):
        raise VssPathError("shadow_account_db_path_invalid")
    return expected


def _assert_shadow_account_source(
    shadow_account: Path, *, source_account_name: str,
) -> Path:
    account_db_relative_path(source_account_name)
    shadow_text = str(shadow_account)
    match = re.fullmatch(
        r"(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[1-9][0-9]*)\\(.+)",
        shadow_text,
    )
    if match is None:
        raise VssPathError("shadow_account_path_invalid")
    assert_device_object(match.group(1))
    try:
        relative = _relative_volume_path(match.group(2))
    except VssPathError as error:
        raise VssPathError("shadow_account_path_invalid") from error
    if relative.parts[-1] != source_account_name:
        raise VssPathError("shadow_account_path_invalid")
    return shadow_account


_MEDIA_ROOTS = (
    PureWindowsPath("msg", "attach"),
    PureWindowsPath("msg", "video"),
)
# Match the project's existing preflight floor while accounting separately
# for both the partial tree and its durable published form.
_MEDIA_STAGING_FREE_SPACE_RESERVE_BYTES = 2**30


def _assert_media_root_chain(
    account_root: Path,
    relative_root: PureWindowsPath,
) -> None:
    current = account_root
    for component in ("", *relative_root.parts):
        if component:
            current /= component
        if not current.exists():
            return
        if _is_reparse_point(current):
            raise VssPathError("media_root_chain_reparse")
        if not current.is_dir():
            raise VssPathError("media_root_invalid")


def _media_manifest(account_root: Path) -> tuple[MediaStagingFile, ...]:
    files: list[MediaStagingFile] = []
    for relative_root in _MEDIA_ROOTS:
        _assert_media_root_chain(account_root, relative_root)
        root = account_root / relative_root
        if not root.exists():
            continue
        for relative, size, digest in _tree_manifest(root):
            files.append(
                MediaStagingFile(
                    (
                        PureWindowsPath(relative_root)
                        / PureWindowsPath(relative)
                    ).as_posix(),
                    size,
                    digest,
                )
            )
    return tuple(sorted(files, key=lambda item: item.relative_path))


def _media_manifest_sha256(
    files: tuple[MediaStagingFile, ...],
) -> str:
    payload = json.dumps(
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
    return hashlib.sha256(payload).hexdigest().upper()


def _validate_prior_media_inventory(
    value: tuple[MediaStagingFile, ...] | None,
) -> tuple[MediaStagingFile, ...]:
    if value is None:
        return ()
    if type(value) is not tuple:
        raise VssPathError("prior_media_inventory_invalid")
    paths: list[str] = []
    for item in value:
        if (
            type(item) is not MediaStagingFile
            or not isinstance(item.relative_path, str)
            or type(item.size) is not int
            or item.size < 0
            or not isinstance(item.sha256, str)
            or _HASH_RE.fullmatch(item.sha256) is None
        ):
            raise VssPathError("prior_media_inventory_invalid")
        try:
            relative = _relative_volume_path(item.relative_path)
        except VssPathError as error:
            raise VssPathError(
                "prior_media_inventory_invalid"
            ) from error
        if (
            relative.as_posix() != item.relative_path
            or len(relative.parts) < 3
            or PureWindowsPath(*relative.parts[:2]) not in _MEDIA_ROOTS
        ):
            raise VssPathError("prior_media_inventory_invalid")
        paths.append(item.relative_path)
    if paths != sorted(paths) or len({path.casefold() for path in paths}) != len(
            paths):
        raise VssPathError("prior_media_inventory_invalid")
    return value


def copy_owned_shadow_media_to_staging(
    *,
    shadow_account: Path,
    run_root: Path,
    snapshots_root: Path,
    source_account_name: str,
    prior_inventory: tuple[MediaStagingFile, ...] | None = None,
) -> MediaStagingReceipt:
    shadow_account = _assert_shadow_account_source(
        shadow_account,
        source_account_name=source_account_name,
    )
    run_root = _assert_fixed_run_root(
        run_root, snapshots_root=snapshots_root
    )
    prior_inventory = _validate_prior_media_inventory(prior_inventory)
    final = run_root / "media-staging"
    partial = run_root / (".media-staging." + os.urandom(8).hex())
    if final.exists() or partial.exists():
        raise VssPathError("media_staging_destination_exists")
    before = _media_manifest(shadow_account)
    prior_by_path = {
        item.relative_path: item
        for item in prior_inventory
    }
    delta = tuple(
        item
        for item in before
        if prior_by_path.get(item.relative_path) != item
    )
    free = shutil.disk_usage(run_root).free
    required = (
        2 * sum(item.size for item in delta)
        + _MEDIA_STAGING_FREE_SPACE_RESERVE_BYTES
    )
    if type(free) is not int or free < 0:
        raise VssError("media_staging_space_probe_invalid")
    if free < required:
        raise VssError("media_staging_insufficient_space")
    partial_account = partial / source_account_name
    partial_account.mkdir(parents=True)
    for item in delta:
        relative = PureWindowsPath(item.relative_path)
        source = shadow_account / relative
        destination = partial_account / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as reader, destination.open("xb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
        flush_file_durable(destination)
    after = _media_manifest(shadow_account)
    copied = _media_manifest(partial_account)
    if before != after or delta != copied:
        raise VssError("media_staging_copy_verification_failed")
    try:
        replace_write_through(partial, final)
        published = _media_manifest(final / source_account_name)
        if published != delta:
            raise VssError("media_staging_publication_mismatch")
    except BaseException:
        rejected = final.with_name(
            f".{final.name}.rejected.{os.urandom(8).hex()}"
        )
        if final.exists():
            replace_write_through(final, rejected)
        raise
    return MediaStagingReceipt(
        staging_path=final,
        source_account_name=source_account_name,
        files=published,
        file_count=len(published),
        byte_count=sum(item.size for item in published),
        manifest_sha256=_media_manifest_sha256(published),
    )


def copy_owned_shadow_to_staging(*, shadow_source: Path,
                                 run_root: Path,
                                 snapshots_root: Path,
                                 source_account_name: str) -> StagingReceipt:
    relative_db = _assert_shadow_account_db_source(
        shadow_source, source_account_name=source_account_name)
    run_root = _assert_fixed_run_root(
        run_root, snapshots_root=snapshots_root
    )
    final = run_root / "vss-staging"
    partial = run_root / (".vss-staging." + os.urandom(8).hex())
    if final.exists() or partial.exists():
        raise VssPathError("staging_destination_exists")
    before = _tree_manifest(shadow_source)
    partial_db = partial / relative_db
    partial_db.mkdir(parents=True)
    for relative, _, _ in before:
        source = shadow_source / PureWindowsPath(relative)
        destination = partial_db / PureWindowsPath(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as reader, destination.open("xb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
        flush_file_durable(destination)
    after = _tree_manifest(shadow_source)
    copied = _tree_manifest(partial_db)
    if before != after or before != copied:
        raise VssError("staging_copy_verification_failed")
    prefix = relative_db.as_posix() + "/"
    expected_published = tuple(
        (prefix + relative, size, digest)
        for relative, size, digest in before)
    try:
        replace_write_through(partial, final)
        published = verify_published_directory_durable(
            final,
            role=CopyRole.VSS_STAGING,
            source_account_name=source_account_name,
            expected_signature=expected_published,
        )
    except BaseException:
        rejected = final.with_name(
            f".{final.name}.rejected.{os.urandom(8).hex()}")
        if final.exists():
            replace_write_through(final, rejected)
        raise
    return StagingReceipt(
        final, source_account_name, relative_db,
        published.total_files, published.total_bytes,
        staging_receipt_sha256(published))


def _journal_state_name(journal: object) -> str:
    value = getattr(journal, "state")
    return value.value if isinstance(value, ShadowState) else str(value)


def acquire_vss_staging(*, client: VssHelperClient, run_id: str,
                        source_volume: str, live_path: str | PureWindowsPath,
                        source_account_name: str,
                        run_root: Path, snapshots_root: Path) -> StagingReceipt:
    receipt: StagingReceipt | None = None
    primary_error: BaseException | None = None
    try:
        created = client.create(run_id=run_id, source_volume=source_volume)
        _assert_live_source_journal(
            created, source_volume=source_volume
        )
        if created.shadow_id is None:
            raise VssJournalError("created_shadow_id_missing")
        adopted = client.adopt(run_id=run_id, shadow_id=created.shadow_id)
        _assert_live_source_journal(
            adopted, source_volume=source_volume
        )
        owned = client.inspect_owned(run_id=run_id)
        _assert_live_source_journal(
            owned, source_volume=source_volume
        )
        if _journal_state_name(owned) != "adopted" or owned.device_object is None:
            raise VssJournalError("owned_shadow_not_adopted")
        shadow_source = map_volume_path(
            owned.device_object, source_volume=source_volume,
            live_path=live_path)
        receipt = copy_owned_shadow_to_staging(
            shadow_source=shadow_source, run_root=run_root,
            snapshots_root=snapshots_root,
            source_account_name=source_account_name)
    except BaseException as error:
        primary_error = error
    finally:
        try:
            inspected = client.inspect_owned(run_id=run_id)
            _assert_live_source_journal(
                inspected, source_volume=source_volume
            )
            state = _journal_state_name(inspected)
            if state in {"created", "adopted"}:
                if inspected.shadow_id is None:
                    raise VssCleanupError("owned_shadow_id_missing")
                deleted = client.delete_exact(
                    run_id=run_id, shadow_id=inspected.shadow_id)
                _assert_live_source_journal(
                    deleted, source_volume=source_volume
                )
                inspected = client.inspect_owned(run_id=run_id)
                _assert_live_source_journal(
                    inspected, source_volume=source_volume
                )
                state = _journal_state_name(inspected)
            if state != "deleted":
                raise VssCleanupError("owned_shadow_not_deleted")
        except BaseException as cleanup_error:
            cause: BaseException = cleanup_error
            if primary_error is not None:
                cause = BaseExceptionGroup(
                    "vss_primary_and_cleanup_failures",
                    (primary_error, cleanup_error),
                )
            raise VssCleanupError("owned_shadow_cleanup_failed") from cause
    if primary_error is not None:
        raise primary_error
    if receipt is None:
        raise VssError("staging_receipt_missing")
    return receipt


def remove_synthetic_tree(path: Path, *, allowed_root: Path) -> None:
    allowed_lexical = Path(os.path.abspath(allowed_root))
    candidate_lexical = Path(os.path.abspath(path))
    if candidate_lexical == allowed_lexical:
        raise VssPathError("cleanup_root_forbidden")
    if os.path.commonpath((str(candidate_lexical), str(allowed_lexical))) != str(
            allowed_lexical):
        raise VssPathError("cleanup_outside_root")
    current = candidate_lexical
    while True:
        if _is_reparse_point(current):
            raise VssPathError("cleanup_reparse_rejected")
        if current == allowed_lexical:
            break
        current = current.parent
    allowed = allowed_lexical.resolve(strict=True)
    candidate = candidate_lexical.resolve(strict=True)
    if candidate == allowed or os.path.commonpath(
            (str(candidate), str(allowed))) != str(allowed):
        raise VssPathError("cleanup_resolved_outside_root")
    try:
        _assert_tree_has_no_reparse(candidate)
    except VssPathError as error:
        raise VssPathError("cleanup_reparse_rejected") from error
    shutil.rmtree(candidate)
