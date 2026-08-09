from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path, PurePath
import re
from typing import Protocol

from weflow_chat.compatibility import SUPPORTED_WEIXIN
from weflow_chat.paths import canonical_existing, canonical_future
from weflow_chat.processes import (
    ProcessIdentity,
    process_identity_token,
)
from weflow_chat.weixin_trust import (
    LocalTrustReceipt,
    STORED_ENVELOPE_REFRESH,
    RuntimeWeixinDllIdentity,
    TrustState,
    WeixinTrustDecision,
    resolve_weixin_trust,
)


_TEST_HOST_TOKEN = object()
_DISCOVERED_HOST_TOKEN = object()
_HEX64_RE = re.compile(r"[0-9A-F]{64}")
_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|\+00:00)"
)
_SUPPORTED_DB_PATH_SHAPES = {
    "account_dir_instead_of_parent",
    "managed_active_parent",
}
_REASON_CODES = {
    "config_hash_invalid",
    "config_not_regular_file",
    "current_db_path_shape_invalid",
    "formal_weflow_running",
    "historical_backup_contract_invalid",
    "host_adapter_contract_invalid",
    "host_contract_mismatch",
    "insufficient_e_space",
    "process_pid_contract_invalid",
    "run_root_collision",
    "session_db_missing",
    "source_enumeration_invalid",
    "source_recount_changed",
    "source_root_identity_changed",
    "source_volume_not_ntfs",
    "target_account_not_unique",
    "validator_process_residual",
    "vss_unsupported",
    "weixin_adapter_mismatch",
    "weixin_dll_hash_mismatch",
    "weixin_executable_mismatch",
    "weixin_process_identity_invalid",
    "weixin_signature_mismatch",
    "weixin_trial_required",
}


@dataclass(frozen=True, slots=True)
class HostContract:
    source_account: Path
    snapshots_root: Path
    media_store_root: Path
    weflow_cache_root: Path
    formal_weflow: Path
    weixin_install_root: Path
    config_path: Path
    cache_maps_path: Path
    analytics_cache_path: Path
    same_volume_recovery_root: Path
    old_upgrade_backup: Path
    account_id: str
    _test_root: Path | None = field(default=None, repr=False)
    _test_token: object | None = field(default=None, repr=False)
    _discovery_token: object | None = field(default=None, repr=False)

    @property
    def db_storage(self) -> Path:
        return self.source_account / "db_storage"

    @property
    def session_db(self) -> Path:
        return (
            self.db_storage
            / "session"
            / "session.db"
        )

    @property
    def weixin_executable(self) -> Path:
        return self.weixin_install_root / "Weixin.exe"

    @property
    def weixin_dll(self) -> Path:
        return (
            self.weixin_install_root
            / SUPPORTED_WEIXIN["version"]
            / "Weixin.dll"
        )

    @property
    def source_volume(self) -> str:
        if self._test_token is _TEST_HOST_TOKEN:
            return "F:\\"
        anchor = self.source_account.anchor
        if re.fullmatch(r"[A-Za-z]:\\", anchor) is None:
            raise RuntimeError("source_volume_invalid")
        return anchor.upper()

    @classmethod
    def discovered(
        cls,
        *,
        source_account: Path,
        data_root: Path,
        formal_weflow: Path,
        weixin_install_root: Path,
        config_path: Path,
        cache_maps_path: Path,
        analytics_cache_path: Path,
        same_volume_recovery_root: Path,
        account_id: str,
    ) -> "HostContract":
        return cls(
            source_account=source_account,
            snapshots_root=data_root / "Snapshots",
            media_store_root=data_root / "MediaStore",
            weflow_cache_root=data_root / "DerivedCache",
            formal_weflow=formal_weflow,
            weixin_install_root=weixin_install_root,
            config_path=config_path,
            cache_maps_path=cache_maps_path,
            analytics_cache_path=analytics_cache_path,
            same_volume_recovery_root=same_volume_recovery_root,
            old_upgrade_backup=data_root / "LegacyBackup",
            account_id=account_id,
            _discovery_token=_DISCOVERED_HOST_TOKEN,
        )

    @classmethod
    def for_test_root(cls, root: Path) -> "HostContract":
        return cls(
            source_account=root / "F" / "account",
            snapshots_root=root / "E" / "Snapshots",
            media_store_root=root / "E" / "MediaStore",
            weflow_cache_root=root / "E" / "DerivedCache",
            formal_weflow=root / "C" / "WeFlow.exe",
            weixin_install_root=root / "C" / "Weixin",
            config_path=root / "C" / "WeFlow-config.json",
            cache_maps_path=root / "C" / "WeFlow-cache-maps.json",
            analytics_cache_path=root / "C" / "analytics_cache.json",
            same_volume_recovery_root=root / "C" / "WeFlowRecovery",
            old_upgrade_backup=root / "E" / "before-upgrade",
            account_id="wxid_test",
            _test_root=root,
            _test_token=_TEST_HOST_TOKEN,
        )


@dataclass(frozen=True, slots=True)
class PreflightReport:
    ok: bool
    reasonCodes: tuple[str, ...]
    warningCodes: tuple[str, ...]
    sourceFileCount: int
    sourceByteCount: int
    requiredFreeBytes: int
    weixin: "ProcessSummary"
    targetRunRootExists: bool
    targetAccountMatches: int
    formalWeFlowPids: tuple[int, ...]
    validatorPids: tuple[int, ...]
    sessionDbExists: bool
    configSha256: str
    currentDbPathShape: str
    oldUpgradeBackupExists: bool
    historicalBackupCount: int
    newestHistoricalBackupTimestampUtc: str | None

    def to_redacted_json(self) -> str:
        value = asdict(self)
        try:
            if (
                set(value)
                != {
                    "ok",
                    "reasonCodes",
                    "warningCodes",
                    "sourceFileCount",
                    "sourceByteCount",
                    "requiredFreeBytes",
                    "weixin",
                    "targetRunRootExists",
                    "targetAccountMatches",
                    "formalWeFlowPids",
                    "validatorPids",
                    "sessionDbExists",
                    "configSha256",
                    "currentDbPathShape",
                    "oldUpgradeBackupExists",
                    "historicalBackupCount",
                    "newestHistoricalBackupTimestampUtc",
                }
                or type(value["ok"]) is not bool
                or tuple(value["reasonCodes"])
                != tuple(sorted(set(value["reasonCodes"])))
                or any(
                    code not in _REASON_CODES
                    for code in value["reasonCodes"]
                )
                or tuple(value["warningCodes"])
                not in {(), ("old_upgrade_backup_missing",)}
                or value["ok"] != (not value["reasonCodes"])
                or any(
                    type(value[name]) is not int or value[name] < 0
                    for name in (
                        "sourceFileCount",
                        "sourceByteCount",
                        "requiredFreeBytes",
                        "targetAccountMatches",
                        "historicalBackupCount",
                    )
                )
                or any(
                    type(value[name]) is not bool
                    for name in (
                        "targetRunRootExists",
                        "sessionDbExists",
                        "oldUpgradeBackupExists",
                    )
                )
                or any(
                    type(pid) is not int or pid <= 0
                    for name in ("formalWeFlowPids", "validatorPids")
                    for pid in value[name]
                )
                or value["configSha256"] != ""
                and _HEX64_RE.fullmatch(value["configSha256"]) is None
                or value["currentDbPathShape"]
                not in _SUPPORTED_DB_PATH_SHAPES | {"invalid"}
                or (
                    value["newestHistoricalBackupTimestampUtc"]
                    is not None
                    and _TIMESTAMP_RE.fullmatch(
                        value["newestHistoricalBackupTimestampUtc"]
                    )
                    is None
                )
                or set(value["weixin"])
                != {
                    "pid",
                    "architecture",
                    "dllVersion",
                    "dllSha256",
                    "trustState",
                    "capabilities",
                }
                or type(value["weixin"]["pid"]) is not int
                or value["weixin"]["pid"] < 0
                or value["weixin"]["architecture"]
                not in {"x64", "unsupported"}
                or value["weixin"]["dllVersion"]
                != "unsupported"
                and re.fullmatch(
                    r"[0-9]+(?:\.[0-9]+){3}",
                    value["weixin"]["dllVersion"],
                )
                is None
                or value["weixin"]["dllSha256"] != ""
                and _HEX64_RE.fullmatch(
                    value["weixin"]["dllSha256"]
                )
                is None
                or value["weixin"]["trustState"]
                not in {item.value for item in TrustState}
                or tuple(value["weixin"]["capabilities"])
                != tuple(
                    sorted(
                        set(value["weixin"]["capabilities"])
                    )
                )
                or any(
                    capability
                    != STORED_ENVELOPE_REFRESH
                    for capability in value["weixin"]["capabilities"]
                )
                or (
                    value["weixin"]["trustState"]
                    in {
                        TrustState.REJECTED.value,
                        TrustState.TRIAL_REQUIRED.value,
                    }
                    and value["weixin"]["capabilities"]
                )
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError(
                "preflight_report_schema_invalid"
            ) from error
        return json.dumps(
            value, sort_keys=True, separators=(",", ":")
        )


@dataclass(frozen=True, slots=True)
class ProcessSummary:
    pid: int
    architecture: str
    dllVersion: str
    dllSha256: str
    trustState: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceEnumeration:
    root: Path
    rootIdentity: tuple[int, int, int]
    entries: tuple[tuple[str, int, int], ...]


class HostAdapters(Protocol):
    free: int
    fs: str
    vss: bool
    target_exists: bool
    config_regular: bool
    config_sha: str
    db_path_shape: str
    account_matches: int
    my_wxid_matches: bool
    formal: tuple[int, ...]
    validators: tuple[int, ...]
    weixin: ProcessIdentity
    session_exists: bool
    old_upgrade_backup_exists: bool
    historical_backup_count: int
    newest_historical_backup_timestamp_utc: str | None

    def enumerate_source(
        self,
    ) -> SourceEnumeration: ...


def _normalize_source_entries(entries: tuple) -> tuple | None:
    names = []
    normalized = []
    for item in entries:
        if (
            not isinstance(item, tuple)
            or len(item) != 3
            or not isinstance(item[0], str)
            or not item[0]
            or PurePath(item[0]).is_absolute()
            or ".." in PurePath(item[0]).parts
            or type(item[1]) is not int
            or item[1] < 0
            or type(item[2]) is not int
            or item[2] < 0
        ):
            return None
        name = os.path.normcase(str(PurePath(item[0])))
        names.append(name)
        normalized.append((name, item[1], item[2]))
    if len(names) != len(set(names)):
        return None
    return tuple(sorted(normalized))


def _directory_identity(path: Path) -> tuple[int, int, int]:
    information = path.stat(follow_symlinks=False)
    if not path.is_dir():
        raise RuntimeError("source_root_identity_invalid")
    return (
        information.st_dev,
        information.st_ino,
        information.st_ctime_ns,
    )


def _host_contract_allowed(contract: HostContract) -> bool:
    if contract._discovery_token is _DISCOVERED_HOST_TOKEN:
        if (
            re.fullmatch(r"wxid_[A-Za-z0-9_]{1,128}", contract.account_id)
            is None
            or contract.source_account.name != contract.account_id
        ):
            return False
        required_existing = (
            contract.source_account,
            contract.db_storage,
            contract.formal_weflow,
            contract.weixin_executable,
            contract.weixin_install_root,
            contract.config_path,
        )
        required_future = (
            contract.snapshots_root,
            contract.media_store_root,
            contract.weflow_cache_root,
            contract.cache_maps_path,
            contract.analytics_cache_path,
            contract.same_volume_recovery_root,
            contract.old_upgrade_backup,
        )
        try:
            return all(
                canonical_existing(path) == path.absolute()
                for path in required_existing
            ) and all(
                canonical_future(path) == path.absolute()
                for path in required_future
            )
        except (OSError, ValueError):
            return False
    if (
        contract._test_token is not _TEST_HOST_TOKEN
        or contract._test_root is None
        or contract.account_id != "wxid_test"
    ):
        return False
    root = contract._test_root
    paths = (
        contract.source_account,
        contract.snapshots_root,
        contract.media_store_root,
        contract.weflow_cache_root,
        contract.formal_weflow,
        contract.weixin_install_root,
        contract.config_path,
        contract.cache_maps_path,
        contract.analytics_cache_path,
        contract.same_volume_recovery_root,
        contract.old_upgrade_backup,
    )
    try:
        canonical_root = canonical_existing(root)
        return all(
            canonical_future(path).is_relative_to(canonical_root)
            for path in paths
        )
    except (OSError, ValueError):
        return False


def fixed_host() -> HostContract:
    from weflow_chat.host_discovery import load_host_contract

    return load_host_contract()


def require_fixed_host(contract: HostContract) -> HostContract:
    if not _host_contract_allowed(contract):
        raise RuntimeError("host_contract_mismatch")
    return contract


def _weixin_trust_decision(
    identity: ProcessIdentity,
    local_receipts: tuple[LocalTrustReceipt, ...] = (),
) -> WeixinTrustDecision:
    try:
        runtime = RuntimeWeixinDllIdentity(
            version=identity.dll_version,
            architecture=identity.architecture,
            dll_size=identity.dll_size,
            dll_sha256=identity.dll_sha256,
            authenticode_status=(
                identity.dll_authenticode_status
            ),
            signer_subject=identity.dll_signer_subject,
            signer_certificate_sha256=(
                identity.dll_signer_certificate_sha256
            ),
        )
    except (AttributeError, TypeError, ValueError):
        return WeixinTrustDecision(
            TrustState.REJECTED, frozenset()
        )
    return resolve_weixin_trust(
        runtime, local_receipts=local_receipts
    )


def _weixin_reason_codes(
    contract: HostContract,
    identity: ProcessIdentity,
    decision: WeixinTrustDecision,
) -> list[str]:
    reasons = []
    try:
        executable_matches = (
            canonical_existing(identity.executable)
            == canonical_existing(contract.weixin_executable)
        )
    except (AttributeError, OSError, TypeError, ValueError):
        executable_matches = False
    if not executable_matches:
        reasons.append("weixin_executable_mismatch")
    if (
        not isinstance(identity.signer_subject, str)
        or not isinstance(identity.dll_signer_subject, str)
        or identity.authenticode_status
        != SUPPORTED_WEIXIN["authenticode_status"]
        or SUPPORTED_WEIXIN["signer_subject_contains"]
        not in identity.signer_subject
        or identity.dll_authenticode_status
        != SUPPORTED_WEIXIN["authenticode_status"]
        or SUPPORTED_WEIXIN["signer_subject_contains"]
        not in identity.dll_signer_subject
    ):
        reasons.append("weixin_signature_mismatch")
    if identity.architecture != "x64":
        reasons.append("weixin_adapter_mismatch")
    if (
        decision.state is TrustState.REJECTED
        and "weixin_signature_mismatch" not in reasons
        and "weixin_adapter_mismatch" not in reasons
    ):
        reasons.append("weixin_process_identity_invalid")
    try:
        process_identity_token(identity)
    except RuntimeError:
        reasons.append("weixin_process_identity_invalid")
    if identity.isolated_user_data is not None:
        reasons.append("weixin_process_identity_invalid")
    try:
        dll = canonical_existing(identity.dll_path)
        install_root = canonical_existing(
            contract.weixin_install_root
        )
        if (
            dll.name.casefold() != "weixin.dll"
            or dll.parent.parent != install_root
            or dll.parent.name != identity.dll_version
            or type(identity.dll_size) is not int
            or identity.dll_size <= 0
        ):
            raise ValueError
    except (AttributeError, OSError, TypeError, ValueError):
        reasons.append("weixin_process_identity_invalid")
    return reasons


def run_preflight(
    contract: HostContract, adapters: HostAdapters
) -> PreflightReport:
    if not _host_contract_allowed(contract):
        raise RuntimeError("host_contract_mismatch")
    expected_root = canonical_existing(contract.db_storage)
    before_identity = _directory_identity(expected_root)
    first_receipt = adapters.enumerate_source()
    second_receipt = adapters.enumerate_source()
    after_identity = _directory_identity(expected_root)
    if (
        not isinstance(first_receipt, SourceEnumeration)
        or not isinstance(second_receipt, SourceEnumeration)
    ):
        raise RuntimeError("source_enumeration_receipt_invalid")
    try:
        roots_valid = (
            canonical_existing(first_receipt.root) == expected_root
            and canonical_existing(second_receipt.root) == expected_root
        )
    except (OSError, ValueError):
        roots_valid = False
    identities_valid = (
        isinstance(first_receipt.rootIdentity, tuple)
        and isinstance(second_receipt.rootIdentity, tuple)
        and first_receipt.rootIdentity == second_receipt.rootIdentity
        and first_receipt.rootIdentity == before_identity
        and before_identity == after_identity
        and len(first_receipt.rootIdentity) == 3
        and all(
            type(item) is int and item >= 0
            for item in first_receipt.rootIdentity
        )
    )
    first_raw = tuple(first_receipt.entries)
    second_raw = tuple(second_receipt.entries)
    first = _normalize_source_entries(first_raw)
    second = _normalize_source_entries(second_raw)
    reasons = []
    warnings = []
    if not roots_valid or not identities_valid:
        reasons.append("source_root_identity_changed")
    if first is not None and second is not None and first != second:
        reasons.append("source_recount_changed")
    entries_valid = first is not None and second is not None
    if not entries_valid:
        reasons.append("source_enumeration_invalid")
    if adapters.session_exists is not True:
        reasons.append("session_db_missing")
    if adapters.old_upgrade_backup_exists is not True:
        warnings.append("old_upgrade_backup_missing")
    if adapters.fs != "NTFS":
        reasons.append("source_volume_not_ntfs")
    if adapters.vss is not True:
        reasons.append("vss_unsupported")
    total = sum(item[1] for item in second) if second else 0
    required = total * 4 + 2**30
    if type(adapters.free) is not int or adapters.free < required:
        reasons.append("insufficient_e_space")
    if adapters.config_regular is not True:
        reasons.append("config_not_regular_file")
    if (
        not isinstance(adapters.config_sha, str)
        or re.fullmatch(r"[0-9A-F]{64}", adapters.config_sha) is None
    ):
        reasons.append("config_hash_invalid")
    if (
        adapters.account_matches != 1
        or adapters.my_wxid_matches is not True
    ):
        reasons.append("target_account_not_unique")
    if adapters.db_path_shape not in _SUPPORTED_DB_PATH_SHAPES:
        reasons.append("current_db_path_shape_invalid")
    if adapters.target_exists is not False:
        reasons.append("run_root_collision")
    if (
        type(adapters.target_exists) is not bool
        or type(adapters.session_exists) is not bool
        or type(adapters.old_upgrade_backup_exists) is not bool
    ):
        reasons.append("host_adapter_contract_invalid")
    if adapters.formal:
        reasons.append("formal_weflow_running")
    if adapters.validators:
        reasons.append("validator_process_residual")
    raw_local_receipts = getattr(
        adapters, "local_trust_receipts", ()
    )
    local_receipts = (
        tuple(raw_local_receipts)
        if isinstance(raw_local_receipts, (tuple, list))
        and all(
            isinstance(item, LocalTrustReceipt)
            for item in raw_local_receipts
        )
        else ()
    )
    if raw_local_receipts not in ((), []) and not local_receipts:
        reasons.append("host_adapter_contract_invalid")
    trust_decision = _weixin_trust_decision(
        adapters.weixin, local_receipts
    )
    reasons.extend(
        _weixin_reason_codes(
            contract, adapters.weixin, trust_decision
        )
    )
    formal_pids = tuple(
        pid
        for pid in adapters.formal
        if type(pid) is int and pid > 0
    )
    validator_pids = tuple(
        pid
        for pid in adapters.validators
        if type(pid) is int and pid > 0
    )
    if (
        len(formal_pids) != len(adapters.formal)
        or len(validator_pids) != len(adapters.validators)
    ):
        reasons.append("process_pid_contract_invalid")
    history_count = (
        adapters.historical_backup_count
        if type(adapters.historical_backup_count) is int
        and adapters.historical_backup_count >= 0
        else 0
    )
    history_timestamp = (
        adapters.newest_historical_backup_timestamp_utc
        if isinstance(
            adapters.newest_historical_backup_timestamp_utc, str
        )
        and _TIMESTAMP_RE.fullmatch(
            adapters.newest_historical_backup_timestamp_utc
        )
        else None
    )
    if (
        history_count != adapters.historical_backup_count
        or (
            adapters.newest_historical_backup_timestamp_utc is not None
            and history_timestamp is None
        )
    ):
        reasons.append("historical_backup_contract_invalid")
    config_sha = (
        adapters.config_sha
        if isinstance(adapters.config_sha, str)
        and _HEX64_RE.fullmatch(adapters.config_sha)
        else ""
    )
    db_path_shape = (
        adapters.db_path_shape
        if adapters.db_path_shape in _SUPPORTED_DB_PATH_SHAPES
        else "invalid"
    )
    process_pid = (
        adapters.weixin.pid
        if type(adapters.weixin.pid) is int
        and adapters.weixin.pid > 0
        else 0
    )
    return PreflightReport(
        ok=not reasons,
        reasonCodes=tuple(sorted(set(reasons))),
        warningCodes=tuple(sorted(set(warnings))),
        sourceFileCount=len(second) if second else 0,
        sourceByteCount=total,
        requiredFreeBytes=required,
        weixin=ProcessSummary(
            pid=process_pid,
            architecture=(
                adapters.weixin.architecture
                if adapters.weixin.architecture == "x64"
                else "unsupported"
            ),
            dllVersion=(
                adapters.weixin.dll_version
                if isinstance(
                    adapters.weixin.dll_version, str
                )
                and re.fullmatch(
                    r"[0-9]+(?:\.[0-9]+){3}",
                    adapters.weixin.dll_version,
                )
                else "unsupported"
            ),
            dllSha256=(
                adapters.weixin.dll_sha256
                if isinstance(adapters.weixin.dll_sha256, str)
                and _HEX64_RE.fullmatch(
                    adapters.weixin.dll_sha256
                )
                else ""
            ),
            trustState=trust_decision.state.value,
            capabilities=tuple(
                sorted(trust_decision.capabilities)
            ),
        ),
        targetRunRootExists=adapters.target_exists is True,
        targetAccountMatches=(
            adapters.account_matches
            if type(adapters.account_matches) is int
            and adapters.account_matches >= 0
            else 0
        ),
        formalWeFlowPids=formal_pids,
        validatorPids=validator_pids,
        sessionDbExists=adapters.session_exists is True,
        configSha256=config_sha,
        currentDbPathShape=db_path_shape,
        oldUpgradeBackupExists=(
            adapters.old_upgrade_backup_exists is True
        ),
        historicalBackupCount=history_count,
        newestHistoricalBackupTimestampUtc=history_timestamp,
    )


def request_normal_weflow_close(
    process_gate, timeout_seconds: float = 30.0
) -> None:
    if not process_gate.request_normal_close_and_wait(
        timeout_seconds
    ):
        raise TimeoutError("formal_weflow_normal_close_timeout")
