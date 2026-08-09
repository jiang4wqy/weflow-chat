from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Literal, Mapping
import uuid

from weflow_chat.paths import RunLayout, canonical_existing
from weflow_chat.validator.security import _pin_directory


EXPECTED_HASHES = {
    "WeFlow.exe": "5E9007F1FCE332C4038628FB2EAE0518FC6DCA252041A1563B0AD60292FA6A13",
    "app.asar": "F27D53EA61E97365865D999AC7EB03149BDAB670BFEF6851964190CEE5F33E80",
    "main.js": "1ABB5B41D039AA84FD43D734C1213F47815616141A30C99DA92BB183F803AADD",
    "config-chunk": "77F636C0E8C39E10C774E80ECC1AEA5503BAA8BB6E853D16108D2D182D9B6045",
    "worker": "C53892300A724D60CA5C733316332C47E20E41465B5396F764C0BE265C576890",
    "wcdb_api": "5D5DFFE151F6CF7C1122D34FB6C6F5E902685547CFED83891EDF8C23B78907B2",
    "WCDB.dll": "DE80DC7B9117076F7F77E5AB5D6EE8DC44F8D3829C10549A800AF2E4E219EBF8",
}
EXPECTED_ANCHORS = {
    "boot": "var RQ=null,zQ=r.app.requestSingleInstanceLock();",
    "ready": "r.app.whenReady().then(async()=>{if(!zQ)return;kX=new e.t",
}
SUPPORTED_WEIXIN = {
    "architecture": "x64",
    "version": "4.1.11.24",
    "authenticode_status": "Valid",
    "signer_subject_contains": (
        "Tencent Technology (Shenzhen) Company Limited"
    ),
    "dll_sha256": (
        "03968F3F6DF1C4B9872467E05EC5E84F"
        "7B599466021C2FB47EFD8940F16C9952"
    ),
}
_REQUIRED_METHODS = (
    "setPaths",
    "testConnection",
    "open",
    "close",
    "getSessions",
    "listMessageDbs",
    "listMediaDbs",
    "listTables",
    "getTableSchema",
    "getMessageTableStats",
    "getMessageTableTimeRange",
    "getAggregateStats",
    "shutdown",
)
_AFFECTED_ROLES = ("analytics_cache", "cache_maps", "config")
_ACCOUNT_RE = re.compile(r"wxid_[A-Za-z0-9_]{1,128}")
_HEX64_RE = re.compile(r"[0-9A-F]{64}")
_SECRET_FIELDS = ("decryptKey", "imageAesKey", "imageXorKey")
_FORMAL_ASAR_ENTRIES = {
    "main.js": "dist-electron/main.js",
    "config-chunk": "dist-electron/config-C9Ue62at.js",
    "worker": "dist-electron/wcdbWorker.js",
}
_ALLOWED_REASON_CODES = {
    "runtime_hash_contract_invalid",
    "application_version_mismatch",
    "main_anchor_contract_invalid",
    "main_anchor_mismatch",
    "wcdb_method_contract_mismatch",
    "affected_file_contract_invalid",
    "target_account_not_unique",
    "unsupported_envelope_kind",
    "config_schema_invalid",
    *{
        name.lower().replace(".", "_").replace("-", "_")
        + "_hash_mismatch"
        for name in EXPECTED_HASHES
    },
}


@dataclass(frozen=True, slots=True)
class RuntimeContract:
    applicationVersion: str
    files: Mapping[str, Path | str]
    observedHashes: Mapping[str, str]
    mainText: str
    wcdbMethods: tuple[str, ...]
    discoveredAffectedRoles: tuple[str, ...]
    observedAnchorCounts: Mapping[str, int] | None = None


@dataclass(frozen=True, slots=True)
class RedactedConfigContract:
    accountSelectorCount: int
    envelopeKinds: list[str]
    dbPathNodeType: str
    myWxidNodeType: str


@dataclass(frozen=True, slots=True)
class WcdbContract:
    methods: tuple[str, ...]
    adapterSha256: str
    engineSha256: str


@dataclass(frozen=True, slots=True)
class CompatibilityReport:
    schemaVersion: int
    runId: str
    applicationVersion: str
    runtimeHashes: dict[str, str]
    config: RedactedConfigContract
    wcdb: WcdbContract
    patchAnchors: dict[str, int]
    affectedFiles: tuple[str, ...]
    status: Literal["compatible", "compatibility_blocked"]
    reasonCodes: tuple[str, ...]

    def to_redacted_json(self) -> str:
        value = asdict(self)
        _validate_report_dict(value)
        return json.dumps(
            value, sort_keys=True, separators=(",", ":")
        )


def _validate_report_dict(value: dict) -> None:
    try:
        runtime_hashes = value["runtimeHashes"]
        config = value["config"]
        wcdb = value["wcdb"]
        anchors = value["patchAnchors"]
        affected = value["affectedFiles"]
        reasons = value["reasonCodes"]
        if (
            set(value) != {
                "schemaVersion",
                "runId",
                "applicationVersion",
                "runtimeHashes",
                "config",
                "wcdb",
                "patchAnchors",
                "affectedFiles",
                "status",
                "reasonCodes",
            }
            or value["schemaVersion"] != 1
            or str(uuid.UUID(value["runId"])) != value["runId"]
            or value["applicationVersion"] not in {"6.1.0", "unsupported"}
            or value["status"]
            not in {"compatible", "compatibility_blocked"}
            or not isinstance(runtime_hashes, dict)
            or set(runtime_hashes) != set(EXPECTED_HASHES)
            or not all(
                item == ""
                or (
                    isinstance(item, str)
                    and _HEX64_RE.fullmatch(item) is not None
                )
                for item in runtime_hashes.values()
            )
            or not isinstance(config, dict)
            or set(config)
            != {
                "accountSelectorCount",
                "envelopeKinds",
                "dbPathNodeType",
                "myWxidNodeType",
            }
            or type(config["accountSelectorCount"]) is not int
            or not 0 <= config["accountSelectorCount"] <= 2**31 - 1
            or not isinstance(config["envelopeKinds"], list)
            or config["envelopeKinds"]
            != sorted(set(config["envelopeKinds"]))
            or any(
                item not in {"safe", "lock", "other"}
                for item in config["envelopeKinds"]
            )
            or config["dbPathNodeType"]
            not in {"null", "str", "dict", "list", "int", "float", "bool"}
            or config["myWxidNodeType"]
            not in {"null", "str", "dict", "list", "int", "float", "bool"}
            or not isinstance(wcdb, dict)
            or set(wcdb)
            != {"methods", "adapterSha256", "engineSha256"}
            or tuple(wcdb["methods"]) != _REQUIRED_METHODS
            or any(
                item != ""
                and (
                    not isinstance(item, str)
                    or _HEX64_RE.fullmatch(item) is None
                )
                for item in (
                    wcdb["adapterSha256"],
                    wcdb["engineSha256"],
                )
            )
            or not isinstance(anchors, dict)
            or set(anchors) != set(EXPECTED_ANCHORS)
            or any(
                type(item) is not int or not 0 <= item <= 2**31 - 1
                for item in anchors.values()
            )
            or not isinstance(affected, (list, tuple))
            or tuple(affected)
            != tuple(
                role
                for role in (*_AFFECTED_ROLES, "unknown_role")
                if role in affected
            )
            or any(
                item not in {*_AFFECTED_ROLES, "unknown_role"}
                for item in affected
            )
            or not isinstance(reasons, (list, tuple))
            or tuple(reasons) != tuple(sorted(set(reasons)))
            or any(item not in _ALLOWED_REASON_CODES for item in reasons)
            or (value["status"] == "compatible") != (not reasons)
            or (
                value["status"] == "compatible"
                and (
                    value["applicationVersion"] != "6.1.0"
                    or runtime_hashes != EXPECTED_HASHES
                    or config
                    != {
                        "accountSelectorCount": 1,
                        "envelopeKinds": ["safe"],
                        "dbPathNodeType": "str",
                        "myWxidNodeType": "str",
                    }
                    or wcdb["adapterSha256"]
                    != EXPECTED_HASHES["wcdb_api"]
                    or wcdb["engineSha256"]
                    != EXPECTED_HASHES["WCDB.dll"]
                    or any(item != 1 for item in anchors.values())
                    or tuple(affected) != _AFFECTED_ROLES
                )
            )
        ):
            raise ValueError
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
    ) as error:
        raise RuntimeError("compatibility_report_schema_invalid") from error


def _same_file(*values) -> bool:
    return len(
        {
            (item.st_dev, item.st_ino, item.st_size)
            for item in values
        }
    ) == 1


def _reject_reparse_chain(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except OSError as error:
            raise RuntimeError("compatibility_path_unreadable") from error
        if (
            current.is_symlink()
            or getattr(info, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise RuntimeError("compatibility_reparse_rejected")


def _read_stable_ordinary_file(
    path: Path, *, maximum: int, error_code: str
) -> bytes:
    descriptor = None
    try:
        _reject_reparse_chain(path)
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(error_code)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _same_file(before, opened)
        ):
            raise RuntimeError(error_code)
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum:
            raise RuntimeError(error_code)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(named.st_mode)
            or not _same_file(before, opened, after, named)
            or after.st_size != len(payload)
        ):
            raise RuntimeError(error_code)
        return payload
    except RuntimeError:
        raise
    except OSError as error:
        raise RuntimeError(error_code) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def _decode_strict_json(payload: bytes, *, error_code: str):
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("nonfinite_json_number")
            ),
        )
    except (
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        RecursionError,
    ) as error:
        raise RuntimeError(error_code) from error


def _read_config(path: Path) -> dict:
    try:
        payload = _read_stable_ordinary_file(
            path,
            maximum=4 * 1024 * 1024,
            error_code="compatibility_config_json_invalid",
        )
    except RuntimeError as error:
        raise RuntimeError(
            "compatibility_config_json_invalid"
        ) from error
    value = _decode_strict_json(
        payload, error_code="compatibility_config_json_invalid"
    )
    if not isinstance(value, dict):
        raise RuntimeError("compatibility_config_json_invalid")
    return value


def _safe_envelope(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("safe:")
        and len(value) > len("safe:")
    )


def _envelope_kind(value: object) -> str:
    if _safe_envelope(value):
        return "safe"
    if isinstance(value, str) and value.startswith("lock:") and len(value) > 5:
        return "lock"
    return "other"


def _kind(value: object) -> str:
    return "null" if value is None else type(value).__name__


def _config_contract(value: dict) -> tuple[RedactedConfigContract, list[str]]:
    reasons = []
    selectors = value.get("wxidConfigs")
    selector_count = len(selectors) if isinstance(selectors, dict) else 0
    current_name = value.get("myWxid")
    current = (
        selectors.get(current_name)
        if isinstance(selectors, dict) and isinstance(current_name, str)
        else None
    )
    kinds = sorted(
        {
            _envelope_kind(value.get("decryptKey")),
            _envelope_kind(
                current.get("decryptKey")
                if isinstance(current, dict)
                else None
            ),
        }
    )
    if selector_count != 1:
        reasons.append("target_account_not_unique")
    if kinds != ["safe"]:
        reasons.append("unsupported_envelope_kind")
    schema_ok = (
        isinstance(value.get("dbPath"), str)
        and bool(value["dbPath"])
        and isinstance(value.get("cachePath"), str)
        and isinstance(current_name, str)
        and _ACCOUNT_RE.fullmatch(current_name) is not None
        and isinstance(selectors, dict)
        and isinstance(current, dict)
    )
    if isinstance(selectors, dict):
        schema_ok = schema_ok and all(
            isinstance(name, str)
            and _ACCOUNT_RE.fullmatch(name) is not None
            and isinstance(container, dict)
            for name, container in selectors.items()
        )
        for container in (value, *selectors.values()):
            if not isinstance(container, dict):
                schema_ok = False
                continue
            for field in _SECRET_FIELDS:
                if field in container and not _safe_envelope(container[field]):
                    schema_ok = False
    if not schema_ok:
        reasons.append("config_schema_invalid")
    return (
        RedactedConfigContract(
            accountSelectorCount=selector_count,
            envelopeKinds=kinds,
            dbPathNodeType=_kind(value.get("dbPath")),
            myWxidNodeType=_kind(current_name),
        ),
        reasons,
    )


def probe_compatibility(
    *, run_id: str, runtime: RuntimeContract, config_path: Path
) -> CompatibilityReport:
    try:
        if str(uuid.UUID(run_id)) != run_id:
            raise ValueError
    except (ValueError, AttributeError, TypeError) as error:
        raise RuntimeError("compatibility_run_id_invalid") from error
    reasons = []
    expected_keys = set(EXPECTED_HASHES)
    observed_keys = set(runtime.observedHashes)
    if observed_keys != expected_keys:
        reasons.append("runtime_hash_contract_invalid")
    rendered_hashes = {}
    for name, expected in EXPECTED_HASHES.items():
        observed = runtime.observedHashes.get(name)
        valid = (
            isinstance(observed, str)
            and _HEX64_RE.fullmatch(observed) is not None
        )
        rendered_hashes[name] = observed if valid else ""
        if observed != expected:
            reasons.append(
                name.lower().replace(".", "_").replace("-", "_")
                + "_hash_mismatch"
            )
    application_version = (
        "6.1.0"
        if runtime.applicationVersion == "6.1.0"
        else "unsupported"
    )
    if application_version != "6.1.0":
        reasons.append("application_version_mismatch")
    if runtime.observedAnchorCounts is None:
        raw_anchors = {
            name: runtime.mainText.count(anchor)
            for name, anchor in EXPECTED_ANCHORS.items()
        }
        wcdb_index = runtime.mainText.find("z=new rn")
        boot_index = runtime.mainText.find(EXPECTED_ANCHORS["boot"])
        ready_index = runtime.mainText.find(EXPECTED_ANCHORS["ready"])
        if (
            runtime.mainText.count("z=new rn") != 1
            or runtime.mainText.count("kX=new e.t") != 1
            or not wcdb_index < boot_index < ready_index
        ):
            reasons.append("main_anchor_contract_invalid")
    else:
        raw_anchors = dict(runtime.observedAnchorCounts)
    if set(raw_anchors) != set(EXPECTED_ANCHORS):
        reasons.append("main_anchor_contract_invalid")
    anchors = {
        name: (
            raw_anchors.get(name)
            if type(raw_anchors.get(name)) is int
            and 0 <= raw_anchors[name] <= 2**31 - 1
            else 0
        )
        for name in EXPECTED_ANCHORS
    }
    if any(value != 1 for value in anchors.values()):
        reasons.append("main_anchor_mismatch")
    if tuple(runtime.wcdbMethods) != _REQUIRED_METHODS:
        reasons.append("wcdb_method_contract_mismatch")
    raw_roles = tuple(runtime.discoveredAffectedRoles)
    valid_roles = (
        all(isinstance(role, str) for role in raw_roles)
        and len(set(raw_roles)) == len(raw_roles)
        and tuple(sorted(raw_roles)) == _AFFECTED_ROLES
    )
    if not valid_roles:
        reasons.append("affected_file_contract_invalid")
    affected = list(
        role for role in _AFFECTED_ROLES if role in set(raw_roles)
    )
    if any(role not in _AFFECTED_ROLES for role in raw_roles):
        affected.append("unknown_role")
    config, config_reasons = _config_contract(_read_config(config_path))
    reasons.extend(config_reasons)
    wcdb = WcdbContract(
        methods=_REQUIRED_METHODS,
        adapterSha256=rendered_hashes.get("wcdb_api", ""),
        engineSha256=rendered_hashes.get("WCDB.dll", ""),
    )
    unique_reasons = tuple(sorted(set(reasons)))
    return CompatibilityReport(
        schemaVersion=1,
        runId=run_id,
        applicationVersion=application_version,
        runtimeHashes=rendered_hashes,
        config=config,
        wcdb=wcdb,
        patchAnchors=anchors,
        affectedFiles=tuple(affected),
        status=(
            "compatible" if not unique_reasons else "compatibility_blocked"
        ),
        reasonCodes=unique_reasons,
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest().upper()


def _read_asar_metadata(archive_payload: bytes) -> dict:
    try:
        if len(archive_payload) < 8:
            raise ValueError
        size_payload = int.from_bytes(
            archive_payload[0:4], "little", signed=False
        )
        header_size = int.from_bytes(
            archive_payload[4:8], "little", signed=False
        )
        if (
            size_payload != 4
            or header_size < 8
            or header_size > 16 * 1024 * 1024
            or 8 + header_size > len(archive_payload)
        ):
            raise ValueError
        header_pickle = archive_payload[8 : 8 + header_size]
        header_payload_size = int.from_bytes(
            header_pickle[0:4], "little", signed=False
        )
        json_size = int.from_bytes(
            header_pickle[4:8], "little", signed=False
        )
        aligned_json_size = (json_size + 3) & ~3
        if (
            header_payload_size != 4 + aligned_json_size
            or header_size != 4 + header_payload_size
            or any(header_pickle[8 + json_size :])
        ):
            raise ValueError
        header = _decode_strict_json(
            header_pickle[8 : 8 + json_size],
            error_code="formal_asar_reader_schema_mismatch",
        )
        if not isinstance(header, dict) or set(header) != {"files"}:
            raise ValueError
        extracted = {}
        ranges = []
        data_start = 8 + header_size
        for name, internal in _FORMAL_ASAR_ENTRIES.items():
            node = header
            for component in internal.split("/"):
                if node.get("unpacked") is True or "link" in node:
                    raise ValueError
                files = node.get("files")
                if (
                    not isinstance(files, dict)
                    or component not in files
                    or not isinstance(files[component], dict)
                ):
                    raise ValueError
                node = files[component]
            size = node.get("size")
            offset = node.get("offset")
            if (
                type(size) is not int
                or size <= 0
                or not isinstance(offset, str)
                or re.fullmatch(r"0|[1-9][0-9]*", offset) is None
                or node.get("unpacked") is True
                or "link" in node
            ):
                raise ValueError
            start = data_start + int(offset)
            end = start + size
            if start < data_start or end > len(archive_payload):
                raise ValueError
            extracted[name] = archive_payload[start:end]
            ranges.append((start, end))
        if any(
            first_start < second_end
            and second_start < first_end
            for index, (first_start, first_end) in enumerate(ranges)
            for second_start, second_end in ranges[index + 1 :]
        ):
            raise ValueError
        texts = {
            name: payload.decode("utf-8")
            for name, payload in extracted.items()
        }
    except (
        AttributeError,
        IndexError,
        KeyError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        raise RuntimeError(
            "formal_asar_reader_schema_mismatch"
        ) from error
    main = texts["main.js"]
    return {
        "hashes": {
            name: _sha256(payload)
            for name, payload in extracted.items()
        },
        "anchorCounts": {
            name: main.count(anchor)
            for name, anchor in EXPECTED_ANCHORS.items()
        },
        "roleEvidence": {
            "config": (
                "dbPath" in texts["config-chunk"]
                and "decryptKey" in texts["config-chunk"]
            ),
            "cache_maps": "snsPageCacheMap" in main,
            "analytics_cache": "analytics_cache" in main,
        },
    }


def discover_fixed_runtime_contract(contract) -> RuntimeContract:
    formal_exe = canonical_existing(contract.formal_weflow)
    if formal_exe != contract.formal_weflow:
        raise RuntimeError("formal_runtime_root_boundary_mismatch")
    root = formal_exe.parent
    disk_paths = {
        "WeFlow.exe": formal_exe,
        "app.asar": root / "resources" / "app.asar",
        "wcdb_api": (
            root
            / "resources"
            / "resources"
            / "wcdb"
            / "win32"
            / "x64"
            / "wcdb_api.dll"
        ),
        "WCDB.dll": (
            root
            / "resources"
            / "resources"
            / "wcdb"
            / "win32"
            / "x64"
            / "WCDB.dll"
        ),
    }
    payloads = {
        name: _read_stable_ordinary_file(
            path,
            maximum=512 * 1024 * 1024,
            error_code="runtime_artifact_not_ordinary",
        )
        for name, path in disk_paths.items()
    }
    observed = {name: _sha256(payload) for name, payload in payloads.items()}
    if observed["app.asar"] != EXPECTED_HASHES["app.asar"]:
        raise RuntimeError("formal_asar_hash_mismatch")
    extracted = _read_asar_metadata(payloads["app.asar"])
    for name, path in disk_paths.items():
        if payloads[name] != _read_stable_ordinary_file(
            path,
            maximum=512 * 1024 * 1024,
            error_code="runtime_artifact_not_ordinary",
        ):
            raise RuntimeError("runtime_artifact_changed")
    observed.update(extracted["hashes"])
    if observed != EXPECTED_HASHES:
        raise RuntimeError("runtime_or_asar_contract_mismatch")
    if not all(extracted["roleEvidence"].values()):
        raise RuntimeError("affected_role_evidence_missing")
    files = dict(disk_paths)
    files.update(
        {
            "main.js": "app.asar!/dist-electron/main.js",
            "config-chunk": (
                "app.asar!/dist-electron/config-C9Ue62at.js"
            ),
            "worker": "app.asar!/dist-electron/wcdbWorker.js",
        }
    )
    return RuntimeContract(
        applicationVersion="6.1.0",
        files=files,
        observedHashes=observed,
        mainText="",
        wcdbMethods=_REQUIRED_METHODS,
        discoveredAffectedRoles=(
            "config",
            "cache_maps",
            "analytics_cache",
        ),
        observedAnchorCounts=extracted["anchorCounts"],
    )


def write_compatibility_report(
    run_root: Path, report: CompatibilityReport
) -> Path:
    layout = RunLayout.from_existing_root(run_root)
    if not layout.root.name.endswith(f"-{report.runId}"):
        raise RuntimeError("compatibility_report_run_id_mismatch")
    destination = layout.compatibility_path
    payload = report.to_redacted_json().encode("utf-8")
    expected_value = _decode_strict_json(
        payload, error_code="compatibility_report_schema_invalid"
    )
    if not isinstance(expected_value, dict):
        raise RuntimeError("compatibility_report_schema_invalid")
    _validate_report_dict(expected_value)
    with _pin_directory(layout.root) as pin:
        pin.verify()
        if os.path.lexists(destination):
            raise RuntimeError("compatibility_report_destination_exists")
        temporary = layout.root / (
            f".compatibility.json.{uuid.uuid4()}.tmp"
        )
        descriptor = None
        published_identity = None
        completed = False
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOINHERIT", 0),
                0o600,
            )
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("compatibility_report_short_write")
                remaining = remaining[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            pin.verify()
            os.link(temporary, destination)
            before = temporary.lstat()
            published = destination.lstat()
            if not _same_file(before, published):
                raise RuntimeError("compatibility_report_publish_failed")
            published_identity = (
                published.st_dev,
                published.st_ino,
            )
            reread = _read_stable_ordinary_file(
                destination,
                maximum=1024 * 1024,
                error_code="compatibility_report_reread_failed",
            )
            if (
                reread != payload
                or _decode_strict_json(
                    reread,
                    error_code="compatibility_report_reread_failed",
                )
                != expected_value
            ):
                raise RuntimeError("compatibility_report_reread_failed")
            pin.verify()
            completed = True
            return destination
        except FileExistsError as error:
            raise RuntimeError(
                "compatibility_report_destination_exists"
            ) from error
        except RuntimeError:
            raise
        except OSError as error:
            raise RuntimeError("compatibility_report_publish_failed") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if (
                not completed
                and published_identity is not None
                and os.path.lexists(destination)
            ):
                current = destination.lstat()
                if (
                    current.st_dev,
                    current.st_ino,
                ) == published_identity:
                    destination.unlink()
            if os.path.lexists(temporary):
                temporary.unlink()
