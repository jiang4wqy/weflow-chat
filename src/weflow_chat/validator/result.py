import json
import os
from pathlib import Path
import re
import stat
import uuid


class ValidationResultError(RuntimeError):
    pass


_TOP = {
    "version",
    "runId",
    "operation",
    "status",
    "reasonCode",
    "gates",
    "validation",
    "callsBeforeOpen",
}
_GATES = {
    "userDataIsolated",
    "documentsIsolated",
    "singleInstanceLockAcquired",
    "safeStorageAvailable",
    "syntheticEnvelopeRoundtrip",
    "nativeProtectionAuthenticated",
    "workerSetPathsCalled",
}
_VALIDATION = {
    "databaseCount",
    "tableCount",
    "recordCount",
    "minTimestamp",
    "maxTimestamp",
    "schemaFingerprint",
    "aggregateFingerprint",
    "databaseCoverageFingerprint",
}
_AVATAR_AGGREGATE = {
    "version",
    "candidateContactCount",
    "avatarUrlCount",
    "headImageBufferCount",
    "finalAvatarCount",
    "missingAvatarCount",
    "reasonCounts",
}
_AVATAR_REASONS = {
    "urlOnly",
    "headImageBufferOnly",
    "urlAndHeadImageBuffer",
    "noSupportedSource",
}
_MEDIA_OPENABILITY = {
    "version",
    "candidateCount",
    "imageCandidateCount",
    "videoCandidateCount",
    "locallyUnavailableCount",
    "localFileCount",
    "readableImageCount",
    "readableVideoCount",
    "unreadableLocalCount",
}
_OPERATIONS = {
    "avatar-aggregate",
    "media-openability",
    "smoke",
    "safe-envelope-roundtrip",
    "validate-snapshot",
}
_STATUSES = {"ok", "compatibility_blocked"}
_REASONS = {
    None,
    "validator_unhandled",
    "single_instance_lock_denied",
    "safe_storage_unavailable",
    "electron_path_mismatch",
    "safe_envelope_roundtrip_failed",
    "safe_envelope_contract",
    "connection_failed",
    "open_failed",
    "sessions_failed",
    "aggregate_failed",
    "media_probe_failed",
    "worker_contract_mismatch",
}
_HEX = re.compile(r"^[0-9A-F]{64}$")
_MAX_BYTES = 64 * 1024
_MAX_SAFE_INTEGER = 2**53 - 1
_OK_GATES = {
    "smoke": {
        "userDataIsolated": True,
        "documentsIsolated": True,
        "singleInstanceLockAcquired": True,
        "safeStorageAvailable": True,
        "syntheticEnvelopeRoundtrip": False,
        "nativeProtectionAuthenticated": False,
        "workerSetPathsCalled": False,
    },
    "safe-envelope-roundtrip": {
        "userDataIsolated": True,
        "documentsIsolated": True,
        "singleInstanceLockAcquired": True,
        "safeStorageAvailable": True,
        "syntheticEnvelopeRoundtrip": True,
        "nativeProtectionAuthenticated": False,
        "workerSetPathsCalled": False,
    },
    "validate-snapshot": {
        "userDataIsolated": True,
        "documentsIsolated": True,
        "singleInstanceLockAcquired": True,
        "safeStorageAvailable": True,
        "syntheticEnvelopeRoundtrip": False,
        "nativeProtectionAuthenticated": True,
        "workerSetPathsCalled": True,
    },
    "avatar-aggregate": {
        "userDataIsolated": True,
        "documentsIsolated": True,
        "singleInstanceLockAcquired": True,
        "safeStorageAvailable": True,
        "syntheticEnvelopeRoundtrip": False,
        "nativeProtectionAuthenticated": True,
        "workerSetPathsCalled": True,
    },
    "media-openability": {
        "userDataIsolated": True,
        "documentsIsolated": True,
        "singleInstanceLockAcquired": True,
        "safeStorageAvailable": True,
        "syntheticEnvelopeRoundtrip": False,
        "nativeProtectionAuthenticated": True,
        "workerSetPathsCalled": True,
    },
}


def _fail(code="result_schema_mismatch"):
    raise ValidationResultError(code)


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("result_json_invalid")
        result[key] = value
    return result


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
            _fail("result_path_invalid")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(before, opened):
            _fail("result_path_changed")
        chunks = []
        remaining = _MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(16 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_BYTES:
            _fail("result_too_large")
        after = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(named.st_mode)
            or not _same_file(before, opened, after, named)
            or after.st_size != len(payload)
        ):
            _fail("result_path_changed")
        return payload
    except ValidationResultError:
        raise
    except OSError as error:
        raise ValidationResultError("result_path_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _decode_strict_json(raw_bytes: bytes):
    try:
        return json.loads(
            raw_bytes.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: _fail("result_json_invalid"),
        )
    except ValidationResultError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValidationResultError("result_json_invalid") from error


def _safe_integer(value, *, nonnegative: bool = False) -> bool:
    return (
        type(value) is int
        and -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER
        and (not nonnegative or value >= 0)
    )


def read_validation_result(
    path: Path, *, expected_run_id: str, expected_operation: str
) -> dict:
    try:
        if (
            not isinstance(expected_run_id, str)
            or str(uuid.UUID(expected_run_id)) != expected_run_id
        ):
            raise ValueError
    except (ValueError, AttributeError, TypeError) as error:
        raise ValidationResultError("result_run_id_invalid") from error
    if (
        not isinstance(expected_operation, str)
        or expected_operation not in _OPERATIONS
    ):
        _fail()
    raw_bytes = _read_bounded_ordinary_file(Path(path))
    value = _decode_strict_json(raw_bytes)
    if (
        not isinstance(value, dict)
        or set(value) != _TOP
        or type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["runId"], str)
        or value["runId"] != expected_run_id
        or not isinstance(value["operation"], str)
        or value["operation"] != expected_operation
        or value["operation"] not in _OPERATIONS
        or not isinstance(value["status"], str)
        or value["status"] not in _STATUSES
        or (
            value["reasonCode"] is not None
            and not isinstance(value["reasonCode"], str)
        )
        or value["reasonCode"] not in _REASONS
        or (value["status"] == "ok") != (value["reasonCode"] is None)
    ):
        _fail()
    if expected_operation == "media-openability" and value[
        "reasonCode"
    ] not in {None, "connection_failed", "open_failed", "media_probe_failed"}:
        _fail()
    gates = value["gates"]
    if (
        not isinstance(gates, dict)
        or set(gates) != _GATES
        or any(type(item) is not bool for item in gates.values())
    ):
        _fail()
    calls = value["callsBeforeOpen"]
    if not isinstance(calls, list) or calls not in (
        [],
        ["setPaths"],
        ["setPaths", "testConnection"],
    ):
        _fail()
    validation = value["validation"]
    if value["status"] == "ok":
        expected_calls = (
            ["setPaths", "testConnection"]
            if expected_operation
            in {
                "avatar-aggregate",
                "media-openability",
                "validate-snapshot",
            }
            else []
        )
        if gates != _OK_GATES[expected_operation] or calls != expected_calls:
            _fail("result_gate_mismatch")
    elif (
        gates["nativeProtectionAuthenticated"]
        or validation is not None
        or gates["workerSetPathsCalled"] != ("setPaths" in calls)
    ):
        _fail("result_gate_mismatch")
    if expected_operation == "avatar-aggregate" and value["status"] == "ok":
        _validate_avatar_aggregate(validation)
    elif (
        expected_operation == "media-openability"
        and value["status"] == "ok"
    ):
        _validate_media_openability(validation)
    elif expected_operation == "validate-snapshot" and value["status"] == "ok":
        if not isinstance(validation, dict) or set(validation) != _VALIDATION:
            _fail()
        for name in ("databaseCount", "tableCount", "recordCount"):
            if not _safe_integer(validation[name], nonnegative=True):
                _fail()
        for name in ("minTimestamp", "maxTimestamp"):
            if (
                validation[name] is not None
                and not _safe_integer(validation[name])
            ):
                _fail()
        minimum = validation["minTimestamp"]
        maximum = validation["maxTimestamp"]
        if (minimum is None) != (maximum is None) or (
            minimum is not None and minimum > maximum
        ):
            _fail()
        for name in (
            "schemaFingerprint",
            "aggregateFingerprint",
            "databaseCoverageFingerprint",
        ):
            if (
                not isinstance(validation[name], str)
                or not _HEX.fullmatch(validation[name])
            ):
                _fail("result_invalid_fingerprint")
    elif validation is not None:
        _fail()
    encoded = raw_bytes.decode("utf-8")
    if re.search(
        r"decryptKey|imageAesKey|imageXorKey|username|content|stack|"
        r"safe:|wxid_|[A-Za-z]:\\|\\\\",
        encoded,
        re.I,
    ):
        _fail("result_sensitive_field")
    return value


def read_avatar_aggregate_result(path: Path) -> dict:
    raw_bytes = _read_bounded_ordinary_file(Path(path))
    value = _decode_strict_json(raw_bytes)
    return _validate_avatar_aggregate(value)


def _validate_avatar_aggregate(value: object) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != _AVATAR_AGGREGATE
        or not isinstance(value["reasonCounts"], dict)
        or set(value["reasonCounts"]) != _AVATAR_REASONS
        or type(value["version"]) is not int
        or value["version"] != 1
        or any(
            not _safe_integer(value[name], nonnegative=True)
            for name in (
                "candidateContactCount",
                "avatarUrlCount",
                "headImageBufferCount",
                "finalAvatarCount",
                "missingAvatarCount",
            )
        )
        or any(
            not _safe_integer(count, nonnegative=True)
            for count in value["reasonCounts"].values()
        )
    ):
        _fail("avatar_aggregate_schema_mismatch")
    reasons = value["reasonCounts"]
    expected = {
        "candidateContactCount": (
            reasons["urlOnly"]
            + reasons["headImageBufferOnly"]
            + reasons["urlAndHeadImageBuffer"]
            + reasons["noSupportedSource"]
        ),
        "avatarUrlCount": (
            reasons["urlOnly"] + reasons["urlAndHeadImageBuffer"]
        ),
        "headImageBufferCount": (
            reasons["headImageBufferOnly"]
            + reasons["urlAndHeadImageBuffer"]
        ),
        "finalAvatarCount": (
            reasons["urlOnly"]
            + reasons["headImageBufferOnly"]
            + reasons["urlAndHeadImageBuffer"]
        ),
        "missingAvatarCount": reasons["noSupportedSource"],
    }
    if any(
        not _safe_integer(count, nonnegative=True)
        or value[name] != count
        for name, count in expected.items()
    ):
        _fail("avatar_aggregate_count_mismatch")
    return value


def _validate_media_openability(value: object) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != _MEDIA_OPENABILITY
        or type(value["version"]) is not int
        or value["version"] != 1
        or any(
            not _safe_integer(value[name], nonnegative=True)
            for name in _MEDIA_OPENABILITY - {"version"}
        )
        or value["candidateCount"]
        != value["imageCandidateCount"] + value["videoCandidateCount"]
        or value["candidateCount"]
        != value["locallyUnavailableCount"] + value["localFileCount"]
        or value["localFileCount"]
        != (
            value["readableImageCount"]
            + value["readableVideoCount"]
            + value["unreadableLocalCount"]
        )
    ):
        _fail("media_openability_schema_mismatch")
    if value["unreadableLocalCount"] != 0:
        _fail("media_openability_unreadable")
    return value
