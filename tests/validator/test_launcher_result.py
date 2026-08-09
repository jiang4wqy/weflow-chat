import copy
import inspect
from pathlib import Path
import subprocess

import pytest

from weflow_chat.validator.launcher import (
    _assert_no_reparse_chain,
    _launch_validator_for_test,
    launch_avatar_aggregate,
    launch_validator,
)
from weflow_chat.validator.result import (
    ValidationResultError,
    read_validation_result,
)
from weflow_chat.validator.launcher import ValidatorBlockedError


def test_launcher_refuses_when_formal_weflow_is_running(validator_layout):
    with pytest.raises(ValidatorBlockedError, match="formal_weflow_running"):
        _launch_validator_for_test(
            layout=validator_layout,
            request_payload={
                "operation": "smoke",
                "runId": "00000000-0000-4000-8000-000000000001",
            },
            process_paths=(
                r"X:\synthetic\WeFlow\WeFlow.exe",
            ),
            verify_runtime=lambda layout: None,
            runner=lambda *args, **kwargs: None,
        )


def test_launcher_fails_closed_when_weflow_path_is_unknown(validator_layout):
    with pytest.raises(RuntimeError, match="formal_process_path_unknown"):
        _launch_validator_for_test(
            layout=validator_layout,
            request_payload={
                "operation": "smoke",
                "runId": "00000000-0000-4000-8000-000000000001",
            },
            process_paths=({"Name": "WeFlow.exe", "ExecutablePath": None},),
            verify_runtime=lambda layout: None,
            runner=lambda *args, **kwargs: None,
        )


def test_timeout_waits_for_child_exit(validator_layout, monkeypatch):
    class TimedOutProcess:
        def __init__(self):
            self.waits = []
            self.signals = []

        def wait(self, timeout):
            self.waits.append(timeout)
            if len(self.waits) == 1:
                raise subprocess.TimeoutExpired("validator", timeout)
            return 70

        def send_signal(self, value):
            self.signals.append(value)

    process = TimedOutProcess()
    monkeypatch.setattr(
        "weflow_chat.validator.launcher._write_request",
        lambda *args, **kwargs: None,
    )
    with pytest.raises(ValidatorBlockedError, match="validator_timeout"):
        _launch_validator_for_test(
            layout=validator_layout,
            request_payload={
                "operation": "smoke",
                "runId": "00000000-0000-4000-8000-000000000001",
            },
            process_paths=(),
            verify_runtime=lambda layout: None,
            runner=lambda *args, **kwargs: process,
            reparse_check=lambda *args, **kwargs: None,
        )
    assert process.waits == [600, 30]
    assert len(process.signals) == 1


def test_lexical_chain_rejects_relative_mismatch_with_fixed_error(tmp_path):
    root = tmp_path / "run"
    root.mkdir()
    with pytest.raises(ValidatorBlockedError, match="validator_path_rejected"):
        _assert_no_reparse_chain(root, tmp_path / "outside")


def test_broken_link_is_rejected_even_when_exists_is_false(tmp_path):
    root = tmp_path / "run"
    root.mkdir()
    broken = root / "broken"
    try:
        broken.symlink_to(root / "missing", target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValidatorBlockedError, match="validator_reparse_rejected"):
        _assert_no_reparse_chain(root, broken / "request.json")


def test_reparse_preflight_blocks_request_write_and_runner(
    validator_layout, monkeypatch
):
    writes, runs = [], []
    monkeypatch.setattr(
        "weflow_chat.validator.launcher._write_request",
        lambda *args, **kwargs: writes.append(args),
    )

    def replaced_root(root, target, *, require_target=False):
        raise ValidatorBlockedError("validator_reparse_rejected")

    with pytest.raises(
        ValidatorBlockedError, match="validator_reparse_rejected"
    ):
        _launch_validator_for_test(
            layout=validator_layout,
            request_payload={
                "operation": "smoke",
                "runId": "00000000-0000-4000-8000-000000000001",
            },
            process_paths=(),
            verify_runtime=lambda layout: None,
            runner=lambda *args, **kwargs: runs.append(args),
            reparse_check=replaced_root,
        )
    assert writes == []
    assert runs == []


def test_launcher_discards_all_child_stdio(validator_layout, monkeypatch):
    class Completed:
        def wait(self, timeout):
            return 0

    captured = {}
    monkeypatch.setattr(
        "weflow_chat.validator.launcher._write_request",
        lambda *args, **kwargs: None,
    )

    def runner(*args, **kwargs):
        captured.update(kwargs)
        return Completed()

    _launch_validator_for_test(
        layout=validator_layout,
        request_payload={
            "operation": "smoke",
            "runId": "00000000-0000-4000-8000-000000000001",
        },
        process_paths=(),
        verify_runtime=lambda layout: None,
        runner=runner,
        reparse_check=lambda *args, **kwargs: None,
    )
    assert captured["stdin"] is subprocess.DEVNULL
    assert captured["stdout"] is subprocess.DEVNULL
    assert captured["stderr"] is subprocess.DEVNULL


def test_public_launcher_has_no_process_or_runner_injection():
    assert tuple(inspect.signature(launch_validator).parameters) == (
        "layout",
        "request_payload",
        "formal_weflow",
        "snapshots_root",
    )


def test_avatar_launcher_accepts_only_fixed_counts_in_the_main_result(
    validator_layout,
    monkeypatch,
):
    aggregate = {
        "version": 1,
        "candidateContactCount": 2,
        "avatarUrlCount": 1,
        "headImageBufferCount": 1,
        "finalAvatarCount": 2,
        "missingAvatarCount": 0,
        "reasonCounts": {
            "urlOnly": 1,
            "headImageBufferOnly": 1,
            "urlAndHeadImageBuffer": 0,
            "noSupportedSource": 0,
        },
    }
    monkeypatch.setattr(
        "weflow_chat.validator.launcher.launch_validator",
        lambda _layout, _request_payload, **_kwargs: {
            "status": "ok",
            "reasonCode": None,
            "validation": aggregate,
        },
    )

    result = launch_avatar_aggregate(
        validator_layout,
        {
            "operation": "avatar-aggregate",
            "runId": "00000000-0000-4000-8000-000000000001",
            "area": "validation",
        },
        formal_weflow=Path(r"X:\synthetic\WeFlow.exe"),
        snapshots_root=validator_layout.run_root.parent,
    )

    assert result == aggregate
    assert tuple(inspect.signature(launch_avatar_aggregate).parameters) == (
        "layout",
        "request_payload",
        "formal_weflow",
        "snapshots_root",
    )


def test_result_accepts_exact_media_openability_counts(
    tmp_path, valid_result_payload, write_result
):
    payload = copy.deepcopy(valid_result_payload)
    payload["operation"] = "media-openability"
    payload["validation"] = {
        "version": 1,
        "candidateCount": 3,
        "imageCandidateCount": 2,
        "videoCandidateCount": 1,
        "locallyUnavailableCount": 1,
        "localFileCount": 2,
        "readableImageCount": 1,
        "readableVideoCount": 1,
        "unreadableLocalCount": 0,
    }

    result = read_validation_result(
        write_result(tmp_path, payload),
        expected_run_id=payload["runId"],
        expected_operation="media-openability",
    )

    assert result["validation"] == payload["validation"]


def test_result_rejects_unreadable_local_media(
    tmp_path, valid_result_payload, write_result
):
    payload = copy.deepcopy(valid_result_payload)
    payload["operation"] = "media-openability"
    payload["validation"] = {
        "version": 1,
        "candidateCount": 1,
        "imageCandidateCount": 1,
        "videoCandidateCount": 0,
        "locallyUnavailableCount": 0,
        "localFileCount": 1,
        "readableImageCount": 0,
        "readableVideoCount": 0,
        "unreadableLocalCount": 1,
    }

    with pytest.raises(
        ValidationResultError, match="^media_openability_unreadable$"
    ):
        read_validation_result(
            write_result(tmp_path, payload),
            expected_run_id=payload["runId"],
            expected_operation="media-openability",
        )


def test_media_openability_rejects_non_media_failure_reason(
    tmp_path, valid_result_payload, write_result
):
    payload = copy.deepcopy(valid_result_payload)
    payload.update(
        operation="media-openability",
        status="compatibility_blocked",
        reasonCode="aggregate_failed",
        validation=None,
    )
    payload["gates"]["nativeProtectionAuthenticated"] = False

    with pytest.raises(
        ValidationResultError, match="^result_schema_mismatch$"
    ):
        read_validation_result(
            write_result(tmp_path, payload),
            expected_run_id=payload["runId"],
            expected_operation="media-openability",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", True),
        ("candidateCount", 0.0),
        ("imageCandidateCount", -1),
        ("videoCandidateCount", 2**53),
        ("candidateCount", 1),
    ],
)
def test_media_openability_requires_safe_partitioned_counts(
    tmp_path, valid_result_payload, write_result, field, value
):
    payload = copy.deepcopy(valid_result_payload)
    payload["operation"] = "media-openability"
    payload["validation"] = {
        "version": 1,
        "candidateCount": 0,
        "imageCandidateCount": 0,
        "videoCandidateCount": 0,
        "locallyUnavailableCount": 0,
        "localFileCount": 0,
        "readableImageCount": 0,
        "readableVideoCount": 0,
        "unreadableLocalCount": 0,
    }
    payload["validation"][field] = value

    with pytest.raises(
        ValidationResultError,
        match="^media_openability_schema_mismatch$",
    ):
        read_validation_result(
            write_result(tmp_path, payload),
            expected_run_id=payload["runId"],
            expected_operation="media-openability",
        )


@pytest.mark.parametrize("field", ["candidateCount", "detail"])
def test_media_openability_requires_exact_count_fields(
    tmp_path, valid_result_payload, write_result, field
):
    payload = copy.deepcopy(valid_result_payload)
    payload["operation"] = "media-openability"
    payload["validation"] = {
        "version": 1,
        "candidateCount": 0,
        "imageCandidateCount": 0,
        "videoCandidateCount": 0,
        "locallyUnavailableCount": 0,
        "localFileCount": 0,
        "readableImageCount": 0,
        "readableVideoCount": 0,
        "unreadableLocalCount": 0,
    }
    if field == "detail":
        payload["validation"][field] = {
            "url": "https://forbidden.invalid/media",
            "filename": "forbidden.jpg",
            "identifier": "forbidden-session",
            "sql": "select forbidden",
            "bytes": "FFD8FFE0",
            "base64": "RkZEOEZGRTQ=",
            "hash": "D" * 64,
            "key": "forbidden-key",
        }
    else:
        payload["validation"].pop(field)

    with pytest.raises(ValidationResultError):
        read_validation_result(
            write_result(tmp_path, payload),
            expected_run_id=payload["runId"],
            expected_operation="media-openability",
        )


def test_result_rejects_secret_fields(tmp_path):
    path = tmp_path / "result.json"
    path.write_text(
        '{"version":1,"runId":"00000000-0000-4000-8000-000000000001",'
        '"status":"ok","decryptKey":"x"}',
        encoding="utf-8",
    )
    with pytest.raises(ValidationResultError):
        read_validation_result(
            path,
            expected_run_id="00000000-0000-4000-8000-000000000001",
            expected_operation="validate-snapshot",
        )


def test_result_requires_all_three_uppercase_fingerprints(
    tmp_path, valid_result_payload, write_result
):
    for field in (
        "schemaFingerprint",
        "aggregateFingerprint",
        "databaseCoverageFingerprint",
    ):
        payload = copy.deepcopy(valid_result_payload)
        payload["validation"].pop(field)
        path = write_result(tmp_path, payload)
        with pytest.raises(
            ValidationResultError, match="result_schema_mismatch"
        ):
            read_validation_result(
                path,
                expected_run_id="00000000-0000-4000-8000-000000000001",
                expected_operation="validate-snapshot",
            )

    payload = copy.deepcopy(valid_result_payload)
    payload["validation"]["schemaFingerprint"] = "a" * 64
    path = write_result(tmp_path, payload)
    with pytest.raises(
        ValidationResultError, match="result_invalid_fingerprint"
    ):
        read_validation_result(
            path,
            expected_run_id="00000000-0000-4000-8000-000000000001",
            expected_operation="validate-snapshot",
        )


def test_every_operation_uses_the_same_top_level_schema(
    tmp_path, valid_result_payload, write_result
):
    keys = set(valid_result_payload)
    exact_gates = {
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
        "avatar-aggregate": valid_result_payload["gates"],
        "media-openability": valid_result_payload["gates"],
        "validate-snapshot": valid_result_payload["gates"],
    }
    for operation in (
        "avatar-aggregate",
        "media-openability",
        "smoke",
        "safe-envelope-roundtrip",
        "validate-snapshot",
    ):
        payload = copy.deepcopy(valid_result_payload)
        payload["operation"] = operation
        payload["gates"] = copy.deepcopy(exact_gates[operation])
        if operation == "avatar-aggregate":
            payload["validation"] = {
                "version": 1,
                "candidateContactCount": 2,
                "avatarUrlCount": 1,
                "headImageBufferCount": 1,
                "finalAvatarCount": 2,
                "missingAvatarCount": 0,
                "reasonCounts": {
                    "urlOnly": 1,
                    "headImageBufferOnly": 1,
                    "urlAndHeadImageBuffer": 0,
                    "noSupportedSource": 0,
                },
            }
        elif operation == "media-openability":
            payload["validation"] = {
                "version": 1,
                "candidateCount": 0,
                "imageCandidateCount": 0,
                "videoCandidateCount": 0,
                "locallyUnavailableCount": 0,
                "localFileCount": 0,
                "readableImageCount": 0,
                "readableVideoCount": 0,
                "unreadableLocalCount": 0,
            }
        elif operation != "validate-snapshot":
            payload["validation"] = None
        if operation not in {
            "avatar-aggregate",
            "media-openability",
            "validate-snapshot",
        }:
            payload["callsBeforeOpen"] = []
        path = write_result(tmp_path, payload)
        value = read_validation_result(
            path,
            expected_run_id=payload["runId"],
            expected_operation=operation,
        )
        assert set(value) == keys


def test_ok_validation_rejects_every_gate_or_call_drift(
    tmp_path, valid_result_payload, write_result
):
    for name in valid_result_payload["gates"]:
        payload = copy.deepcopy(valid_result_payload)
        payload["gates"][name] = not payload["gates"][name]
        with pytest.raises(ValidationResultError, match="result_gate_mismatch"):
            read_validation_result(
                write_result(tmp_path, payload),
                expected_run_id=payload["runId"],
                expected_operation="validate-snapshot",
            )
    payload = copy.deepcopy(valid_result_payload)
    payload["callsBeforeOpen"] = ["setPaths"]
    with pytest.raises(ValidationResultError, match="result_gate_mismatch"):
        read_validation_result(
            write_result(tmp_path, payload),
            expected_run_id=payload["runId"],
            expected_operation="validate-snapshot",
        )


def test_blocked_result_cannot_claim_native_or_validation(
    tmp_path, valid_result_payload, write_result
):
    payload = copy.deepcopy(valid_result_payload)
    payload.update(
        status="compatibility_blocked",
        reasonCode="connection_failed",
        validation=None,
    )
    payload["gates"]["nativeProtectionAuthenticated"] = True
    with pytest.raises(ValidationResultError, match="result_gate_mismatch"):
        read_validation_result(
            write_result(tmp_path, payload),
            expected_run_id=payload["runId"],
            expected_operation="validate-snapshot",
        )


def test_result_rejects_duplicate_top_level_keys(
    tmp_path, valid_result_payload
):
    import json

    encoded = json.dumps(valid_result_payload, separators=(",", ":"))
    encoded = encoded.replace('"version":1', '"version":1,"version":1', 1)
    path = tmp_path / "result.json"
    path.write_text(encoded, encoding="utf-8")
    with pytest.raises(ValidationResultError, match="^result_json_invalid$"):
        read_validation_result(
            path,
            expected_run_id=valid_result_payload["runId"],
            expected_operation="validate-snapshot",
        )


def test_result_rejects_nonstandard_nan(
    tmp_path, valid_result_payload, write_result
):
    payload = copy.deepcopy(valid_result_payload)
    payload["validation"]["databaseCount"] = float("nan")
    path = write_result(tmp_path, payload)
    with pytest.raises(ValidationResultError, match="^result_json_invalid$"):
        read_validation_result(
            path,
            expected_run_id=payload["runId"],
            expected_operation="validate-snapshot",
        )


@pytest.mark.parametrize("raw", [b"\xff", b"{"])
def test_result_wraps_invalid_utf8_and_malformed_json(tmp_path, raw):
    path = tmp_path / "result.json"
    path.write_bytes(raw)
    with pytest.raises(ValidationResultError, match="^result_json_invalid$"):
        read_validation_result(
            path,
            expected_run_id="00000000-0000-4000-8000-000000000001",
            expected_operation="validate-snapshot",
        )


def test_result_rejects_boolean_version(
    tmp_path, valid_result_payload, write_result
):
    payload = copy.deepcopy(valid_result_payload)
    payload["version"] = True
    with pytest.raises(
        ValidationResultError, match="^result_schema_mismatch$"
    ):
        read_validation_result(
            write_result(tmp_path, payload),
            expected_run_id=payload["runId"],
            expected_operation="validate-snapshot",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [("status", []), ("reasonCode", {})],
)
def test_result_wraps_unhashable_status_and_reason(
    tmp_path, valid_result_payload, write_result, field, value
):
    payload = copy.deepcopy(valid_result_payload)
    payload[field] = value
    with pytest.raises(
        ValidationResultError, match="^result_schema_mismatch$"
    ):
        read_validation_result(
            write_result(tmp_path, payload),
            expected_run_id=payload["runId"],
            expected_operation="validate-snapshot",
        )


def test_result_rejects_files_larger_than_64_kib(tmp_path):
    path = tmp_path / "result.json"
    path.write_bytes(b"{" + b" " * (64 * 1024))
    with pytest.raises(ValidationResultError, match="^result_too_large$"):
        read_validation_result(
            path,
            expected_run_id="00000000-0000-4000-8000-000000000001",
            expected_operation="validate-snapshot",
        )


@pytest.mark.parametrize("expected_run_id", ["not-a-uuid", None])
def test_result_wraps_invalid_expected_uuid(
    tmp_path, valid_result_payload, write_result, expected_run_id
):
    with pytest.raises(
        ValidationResultError, match="^result_run_id_invalid$"
    ):
        read_validation_result(
            write_result(tmp_path, valid_result_payload),
            expected_run_id=expected_run_id,
            expected_operation="validate-snapshot",
        )


@pytest.mark.parametrize("expected_operation", ["other", None])
def test_result_rejects_invalid_expected_operation(
    tmp_path, valid_result_payload, write_result, expected_operation
):
    with pytest.raises(
        ValidationResultError, match="^result_schema_mismatch$"
    ):
        read_validation_result(
            write_result(tmp_path, valid_result_payload),
            expected_run_id=valid_result_payload["runId"],
            expected_operation=expected_operation,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("databaseCount", 2**53),
        ("tableCount", 2**53),
        ("recordCount", 2**53),
        ("minTimestamp", -(2**53)),
        ("maxTimestamp", 2**53),
    ],
)
def test_result_requires_javascript_safe_integers(
    tmp_path, valid_result_payload, write_result, field, value
):
    payload = copy.deepcopy(valid_result_payload)
    payload["validation"][field] = value
    with pytest.raises(
        ValidationResultError, match="^result_schema_mismatch$"
    ):
        read_validation_result(
            write_result(tmp_path, payload),
            expected_run_id=payload["runId"],
            expected_operation="validate-snapshot",
        )


def test_result_rejects_reversed_timestamp_range(
    tmp_path, valid_result_payload, write_result
):
    payload = copy.deepcopy(valid_result_payload)
    payload["validation"]["minTimestamp"] = 6
    payload["validation"]["maxTimestamp"] = 5
    with pytest.raises(
        ValidationResultError, match="^result_schema_mismatch$"
    ):
        read_validation_result(
            write_result(tmp_path, payload),
            expected_run_id=payload["runId"],
            expected_operation="validate-snapshot",
        )
