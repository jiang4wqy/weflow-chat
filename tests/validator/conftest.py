import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from weflow_chat.validator.contracts import ValidatorLayout


@pytest.fixture
def validator_layout(tmp_path):
    run_root = tmp_path / "run"
    attempt = (
        run_root
        / "validator"
        / "validation"
        / "00000000-0000-4000-8000-000000000099"
    )
    runtime = run_root / "runtime" / "WeFlow"
    user_data = attempt / "profile"
    documents = attempt / "documents"
    cache = attempt / "cache"
    request = attempt / "request" / "request.json"
    result = attempt / "result" / "result.json"
    for directory in (
        runtime,
        user_data,
        documents,
        cache,
        request.parent,
        result.parent,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    return ValidatorLayout(
        run_root=run_root,
        attempt_root=attempt,
        runtime_exe=runtime / "WeFlow.exe",
        request_path=request,
        result_path=result,
        user_data_dir=user_data,
        documents_dir=documents,
        cache_dir=cache,
    )


@pytest.fixture
def valid_result_payload():
    return {
        "version": 1,
        "runId": "00000000-0000-4000-8000-000000000001",
        "operation": "validate-snapshot",
        "status": "ok",
        "reasonCode": None,
        "gates": {
            "userDataIsolated": True,
            "documentsIsolated": True,
            "singleInstanceLockAcquired": True,
            "safeStorageAvailable": True,
            "syntheticEnvelopeRoundtrip": False,
            "nativeProtectionAuthenticated": True,
            "workerSetPathsCalled": True,
        },
        "callsBeforeOpen": ["setPaths", "testConnection"],
        "validation": {
            "databaseCount": 2,
            "tableCount": 3,
            "recordCount": 5,
            "minTimestamp": 1,
            "maxTimestamp": 5,
            "schemaFingerprint": "A" * 64,
            "aggregateFingerprint": "B" * 64,
            "databaseCoverageFingerprint": "C" * 64,
        },
    }


@pytest.fixture
def write_result():
    def write(root: Path, payload: dict) -> Path:
        target = root / "result.json"
        target.write_text(
            json.dumps(payload, separators=(",", ":")), encoding="utf-8"
        )
        return target

    return write


@pytest.fixture
def synthetic_full_config(tmp_path):
    value = {
        "dbPath": r"C:\synthetic\old-parent",
        "cachePath": r"C:\synthetic\old-cache",
        "myWxid": "wxid_test",
        "decryptKey": "safe:VE9QX0xFVkVMX1NZTlRIRVRJQw==",
        "imageAesKey": "safe:SU1BR0VfU1lOVEhFVElD",
        "imageXorKey": "safe:MTIz",
        "wxidConfigs": {
            "wxid_test": {
                "decryptKey": "safe:TkVTVEVEX1NZTlRIRVRJQw==",
                "imageAesKey": "safe:TkVTVEVEX0lNQUdF",
                "imageXorKey": "safe:MTIz",
                "updatedAt": 1_700_000_000_000,
                "futureNested": {"enabled": True},
            },
            "wxid_other": {
                "decryptKey": "safe:T1RIRVJfU1lOVEhFVElD",
                "updatedAt": 1_600_000_000_000,
            },
        },
        "onboardingDone": True,
        "unknownFutureField": {"items": [1, "two", False]},
    }
    path = tmp_path / "WeFlow-config.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return SimpleNamespace(path=path, value=copy.deepcopy(value))
