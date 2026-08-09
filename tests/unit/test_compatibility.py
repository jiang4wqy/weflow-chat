from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import weflow_chat.compatibility as compatibility
from weflow_chat.compatibility import (
    EXPECTED_ANCHORS,
    EXPECTED_HASHES,
    RuntimeContract,
    discover_fixed_runtime_contract,
    probe_compatibility,
    write_compatibility_report,
)


RUN_ID = "11111111-1111-1111-1111-111111111111"


@pytest.fixture
def runtime_fixture(tmp_path: Path) -> RuntimeContract:
    files = {}
    for name in EXPECTED_HASHES:
        path = tmp_path / name.replace("/", "_")
        path.write_bytes(name.encode("ascii"))
        files[name] = path
    return RuntimeContract(
        applicationVersion="6.1.0",
        files=files,
        observedHashes=dict(EXPECTED_HASHES),
        mainText=(
            "z=new rn\n"
            + "\n".join(EXPECTED_ANCHORS.values())
        ),
        wcdbMethods=(
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
        ),
        discoveredAffectedRoles=(
            "config",
            "cache_maps",
            "analytics_cache",
        ),
    )


@pytest.fixture
def config_fixture(tmp_path: Path) -> Path:
    path = tmp_path / "WeFlow-config.json"
    path.write_text(
        json.dumps(
            {
                "dbPath": r"F:\old\account",
                "cachePath": r"C:\synthetic-cache",
                "myWxid": "wxid_secret",
                "decryptKey": "safe:TOP_SECRET_PAYLOAD",
                "wxidConfigs": {
                    "wxid_secret": {
                        "decryptKey": "safe:NESTED_SECRET_PAYLOAD",
                        "imageAesKey": "safe:IMAGE_SECRET",
                        "imageXorKey": "safe:XOR_SECRET",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def test_report_is_structural_and_redacted(
    runtime_fixture, config_fixture
):
    report = probe_compatibility(
        run_id=RUN_ID,
        runtime=runtime_fixture,
        config_path=config_fixture,
    )

    rendered = report.to_redacted_json()

    assert report.status == "compatible"
    assert report.config.accountSelectorCount == 1
    assert report.config.envelopeKinds == ["safe"]
    assert report.patchAnchors == {"boot": 1, "ready": 1}
    for forbidden in (
        "wxid_secret",
        "TOP_SECRET",
        "NESTED_SECRET",
        "IMAGE_SECRET",
        "XOR_SECRET",
        r"F:\old\account",
        str(config_fixture),
    ):
        assert forbidden not in rendered


def test_official_empty_cache_path_is_compatible(
    runtime_fixture, config_fixture
):
    value = json.loads(config_fixture.read_text(encoding="utf-8"))
    value["cachePath"] = ""
    config_fixture.write_text(json.dumps(value), encoding="utf-8")

    report = probe_compatibility(
        run_id=RUN_ID,
        runtime=runtime_fixture,
        config_path=config_fixture,
    )

    assert report.status == "compatible"
    assert report.reasonCodes == ()


def test_any_contract_drift_blocks_before_vss(
    runtime_fixture, config_fixture
):
    runtime_fixture = replace(
        runtime_fixture,
        observedHashes={
            **runtime_fixture.observedHashes,
            "main.js": "0" * 64,
        },
    )

    report = probe_compatibility(
        run_id=RUN_ID,
        runtime=runtime_fixture,
        config_path=config_fixture,
    )

    assert report.status == "compatibility_blocked"
    assert report.reasonCodes == ("main_js_hash_mismatch",)


def test_unbacked_discovered_affected_role_blocks(
    runtime_fixture, config_fixture
):
    runtime_fixture = replace(
        runtime_fixture,
        discoveredAffectedRoles=(
            runtime_fixture.discoveredAffectedRoles
            + ("confirmed_legacy_cache",)
        ),
    )

    report = probe_compatibility(
        run_id=RUN_ID,
        runtime=runtime_fixture,
        config_path=config_fixture,
    )

    assert report.status == "compatibility_blocked"
    assert report.affectedFiles == (
        "analytics_cache", "cache_maps", "config", "unknown_role"
    )
    assert "affected_file_contract_invalid" in report.reasonCodes
    assert "confirmed_legacy_cache" not in report.to_redacted_json()


def test_duplicate_config_key_is_rejected_with_fixed_code(
    runtime_fixture, config_fixture
):
    original = config_fixture.read_text(encoding="utf-8")
    duplicate = original.replace(
        '"dbPath": "F:\\\\old\\\\account"',
        (
            '"dbPath": "F:\\\\old\\\\account", '
            '"dbPath": "F:\\\\old\\\\account"'
        ),
        1,
    )
    assert duplicate != original
    config_fixture.write_text(duplicate, encoding="utf-8")

    with pytest.raises(
        RuntimeError, match=r"^compatibility_config_json_invalid$"
    ):
        probe_compatibility(
            run_id=RUN_ID,
            runtime=runtime_fixture,
            config_path=config_fixture,
        )


def test_config_identity_change_during_open_is_rejected(
    runtime_fixture, config_fixture, tmp_path, monkeypatch
):
    replacement = tmp_path / "replacement-config.json"
    replacement.write_bytes(config_fixture.read_bytes())
    real_open = compatibility.os.open
    swapped = False

    def swapping_open(path, flags, *args):
        nonlocal swapped
        if Path(path) == config_fixture and not swapped:
            swapped = True
            replacement.replace(config_fixture)
        return real_open(path, flags, *args)

    monkeypatch.setattr(compatibility.os, "open", swapping_open)
    with pytest.raises(
        RuntimeError, match=r"^compatibility_config_json_invalid$"
    ):
        probe_compatibility(
            run_id=RUN_ID,
            runtime=runtime_fixture,
            config_path=config_fixture,
        )


def test_extra_runtime_keys_are_blocked_and_never_rendered(
    runtime_fixture, config_fixture
):
    runtime_fixture = replace(
        runtime_fixture,
        observedHashes={
            **runtime_fixture.observedHashes,
            "SECRET_ACCOUNT_VALUE": "C" * 64,
        },
        observedAnchorCounts={
            "boot": 1,
            "ready": 1,
            "SECRET_ANCHOR": 1,
        },
    )

    report = probe_compatibility(
        run_id=RUN_ID,
        runtime=runtime_fixture,
        config_path=config_fixture,
    )

    assert report.status == "compatibility_blocked"
    assert "runtime_hash_contract_invalid" in report.reasonCodes
    assert "main_anchor_contract_invalid" in report.reasonCodes
    assert "SECRET" not in report.to_redacted_json()


def test_empty_safe_envelope_is_blocked_without_payload_disclosure(
    runtime_fixture, config_fixture
):
    value = json.loads(config_fixture.read_text(encoding="utf-8"))
    value["decryptKey"] = "safe:"
    config_fixture.write_text(json.dumps(value), encoding="utf-8")

    report = probe_compatibility(
        run_id=RUN_ID,
        runtime=runtime_fixture,
        config_path=config_fixture,
    )

    assert report.status == "compatibility_blocked"
    assert "unsupported_envelope_kind" in report.reasonCodes
    assert r"F:\old\account" not in report.to_redacted_json()


def test_report_publication_never_replaces_existing_destination(
    tmp_path, runtime_fixture, config_fixture
):
    report = probe_compatibility(
        run_id=RUN_ID,
        runtime=runtime_fixture,
        config_path=config_fixture,
    )
    run_root = tmp_path / f"run-{RUN_ID}"
    run_root.mkdir()

    destination = write_compatibility_report(run_root, report)

    assert destination.read_text(encoding="utf-8") == (
        report.to_redacted_json()
    )
    destination.write_bytes(b"sentinel")
    with pytest.raises(
        RuntimeError, match="compatibility_report_destination_exists"
    ):
        write_compatibility_report(run_root, report)
    assert destination.read_bytes() == b"sentinel"
    with pytest.raises(
        RuntimeError, match="compatibility_report_schema_invalid"
    ):
        replace(
            report, applicationVersion="SECRET_ACCOUNT_VALUE"
        ).to_redacted_json()
    with pytest.raises(
        RuntimeError, match="compatibility_report_schema_invalid"
    ):
        replace(
            report,
            runtimeHashes={name: "" for name in EXPECTED_HASHES},
        ).to_redacted_json()
    wrong_run = tmp_path / (
        "run-22222222-2222-2222-2222-222222222222"
    )
    wrong_run.mkdir()
    with pytest.raises(
        RuntimeError, match="compatibility_report_run_id_mismatch"
    ):
        write_compatibility_report(wrong_run, report)


def test_report_publication_loses_race_without_replacing_sentinel(
    tmp_path, runtime_fixture, config_fixture, monkeypatch
):
    report = probe_compatibility(
        run_id=RUN_ID,
        runtime=runtime_fixture,
        config_path=config_fixture,
    )
    run_root = tmp_path / f"run-{RUN_ID}"
    run_root.mkdir()
    destination = run_root / "compatibility.json"
    real_link = compatibility.os.link

    def competing_link(source, target):
        Path(target).write_bytes(b"sentinel")
        return real_link(source, target)

    monkeypatch.setattr(compatibility.os, "link", competing_link)
    with pytest.raises(
        RuntimeError, match="compatibility_report_destination_exists"
    ):
        write_compatibility_report(run_root, report)
    assert destination.read_bytes() == b"sentinel"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def _build_asar(source: Path, archive: Path) -> None:
    directory = source / "dist-electron"
    files = {}
    payloads = []
    offset = 0
    for name in (
        "main.js",
        "config-C9Ue62at.js",
        "wcdbWorker.js",
    ):
        payload = (directory / name).read_bytes()
        files[name] = {"size": len(payload), "offset": str(offset)}
        payloads.append(payload)
        offset += len(payload)
    header_json = json.dumps(
        {"files": {"dist-electron": {"files": files}}},
        separators=(",", ":"),
    ).encode("utf-8")
    aligned_size = (len(header_json) + 3) & ~3
    header_payload_size = 4 + aligned_size
    header_pickle = (
        header_payload_size.to_bytes(4, "little")
        + len(header_json).to_bytes(4, "little")
        + header_json
        + bytes(aligned_size - len(header_json))
    )
    archive.write_bytes(
        (4).to_bytes(4, "little")
        + len(header_pickle).to_bytes(4, "little")
        + header_pickle
        + b"".join(payloads)
    )


def test_discovery_reads_fixed_asar_without_executing_it(
    tmp_path, monkeypatch
):
    root = tmp_path / "formal"
    resources = root / "resources"
    wcdb = resources / "resources" / "wcdb" / "win32" / "x64"
    wcdb.mkdir(parents=True)
    (root / "WeFlow.exe").write_bytes(b"synthetic-weflow-exe")
    (wcdb / "wcdb_api.dll").write_bytes(b"synthetic-wcdb-api")
    (wcdb / "WCDB.dll").write_bytes(b"synthetic-wcdb-engine")
    source = tmp_path / "asar-source" / "dist-electron"
    source.mkdir(parents=True)
    texts = {
        "main.js": (
            "var z=new rn;"
            + EXPECTED_ANCHORS["boot"]
            + EXPECTED_ANCHORS["ready"]
            + ";snsPageCacheMap;analytics_cache"
        ),
        "config-C9Ue62at.js": "dbPath decryptKey",
        "wcdbWorker.js": "worker",
    }
    for name, text in texts.items():
        (source / name).write_text(text, encoding="utf-8")
    archive = resources / "app.asar"
    _build_asar(source.parent, archive)
    expected = {
        "WeFlow.exe": _sha256(root / "WeFlow.exe"),
        "app.asar": _sha256(archive),
        "main.js": _sha256(source / "main.js"),
        "config-chunk": _sha256(source / "config-C9Ue62at.js"),
        "worker": _sha256(source / "wcdbWorker.js"),
        "wcdb_api": _sha256(wcdb / "wcdb_api.dll"),
        "WCDB.dll": _sha256(wcdb / "WCDB.dll"),
    }
    monkeypatch.setattr(compatibility, "EXPECTED_HASHES", expected)
    runtime = discover_fixed_runtime_contract(
        SimpleNamespace(formal_weflow=root / "WeFlow.exe")
    )

    assert runtime.observedHashes == expected
    assert runtime.observedAnchorCounts == {"boot": 1, "ready": 1}


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x04\x00\x00\x00\x08\x00\x00\x00"
        b"\x04\x00\x00\x00\x00\x00\x00\x00",
    ],
)
def test_asar_parser_rejects_malformed_headers(payload):
    with pytest.raises(
        RuntimeError, match=r"^formal_asar_reader_schema_mismatch$"
    ):
        compatibility._read_asar_metadata(payload)
