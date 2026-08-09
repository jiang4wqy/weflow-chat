from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import conftest as gates


RUN_ID = "00000000-0000-4000-8000-000000000001"


def synthetic_manifest_layout(tmp_path):
    from weflow_chat import __version__
    from weflow_chat.manifest import (
        ResidualRisk,
        RunManifest,
        SnapshotMethod,
        build_manifest,
        publish_run_manifest,
    )
    from weflow_chat.models import CopyRole
    from weflow_chat.paths import RunLayout

    root = tmp_path / "run"
    root.mkdir()
    layout = RunLayout.from_existing_root(root)
    for directory in (layout.source, layout.validation, layout.active):
        (
            directory
            / gates._SOURCE_ACCOUNT_NAME
            / "db_storage"
        ).mkdir(parents=True)
    (
        layout.source
        / gates._SOURCE_ACCOUNT_NAME
        / "db_storage"
        / "message.db"
    ).write_bytes(b"synthetic")
    source = build_manifest(layout.source, role=CopyRole.SOURCE)
    publish_run_manifest(
        layout,
        RunManifest(
            schema_version=1,
            tool_version=__version__,
            run_id=RUN_ID,
            source_account_name=gates._SOURCE_ACCOUNT_NAME,
            captured_at_utc="2026-07-21T00:00:00Z",
            source_volume="F:\\",
            shadow_id="00000000-0000-4000-8000-000000000002",
            staging_manifest_sha256="A" * 64,
            snapshot_method=SnapshotMethod.VSS_CRASH_CONSISTENT,
            residual_risk=(
                ResidualRisk.NO_CROSS_DATABASE_ATOMICITY_PROOF
            ),
            source=source,
        ),
    )
    return layout


def test_exact_manifest_gate_compares_every_file_field(tmp_path):
    from weflow_chat.manifest import build_manifest
    from weflow_chat.models import CopyRole

    layout = synthetic_manifest_layout(tmp_path)
    assert gates._read_exact_run_manifest(layout, RUN_ID).source == (
        build_manifest(layout.source, role=CopyRole.SOURCE)
    )
    original = layout.manifest_path.read_text(encoding="utf-8")
    raw = json.loads(original)
    raw["source"]["files"][0]["mtimeNs"] += 1
    layout.manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(
        RuntimeError, match="source_manifest_content_mismatch"
    ):
        gates._read_exact_run_manifest(layout, RUN_ID)
    duplicate = original.replace(
        f'"runId":"{RUN_ID}"',
        f'"runId":"{RUN_ID}","runId":"{RUN_ID}"',
        1,
    )
    layout.manifest_path.write_text(duplicate, encoding="utf-8")
    with pytest.raises(
        RuntimeError, match="real_gate_json_duplicate_key"
    ):
        gates._read_exact_run_manifest(layout, RUN_ID)


def test_exact_manifest_gate_checks_every_role_for_reparse(
    tmp_path, monkeypatch
):
    layout = synthetic_manifest_layout(tmp_path)
    original = gates._is_reparse
    monkeypatch.setattr(
        gates,
        "_is_reparse",
        lambda path: path == layout.validation or original(path),
    )
    with pytest.raises(
        RuntimeError, match="real_gate_reparse_rejected"
    ):
        gates._read_exact_run_manifest(layout, RUN_ID)


def test_real_layout_filter_reads_no_unapproved_manifest(
    tmp_path, monkeypatch
):
    snapshots = tmp_path / "Snapshots"
    snapshots.mkdir()
    unrelated = snapshots / "unrelated-run"
    unrelated.mkdir()
    (unrelated / "manifest.json").write_text(
        "this must never be parsed", encoding="utf-8"
    )
    approved = snapshots / f"approved-{RUN_ID}"
    approved.mkdir()
    monkeypatch.setattr(gates, "SNAPSHOTS_ROOT", snapshots)

    layout, identity = gates._find_real_layout(RUN_ID)

    assert layout.root == approved.resolve()
    assert identity == gates._identity(approved)


def test_attempt_audit_is_bound_to_published_profile_and_request(tmp_path):
    root = tmp_path / "run"
    layout = SimpleNamespace(
        source=root / "source",
        validation=root / "validation",
        active=root / "active",
    )
    requests = []
    attempts = []
    for index, area in enumerate(("validation", "active"), start=10):
        attempt_root = (
            root
            / "validator"
            / area
            / f"00000000-0000-4000-8000-{index:012d}"
        )
        config_path = (
            attempt_root / "profile" / "WeFlow-config.json"
        )
        request_path = attempt_root / "request" / "request.json"
        cache_path = attempt_root / "cache"
        config_path.parent.mkdir(parents=True)
        request_path.parent.mkdir(parents=True)
        cache_path.mkdir()
        config = {
            "dbPath": str(getattr(layout, area)),
            "cachePath": str(cache_path),
            "future": {"safe": "value"},
        }
        config_payload = json.dumps(
            config, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        config_path.write_bytes(config_payload)
        request = {
            "operation": "validate-snapshot",
            "runId": RUN_ID,
            "area": area,
        }
        request_path.write_text(
            json.dumps(request), encoding="utf-8"
        )
        requests.append(request)
        attempts.append(
            {
                "area": area,
                "attemptRoot": str(attempt_root),
                "configPath": str(config_path),
                "effectiveDbPath": str(getattr(layout, area)),
                "effectiveCachePath": str(cache_path),
                "sourcePathAbsent": True,
                "changedFields": ("dbPath", "cachePath"),
                "sourceSha256": "A" * 64,
                "destinationSha256": hashlib.sha256(
                    config_payload
                ).hexdigest().upper(),
            }
        )
    real_run = SimpleNamespace(
        run_id=RUN_ID,
        layout=layout,
        validator=SimpleNamespace(
            request_audit=tuple(requests),
            attempt_audit=tuple(attempts),
        ),
        request_audit_start=0,
        attempt_audit_start=0,
    )

    gates.RealRun.assert_validator_never_received_source_path(real_run)

    tampered_path = Path(attempts[0]["configPath"])
    tampered = json.loads(tampered_path.read_text(encoding="utf-8"))
    tampered["future"]["source"] = str(layout.source)
    tampered_payload = json.dumps(
        tampered, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    tampered_path.write_bytes(tampered_payload)
    attempts[0]["destinationSha256"] = hashlib.sha256(
        tampered_payload
    ).hexdigest().upper()
    with pytest.raises(AssertionError):
        gates.RealRun.assert_validator_never_received_source_path(
            real_run
        )


@pytest.mark.skipif(
    os.environ.get("WEFLOW_RUN_REAL_COPY_VALIDATION") != "1"
    or os.environ.get("WEFLOW_RUN_HOST_CONTRACT") != "1",
    reason="requires the user-approved local snapshot run",
)
def test_existing_envelope_opens_validation_and_active(real_run):
    validation = real_run.validator.validate(
        area="validation",
        layout=real_run.layout,
        run_id=real_run.run_id,
    )
    assert validation.status == "ok"
    assert validation.fingerprints is not None
    active = real_run.validator.validate(
        area="active",
        layout=real_run.layout,
        run_id=real_run.run_id,
    )
    assert active.status == "ok"
    assert active.fingerprints is not None
    assert active.fingerprints == validation.fingerprints
    real_run.assert_validator_never_received_source_path()
    real_run.assert_source_manifest_unchanged()
    real_run.assert_transaction_still_validated()
    real_run.assert_formal_files_unchanged()
