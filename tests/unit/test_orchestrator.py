import builtins
from dataclasses import replace
import hashlib
import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from tests.fakes import SHADOW_ID, SyntheticFaultController, build_synthetic_flow
import weflow_chat
from weflow_chat.atomic_io import atomic_write_json
import weflow_chat.cli as cli
from weflow_chat.cli import build_parser, execute_refresh
from weflow_chat.manifest import (
    ResidualRisk,
    RunManifest,
    SnapshotMethod,
    build_manifest,
    content_signature,
    publish_run_manifest,
    sha256_file,
)
from weflow_chat.media import (
    import_media_staging as import_real_media_staging,
)
from weflow_chat.media_budget import MediaBudgetError
from weflow_chat.models import CopyRole, TxState
import weflow_chat.orchestrator as orchestrator
from weflow_chat.orchestrator import RefreshMode, RefreshStage
from weflow_chat.security import BackupBundle
from weflow_chat.transaction import _record_json
from weflow_chat.vss import (
    MediaStagingFile,
    MediaStagingReceipt,
    ShadowState,
)
from weflow_chat.weixin_trust import (
    RuntimeWeixinDllIdentity,
    TrustState,
    read_local_trust_bundle,
    verify_local_trust_artifacts,
)


@pytest.fixture
def backends(tmp_path):
    faults = SyntheticFaultController(tmp_path)
    try:
        flow = build_synthetic_flow(
            tmp_path=tmp_path,
            timestamp="20260721-090000",
            faults=faults,
        )
        yield SimpleNamespace(flow=flow, faults=faults)
    finally:
        faults.close()


def test_synthetic_fault_controller_restores_module_patches(tmp_path):
    original = orchestrator.build_manifest
    faults = SyntheticFaultController(tmp_path)
    try:
        build_synthetic_flow(
            tmp_path=tmp_path,
            timestamp="20260721-090000",
            faults=faults,
        )
        assert orchestrator.build_manifest is not original
    finally:
        faults.close()
    assert orchestrator.build_manifest is original


def test_compatibility_report_precedes_vss(backends):
    backends.flow.prepare_snapshot()
    assert backends.faults.events.index("compatibility_written") < (
        backends.faults.events.index("vss_create"))


def test_prepare_snapshot_has_no_active_before_key_validation(backends):
    flow = backends.flow
    flow.prepare_snapshot()
    assert flow.stage is RefreshStage.SNAPSHOT_READY
    assert not flow.layout.active.exists()
    assert flow.production_write_count == 0


def _configure_trial_flow(flow):
    identity = RuntimeWeixinDllIdentity(
        version="4.1.13.1",
        architecture="x64",
        dll_size=123,
        dll_sha256="D" * 64,
        authenticode_status="Valid",
        signer_subject=(
            "Tencent Technology (Shenzhen) Company Limited"
        ),
        signer_certificate_sha256="E" * 64,
    )
    flow.dependencies.validation_only = True
    flow.dependencies.weixin_trust_state = TrustState.TRIAL_REQUIRED
    flow.dependencies.weixin_runtime_identity = identity
    flow.dependencies.trial_identity_revalidator = lambda: identity
    flow.dependencies.trust_security = flow.dependencies.security
    flow.trust_status = "trial_required"
    return identity


def test_trial_validation_rolls_back_before_enrolling_local_trust(backends):
    flow = backends.flow
    identity = _configure_trial_flow(flow)
    flow.prepare_snapshot()
    flow.layout.compatibility_path.write_text(
        json.dumps(
            {"runId": flow.run_id, "status": "compatible"},
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    source = build_manifest(
        flow.layout.source, role=CopyRole.SOURCE
    )
    publish_run_manifest(
        flow.layout,
        RunManifest(
            schema_version=1,
            tool_version="synthetic-test",
            run_id=flow.run_id,
            source_account_name=(
                flow.dependencies.contract.account_id
            ),
            captured_at_utc="2026-07-21T00:00:00+00:00",
            source_volume="F:\\",
            shadow_id=SHADOW_ID,
            staging_manifest_sha256="A" * 64,
            snapshot_method=(
                SnapshotMethod.VSS_CRASH_CONSISTENT
            ),
            residual_risk=(
                ResidualRisk.NO_CROSS_DATABASE_ATOMICITY_PROOF
            ),
            source=source,
        ),
    )
    flow.validate_copies()

    result = flow.complete_validation_only()

    assert result.stage is RefreshStage.ROLLED_BACK
    assert result.productionWriteCount == 0
    assert result.trustStatus == "local_trust_enrolled"
    assert flow.transaction.state is TxState.ROLLED_BACK
    receipt, evidence = read_local_trust_bundle(
        primary_root=flow.layout.root,
        recovery_root=(
            flow.dependencies.recovery_backup_root.parent
        ),
        verify=lambda _path: None,
    )
    assert receipt.matches(identity)
    assert evidence.transaction_sha256 == (
        flow.dependencies.store.read_equal().canonical_sha256
    )
    assert evidence.production_write_count == 0
    assert verify_local_trust_artifacts(
        primary_root=flow.layout.root,
        recovery_root=(
            flow.dependencies.recovery_backup_root.parent
        ),
        account_name=flow.dependencies.contract.account_id,
        verify=lambda _path: None,
    ) == receipt
    with pytest.raises(
        RuntimeError, match="validation_only_cutover_forbidden"
    ):
        flow.prepare_cutover()


def test_trial_receipt_write_failure_stays_rolled_back_and_untrusted(
    backends,
):
    flow = backends.flow
    _configure_trial_flow(flow)
    flow.prepare_snapshot()
    flow.layout.manifest_path.write_text(
        '{"synthetic":"manifest"}', encoding="utf-8"
    )
    flow.validate_copies()
    recovery_root = flow.dependencies.recovery_backup_root.parent
    (recovery_root / "local-weixin-trust.json").write_text(
        "partial", encoding="utf-8"
    )

    result = flow.complete_validation_only()

    assert result.stage is RefreshStage.ROLLED_BACK
    assert result.productionWriteCount == 0
    assert result.trustStatus == "local_trust_not_enrolled"
    assert flow.transaction.state is TxState.ROLLED_BACK
    assert not (
        flow.layout.root / "local-weixin-trust.json"
    ).exists()


def test_snapshot_stages_database_and_media_from_same_owned_shadow(
    backends,
    monkeypatch,
):
    flow = backends.flow
    contract = flow.dependencies.contract
    observed = []

    def map_snapshot(device_object, *, source_volume, live_path):
        observed.append(("map", device_object, source_volume, live_path))
        if live_path == contract.db_storage:
            return Path("shadow") / "db_storage"
        if live_path == contract.source_account:
            return Path("shadow") / "account"
        raise AssertionError("unexpected live snapshot path")

    staged = MediaStagingReceipt(
        staging_path=flow.layout.root / "media-staging",
        source_account_name=contract.account_id,
        files=(),
        file_count=0,
        byte_count=0,
        manifest_sha256=hashlib.sha256(
            b"[]"
        ).hexdigest().upper(),
    )
    imported = SimpleNamespace(
        schema_version=1,
        manifest_path=contract.media_store_root / "media-manifest.json",
        manifest_sha256="B" * 64,
        file_count=0,
        byte_count=0,
    )

    def copy_media(**values):
        observed.append(("copy-media", values))
        assert values == {
            "shadow_account": Path("shadow") / "account",
            "run_root": flow.layout.root,
            "snapshots_root": contract.snapshots_root,
            "source_account_name": contract.account_id,
            "prior_inventory": None,
        }
        staged.staging_path.mkdir(parents=True)
        return staged

    def import_media(receipt, *, media_store_root):
        observed.append(("import-media", receipt, media_store_root))
        assert receipt is staged
        assert media_store_root == contract.media_store_root
        return imported

    original_delete = flow.dependencies.vss.delete_exact

    def delete_exact(**values):
        observed.append(("delete-shadow", values))
        return original_delete(**values)

    monkeypatch.setattr(orchestrator, "map_volume_path", map_snapshot)
    monkeypatch.setattr(
        orchestrator,
        "copy_owned_shadow_media_to_staging",
        copy_media,
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator,
        "import_media_staging",
        import_media,
        raising=False,
    )
    monkeypatch.setattr(
        flow.dependencies.vss,
        "delete_exact",
        delete_exact,
    )

    flow.prepare_snapshot()

    assert [
        item[3]
        for item in observed
        if item[0] == "map"
    ] == [contract.db_storage, contract.source_account]
    assert [item[0] for item in observed].index("copy-media") < (
        [item[0] for item in observed].index("delete-shadow")
    )
    assert [item[0] for item in observed].index("delete-shadow") < (
        [item[0] for item in observed].index("import-media")
    )
    assert flow.media_receipt is imported


def test_snapshot_projects_verified_store_receipt_to_prior_inventory(
    backends,
    monkeypatch,
):
    flow = backends.flow
    payload = b"prior-media"
    expected = MediaStagingFile(
        relative_path="msg/attach/prior.bin",
        size=len(payload),
        sha256=(
            "D55C8698B407EA5A3800AC91C0BFD7E6"
            "7A9A10E53794F028CEB0109A51CC1B03"
        ),
    )
    prior_receipt = SimpleNamespace(
        manifest=SimpleNamespace(
            files=(
                SimpleNamespace(
                    relative_path=expected.relative_path,
                    size=expected.size,
                    sha256=expected.sha256,
                    volume_serial=11,
                    file_id=22,
                ),
            ),
        ),
    )
    original_copy = (
        orchestrator
        .copy_owned_shadow_media_to_staging
    )
    observed = []

    def read_prior(root, account_name):
        observed.append("prior_media_read")
        assert root == (
            flow.dependencies.contract.media_store_root
        )
        assert account_name == (
            flow.dependencies.contract.account_id
        )
        return prior_receipt

    def copy_media(**values):
        observed.append(values["prior_inventory"])
        return original_copy(**values)

    monkeypatch.setattr(
        orchestrator,
        "read_media_store_receipt",
        read_prior,
    )
    monkeypatch.setattr(
        orchestrator,
        "copy_owned_shadow_media_to_staging",
        copy_media,
    )

    flow.prepare_snapshot()

    assert observed == [
        "prior_media_read",
        (expected,),
    ]
    assert backends.faults.events.index(
        "compatibility_written"
    ) < backends.faults.events.index("vss_create")


def test_successful_media_import_removes_owned_staging(
    backends,
):
    flow = backends.flow
    source_account = (
        flow.dependencies.contract.source_account
    )

    flow.prepare_snapshot()

    assert not (
        flow.layout.root / "media-staging"
    ).exists()
    assert source_account.is_dir()
    assert (
        flow.dependencies.contract.media_store_root
        / "media-manifest.json"
    ).is_file()


def test_post_staging_space_gate_precedes_database_and_media_imports(
    backends,
    monkeypatch,
):
    flow = backends.flow
    contract = flow.dependencies.contract
    observed = []

    def calculate_budget(**values):
        observed.append(("budget", values))
        assert "vss_delete_exact" in backends.faults.events
        assert values["prior_inventory"] is None
        assert values["source_db_bytes"] == 17
        assert values["validation_db_bytes"] == 17
        assert values["active_db_bytes"] == 17
        assert values["presentation_db_bytes"] == 17
        assert values["existing_destination_volume_root"] == (
            contract.media_store_root.parent
        )
        return SimpleNamespace(
            mergedMediaBytes=15,
            deltaBytes=15,
            requiredFreeBytes=2**30 + 98,
            observedFreeBytes=10 * 2**30,
        )

    original_source_import = orchestrator.import_vss_staging
    original_media_import = orchestrator.import_media_staging

    def import_source(*args, **kwargs):
        observed.append(("source-import", None))
        return original_source_import(*args, **kwargs)

    def import_media(*args, **kwargs):
        observed.append(("media-import", None))
        return original_media_import(*args, **kwargs)

    monkeypatch.setattr(
        orchestrator,
        "calculate_media_post_staging_budget",
        calculate_budget,
    )
    monkeypatch.setattr(
        orchestrator,
        "import_vss_staging",
        import_source,
    )
    monkeypatch.setattr(
        orchestrator,
        "import_media_staging",
        import_media,
    )

    flow.prepare_snapshot()

    labels = [item[0] for item in observed]
    assert labels == ["budget", "source-import", "media-import"]
    assert backends.faults.events.index(
        "vss_delete_exact"
    ) < backends.faults.events.index("media_import")


def test_insufficient_post_staging_space_preserves_staging_and_imports_nothing(
    backends,
    monkeypatch,
):
    flow = backends.flow
    contract = flow.dependencies.contract

    def reject_space(**_values):
        raise MediaBudgetError(
            "media_post_staging_space_insufficient"
        )

    monkeypatch.setattr(
        orchestrator,
        "calculate_media_post_staging_budget",
        reject_space,
    )
    monkeypatch.setattr(
        orchestrator,
        "import_vss_staging",
        lambda *args, **kwargs: pytest.fail(
            "database import must not run"
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        "import_media_staging",
        lambda *args, **kwargs: pytest.fail(
            "media import must not run"
        ),
    )

    with pytest.raises(
        MediaBudgetError,
        match=r"^media_post_staging_space_insufficient$",
    ):
        flow.prepare_snapshot()

    assert flow.layout.vss_staging.is_dir()
    assert (flow.layout.root / "media-staging").is_dir()
    assert not flow.layout.source.exists()
    assert not (
        contract.media_store_root / "media-manifest.json"
    ).exists()
    assert "vss_delete_exact" in backends.faults.events


def test_failed_media_import_preserves_owned_staging(
    backends,
):
    flow = backends.flow
    backends.faults.active = "media_import"

    with pytest.raises(
        RuntimeError,
        match="^media_import$",
    ):
        flow.prepare_snapshot()

    assert (
        flow.layout.root / "media-staging"
    ).is_dir()


def test_prepare_snapshot_never_deletes_after_partial_shadow_mirror_write(
        backends, monkeypatch):
    flow = backends.flow
    store = flow.dependencies.store
    before = store.read_equal().record
    original_record = store.record_shadow

    def partial_record(**kwargs):
        original_record(**kwargs)
        atomic_write_json(store.primary_path, _record_json(before))
        raise RuntimeError("synthetic_primary_shadow_write_failure")

    monkeypatch.setattr(store, "record_shadow", partial_record)
    monkeypatch.setattr(
        flow.dependencies.vss, "inspect_owned",
        lambda **_: (_ for _ in ()).throw(
            AssertionError("VSS inspection before equal-mirror gate")))
    with pytest.raises(RuntimeError, match="shadow_cleanup_recovery_pending"):
        flow.prepare_snapshot()
    assert flow.stage is RefreshStage.RECOVERY_PENDING
    assert flow.dependencies.vss.state is ShadowState.CREATED


def test_prepare_snapshot_source_identity_drift_never_deletes(
        backends, monkeypatch):
    flow = backends.flow
    original_inspect = flow.dependencies.vss.inspect_owned

    def drifted_inspect(*, run_id):
        value = original_inspect(run_id=run_id)
        return SimpleNamespace(
            run_id=value.run_id, source_volume="E:\\",
            state=value.state, shadow_id=value.shadow_id,
            device_object=value.device_object)

    monkeypatch.setattr(
        flow.dependencies.vss, "inspect_owned", drifted_inspect)
    monkeypatch.setattr(
        flow.dependencies.vss, "delete_exact",
        lambda **_: (_ for _ in ()).throw(
            AssertionError("delete with source identity drift")))
    with pytest.raises(RuntimeError, match="shadow_cleanup_recovery_pending"):
        flow.prepare_snapshot()
    assert flow.stage is RefreshStage.RECOVERY_PENDING


def test_prepare_timeout_without_journal_stays_pending_across_late_prepare(
        backends):
    flow = backends.flow
    backends.faults.active = "vss_prepare_timeout"
    with pytest.raises(
            RuntimeError, match="helper_timeout_journal_unreadable"):
        flow.prepare_snapshot()
    assert (flow.dependencies.store.read_equal().record.state is
            TxState.RECOVERY_PENDING)
    assert not flow.dependencies.journal_exists(flow.run_id)
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING
    assert flow.rollback(
        "operator_requested_during_unknown_create").stage is (
            RefreshStage.RECOVERY_PENDING)

    # The timed-out non-elevated wrapper publishes PrepareCreate late. It did
    # not launch elevated Create, and neither the absent nor creating journal
    # observation may terminalize the already-pending transaction.
    flow.dependencies.vss.publish_creating_intent(
        run_id=flow.run_id, source_volume="F:\\")
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING
    assert (flow.dependencies.store.read_equal().record.state is
            TxState.RECOVERY_PENDING)
    assert "vss_create" not in backends.faults.events
    assert "vss_delete_exact" not in backends.faults.events


def test_invalid_existing_envelope_stops_without_scanner_or_active(backends):
    backends.faults.active = "validation"
    flow = backends.flow
    flow.prepare_snapshot()
    result = flow.validate_copies()
    assert result.status == "compatibility_blocked"
    assert not flow.layout.active.exists()
    assert "memory_scanner" not in backends.faults.events
    assert flow.production_write_count == 0


def test_active_is_created_only_after_validation_and_matches_source(backends):
    flow = backends.flow
    flow.prepare_snapshot()
    baseline = flow.validate_copies()
    assert flow.stage is RefreshStage.VALIDATED
    assert flow.layout.active.exists()
    assert content_signature(flow.manifest("active")) == content_signature(
        flow.manifest("source"))
    assert baseline.fingerprints == flow.validation_fingerprints


def test_media_probe_runs_after_verified_presentation_before_production_write(
    backends,
):
    flow = backends.flow
    observed = []
    counts = {
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

    def media_openability(**values):
        observed.append(
            (
                values,
                flow.presentation_receipt is not None,
                flow.production_write_count,
            )
        )
        return counts

    flow.dependencies.validator.media_openability = media_openability
    flow.prepare_snapshot()

    receipt = flow.validate_copies()

    assert receipt.status == "ok"
    assert observed == [
        (
            {
                "area": "presentation",
                "layout": flow.layout,
                "run_id": flow.run_id,
            },
            True,
            0,
        )
    ]
    assert flow.media_openability_counts == counts
    assert flow.production_write_count == 0


def test_rejected_media_probe_rolls_back_without_production_write(backends):
    flow = backends.flow
    config_path = flow.dependencies.contract.config_path
    config_before = config_path.read_bytes()

    def reject_media(**_values):
        raise orchestrator.ValidatorBlockedError("media_probe_failed")

    flow.dependencies.validator.media_openability = reject_media
    flow.prepare_snapshot()

    receipt = flow.validate_copies()

    assert receipt == orchestrator.ValidationReceipt(
        "compatibility_blocked", "media_probe_failed", None
    )
    assert flow.stage is RefreshStage.COMPATIBILITY_BLOCKED
    assert flow.production_write_count == 0
    assert flow.media_openability_counts is None
    assert config_path.read_bytes() == config_before
    assert (
        flow.dependencies.store.read_equal().record.state
        is TxState.ROLLED_BACK
    )


def test_presentation_is_built_only_after_database_validation(backends):
    flow = backends.flow
    contract = flow.dependencies.contract
    presentation = flow.layout.root / "presentation"

    flow.prepare_snapshot()

    assert not presentation.exists()
    receipt = flow.validate_copies()

    assert receipt.status == "ok"
    assert flow.stage is RefreshStage.VALIDATED
    assert flow.presentation_receipt.presentation_root == presentation
    active_db = flow.layout.active / contract.account_id / "db_storage"
    presented_db = presentation / contract.account_id / "db_storage"
    assert (presented_db / "session" / "session.db").read_bytes() == (
        active_db / "session" / "session.db"
    ).read_bytes()
    assert (
        (presented_db / "session" / "session.db").stat().st_ino
        != (active_db / "session" / "session.db").stat().st_ino
    )
    store_media = (
        contract.media_store_root
        / contract.account_id
        / "msg"
        / "attach"
        / "synthetic-image.bin"
    )
    presented_media = (
        presentation
        / contract.account_id
        / "msg"
        / "attach"
        / "synthetic-image.bin"
    )
    assert presented_media.read_bytes() == store_media.read_bytes()
    assert (
        presented_media.stat().st_dev,
        presented_media.stat().st_ino,
    ) != (
        store_media.stat().st_dev,
        store_media.stat().st_ino,
    )


def test_validation_manifest_drift_persists_compatibility_block(backends):
    flow = backends.flow
    flow.prepare_snapshot()
    validation_db = flow.layout.role_db_storage(
        CopyRole.VALIDATION,
        flow.dependencies.contract.account_id,
    )
    (validation_db / "session.db").write_bytes(
        b"validation-drift"
    )
    receipt = flow.validate_copies()
    assert receipt.status == "compatibility_blocked"
    assert receipt.reasonCode == (
        "validation_source_manifest_mismatch"
    )
    assert flow.stage is RefreshStage.COMPATIBILITY_BLOCKED
    assert (
        flow.dependencies.store.read_equal().record.state
        is TxState.ROLLED_BACK
    )


def test_validation_db_and_wal_recovery_still_allows_active_copy(
        backends, monkeypatch):
    flow = backends.flow
    original_validate = flow.dependencies.validator.validate

    def validate_with_wal_recovery(*, area, layout, run_id):
        receipt = original_validate(
            area=area,
            layout=layout,
            run_id=run_id,
        )
        if area == "validation":
            validation_db = layout.role_db_storage(
                CopyRole.VALIDATION,
                flow.dependencies.contract.account_id,
            )
            (validation_db / "session.db").write_bytes(
                b"recovered-database"
            )
            (validation_db / "session.db-wal").write_bytes(
                b"recovered-wal"
            )
        return receipt

    monkeypatch.setattr(
        flow.dependencies.validator,
        "validate",
        validate_with_wal_recovery,
    )

    flow.prepare_snapshot()
    receipt = flow.validate_copies()

    assert receipt.status == "ok"
    assert flow.stage is RefreshStage.VALIDATED
    assert content_signature(flow.manifest("active")) == (
        content_signature(flow.manifest("source"))
    )


def test_validation_shm_content_change_still_allows_active_copy(
        backends,
        monkeypatch,
):
    flow = backends.flow
    original_staging_copy = (
        orchestrator.copy_owned_shadow_to_staging
    )

    def staging_copy_with_shm(**values):
        receipt = original_staging_copy(**values)
        shm_path = (
            receipt.staging_path
            / flow.dependencies.contract.account_id
            / "db_storage"
            / "session"
            / "session.db-shm"
        )
        shm_path.write_bytes(b"A" * 32768)
        return receipt

    monkeypatch.setattr(
        orchestrator,
        "copy_owned_shadow_to_staging",
        staging_copy_with_shm,
    )
    original_validate = flow.dependencies.validator.validate

    def validate_with_shm_change(*, area, layout, run_id):
        receipt = original_validate(
            area=area,
            layout=layout,
            run_id=run_id,
        )
        if area == "validation":
            validation_db = layout.role_db_storage(
                CopyRole.VALIDATION,
                flow.dependencies.contract.account_id,
            )
            (validation_db / "session" / "session.db-shm").write_bytes(
                b"B" * 32768
            )
        return receipt

    monkeypatch.setattr(
        flow.dependencies.validator,
        "validate",
        validate_with_shm_change,
    )

    flow.prepare_snapshot()
    receipt = flow.validate_copies()

    assert receipt.status == "ok"
    assert flow.stage is RefreshStage.VALIDATED
    assert flow.layout.active.exists()


def test_active_manifest_drift_persists_compatibility_block(
        backends,
        monkeypatch,
):
    flow = backends.flow
    original = orchestrator.materialize_role_copy

    def materialize_with_drift(
        layout,
        role,
        *,
        source_account_name,
    ):
        result = original(
            layout,
            role,
            source_account_name=source_account_name,
        )
        if role is CopyRole.ACTIVE:
            active_db = layout.role_db_storage(
                CopyRole.ACTIVE,
                source_account_name,
            )
            (active_db / "session.db").write_bytes(
                b"active-drift"
            )
        return result

    monkeypatch.setattr(
        orchestrator,
        "materialize_role_copy",
        materialize_with_drift,
    )
    flow.prepare_snapshot()
    receipt = flow.validate_copies()
    assert receipt.status == "compatibility_blocked"
    assert receipt.reasonCode == (
        "active_source_manifest_mismatch"
    )
    assert flow.stage is RefreshStage.COMPATIBILITY_BLOCKED
    assert (
        flow.dependencies.store.read_equal().record.state
        is TxState.ROLLED_BACK
    )


def test_change_plan_is_built_after_preflight_from_same_current_config(backends):
    path = backends.flow.dependencies.contract.config_path
    value = json.loads(path.read_text(encoding="utf-8"))
    value["addedAfterFlowConstruction"] = {"must": "survive"}
    path.write_text(json.dumps(value), encoding="utf-8")
    backends.flow.prepare_snapshot()
    backends.flow.validate_copies()
    assert backends.flow.prepare_cutover().stage is RefreshStage.CONFIG_REPLACED
    after = json.loads(path.read_text(encoding="utf-8"))
    assert after["addedAfterFlowConstruction"] == {"must": "survive"}


def test_cutover_points_to_presentation_and_dedicated_cache(backends):
    flow = backends.flow
    contract = flow.dependencies.contract
    config = json.loads(
        contract.config_path.read_text(encoding="utf-8")
    )
    config["cachePath"] = "old-cache"
    contract.config_path.write_text(
        json.dumps(config),
        encoding="utf-8",
    )
    contract.weflow_cache_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    flow.prepare_snapshot()
    flow.validate_copies()
    result = flow.prepare_cutover()

    assert result.stage is RefreshStage.CONFIG_REPLACED
    after = json.loads(
        contract.config_path.read_text(encoding="utf-8")
    )
    assert after["dbPath"] == str(
        flow.layout.root / "presentation"
    )
    assert after["cachePath"] == str(
        contract.weflow_cache_root.resolve(strict=True)
    )


def test_database_only_refresh_skips_every_media_dependency(
    backends,
    monkeypatch,
):
    flow = backends.flow
    flow.dependencies.refresh_mode = RefreshMode.DATABASE_ONLY

    def forbidden(*_args, **_kwargs):
        raise AssertionError("database-only mode touched media")

    for name in (
        "read_media_store_receipt",
        "copy_owned_shadow_media_to_staging",
        "calculate_media_post_staging_budget",
        "import_media_staging",
        "build_presentation",
    ):
        monkeypatch.setattr(orchestrator, name, forbidden)
    monkeypatch.setattr(
        flow.dependencies.validator,
        "media_openability",
        forbidden,
    )

    assert (
        flow.prepare_snapshot().stage
        is RefreshStage.SNAPSHOT_READY
    )
    receipt = flow.validate_copies()

    assert receipt.status == "ok"
    assert flow.stage is RefreshStage.VALIDATED
    assert flow.media_receipt is None
    assert flow.presentation_receipt is None
    assert not (flow.layout.root / "media-staging").exists()
    assert not (flow.layout.root / "presentation").exists()


def test_database_only_cutover_preserves_cache_and_commits_active(
    backends,
    monkeypatch,
):
    flow = backends.flow
    flow.dependencies.refresh_mode = RefreshMode.DATABASE_ONLY
    contract = flow.dependencies.contract
    before = json.loads(
        contract.config_path.read_text(encoding="utf-8")
    )
    before["cachePath"] = "existing-cache"
    contract.config_path.write_text(
        json.dumps(before),
        encoding="utf-8",
    )
    areas = []
    opened = []
    original_validate = flow.dependencies.validator.validate

    def observed_validate(*, area, layout, run_id):
        areas.append(area)
        return original_validate(
            area=area,
            layout=layout,
            run_id=run_id,
        )

    monkeypatch.setattr(
        flow.dependencies.validator,
        "validate",
        observed_validate,
    )
    monkeypatch.setattr(
        flow.dependencies.formal_ui,
        "launch_and_require_account_open",
        lambda parent: opened.append(parent) or True,
    )

    flow.prepare_snapshot()
    flow.validate_copies()
    prepared = flow.prepare_cutover()

    assert prepared.stage is RefreshStage.CONFIG_REPLACED
    production = json.loads(
        contract.config_path.read_text(encoding="utf-8")
    )
    assert production["dbPath"] == str(flow.layout.active)
    assert production["cachePath"] == "existing-cache"
    transaction = flow.dependencies.store.read_equal().record
    assert transaction.presentation_manifest_sha256 is None
    assert transaction.media_store_manifest_sha256 is None

    flow.launch_formal_for_ui()
    accepted = flow.record_ui_confirmation(
        f"CONFIRM {flow.run_id}"
    )
    acceptance = json.loads(
        (flow.layout.root / "acceptance.json").read_text(
            encoding="utf-8"
        )
    )
    assert accepted.stage is RefreshStage.UI_CONFIRMED
    assert opened == [flow.layout.active]
    assert acceptance["presentationManifestSha256"] is None
    assert acceptance["mediaStoreManifestSha256"] is None
    current = flow.dependencies.store.read_equal().record
    current_hashes = {
        item.live_path: item.expected_new_sha256
        for item in current.planned_files
    }
    assert flow._accepted_revalidator(current, current_hashes)

    result = flow.finalize()

    assert result.stage is RefreshStage.COMMITTED
    assert result.activeParent == flow.layout.active
    assert areas == ["validation", "active", "active"]


def _seed_prior_media(flow):
    receipt = orchestrator.copy_owned_shadow_media_to_staging(
        shadow_account=flow.dependencies.contract.source_account,
        run_root=flow.layout.root,
        snapshots_root=flow.dependencies.contract.snapshots_root,
        source_account_name=flow.dependencies.contract.account_id,
        prior_inventory=None,
    )
    stored = import_real_media_staging(
        receipt,
        media_store_root=(
            flow.dependencies.contract.media_store_root
        ),
    )
    orchestrator.remove_owned_staging_tree(
        receipt.staging_path,
        allowed_root=flow.layout.root,
    )
    flow.dependencies.vss.faults.events.clear()
    return stored


def test_prior_media_mode_reuses_store_without_source_media_or_probe(
    backends,
    monkeypatch,
):
    flow = backends.flow
    stored = _seed_prior_media(flow)
    flow.dependencies.refresh_mode = RefreshMode.PRIOR_MEDIA
    budget_receipts = []
    original_budget = orchestrator.calculate_media_post_staging_budget

    def observed_budget(**values):
        budget_receipts.append(values["delta_receipt"])
        return original_budget(**values)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("prior-media mode copied current media")

    monkeypatch.setattr(
        orchestrator,
        "copy_owned_shadow_media_to_staging",
        forbidden,
    )
    monkeypatch.setattr(
        orchestrator,
        "import_media_staging",
        forbidden,
    )
    monkeypatch.setattr(
        orchestrator,
        "calculate_media_post_staging_budget",
        observed_budget,
    )
    monkeypatch.setattr(
        flow.dependencies.validator,
        "media_openability",
        forbidden,
    )

    flow.prepare_snapshot()
    receipt = flow.validate_copies()

    assert receipt.status == "ok"
    assert flow.media_receipt.manifest_sha256 == (
        stored.manifest_sha256
    )
    assert len(budget_receipts) == 1
    assert budget_receipts[0].file_count == 0
    assert flow.presentation_receipt is not None
    assert (flow.layout.root / "presentation").is_dir()
    assert "media_openability" not in backends.faults.events

    prepared = flow.prepare_cutover()
    production = json.loads(
        flow.dependencies.contract.config_path.read_text(
            encoding="utf-8"
        )
    )
    assert prepared.stage is RefreshStage.CONFIG_REPLACED
    assert production["dbPath"] == str(
        flow.layout.root / "presentation"
    )
    assert production["cachePath"] == str(
        flow.dependencies.contract.weflow_cache_root.resolve(
            strict=True
        )
    )
    flow.launch_formal_for_ui()
    flow.record_ui_confirmation(f"CONFIRM {flow.run_id}")
    assert flow.finalize().stage is RefreshStage.COMMITTED


def test_prior_media_mode_stops_before_vss_when_store_is_missing(
    backends,
):
    flow = backends.flow
    flow.dependencies.refresh_mode = RefreshMode.PRIOR_MEDIA

    result = flow.prepare_snapshot()

    assert result.stage is RefreshStage.COMPATIBILITY_BLOCKED
    assert flow.dependencies.store.read_equal().record.state is (
        TxState.ROLLED_BACK
    )
    assert "vss_create" not in backends.faults.events
    assert ("prior_media_store_missing", False) in flow.audit_events


def test_cutover_creates_only_the_fixed_dedicated_cache(backends):
    flow = backends.flow
    cache = flow.dependencies.contract.weflow_cache_root
    cache.rmdir()

    flow.prepare_snapshot()
    flow.validate_copies()
    result = flow.prepare_cutover()

    assert result.stage is RefreshStage.CONFIG_REPLACED
    assert cache.is_dir()
    assert not cache.is_symlink()


def test_formal_ui_opens_the_presentation_parent(
    backends,
    monkeypatch,
):
    flow = backends.flow
    opened = []
    monkeypatch.setattr(
        flow.dependencies.formal_ui,
        "launch_and_require_account_open",
        lambda parent: opened.append(parent) or True,
    )

    flow.prepare_snapshot()
    flow.validate_copies()
    flow.prepare_cutover()
    flow.launch_formal_for_ui()

    assert opened == [flow.layout.root / "presentation"]


def test_cutover_preserves_existing_stored_envelope(backends):
    flow = backends.flow
    path = flow.dependencies.contract.config_path
    value = {
        "dbPath": "old",
        "cachePath": "",
        "myWxid": "wxid_test",
        "decryptKey": "safe:CURRENT_STORED",
        "wxidConfigs": {
            "wxid_test": {
                "decryptKey": "safe:CURRENT_STORED",
                "preserved": True,
            },
            "wxid_other": {
                "decryptKey": "safe:OTHER_ACCOUNT",
            },
        },
    }
    path.write_text(json.dumps(value), encoding="utf-8")

    flow.prepare_snapshot()
    flow.validate_copies()
    assert flow.prepare_cutover().stage is RefreshStage.CONFIG_REPLACED

    after = json.loads(path.read_text(encoding="utf-8"))
    assert after["decryptKey"] == "safe:CURRENT_STORED"
    assert (
        after["wxidConfigs"]["wxid_test"]["decryptKey"]
        == "safe:CURRENT_STORED"
    )
    assert (
        after["wxidConfigs"]["wxid_other"]["decryptKey"]
        == "safe:OTHER_ACCOUNT"
    )


def test_manifest_tuple_contract_is_unpacked_for_both_acceptance_paths(backends):
    flow = backends.flow
    flow.prepare_snapshot()
    flow.validate_copies()
    flow.prepare_cutover()
    flow.launch_formal_for_ui()
    flow.record_ui_confirmation(f"CONFIRM {flow.run_id}")
    record = flow.dependencies.store.inspect_conservative().record
    current_hashes = {
        item.live_path: (item.expected_new_sha256 or "A" * 64)
        for item in record.planned_files
    }
    assert flow._accepted_revalidator(record, current_hashes)
    assert flow.finalize().stage is RefreshStage.COMMITTED


def test_finalize_validates_presentation_database_and_receipt(
    backends,
    monkeypatch,
):
    flow = backends.flow
    areas = []
    original_validate = flow.dependencies.validator.validate

    def observed_validate(*, area, layout, run_id):
        areas.append(area)
        return original_validate(
            area=area,
            layout=layout,
            run_id=run_id,
        )

    monkeypatch.setattr(
        flow.dependencies.validator,
        "validate",
        observed_validate,
    )
    flow.prepare_snapshot()
    flow.validate_copies()
    flow.prepare_cutover()
    flow.launch_formal_for_ui()
    flow.record_ui_confirmation(f"CONFIRM {flow.run_id}")

    assert flow.finalize().stage is RefreshStage.COMMITTED
    assert areas == ["validation", "presentation"]


def test_finalize_rolls_back_when_presentation_media_changes(
    backends,
):
    flow = backends.flow
    flow.prepare_snapshot()
    flow.validate_copies()
    flow.prepare_cutover()
    flow.launch_formal_for_ui()
    flow.record_ui_confirmation(f"CONFIRM {flow.run_id}")
    media = (
        flow.layout.root
        / "presentation"
        / flow.dependencies.contract.account_id
        / "msg"
        / "attach"
        / "synthetic-image.bin"
    )
    media.write_bytes(b"tampered-presentation-media")

    assert flow.finalize().stage is RefreshStage.ROLLED_BACK
    assert (
        "presentation_receipt_mismatch",
        False,
    ) in flow.audit_events


def test_acceptance_anchors_exact_presentation_generation(
    backends,
    monkeypatch,
):
    flow = backends.flow
    flow.prepare_snapshot()
    flow.validate_copies()
    flow.prepare_cutover()
    flow.launch_formal_for_ui()
    flow.record_ui_confirmation(f"CONFIRM {flow.run_id}")
    acceptance = json.loads(
        (flow.layout.root / "acceptance.json").read_text(
            encoding="utf-8"
        )
    )
    assert acceptance["presentationManifestSha256"] == (
        flow.presentation_receipt.manifest_sha256
    )
    assert acceptance["mediaStoreManifestSha256"] == (
        flow.presentation_receipt.manifest.media_store_manifest_sha256
    )
    monkeypatch.setattr(
        orchestrator,
        "read_presentation_receipt",
        lambda *args, **kwargs: replace(
            flow.presentation_receipt,
            manifest_sha256="D" * 64,
        ),
    )

    assert flow.finalize().stage is RefreshStage.ROLLED_BACK
    assert (
        "presentation_receipt_mismatch",
        False,
    ) in flow.audit_events


def test_finalize_rejects_unanchored_acceptance_mutation(
    backends,
):
    flow = backends.flow
    flow.prepare_snapshot()
    flow.validate_copies()
    flow.prepare_cutover()
    flow.launch_formal_for_ui()
    flow.record_ui_confirmation(f"CONFIRM {flow.run_id}")
    acceptance_path = flow.layout.root / "acceptance.json"
    acceptance = json.loads(
        acceptance_path.read_text(encoding="utf-8")
    )
    acceptance["unanchored"] = True
    atomic_write_json(acceptance_path, acceptance)

    assert flow.finalize().stage is RefreshStage.ROLLED_BACK
    assert (
        "acceptance_receipt_mismatch",
        False,
    ) in flow.audit_events


@pytest.mark.parametrize("failure", ["backup_copy", "backup_acl"])
def test_accepted_restart_revalidator_rechecks_backup_and_acl(
        backends, monkeypatch, failure):
    flow = backends.flow
    flow.prepare_snapshot()
    flow.validate_copies()
    flow.prepare_cutover()
    flow.launch_formal_for_ui()
    flow.record_ui_confirmation(f"CONFIRM {flow.run_id}")
    record = flow.dependencies.store.inspect_conservative().record
    current_hashes = {item.live_path: "A" * 64 for item in record.planned_files}
    if failure == "backup_copy":
        def reject_backup(_self):
            raise RuntimeError("backup_copy")

        monkeypatch.setattr(BackupBundle, "verify_backup_copies", reject_backup)
    else:
        backends.faults.active = "backup_acl"
    assert not flow._accepted_revalidator(record, current_hashes)


def test_accepted_restart_revalidator_rejects_replaced_f_source(
        backends, monkeypatch):
    flow = backends.flow
    flow.prepare_snapshot()
    flow.validate_copies()
    flow.prepare_cutover()
    flow.launch_formal_for_ui()
    flow.record_ui_confirmation(f"CONFIRM {flow.run_id}")
    record = flow.dependencies.store.inspect_conservative().record
    current_hashes = {item.live_path: "A" * 64 for item in record.planned_files}
    real_canonical = orchestrator.canonical_existing
    source_db = flow.dependencies.contract.session_db
    monkeypatch.setattr(
        orchestrator, "canonical_existing",
        lambda path: (path.parent / "replaced-session.db"
                      if path == source_db else real_canonical(path)))
    assert not flow._accepted_revalidator(record, current_hashes)


def _reject_unplanned_backup_read(**kwargs):
    raise AssertionError("backup reader must not run without a persisted plan")


def test_resume_deleted_recorded_shadow_with_journal_rolls_back_without_backup(
        backends, monkeypatch):
    flow = backends.flow
    flow.dependencies.store.record_shadow(
        expected=TxState.DISCOVERED, shadow_id=SHADOW_ID,
        source_volume="F:\\")
    flow.dependencies.vss.publish_creating_intent(
        run_id=flow.run_id, source_volume="F:\\")
    flow.dependencies.vss.state = ShadowState.DELETED
    monkeypatch.setattr(
        orchestrator, "read_backup_bundle", _reject_unplanned_backup_read)
    assert flow.resume().stage is RefreshStage.ROLLED_BACK
    assert flow.dependencies.journal_exists(flow.run_id)


def test_resume_rejects_newer_single_mirror_rolled_back(backends):
    flow = backends.flow
    store = flow.dependencies.store
    current = store.read_equal().record
    partial_terminal = replace(
        current,
        sequence=current.sequence + 1,
        state=TxState.ROLLED_BACK,
    )
    atomic_write_json(
        store.recovery_path,
        _record_json(partial_terminal),
    )
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING


def test_resume_rejects_equal_sequence_content_divergence(backends):
    flow = backends.flow
    store = flow.dependencies.store
    current = store.read_equal().record
    atomic_write_json(
        store.primary_path,
        _record_json(
            replace(
                current,
                run_id=(
                    "33333333-3333-3333-3333-333333333333"
                ),
            )
        ),
    )
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING


def test_resume_retries_exact_shadow_cleanup_then_rolls_back_without_backup(
        backends, monkeypatch):
    flow = backends.flow
    flow.dependencies.store.record_shadow(
        expected=TxState.DISCOVERED, shadow_id=SHADOW_ID,
        source_volume="F:\\")
    flow.dependencies.vss.publish_creating_intent(
        run_id=flow.run_id, source_volume="F:\\")
    flow.dependencies.vss.state = ShadowState.CREATING
    monkeypatch.setattr(
        orchestrator, "read_backup_bundle", _reject_unplanned_backup_read)
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING
    flow.dependencies.vss.state = ShadowState.ADOPTED
    assert flow.resume().stage is RefreshStage.ROLLED_BACK
    assert flow.dependencies.vss.state is ShadowState.DELETED


def test_resume_late_created_shadow_binds_both_mirrors_before_delete(
        backends, monkeypatch):
    flow = backends.flow
    backends.faults.active = "vss_create_timeout"
    with pytest.raises(RuntimeError, match="shadow_cleanup_recovery_pending"):
        flow.prepare_snapshot()
    assert (flow.dependencies.store.read_equal().record.state is
            TxState.RECOVERY_PENDING)
    assert flow.dependencies.vss.state is ShadowState.CREATING
    monkeypatch.setattr(
        orchestrator, "read_backup_bundle", _reject_unplanned_backup_read)
    assert flow.dependencies.store.inspect_conservative().record.shadow_id is None

    backends.faults.active = None
    flow.dependencies.vss.state = ShadowState.CREATED
    backends.faults.trace_late_bind_writes = True
    original_delete = flow.dependencies.vss.delete_exact

    def require_joint_identity_before_delete(*, run_id, shadow_id):
        record = flow.dependencies.store.read_equal().record
        assert record.state is TxState.RECOVERY_PENDING
        assert record.shadow_id == shadow_id == SHADOW_ID
        return original_delete(run_id=run_id, shadow_id=shadow_id)

    monkeypatch.setattr(
        flow.dependencies.vss, "delete_exact",
        require_joint_identity_before_delete)
    assert flow.resume().stage is RefreshStage.ROLLED_BACK
    assert flow.dependencies.vss.state is ShadowState.DELETED
    assert flow.dependencies.store.read_equal().record.shadow_id == SHADOW_ID
    ordered = [
        "vss_prepare_create_durable", "vss_create",
        "late_bind_c", "late_bind_e", "vss_delete_exact",
    ]
    assert [event for event in backends.faults.events
            if event in ordered] == ordered


def test_resume_never_late_binds_unrecorded_adopted_shadow(
        backends, monkeypatch):
    flow = backends.flow
    flow.dependencies.store.force_conservative_state(
        TxState.RECOVERY_PENDING)
    flow.dependencies.vss.publish_creating_intent(
        run_id=flow.run_id, source_volume="F:\\")
    flow.dependencies.vss.state = ShadowState.ADOPTED
    monkeypatch.setattr(
        orchestrator, "read_backup_bundle", _reject_unplanned_backup_read)
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING
    assert flow.dependencies.store.inspect_conservative().record.shadow_id is None
    assert flow.dependencies.vss.state is ShadowState.ADOPTED


def test_resume_late_bind_failure_never_deletes_shadow(backends, monkeypatch):
    flow = backends.flow
    flow.dependencies.store.force_conservative_state(
        TxState.RECOVERY_PENDING)
    flow.dependencies.vss.publish_creating_intent(
        run_id=flow.run_id, source_volume="F:\\")
    flow.dependencies.vss.state = ShadowState.CREATED
    monkeypatch.setattr(
        flow.dependencies.store, "late_bind_created_shadow_for_cleanup",
        lambda **_: (_ for _ in ()).throw(RuntimeError("mirror_write_failed")))
    monkeypatch.setattr(
        flow.dependencies.vss, "delete_exact",
        lambda **_: (_ for _ in ()).throw(
            AssertionError("delete before joint transaction identity")))
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING
    assert flow.dependencies.vss.state is ShadowState.CREATED


@pytest.mark.parametrize("failure", ["diverged", "primary_unavailable"])
def test_resume_never_deletes_with_less_than_two_equal_transaction_mirrors(
        backends, monkeypatch, failure):
    flow = backends.flow
    store = flow.dependencies.store
    before = store.read_equal().record
    store.record_shadow(
        expected=TxState.DISCOVERED, shadow_id=SHADOW_ID,
        source_volume="F:\\")
    flow.dependencies.vss.publish_creating_intent(
        run_id=flow.run_id, source_volume="F:\\")
    flow.dependencies.vss.state = ShadowState.CREATED
    if failure == "diverged":
        atomic_write_json(store.primary_path, _record_json(before))
    else:
        store.primary_path.unlink()
    monkeypatch.setattr(
        flow.dependencies.vss, "inspect_owned",
        lambda **_: (_ for _ in ()).throw(
            AssertionError("VSS inspection before equal-mirror gate")))
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING
    assert flow.dependencies.vss.state is ShadowState.CREATED


def test_resume_never_deletes_shadow_with_source_identity_drift(
        backends, monkeypatch):
    flow = backends.flow
    flow.dependencies.store.record_shadow(
        expected=TxState.DISCOVERED, shadow_id=SHADOW_ID,
        source_volume="F:\\")
    flow.dependencies.vss.publish_creating_intent(
        run_id=flow.run_id, source_volume="F:\\")
    flow.dependencies.vss.state = ShadowState.CREATED
    monkeypatch.setattr(
        flow.dependencies.vss, "inspect_owned",
        lambda **_: SimpleNamespace(
            run_id=flow.run_id, source_volume="E:\\",
            state=ShadowState.CREATED, shadow_id=SHADOW_ID,
            device_object=r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy99"))
    monkeypatch.setattr(
        flow.dependencies.vss, "delete_exact",
        lambda **_: (_ for _ in ()).throw(
            AssertionError("delete with source identity drift")))
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING


def test_resume_never_deletes_shadow_with_run_identity_drift(
        backends, monkeypatch):
    flow = backends.flow
    flow.dependencies.store.record_shadow(
        expected=TxState.DISCOVERED, shadow_id=SHADOW_ID,
        source_volume="F:\\")
    flow.dependencies.vss.publish_creating_intent(
        run_id=flow.run_id, source_volume="F:\\")
    flow.dependencies.vss.state = ShadowState.CREATED
    monkeypatch.setattr(
        flow.dependencies.vss, "inspect_owned",
        lambda **_: SimpleNamespace(
            run_id="99999999-9999-4999-8999-999999999999",
            source_volume="F:\\", state=ShadowState.CREATED,
            shadow_id=SHADOW_ID,
            device_object=r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy99"))
    monkeypatch.setattr(
        flow.dependencies.vss, "delete_exact",
        lambda **_: (_ for _ in ()).throw(
            AssertionError("delete with run identity drift")))
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING


def test_validated_close_timeout_with_historical_shadow_has_no_backup_read(
        backends, monkeypatch):
    flow = backends.flow
    flow.prepare_snapshot()
    flow.validate_copies()
    assert flow.transaction.shadow_id == SHADOW_ID
    assert flow.dependencies.vss.state is ShadowState.DELETED
    backends.faults.active = "normal_close_timeout"
    assert flow.prepare_cutover().stage is RefreshStage.RECOVERY_PENDING
    monkeypatch.setattr(
        orchestrator, "read_backup_bundle", _reject_unplanned_backup_read)
    assert flow.resume().stage is RefreshStage.ROLLED_BACK


@pytest.mark.parametrize("failure", ["both_manifests_unavailable", "backup_acl"])
def test_resume_backup_rebuild_failure_persists_pending(
        backends, monkeypatch, failure):
    flow = backends.flow
    flow.prepare_snapshot()
    flow.validate_copies()
    flow.prepare_cutover()
    flow.bundle = None
    error = (OSError("both_manifests_unavailable")
             if failure == "both_manifests_unavailable"
             else RuntimeError("backup_acl_verification_failed"))
    monkeypatch.setattr(
        orchestrator, "read_backup_bundle",
        lambda **kwargs: (_ for _ in ()).throw(error))
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING
    assert (flow.dependencies.store.inspect_conservative().record.state is
            TxState.RECOVERY_PENDING)


def fully_cut_over_flow(backends):
    flow = backends.flow
    flow.prepare_snapshot()
    flow.validate_copies()
    assert flow.prepare_cutover().stage is RefreshStage.CONFIG_REPLACED
    flow.launch_formal_for_ui()
    return flow


def fully_ui_confirmed_flow(backends):
    flow = fully_cut_over_flow(backends)
    record = flow.record_ui_confirmation(f"CONFIRM {flow.run_id}")
    assert record.stage is RefreshStage.UI_CONFIRMED
    return flow


def test_exact_confirmation_is_persisted_as_boolean_only(backends):
    flow = fully_cut_over_flow(backends)
    flow.record_ui_confirmation(f"CONFIRM {flow.run_id}")
    assert flow.stage is RefreshStage.UI_CONFIRMED
    accepted = flow.dependencies.store.read_equal().record
    assert accepted.state is TxState.ACCEPTED
    persisted = json.loads(
        (flow.layout.root / "acceptance.json").read_text(encoding="utf-8"))
    assert persisted["uiConfirmed"] is True
    assert accepted.acceptance_sha256 == sha256_file(
        flow.layout.root / "acceptance.json"
    )
    assert f"CONFIRM {flow.run_id}" not in flow.audit_text()


@pytest.mark.parametrize("field", [
    "schemaFingerprint", "aggregateFingerprint", "databaseCoverageFingerprint"
])
def test_each_active_fingerprint_mismatch_rolls_back(backends, field):
    flow = fully_ui_confirmed_flow(backends)
    backends.faults.active = {
        "schemaFingerprint": "schema_mismatch",
        "aggregateFingerprint": "aggregate_mismatch",
        "databaseCoverageFingerprint": "coverage_mismatch",
    }[field]
    assert flow.finalize().stage is RefreshStage.ROLLED_BACK
    backends.faults.assert_complete_old_fileset()


def test_active_wal_shm_file_changes_after_ui_still_commit(backends):
    flow = fully_ui_confirmed_flow(backends)
    active_db = flow.layout.role_db_storage(
        CopyRole.ACTIVE, flow.dependencies.contract.account_id)
    (active_db / "message.db-wal").write_bytes(b"synthetic-ui-wal-change")
    (active_db / "message.db-shm").write_bytes(b"synthetic-ui-shm-change")
    assert flow.finalize().stage is RefreshStage.COMMITTED


def test_formal_ui_derived_file_hashes_are_recorded_then_commit(backends):
    flow = fully_ui_confirmed_flow(backends)
    contract = flow.dependencies.contract
    config = json.loads(
        contract.config_path.read_text(encoding="utf-8")
    )
    config["uiDerived"] = True
    contract.config_path.write_text(
        json.dumps(config),
        encoding="utf-8",
    )
    contract.cache_maps_path.write_bytes(b'{"uiDerived":true}')
    observed = {
        str(contract.config_path): sha256_file(contract.config_path),
        str(contract.cache_maps_path): sha256_file(
            contract.cache_maps_path
        ),
    }
    before = flow.dependencies.store.read_equal().record
    assert any(
        item.action == "replace"
        and item.expected_new_sha256 != observed[item.live_path]
        for item in before.planned_files
    )

    assert flow.finalize().stage is RefreshStage.COMMITTED

    committed = flow.dependencies.store.read_equal().record
    assert {
        item.live_path: item.expected_new_sha256
        for item in committed.planned_files
        if item.action == "replace"
    } == observed


def test_formal_ui_derived_file_hashes_can_still_roll_back(backends):
    flow = fully_ui_confirmed_flow(backends)
    contract = flow.dependencies.contract
    config = json.loads(
        contract.config_path.read_text(encoding="utf-8")
    )
    config["uiDerived"] = True
    contract.config_path.write_text(
        json.dumps(config),
        encoding="utf-8",
    )
    contract.cache_maps_path.write_bytes(b'{"uiDerived":true}')
    backends.faults.active = "schema_mismatch"

    assert flow.finalize().stage is RefreshStage.ROLLED_BACK
    backends.faults.assert_complete_old_fileset()


def test_resume_rejects_newer_single_mirror_committed(backends):
    flow = fully_ui_confirmed_flow(backends)
    assert flow.finalize().stage is RefreshStage.COMMITTED
    store = flow.dependencies.store
    committed = store.read_equal().record
    atomic_write_json(
        store.primary_path,
        _record_json(
            replace(
                committed,
                sequence=committed.sequence - 1,
                state=TxState.ACCEPTED,
            )
        ),
    )
    assert flow.resume().stage is RefreshStage.RECOVERY_PENDING


def test_source_file_change_after_ui_always_rolls_back(backends):
    flow = fully_ui_confirmed_flow(backends)
    source_db = flow.layout.role_db_storage(
        CopyRole.SOURCE, flow.dependencies.contract.account_id)
    (source_db / "session.db").write_bytes(b"tampered-source")
    assert flow.finalize().stage is RefreshStage.ROLLED_BACK
    backends.faults.assert_complete_old_fileset()


@pytest.fixture
def parser():
    return build_parser()


@pytest.fixture
def cli_harness(tmp_path):
    faults = SyntheticFaultController(tmp_path)
    try:
        flow = build_synthetic_flow(
            tmp_path=tmp_path,
            timestamp="20260721-100000",
            faults=faults,
        )

        def input_for(value):
            if isinstance(value, BaseException):
                def raise_value(_prompt):
                    raise value

                return raise_value
            return lambda _prompt: value

        yield SimpleNamespace(flow=flow, input_for=input_for)
    finally:
        faults.close()


@pytest.mark.parametrize("forbidden", [
    ["refresh", "--key", "deadbeef"],
    ["refresh", "--source", r"C:\other"],
    ["refresh", "--upload-url", "https://example.invalid"],
    ["refresh", "--delete"],
])
def test_cli_rejects_expansive_inputs(parser, forbidden):
    with pytest.raises(SystemExit):
        parser.parse_args(forbidden)


@pytest.mark.parametrize("argv", [
    ["refresh", "--key", "SENSITIVE-KEY-SENTINEL"],
    ["resume", "--run-id", "SENSITIVE-GUID-SENTINEL"],
])
def test_cli_parse_errors_never_echo_argument_values(
        parser, capsys, argv):
    with pytest.raises(SystemExit) as error:
        parser.parse_args(argv)
    assert error.value.code == 2
    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert "SENSITIVE-" not in rendered


def test_refresh_prompts_exact_confirmation_and_commits(cli_harness):
    result = execute_refresh(
        cli_harness.flow,
        input_fn=lambda _: f"CONFIRM {cli_harness.flow.run_id}",
    )
    assert result.stage is RefreshStage.COMMITTED


def test_refresh_prints_redacted_cutover_paths_before_first_write(
        cli_harness):
    emitted = []
    original = cli_harness.flow.prepare_cutover

    def prepare_after_notice():
        assert len(emitted) == 1
        return original()

    cli_harness.flow.prepare_cutover = prepare_after_notice
    result = execute_refresh(
        cli_harness.flow,
        input_fn=lambda _: "",
        output_fn=emitted.append,
    )
    assert result.stage is RefreshStage.ROLLED_BACK
    notice = json.loads(emitted[0])
    assert notice == {
        "activeParent": str(cli_harness.flow.layout.active),
        "primaryBackupRoot": str(
            cli_harness.flow.dependencies.primary_backup_root),
        "recoveryBackupRoot": str(
            cli_harness.flow.dependencies.recovery_backup_root),
        "runId": cli_harness.flow.run_id,
    }


@pytest.mark.parametrize("answer", [
    "yes",
    "CONFIRM wrong-id",
    "",
    EOFError(),
])
def test_refresh_rejection_rolls_back(cli_harness, answer):
    result = execute_refresh(
        cli_harness.flow,
        input_fn=cli_harness.input_for(answer),
    )
    assert result.stage is RefreshStage.ROLLED_BACK


def test_refresh_compatibility_block_stays_blocked(
        cli_harness, monkeypatch):
    cli_harness.flow.dependencies.vss.faults.active = (
        "compatibility"
    )
    result = execute_refresh(
        cli_harness.flow,
        input_fn=lambda _: (_ for _ in ()).throw(
            AssertionError("blocked flow must not prompt")
        ),
    )
    assert result.stage is RefreshStage.COMPATIBILITY_BLOCKED
    monkeypatch.setattr(cli, "dispatch", lambda args: result)
    monkeypatch.setattr(
        cli,
        "print_redacted_result",
        lambda value: None,
    )
    assert cli.main(["refresh"]) == 2


def test_task4_cli_import_does_not_resolve_future_live_module(monkeypatch):
    real_import = builtins.__import__
    original_package_cli = weflow_chat.cli

    def reject_future_live(name, *args, **kwargs):
        if name == "weflow_chat.live":
            raise AssertionError("Task 4 must not import Task 6 live.py")
        return real_import(name, *args, **kwargs)

    try:
        monkeypatch.setattr(
            builtins,
            "__import__",
            reject_future_live,
        )
        monkeypatch.delitem(
            sys.modules,
            "weflow_chat.cli",
            raising=False,
        )
        imported = importlib.import_module(
            "weflow_chat.cli"
        )
        assert (
            imported.build_parser()
            .parse_args(["preflight"]).command
            == "preflight"
        )
    finally:
        weflow_chat.cli = original_package_cli


def test_main_returns_error_for_blocked_preflight(monkeypatch):
    monkeypatch.setattr(
        cli, "dispatch", lambda args: SimpleNamespace(ok=False))
    monkeypatch.setattr(cli, "print_redacted_result", lambda result: None)
    assert cli.main(["preflight"]) == 2
