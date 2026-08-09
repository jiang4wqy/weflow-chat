import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.fakes import (
    SHADOW_ID,
    SyntheticFaultController,
    build_synthetic_flow,
)
from weflow_chat.config import read_backup_bundle
from weflow_chat.models import TxState
from weflow_chat.orchestrator import (
    RefreshOrchestrator,
    RefreshStage,
)
from weflow_chat.vss import ShadowState


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): (
            hashlib.sha256(path.read_bytes())
            .hexdigest()
            .upper()
        )
        for path in sorted(
            item
            for item in root.rglob("*")
            if item.is_file()
        )
    }


def test_synthetic_refresh_commits_after_all_acceptance_gates(
    synthetic_refresh,
):
    result = synthetic_refresh.run(
        ui_response=f"CONFIRM {synthetic_refresh.flow.run_id}"
    )
    assert result.stage is RefreshStage.COMMITTED
    production = json.loads(
        (
            synthetic_refresh.faults.production_root
            / "WeFlow-config.json"
        ).read_text(encoding="utf-8")
    )
    assert Path(production["dbPath"]) == result.activeParent
    synthetic_refresh.assert_source_unchanged()
    synthetic_refresh.assert_no_real_host_paths_touched()


def test_second_refresh_never_mutates_first_committed_run(
    synthetic_refresh,
):
    first = synthetic_refresh.run_successfully(
        timestamp="20260721-120000"
    )
    assert first.stage is RefreshStage.COMMITTED
    first_hashes = _tree_hashes(first.runRoot)
    first_recovery_backup = (
        synthetic_refresh.flow.dependencies
        .recovery_backup_root
    )
    first_recovery_backup_hashes = _tree_hashes(
        first_recovery_backup
    )

    second = synthetic_refresh.run_successfully(
        timestamp="20260721-130000"
    )
    assert second.stage is RefreshStage.COMMITTED
    assert second.runRoot != first.runRoot
    assert _tree_hashes(first.runRoot) == first_hashes
    assert (
        _tree_hashes(first_recovery_backup)
        == first_recovery_backup_hashes
    )

    production = json.loads(
        (
            synthetic_refresh.faults.production_root
            / "WeFlow-config.json"
        ).read_text(encoding="utf-8")
    )
    assert Path(production["dbPath"]) == second.activeParent
    assert (
        "20260721-130000"
        in second.activeParent.parent.name
    )
    second_flow = synthetic_refresh.flow
    transaction = (
        second_flow.dependencies.store
        .read_equal()
        .record
    )
    persisted_bundle = read_backup_bundle(
        primary_manifest_path=(
            transaction.backup_primary_manifest_path
        ),
        recovery_manifest_path=(
            transaction.backup_recovery_manifest_path
        ),
        expected_run_id=second.runId,
        expected_sha256=(
            transaction.backup_manifest_sha256
        ),
        security_adapter=(
            second_flow.dependencies.security
        ),
    )
    config_backup = next(
        item
        for item in persisted_bundle.items
        if Path(item.live_path).name
        == "WeFlow-config.json"
    )
    for stored_path in (
        config_backup.primary_backup_path,
        config_backup.recovery_backup_path,
    ):
        persisted_config = json.loads(
            Path(stored_path).read_text(
                encoding="utf-8"
            )
        )
        assert (
            persisted_config["dbPath"]
            == str(first.activeParent)
        )


def test_restart_rebuilds_backup_from_persisted_transaction_receipt(
    synthetic_refresh,
):
    flow = synthetic_refresh.flow
    flow.prepare_snapshot()
    assert flow.validate_copies().status == "ok"
    assert (
        flow.prepare_cutover().stage
        is RefreshStage.CONFIG_REPLACED
    )
    in_memory_bundle = flow.bundle
    flow.bundle = None  # Model a new process with no in-memory backup object.
    result = flow.resume()
    assert result.stage is RefreshStage.ROLLED_BACK
    assert flow.bundle is not None
    assert flow.bundle is not in_memory_bundle
    assert "backup_manifest_read" in synthetic_refresh.faults.events
    synthetic_refresh.assert_complete_old_fileset()


def test_new_process_operator_rollback_rebuilds_bundle_and_restores_three_files(
    synthetic_refresh,
):
    flow = synthetic_refresh.flow
    flow.prepare_snapshot()
    flow.validate_copies()
    flow.prepare_cutover()
    restarted = RefreshOrchestrator(
        flow.dependencies, flow.run_id
    )
    assert restarted.bundle is None
    assert (
        restarted.rollback_existing().stage
        is RefreshStage.ROLLED_BACK
    )
    assert restarted.bundle is not None
    assert restarted.bundle is not flow.bundle
    assert "backup_manifest_read" in (
        synthetic_refresh.faults.events
    )
    synthetic_refresh.assert_complete_old_fileset()


def test_discovered_before_vss_create_is_only_absent_journal_terminal_case(
    tmp_path,
):
    faults = SyntheticFaultController(tmp_path)
    try:
        flow = build_synthetic_flow(
            tmp_path=tmp_path,
            timestamp="20260721-110400",
            faults=faults,
        )
        assert (
            flow.dependencies.store.read_equal().record.state
            is TxState.DISCOVERED
        )
        assert not flow.dependencies.journal_exists(flow.run_id)
        assert flow.resume().stage is RefreshStage.ROLLED_BACK
    finally:
        faults.close()


def test_resume_deleted_journal_id_mismatch_persists_pending(
    tmp_path,
):
    faults = SyntheticFaultController(tmp_path)
    try:
        flow = build_synthetic_flow(
            tmp_path=tmp_path,
            timestamp="20260721-110401",
            faults=faults,
        )
        flow.dependencies.store.record_shadow(
            expected=TxState.DISCOVERED,
            shadow_id=SHADOW_ID,
            source_volume="F:\\",
        )
        flow.dependencies.vss.publish_creating_intent(
            run_id=flow.run_id, source_volume="F:\\"
        )
        flow.dependencies.vss.inspect_owned = (
            lambda **kwargs: SimpleNamespace(
                run_id=flow.run_id,
                source_volume="F:\\",
                state=ShadowState.DELETED,
                shadow_id=(
                    "{99999999-9999-4999-8999-999999999999}"
                ),
                device_object=None,
            )
        )
        assert (
            flow.resume().stage
            is RefreshStage.RECOVERY_PENDING
        )
    finally:
        faults.close()


def test_absent_analytics_created_by_ui_is_hash_bound_then_deleted(
    tmp_path, monkeypatch,
):
    faults = SyntheticFaultController(tmp_path)
    try:
        flow = build_synthetic_flow(
            tmp_path=tmp_path,
            timestamp="20260721-110500",
            faults=faults,
            analytics_absent_before=True,
        )
        flow.prepare_snapshot()
        assert flow.validate_copies().status == "ok"
        assert (
            flow.prepare_cutover().stage
            is RefreshStage.CONFIG_REPLACED
        )
        flow.launch_formal_for_ui()
        assert (
            flow.dependencies.contract.analytics_cache_path
            .is_file()
        )
        with monkeypatch.context() as scoped:
            scoped.setattr(
                "weflow_chat.orchestrator.recover_transaction",
                lambda **kwargs: (_ for _ in ()).throw(
                    RuntimeError(
                        "crash_after_derived_hash_receipt"
                    )
                ),
            )
            with pytest.raises(
                RuntimeError,
                match="crash_after_derived_hash_receipt",
            ):
                flow.record_ui_confirmation("")
        planned = (
            flow.dependencies.store
            .inspect_conservative()
            .record.planned_files
        )
        analytics = next(
            item
            for item in planned
            if item.live_path.endswith("analytics_cache.json")
        )
        assert analytics.action == "delete_if_created"
        assert analytics.expected_new_sha256 is not None
        flow.bundle = None
        restarted = RefreshOrchestrator(
            flow.dependencies,
            flow.run_id,
        )
        result = restarted.rollback_existing()
        assert result.stage is RefreshStage.ROLLED_BACK
        assert restarted.bundle is not None
        assert "backup_manifest_read" in faults.events
        assert not (
            flow.dependencies.contract.analytics_cache_path
            .exists()
        )
    finally:
        faults.close()


def test_created_analytics_reparse_identity_failure_persists_pending(
    tmp_path, monkeypatch,
):
    faults = SyntheticFaultController(tmp_path)
    try:
        flow = build_synthetic_flow(
            tmp_path=tmp_path,
            timestamp="20260721-110501",
            faults=faults,
            analytics_absent_before=True,
        )
        flow.prepare_snapshot()
        flow.validate_copies()
        flow.prepare_cutover()
        flow.launch_formal_for_ui()
        with monkeypatch.context() as scoped:
            scoped.setattr(
                "weflow_chat.orchestrator.read_current_hashes",
                lambda planned: (_ for _ in ()).throw(
                    RuntimeError("live_path_identity_changed")
                ),
            )
            with pytest.raises(
                RuntimeError,
                match="live_path_identity_changed",
            ):
                flow.record_ui_confirmation("")
        assert (
            flow.dependencies.store
            .inspect_conservative()
            .record.state
            is TxState.RECOVERY_PENDING
        )
    finally:
        faults.close()


@pytest.mark.parametrize("fault", [
    "compatibility",
    "vss_prepare_timeout",
    "vss_create",
    "vss_create_timeout",
        "vss_return_after_create",
        "staging_copy",
        "media_staging_copy",
        "media_import",
        "source_copy",
        "validation",
        "active_copy",
        "presentation",
    "backup",
    "first_cache_replace",
    "analytics_delete",
    "config_replace",
    "ui_reject",
    "schema_mismatch",
    "aggregate_mismatch",
    "coverage_mismatch",
    "normal_close_timeout",
    "mirror_divergence",
    "formal_launch",
    "account_open",
])
def test_faults_never_leave_unrecoverable_config(
    synthetic_refresh, fault,
):
    synthetic_refresh.inject_fault(fault)
    fingerprint_faults = {
        "schema_mismatch",
        "aggregate_mismatch",
        "coverage_mismatch",
    }
    response = (
        f"CONFIRM {synthetic_refresh.flow.run_id}"
        if fault in fingerprint_faults
        else None
    )
    result = synthetic_refresh.run(ui_response=response)
    blocked = {"compatibility", "validation"}
    pending = {
        "vss_prepare_timeout",
        "vss_create",
        "vss_create_timeout",
        "normal_close_timeout",
        "mirror_divergence",
    }
    expected = (
        RefreshStage.COMPATIBILITY_BLOCKED
        if fault in blocked
        else (
            RefreshStage.RECOVERY_PENDING
            if fault in pending
            else RefreshStage.ROLLED_BACK
        )
    )
    assert result.stage is expected
    assert (
        synthetic_refresh.faults.capture_formal_hashes()
        == synthetic_refresh.formal_hashes
    )
    if fault in fingerprint_faults:
            assert "validator_presentation" in (
                synthetic_refresh.faults.events
            )
    if fault == "analytics_delete":
        assert "cutover_after_analytics_delete" in (
            synthetic_refresh.faults.events
        )


@pytest.mark.parametrize("fault", [
    "first_cache_replace",
    "analytics_delete",
    "config_replace",
    "ui_reject",
    "schema_mismatch",
    "aggregate_mismatch",
    "coverage_mismatch",
    "formal_launch",
    "account_open",
])
def test_every_post_prepared_crash_restores_exact_three_file_hashes(
    synthetic_refresh, fault,
):
    synthetic_refresh.inject_fault(fault)
    response = (
        f"CONFIRM {synthetic_refresh.flow.run_id}"
        if fault in {
            "schema_mismatch",
            "aggregate_mismatch",
            "coverage_mismatch",
        }
        else None
    )
    result = synthetic_refresh.run(ui_response=response)
    assert result.stage is RefreshStage.ROLLED_BACK
    assert (
        synthetic_refresh.faults.capture_formal_hashes()
        == synthetic_refresh.formal_hashes
    )
    if fault in {
        "schema_mismatch",
        "aggregate_mismatch",
        "coverage_mismatch",
    }:
            assert "validator_presentation" in (
                synthetic_refresh.faults.events
            )
    if fault == "analytics_delete":
        assert "cutover_after_analytics_delete" in (
            synthetic_refresh.faults.events
        )
