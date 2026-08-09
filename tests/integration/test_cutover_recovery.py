from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import shutil
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

from weflow_chat.audit import AuditErrorCode, AuditStage, AuditStatus
from weflow_chat.config import (
    BackupBundle,
    PreparedChange,
    build_planned_files,
    create_dual_config_backup,
    prepare_stored_key_cutover,
    read_backup_bundle,
)
from weflow_chat.manifest import (
    build_manifest,
    file_set_receipt,
    staging_receipt_sha256,
)
from weflow_chat.models import CopyRole, TxState
from weflow_chat.paths import RunLayout
from weflow_chat.recovery import (
    CutoverCheckpoint,
    execute_cutover,
    recover_transaction,
    sha256_path,
)
from weflow_chat.security import SecurityAdapter, SecurityMetadata
from weflow_chat.transaction import (
    MirroredTransactionStore,
    TransactionRecord,
)


class InjectedCrash(RuntimeError):
    pass


class StoppedProcessGate:
    def request_normal_close_and_wait(self, timeout_seconds):
        return True


class FakeSecurityAdapter:
    def __init__(self):
        self.values = {}
        self.restricted = set()

    def capture(self, path):
        return self.values.setdefault(
            str(path.resolve()),
            SecurityMetadata(
                file_attributes=32,
                owner_sid="S-1-5-21-test",
                group_sid="S-1-5-18",
                dacl_sddl="D:synthetic",
            ),
        )

    def restrict_backup_tree(self, path):
        self.restricted.add(str(path.resolve()))

    def verify_restricted_backup_tree(self, path):
        assert str(path.resolve()) in self.restricted

    def restore(self, path, value):
        self.values[str(path.resolve())] = value

    def verify(self, path, value):
        assert self.values[str(path.resolve())] == value


@pytest.fixture
def fake_security_adapter():
    return FakeSecurityAdapter()


def assert_exact_synthetic_role_tree(
    root: Path, source_account_name: str
) -> None:
    """Audit the on-disk fixture shape without using the core tree validator."""
    top_level = list(root.iterdir())
    assert len(top_level) == 1
    assert top_level[0].name == source_account_name
    assert top_level[0].is_dir()
    assert not any(path.is_file() for path in top_level)

    account_children = list(top_level[0].iterdir())
    assert len(account_children) == 1
    assert account_children[0].name == "db_storage"
    assert account_children[0].is_dir()

    directories = [
        root,
        top_level[0],
        account_children[0],
        *(
            path
            for path in account_children[0].rglob("*")
            if path.is_dir()
        ),
    ]
    assert all(any(directory.iterdir()) for directory in directories)
    database_files = [
        path
        for path in account_children[0].rglob("*")
        if path.is_file()
    ]
    assert database_files
    assert all(path.parent != root for path in database_files)


@dataclass
class SyntheticCutover:
    layout: RunLayout
    source_account_name: str
    config: Path
    cache: Path
    analytics: Path
    source_file: Path
    source_hash: str
    old_bytes: dict[Path, bytes]
    changes: tuple[PreparedChange, ...]
    bundle: BackupBundle | None
    staging_receipt: object
    store: MirroredTransactionStore
    security: SecurityAdapter

    def assert_old_set_and_source(self, rebuilt_bundle):
        for path, payload in self.old_bytes.items():
            assert path.read_bytes() == payload
        assert sha256_path(self.source_file) == self.source_hash
        rebuilt_bundle.verify_restored_old_set(self.security)

    def restart_inputs(self):
        record = self.store.inspect_conservative().record
        rebuilt = read_backup_bundle(
            primary_manifest_path=record.backup_primary_manifest_path,
            recovery_manifest_path=record.backup_recovery_manifest_path,
            expected_run_id=record.run_id,
            expected_sha256=record.backup_manifest_sha256,
            security_adapter=self.security,
        )
        restarted_store = MirroredTransactionStore(
            primary_path=self.store.primary_path,
            recovery_path=self.store.recovery_path,
        )
        return rebuilt, restarted_store


def build_synthetic_cutover(
    tmp_path, fake_security_adapter, *, analytics_present=True
):
    live = tmp_path / "live"
    live.mkdir()
    config = live / "WeFlow-config.json"
    cache = live / "WeFlow-cache-maps.json"
    analytics = live / "analytics_cache.json"
    config.write_text(
        json.dumps(
            {
                "dbPath": r"E:\old",
                "myWxid": "synthetic-account",
                "decryptKey": "safe:SYNTHETIC_NOT_A_REAL_ENVELOPE",
            }
        ),
        encoding="utf-8",
    )
    cache.write_text(
        json.dumps(
            {
                "snsPageCacheMap": {
                    "sns_page:synthetic-account": {"old": True},
                    "sns_page:other": {"keep": True},
                }
            }
        ),
        encoding="utf-8",
    )
    if analytics_present:
        analytics.write_bytes(b"old-analytics")
    run_root = tmp_path / "run"
    run_root.mkdir()
    layout = RunLayout.from_existing_root(run_root)
    source_account_name = "wxid_synthetic_66a8"
    staging_root = layout.vss_staging
    staging_db = (
        staging_root / source_account_name / "db_storage"
    )
    staging_db.mkdir(parents=True)
    (staging_db / "session.db").write_bytes(b"immutable-source")
    staging_manifest = build_manifest(
        staging_root, role=CopyRole.VSS_STAGING
    )
    staging_receipt = SimpleNamespace(
        staging_path=staging_root,
        source_account_name=source_account_name,
        account_db_relative_path=PureWindowsPath(
            source_account_name, "db_storage"
        ),
        file_count=staging_manifest.total_files,
        byte_count=staging_manifest.total_bytes,
        manifest_sha256=staging_receipt_sha256(staging_manifest),
    )
    shutil.copytree(staging_root, layout.source)
    shutil.copytree(staging_root, layout.validation)
    shutil.copytree(staging_root, layout.active)
    source_file = (
        layout.source
        / source_account_name
        / "db_storage"
        / "session.db"
    )
    role_roots = {
        CopyRole.VSS_STAGING: layout.vss_staging,
        CopyRole.SOURCE: layout.source,
        CopyRole.VALIDATION: layout.validation,
        CopyRole.ACTIVE: layout.active,
    }
    for root in role_roots.values():
        assert_exact_synthetic_role_tree(root, source_account_name)
    assert staging_receipt.staging_path == layout.vss_staging
    assert staging_receipt.source_account_name == source_account_name
    assert staging_receipt.account_db_relative_path == PureWindowsPath(
        source_account_name, "db_storage"
    )
    manifests = {
        role: build_manifest(root, role=role)
        for role, root in role_roots.items()
    }
    expected_prefix = f"{source_account_name}/db_storage/"
    assert all(
        manifest.files
        and all(
            item.relative_path.startswith(expected_prefix)
            for item in manifest.files
        )
        for manifest in manifests.values()
    )
    source_receipt = file_set_receipt(
        manifests[CopyRole.SOURCE]
    )
    validation_receipt = file_set_receipt(
        manifests[CopyRole.VALIDATION]
    )
    active_receipt = file_set_receipt(
        manifests[CopyRole.ACTIVE]
    )
    assert (
        file_set_receipt(
            manifests[CopyRole.VSS_STAGING]
        ).content_sha256
        == source_receipt.content_sha256
        == validation_receipt.content_sha256
        == active_receipt.content_sha256
    )
    old_bytes = {
        path: path.read_bytes()
        for path in (config, cache, analytics)
        if path.exists()
    }
    bundle = create_dual_config_backup(
        (config, cache, analytics),
        primary_root=tmp_path / "e-backup",
        recovery_root=tmp_path / "c-backup",
        run_id="11111111-1111-1111-1111-111111111111",
        security_adapter=fake_security_adapter,
    )
    changes = prepare_stored_key_cutover(
        config_path=config,
        cache_path=cache,
        analytics_path=analytics,
        active_parent=layout.active,
        account_id="synthetic-account",
    )
    planned = build_planned_files(changes, bundle)
    store = MirroredTransactionStore(
        primary_path=tmp_path / "e" / "transaction.json",
        recovery_path=tmp_path / "c" / "transaction.json",
    )
    record = TransactionRecord(
        schema_version=1,
        run_id="11111111-1111-1111-1111-111111111111",
        sequence=0,
        state=TxState.DISCOVERED,
        shadow_id=None,
        shadow_source_volume=None,
        planned_files=(),
    )
    store.create(record)
    store.record_shadow(
        expected=TxState.DISCOVERED,
        shadow_id="{22222222-2222-2222-2222-222222222222}",
        source_volume="F:\\",
    )
    store.transition(TxState.DISCOVERED, TxState.SNAPSHOT_READY)
    store.transition(TxState.SNAPSHOT_READY, TxState.VALIDATED)
    store.record_cutover_plan(
        expected=TxState.VALIDATED,
        planned_files=planned,
        backup_receipt=bundle.receipt,
        source_receipt=source_receipt,
        active_receipt=active_receipt,
        presentation_receipt=SimpleNamespace(
            manifest_sha256="D" * 64,
            manifest=SimpleNamespace(
                media_store_manifest_sha256="E" * 64,
            ),
        ),
    )
    store.transition(TxState.VALIDATED, TxState.PREPARED)
    return SyntheticCutover(
        layout=layout,
        source_account_name=source_account_name,
        config=config,
        cache=cache,
        analytics=analytics,
        source_file=source_file,
        source_hash=sha256_path(source_file),
        old_bytes=old_bytes,
        changes=changes,
        bundle=bundle,
        staging_receipt=staging_receipt,
        store=store,
        security=fake_security_adapter,
    )


@pytest.mark.parametrize(
    "crash_point",
    [
        CutoverCheckpoint.AFTER_REPLACING,
        CutoverCheckpoint.AFTER_CACHE_REPLACE,
        CutoverCheckpoint.AFTER_ANALYTICS_DELETE,
        CutoverCheckpoint.AFTER_CONFIG_REPLACE,
        CutoverCheckpoint.AFTER_CONFIG_REPLACED_STATE,
    ],
)
def test_restart_restores_complete_old_set(
    tmp_path, fake_security_adapter, monkeypatch, crash_point
):
    scenario = build_synthetic_cutover(tmp_path, fake_security_adapter)

    def fail_at(checkpoint):
        if checkpoint is crash_point:
            raise InjectedCrash(checkpoint.value)

    def recursive_delete_forbidden(*args, **kwargs):
        raise AssertionError("recursive delete called")

    monkeypatch.setattr(shutil, "rmtree", recursive_delete_forbidden)
    with pytest.raises(InjectedCrash):
        execute_cutover(
            scenario.changes,
            bundle=scenario.bundle,
            store=scenario.store,
            security_adapter=scenario.security,
            checkpoint=fail_at,
            audit_path=tmp_path / "audit.jsonl",
        )
    scenario.bundle = None
    rebuilt_bundle, restarted_store = scenario.restart_inputs()
    recovered = recover_transaction(
        store=restarted_store,
        bundle=rebuilt_bundle,
        process_gate=StoppedProcessGate(),
        security_adapter=scenario.security,
        accepted_revalidator=lambda _, __: False,
        timeout_seconds=1.0,
        audit_path=tmp_path / "audit.jsonl",
    )
    assert recovered.state is TxState.ROLLED_BACK
    scenario.assert_old_set_and_source(rebuilt_bundle)


class ToggleProcessGate:
    running = True

    def request_normal_close_and_wait(self, timeout_seconds):
        return not self.running


def test_recovery_pending_then_normal_exit(
    tmp_path, fake_security_adapter
):
    scenario = build_synthetic_cutover(tmp_path, fake_security_adapter)
    with pytest.raises(InjectedCrash):
        execute_cutover(
            scenario.changes,
            bundle=scenario.bundle,
            store=scenario.store,
            security_adapter=scenario.security,
            checkpoint=lambda point: (_ for _ in ()).throw(
                InjectedCrash(point.value)
            )
            if point is CutoverCheckpoint.AFTER_CONFIG_REPLACE
            else None,
            audit_path=tmp_path / "audit.jsonl",
        )
    scenario.bundle = None
    rebuilt_bundle, restarted_store = scenario.restart_inputs()
    gate = ToggleProcessGate()
    first = recover_transaction(
        store=restarted_store,
        bundle=rebuilt_bundle,
        process_gate=gate,
        security_adapter=scenario.security,
        accepted_revalidator=lambda _, __: False,
        timeout_seconds=1.0,
        audit_path=tmp_path / "audit.jsonl",
    )
    assert first.state is TxState.RECOVERY_PENDING
    gate.running = False
    second = recover_transaction(
        store=restarted_store,
        bundle=rebuilt_bundle,
        process_gate=gate,
        security_adapter=scenario.security,
        accepted_revalidator=lambda _, __: False,
        timeout_seconds=1.0,
        audit_path=tmp_path / "audit.jsonl",
    )
    assert second.state is TxState.ROLLED_BACK
    scenario.assert_old_set_and_source(rebuilt_bundle)


def test_absent_analytics_is_planned_and_restart_safe(
    tmp_path, fake_security_adapter
):
    scenario = build_synthetic_cutover(
        tmp_path, fake_security_adapter, analytics_present=False
    )
    sentinel = next(
        item
        for item in scenario.store.read_equal().record.planned_files
        if item.live_path.endswith("analytics_cache.json")
    )
    assert sentinel.action == "delete_if_created"
    with pytest.raises(InjectedCrash):
        execute_cutover(
            scenario.changes,
            bundle=scenario.bundle,
            store=scenario.store,
            security_adapter=scenario.security,
            checkpoint=lambda point: (_ for _ in ()).throw(
                InjectedCrash(point.value)
            )
            if point is CutoverCheckpoint.AFTER_CACHE_REPLACE
            else None,
            audit_path=tmp_path / "audit.jsonl",
        )
    scenario.bundle = None
    rebuilt_bundle, restarted_store = scenario.restart_inputs()
    recovered = recover_transaction(
        store=restarted_store,
        bundle=rebuilt_bundle,
        process_gate=StoppedProcessGate(),
        security_adapter=scenario.security,
        accepted_revalidator=lambda _, __: False,
        timeout_seconds=1.0,
        audit_path=tmp_path / "audit.jsonl",
    )
    assert recovered.state is TxState.ROLLED_BACK
    assert not scenario.analytics.exists()
    scenario.assert_old_set_and_source(rebuilt_bundle)


def test_restart_recovers_from_c_manifest_when_e_backup_is_offline(
    tmp_path, fake_security_adapter
):
    scenario = build_synthetic_cutover(tmp_path, fake_security_adapter)
    assert scenario.source_file == scenario.layout.role_db_storage(
        CopyRole.SOURCE, scenario.source_account_name
    ) / "session.db"
    assert not (scenario.layout.source / "session.db").exists()
    with pytest.raises(InjectedCrash):
        execute_cutover(
            scenario.changes,
            bundle=scenario.bundle,
            store=scenario.store,
            security_adapter=scenario.security,
            checkpoint=lambda point: (_ for _ in ()).throw(
                InjectedCrash(point.value)
            )
            if point is CutoverCheckpoint.AFTER_CONFIG_REPLACE
            else None,
            audit_path=tmp_path / "audit.jsonl",
        )
    primary_root = Path(scenario.bundle.primary_root)
    primary_root.rename(primary_root.with_name("e-backup.offline"))
    primary_transaction_root = scenario.store.primary_path.parent
    primary_transaction_root.rename(
        primary_transaction_root.with_name("e-transaction.offline")
    )
    scenario.bundle = None
    rebuilt_bundle, restarted_store = scenario.restart_inputs()
    recovered = recover_transaction(
        store=restarted_store,
        bundle=rebuilt_bundle,
        process_gate=StoppedProcessGate(),
        security_adapter=scenario.security,
        accepted_revalidator=lambda _, __: False,
        timeout_seconds=1.0,
        audit_path=restarted_store.primary_path.parent / "audit.jsonl",
    )
    assert recovered.state is TxState.ROLLED_BACK
    assert recovered.mirror_degraded is True
    assert not restarted_store.primary_path.exists()
    assert not restarted_store.primary_path.parent.exists()
    assert (
        restarted_store._read_one(restarted_store.recovery_path).record
        == recovered
    )
    assert (
        restarted_store.recovery_path.parent / "recovery-audit.jsonl"
    ).is_file()
    scenario.assert_old_set_and_source(rebuilt_bundle)


@pytest.mark.parametrize("accepted", [False, True])
def test_accepted_all_new_requires_fresh_revalidator(
    tmp_path, fake_security_adapter, accepted
):
    scenario = build_synthetic_cutover(tmp_path, fake_security_adapter)
    execute_cutover(
        scenario.changes,
        bundle=scenario.bundle,
        store=scenario.store,
        security_adapter=scenario.security,
        audit_path=tmp_path / "audit.jsonl",
    )
    scenario.store.record_ui_acceptance(
        acceptance_sha256="F" * 64,
    )
    source_hash = scenario.source_hash
    scenario.bundle = None
    rebuilt_bundle, restarted_store = scenario.restart_inputs()
    calls = []

    def revalidate_current(record, current_hashes):
        calls.append((record, current_hashes))
        assert (
            record.source_manifest_sha256
            == record.active_manifest_sha256
        )
        assert sha256_path(scenario.source_file) == source_hash
        return accepted

    recovered = recover_transaction(
        store=restarted_store,
        bundle=rebuilt_bundle,
        process_gate=StoppedProcessGate(),
        security_adapter=scenario.security,
        accepted_revalidator=revalidate_current,
        timeout_seconds=1.0,
        audit_path=tmp_path / "audit.jsonl",
    )
    assert len(calls) == 1
    assert recovered.state is (
        TxState.COMMITTED if accepted else TxState.ROLLED_BACK
    )
    if not accepted:
        scenario.assert_old_set_and_source(rebuilt_bundle)


def test_accepted_mixed_live_set_rolls_back_without_revalidator(
    tmp_path, fake_security_adapter
):
    scenario = build_synthetic_cutover(tmp_path, fake_security_adapter)
    execute_cutover(
        scenario.changes,
        bundle=scenario.bundle,
        store=scenario.store,
        security_adapter=scenario.security,
        audit_path=tmp_path / "audit.jsonl",
    )
    scenario.store.record_ui_acceptance(
        acceptance_sha256="F" * 64,
    )
    assert scenario.config.read_bytes() != scenario.old_bytes[scenario.config]
    scenario.cache.write_bytes(scenario.old_bytes[scenario.cache])
    assert scenario.cache.read_bytes() == scenario.old_bytes[scenario.cache]
    assert not scenario.analytics.exists()

    scenario.bundle = None
    rebuilt_bundle, restarted_store = scenario.restart_inputs()
    calls = []
    recovered = recover_transaction(
        store=restarted_store,
        bundle=rebuilt_bundle,
        process_gate=StoppedProcessGate(),
        security_adapter=scenario.security,
        accepted_revalidator=lambda *args: calls.append(args) or True,
        timeout_seconds=1.0,
        audit_path=tmp_path / "audit.jsonl",
    )

    assert calls == []
    assert recovered.state is TxState.ROLLED_BACK
    scenario.assert_old_set_and_source(rebuilt_bundle)


def test_completion_audit_contains_backup_cutover_and_recovery(
    tmp_path, fake_security_adapter
):
    scenario = build_synthetic_cutover(tmp_path, fake_security_adapter)
    with pytest.raises(InjectedCrash):
        execute_cutover(
            scenario.changes,
            bundle=scenario.bundle,
            store=scenario.store,
            security_adapter=scenario.security,
            checkpoint=lambda point: (_ for _ in ()).throw(
                InjectedCrash(point.value)
            )
            if point is CutoverCheckpoint.AFTER_REPLACING
            else None,
            audit_path=tmp_path / "audit.jsonl",
        )
    scenario.bundle = None
    rebuilt_bundle, restarted_store = scenario.restart_inputs()
    recover_transaction(
        store=restarted_store,
        bundle=rebuilt_bundle,
        process_gate=StoppedProcessGate(),
        security_adapter=scenario.security,
        accepted_revalidator=lambda _, __: False,
        timeout_seconds=1.0,
        audit_path=tmp_path / "audit.jsonl",
    )
    records = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    fixed_fields = {
        "atUtc",
        "stage",
        "status",
        "errorCode",
        "normalizedPaths",
        "fileCount",
        "byteCount",
        "sha256Values",
        "pid",
        "candidateCount",
    }
    stages = {stage.value for stage in AuditStage}
    statuses = {status.value for status in AuditStatus}
    error_codes = {code.value for code in AuditErrorCode}
    for record in records:
        assert set(record) == fixed_fields
        assert type(record["atUtc"]) is str
        timestamp = datetime.fromisoformat(record["atUtc"])
        assert timestamp.tzinfo is not None
        assert timestamp.utcoffset() == timedelta(0)
        assert type(record["stage"]) is str
        assert record["stage"] in stages
        assert type(record["status"]) is str
        assert record["status"] in statuses
        if record["status"] in {
            AuditStatus.BLOCKED.value,
            AuditStatus.FAILED.value,
        }:
            assert type(record["errorCode"]) is str
            assert record["errorCode"] in error_codes
        else:
            assert record["errorCode"] is None
        assert type(record["normalizedPaths"]) is list
        assert all(
            type(path) is str for path in record["normalizedPaths"]
        )
        for field in (
            "fileCount",
            "byteCount",
            "pid",
            "candidateCount",
        ):
            assert (
                record[field] is None or type(record[field]) is int
            )
            if record[field] is not None:
                assert record[field] >= 0
        assert type(record["sha256Values"]) is list
        assert all(
            type(value) is str
            and len(value) == 64
            and not set(value) - set("0123456789abcdef")
            for value in record["sha256Values"]
        )
    flow_events = {
        (record["stage"], record["status"]) for record in records
    }
    assert {
        (AuditStage.BACKUP.value, AuditStatus.STARTED.value),
        (AuditStage.BACKUP.value, AuditStatus.OK.value),
        (AuditStage.CUTOVER.value, AuditStatus.STARTED.value),
        (AuditStage.RECOVERY.value, AuditStatus.STARTED.value),
        (AuditStage.RECOVERY.value, AuditStatus.OK.value),
    } <= flow_events
