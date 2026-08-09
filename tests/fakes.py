from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
from pathlib import Path, PureWindowsPath
import shutil
from types import SimpleNamespace
from unittest.mock import patch
import uuid

from weflow_chat.atomic_io import atomic_write_json
from weflow_chat.compatibility import (
    CompatibilityReport,
    RedactedConfigContract,
    RuntimeContract,
    WcdbContract,
)
from weflow_chat.config import (
    build_planned_files as build_real_planned_files,
    create_dual_config_backup as create_real_backup,
    prepare_stored_key_cutover as prepare_real_cutover,
    read_backup_bundle as read_real_backup,
)
from weflow_chat.models import (
    CopyRole,
    TxState,
)
from weflow_chat.manifest import (
    build_manifest as build_real_manifest,
    file_set_receipt as build_real_file_set_receipt,
)
from weflow_chat.media import (
    import_media_staging as import_real_media_staging,
)
from weflow_chat.paths import RunLayout
from weflow_chat.preflight import HostContract
from weflow_chat.presentation import (
    build_presentation as build_real_presentation,
)
from weflow_chat.recovery import (
    CutoverCheckpoint,
    execute_cutover as execute_real_cutover,
    recover_transaction as recover_real_transaction,
)
from weflow_chat.security import SecurityMetadata
from weflow_chat.transaction import (
    MirroredTransactionStore,
    TransactionRecord,
)
from weflow_chat.validator.contracts import (
    FingerprintSet,
    ValidationReceipt,
)
from weflow_chat.vss import (
    MediaStagingFile,
    MediaStagingReceipt,
    ShadowState,
    StagingReceipt,
)


RUN_ID = "11111111-1111-1111-1111-111111111111"
SHADOW_ID = "{22222222-2222-2222-2222-222222222222}"


class FakeVss:
    def __init__(self, faults: "SyntheticFaultController") -> None:
        self.faults = faults
        self.state = ShadowState.DELETED
        self.ever_created = False
        self.journal_run_id = None
        self.journal_source_volume = None

    def create(self, *, run_id, source_volume):
        if self.faults.active == "vss_prepare_timeout":
            raise RuntimeError("helper_timeout_journal_unreadable")
        self.publish_creating_intent(
            run_id=run_id, source_volume=source_volume
        )
        self.faults.events.append("vss_create")
        if self.faults.active == "vss_create":
            raise RuntimeError("vss_create")
        if self.faults.active == "vss_create_timeout":
            raise RuntimeError("create_state_invalid")
        self.state = ShadowState.CREATED
        value = SimpleNamespace(
            run_id=run_id,
            source_volume=source_volume,
            state=self.state,
            shadow_id=SHADOW_ID,
            device_object=(
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy99"
            ),
            created_at_utc="2026-07-21T00:00:00+00:00",
        )
        if self.faults.active == "vss_return_after_create":
            raise RuntimeError("vss_return_after_create")
        return value

    def adopt(self, *, run_id, shadow_id):
        if run_id != self.journal_run_id or shadow_id != SHADOW_ID:
            raise RuntimeError("journal_identity_invalid")
        self.state = ShadowState.ADOPTED
        return self.inspect_owned(run_id=run_id)

    def inspect_owned(self, *, run_id):
        if not self.ever_created or run_id != self.journal_run_id:
            raise RuntimeError("journal_identity_invalid")
        return SimpleNamespace(
            run_id=self.journal_run_id,
            source_volume=self.journal_source_volume,
            state=self.state,
            shadow_id=SHADOW_ID,
            device_object=(
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy99"
            ),
        )

    def delete_exact(self, *, run_id, shadow_id):
        if run_id != self.journal_run_id or shadow_id != SHADOW_ID:
            raise RuntimeError("journal_identity_invalid")
        self.faults.events.append("vss_delete_exact")
        self.state = ShadowState.DELETED
        return self.inspect_owned(run_id=run_id)

    def publish_creating_intent(self, *, run_id, source_volume):
        self.faults.events.append("vss_prepare_create_durable")
        self.ever_created = True
        self.journal_run_id = run_id
        self.journal_source_volume = source_volume
        self.state = ShadowState.CREATING

    def journal_exists(self, run_id):
        return self.ever_created and run_id == self.journal_run_id


class FakeValidator:
    def __init__(self, faults: "SyntheticFaultController") -> None:
        self.faults = faults
        self.baseline = FingerprintSet(
            "A" * 64, "B" * 64, "C" * 64
        )

    def validate(self, *, area, layout, run_id):
        self.faults.events.append(f"validator_{area}")
        if self.faults.active == "validation" and area == "validation":
            return ValidationReceipt("invalid_key", "invalid_key", None)
        value = self.baseline
        mutation = {
            "schema_mismatch": "schemaFingerprint",
            "aggregate_mismatch": "aggregateFingerprint",
            "coverage_mismatch": "databaseCoverageFingerprint",
        }.get(self.faults.active)
        if area in {"active", "presentation"} and mutation is not None:
            value = replace(value, **{mutation: "D" * 64})
        return ValidationReceipt("ok", None, value)

    def media_openability(self, *, area, layout, run_id):
        self.faults.events.append("media_openability")
        return {
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


class FakeProcessGate:
    def __init__(self, faults: "SyntheticFaultController") -> None:
        self.faults = faults

    def request_normal_close_and_wait(self, timeout_seconds):
        return self.faults.active != "normal_close_timeout"


class FakeFormalUi:
    def __init__(self, faults: "SyntheticFaultController") -> None:
        self.faults = faults
        self.relaunched = False

    def launch_and_require_account_open(self, active_parent):
        if self.faults.create_on_launch is not None:
            self.faults.create_on_launch.write_bytes(
                b"ui-created-analytics"
            )
        return self.faults.active not in {
            "formal_launch",
            "account_open",
        }

    def relaunch_after_commit(self):
        self.relaunched = True


class FakeSecurity:
    def __init__(self, faults):
        self.faults = faults

    def capture(self, path):
        return SecurityMetadata(
            file_attributes=0,
            owner_sid="S-1-5-21-test",
            group_sid="S-1-5-21-test",
            dacl_sddl="D:P",
        )

    def restrict_backup_tree(self, path):
        Path(path).mkdir(parents=True, exist_ok=True)

    def verify_restricted_backup_tree(self, path):
        self.faults.events.append("backup_acl_verified")
        if self.faults.active == "backup_acl":
            raise RuntimeError("backup_acl")
        assert Path(path).is_dir()

    def restrict_local_trust_artifact(self, path):
        self.faults.events.append(("trust_acl_restrict", Path(path)))

    def verify_local_trust_artifact(self, path):
        self.faults.events.append(("trust_acl_verify", Path(path)))

    def restore(self, path, value):
        assert Path(path).exists()

    def verify(self, path, value):
        assert Path(path).exists()


@dataclass(slots=True)
class SyntheticFaultController:
    root: Path
    active: str | None = None
    production_root: Path = field(init=False)
    old_bytes: dict[str, bytes] = field(init=False)
    current_backup: dict[str, bytes] = field(init=False)
    _patches: list = field(init=False)
    events: list[str] = field(init=False)
    trace_late_bind_writes: bool = field(init=False)
    absent_formal_names: set[str] = field(init=False)
    create_on_launch: Path | None = field(init=False)

    def __post_init__(self) -> None:
        self.production_root = self.root / "formal"
        self.production_root.mkdir(parents=True, exist_ok=True)
        self.old_bytes = {
            "WeFlow-config.json": (
                b'{"dbPath":"old","cachePath":"old-cache",'
                b'"myWxid":"wxid_test"}'
            ),
            "WeFlow-cache-maps.json": b"{}",
            "analytics_cache.json": b"{}",
        }
        for name, value in self.old_bytes.items():
            (self.production_root / name).write_bytes(value)
        self.current_backup = dict(self.old_bytes)
        self._patches = []
        self.events = []
        self.trace_late_bind_writes = False
        self.absent_formal_names = set()
        self.create_on_launch = None

    def capture_formal_hashes(self):
        return {
            name: hashlib.sha256(
                (self.production_root / name).read_bytes()
            ).hexdigest()
            for name in self.old_bytes
        }

    def assert_complete_old_fileset(self):
        for name, value in self.old_bytes.items():
            path = self.production_root / name
            if name in self.absent_formal_names:
                assert not path.exists()
            else:
                assert path.read_bytes() == value

    def assert_no_production_paths(self):
        assert all(
            str(path).startswith(str(self.root))
            for path in self.production_root.iterdir()
        )

    def keep_patch(self, target, replacement):
        item = patch(target, replacement)
        item.start()
        self._patches.append(item)

    def close(self) -> None:
        while self._patches:
            self._patches.pop().stop()


def build_synthetic_flow(
    *,
    tmp_path: Path,
    timestamp: str,
    faults: SyntheticFaultController,
    analytics_absent_before: bool = False,
) -> "RefreshOrchestrator":
    from weflow_chat.orchestrator import (
        RefreshDependencies,
        RefreshOrchestrator,
    )

    run_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL, f"weflow-refresh:{timestamp}"
        )
    )
    run_root = tmp_path / "runs" / f"{timestamp}-{run_id}"
    run_root.mkdir(parents=True, exist_ok=False)
    layout = RunLayout.from_existing_root(run_root)
    recovery_root = tmp_path / "recovery" / run_id
    recovery_root.mkdir(parents=True)
    recovery_transaction = recovery_root / "transaction.json"

    def write_transaction(path, payload):
        if (
            faults.trace_late_bind_writes
            and payload.get("state") == TxState.RECOVERY_PENDING.value
            and payload.get("shadowId") == SHADOW_ID
        ):
            faults.events.append(
                "late_bind_c"
                if path == recovery_transaction
                else "late_bind_e"
            )
        atomic_write_json(path, payload)

    store = MirroredTransactionStore(
        primary_path=layout.transaction_path,
        recovery_path=recovery_transaction,
        write_json=write_transaction,
    )
    store.create(
        TransactionRecord(
            schema_version=1,
            run_id=run_id,
            sequence=0,
            state=TxState.DISCOVERED,
            shadow_id=None,
            shadow_source_volume=None,
            planned_files=(),
            applied_files=(),
        )
    )
    contract = replace(
        HostContract.for_test_root(tmp_path / timestamp),
        config_path=faults.production_root / "WeFlow-config.json",
        cache_maps_path=(
            faults.production_root / "WeFlow-cache-maps.json"
        ),
        analytics_cache_path=(
            faults.production_root / "analytics_cache.json"
        ),
    )
    if analytics_absent_before:
        contract.analytics_cache_path.unlink(missing_ok=True)
        faults.absent_formal_names.add("analytics_cache.json")
        faults.create_on_launch = contract.analytics_cache_path
    contract.weflow_cache_root.mkdir(parents=True)
    contract.source_account.mkdir(parents=True)
    contract.db_storage.mkdir()
    contract.session_db.parent.mkdir()
    contract.session_db.write_bytes(b"synthetic-session")
    compatible = CompatibilityReport(
        1,
        run_id,
        "6.1.0",
        {},
        RedactedConfigContract(1, ["safe"], "str", "str"),
        WcdbContract((), "A" * 64, "B" * 64),
        {"boot": 1, "ready": 1},
        ("analytics_cache", "cache_maps", "config"),
        "compatible",
        (),
    )
    faults.keep_patch(
        "weflow_chat.orchestrator.run_preflight",
        lambda contract, adapters: SimpleNamespace(
            ok=faults.active != "compatibility",
            configSha256=hashlib.sha256(
                contract.config_path.read_bytes()
            )
            .hexdigest()
            .upper(),
        ),
    )
    faults.keep_patch(
        "weflow_chat.orchestrator.probe_compatibility",
        lambda **values: compatible,
    )

    def write_report(root, report):
        faults.events.append("compatibility_written")
        path = root / "compatibility.json"
        path.write_text(
            json.dumps({"status": report.status}),
            encoding="utf-8",
        )
        return path

    faults.keep_patch(
        "weflow_chat.orchestrator.write_compatibility_report",
        write_report,
    )
    faults.keep_patch(
        "weflow_chat.orchestrator.map_volume_path",
        lambda device_object, **values: (
            Path("shadow") / "db_storage"
        ),
    )

    def copy_staging(**values):
        if faults.active == "staging_copy":
            raise RuntimeError("staging_copy")
        assert values["source_account_name"] == contract.account_id
        account_db = (
            layout.vss_staging / contract.account_id / "db_storage"
        )
        account_db.mkdir(parents=True)
        session_dir = account_db / "session"
        session_dir.mkdir()
        (session_dir / "session.db").write_bytes(
            b"synthetic-session"
        )
        return StagingReceipt(
            staging_path=layout.vss_staging,
            source_account_name=contract.account_id,
            account_db_relative_path=PureWindowsPath(
                contract.account_id, "db_storage"
            ),
            file_count=1,
            byte_count=17,
            manifest_sha256="A" * 64,
        )

    faults.keep_patch(
        "weflow_chat.orchestrator.copy_owned_shadow_to_staging",
        copy_staging,
    )

    def copy_media_staging(**values):
        if faults.active == "media_staging_copy":
            raise RuntimeError("media_staging_copy")
        assert values["source_account_name"] == contract.account_id
        account = (
            layout.root
            / "media-staging"
            / contract.account_id
        )
        media = account / "msg" / "attach" / "synthetic-image.bin"
        media.parent.mkdir(parents=True)
        payload = b"synthetic-image"
        media.write_bytes(payload)
        item = MediaStagingFile(
            relative_path="msg/attach/synthetic-image.bin",
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest().upper(),
        )
        manifest_payload = json.dumps(
            [
                {
                    "relativePath": item.relative_path,
                    "size": item.size,
                    "sha256": item.sha256,
                }
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return MediaStagingReceipt(
            staging_path=layout.root / "media-staging",
            source_account_name=contract.account_id,
            files=(item,),
            file_count=1,
            byte_count=len(payload),
            manifest_sha256=hashlib.sha256(
                manifest_payload
            ).hexdigest().upper(),
        )

    faults.keep_patch(
        (
            "weflow_chat.orchestrator."
            "copy_owned_shadow_media_to_staging"
        ),
        copy_media_staging,
    )

    def import_media_staging(*args, **kwargs):
        faults.events.append("media_import")
        if faults.active == "media_import":
            raise RuntimeError("media_import")
        return import_real_media_staging(*args, **kwargs)

    faults.keep_patch(
        "weflow_chat.orchestrator.import_media_staging",
        import_media_staging,
    )

    def import_staging(layout, **values):
        if faults.active == "source_copy":
            raise RuntimeError("source_copy")
        shutil.copytree(layout.vss_staging, layout.source)
        return SimpleNamespace(
            snapshot_method="vss-crash-consistent",
            residual_risk=(
                "crash_consistent_no_cross_database_atomicity_proof"
            ),
        )

    faults.keep_patch(
        "weflow_chat.orchestrator.import_vss_staging",
        import_staging,
    )
    def read_synthetic_manifest(layout, **kwargs):
        source = build_real_manifest(
            layout.source,
            role=CopyRole.SOURCE,
        )
        return (
            SimpleNamespace(source=source),
            SimpleNamespace(canonical_sha256="B" * 64),
        )

    faults.keep_patch(
        "weflow_chat.orchestrator.read_run_manifest",
        read_synthetic_manifest,
    )

    def materialize(layout, role, *, source_account_name):
        assert source_account_name == contract.account_id
        if faults.active == "active_copy" and role.value == "active":
            raise RuntimeError("active_copy")
        shutil.copytree(layout.source, getattr(layout, role.value))
        return SimpleNamespace()

    faults.keep_patch(
        "weflow_chat.orchestrator.materialize_role_copy",
        materialize,
    )

    def build_presentation(**values):
        faults.events.append("presentation_build")
        if faults.active == "presentation":
            raise RuntimeError("presentation")
        return build_real_presentation(**values)

    faults.keep_patch(
        "weflow_chat.orchestrator.build_presentation",
        build_presentation,
    )

    faults.keep_patch(
        "weflow_chat.orchestrator.build_manifest",
        lambda root, role: build_real_manifest(
            root,
            role=role,
        ),
    )
    faults.keep_patch(
        "weflow_chat.orchestrator.content_signature",
        lambda manifest: manifest.files,
    )
    faults.keep_patch(
        "weflow_chat.orchestrator.file_set_receipt",
        build_real_file_set_receipt,
    )

    faults.keep_patch(
        "weflow_chat.orchestrator.prepare_stored_key_cutover",
        prepare_real_cutover,
    )
    faults.keep_patch(
        "weflow_chat.orchestrator.build_planned_files",
        build_real_planned_files,
    )
    primary_root = run_root / "config-backup"
    backup_recovery_root = recovery_root / "config-backup"

    def create_backup(*args, **kwargs):
        if faults.active == "backup":
            raise RuntimeError("backup")
        return create_real_backup(*args, **kwargs)

    faults.keep_patch(
        "weflow_chat.orchestrator.create_dual_config_backup",
        create_backup,
    )

    def read_backup(**values):
        faults.events.append("backup_manifest_read")
        return read_real_backup(**values)

    faults.keep_patch(
        "weflow_chat.orchestrator.read_backup_bundle",
        read_backup,
    )

    def execute(changes, *, bundle, store, security_adapter):
        def checkpoint(point):
            faults.events.append(
                f"cutover_{point.value}"
            )
            if (
                faults.active == "mirror_divergence"
                and point is CutoverCheckpoint.AFTER_REPLACING
            ):
                store.primary_path.write_text(
                    "{}",
                    encoding="utf-8",
                )
                raise RuntimeError(
                    "transaction_mirror_divergence"
                )
            if (
                faults.active == "first_cache_replace"
                and point
                is CutoverCheckpoint.AFTER_CACHE_REPLACE
            ):
                raise RuntimeError("first_cache_replace")
            if (
                faults.active == "analytics_delete"
                and point
                is CutoverCheckpoint.AFTER_ANALYTICS_DELETE
            ):
                raise RuntimeError("analytics_delete")
            if (
                faults.active == "config_replace"
                and point
                is CutoverCheckpoint.AFTER_CONFIG_REPLACE
            ):
                raise RuntimeError("config_replace")

        return execute_real_cutover(
            changes,
            bundle=bundle,
            store=store,
            security_adapter=security_adapter,
            checkpoint=checkpoint,
        )

    faults.keep_patch(
        "weflow_chat.orchestrator.execute_cutover", execute
    )

    faults.keep_patch(
        "weflow_chat.orchestrator.recover_transaction",
        recover_real_transaction,
    )

    runtime = RuntimeContract(
        "6.1.0",
        {},
        {},
        "",
        (),
        ("config", "cache_maps", "analytics_cache"),
    )
    fake_vss = FakeVss(faults)
    dependencies = RefreshDependencies(
        contract=contract,
        layout=layout,
        store=store,
        vss=fake_vss,
        validator=FakeValidator(faults),
        formal_ui=FakeFormalUi(faults),
        process_gate=FakeProcessGate(faults),
        security=FakeSecurity(faults),
        preflight_adapters=SimpleNamespace(),
        runtime_contract=runtime,
        primary_backup_root=primary_root,
        recovery_backup_root=backup_recovery_root,
        now_utc=lambda: "2026-07-21T00:00:00+00:00",
        journal_exists=fake_vss.journal_exists,
    )
    return RefreshOrchestrator(dependencies, run_id)
