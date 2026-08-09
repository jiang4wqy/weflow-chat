from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import uuid

from weflow_chat.compatibility import (
    discover_fixed_runtime_contract,
)
from weflow_chat.models import TxState
from weflow_chat.orchestrator import (
    RefreshDependencies,
    RefreshMode,
    RefreshOrchestrator,
    allocate_refresh_version,
)
from weflow_chat.paths import (
    RunLayout,
    canonical_existing,
)
from weflow_chat.preflight import (
    HostContract,
    fixed_host,
    require_fixed_host,
    run_preflight,
)
from weflow_chat.transaction import (
    MirroredTransactionStore,
)
from weflow_chat.validator.launcher import (
    CopiedWeFlowValidatorBackend,
)
from weflow_chat.validator.install_copy import (
    copy_install_verified,
    patch_copied_runtime,
)
from weflow_chat.vss import VssHelperClient
from weflow_chat.weixin_trust import (
    RuntimeWeixinDllIdentity,
    TrustState,
    verify_local_trust_artifacts,
)
from weflow_chat.windows_adapters import (
    FixedUserOperationMutex,
    RecoveryOnlyHostAdapters,
    ValidationOnlyFormalUiBackend,
    ValidationOnlyProcessGate,
    ValidationOnlySecurityAdapter,
    WindowsFormalUiBackend,
    WindowsHostAdapters,
    WindowsProcessGate,
    WindowsSecurityAdapter,
)


def fixed_operation_mutex():
    """Return the finite-wait lease used by all mutating CLI paths."""
    return FixedUserOperationMutex().acquire()


def _runtime_weixin_identity(adapters) -> RuntimeWeixinDllIdentity:
    identity = adapters.weixin
    return RuntimeWeixinDllIdentity(
        version=identity.dll_version,
        architecture=identity.architecture,
        dll_size=identity.dll_size,
        dll_sha256=identity.dll_sha256,
        authenticode_status=identity.dll_authenticode_status,
        signer_subject=identity.dll_signer_subject,
        signer_certificate_sha256=(
            identity.dll_signer_certificate_sha256
        ),
    )


def _layout_from_bound_root(root: Path) -> RunLayout:
    return RunLayout(
        root=root,
        vss_staging=root / "vss-staging",
        source=root / "source",
        validation=root / "validation",
        active=root / "active",
        manifest_path=root / "manifest.json",
        compatibility_path=root / "compatibility.json",
        transaction_path=root / "transaction.json",
        audit_path=root / "audit.jsonl",
        config_backup=root / "config-backup",
    )


def _is_reparse(path: Path) -> bool:
    return bool(
        getattr(
            path.lstat(),
            "st_file_attributes",
            0,
        ) & 0x400
    )


def _reject_reparse_chain(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    candidates = [current]
    for component in absolute.parts[1:]:
        current /= component
        candidates.append(current)
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise RuntimeError(
                "fixed_existing_path_unreadable"
            ) from exc
        if (
            candidate.is_symlink()
            or getattr(
                metadata,
                "st_file_attributes",
                0,
            ) & 0x400
        ):
            raise RuntimeError(
                "fixed_existing_reparse_chain_rejected"
            )


def _discover_fixed_existing(
    contract: HostContract,
    run_id: str,
):
    canonical_id = str(uuid.UUID(run_id))
    _reject_reparse_chain(
        contract.same_volume_recovery_root
    )
    recovery_base = (
        contract.same_volume_recovery_root.resolve(
            strict=True
        )
    )
    recovery_root = (
        contract.same_volume_recovery_root
        / canonical_id
    )
    _reject_reparse_chain(recovery_root)
    if (
        not recovery_root.is_dir()
        or recovery_root.is_symlink()
        or _is_reparse(recovery_root)
        or recovery_root.resolve(strict=True).parent
        != recovery_base
    ):
        raise RuntimeError(
            "fixed_recovery_run_not_found"
        )
    locator_path = recovery_root / "run-locator.json"
    recovery_tx = recovery_root / "transaction.json"
    _reject_reparse_chain(locator_path)
    _reject_reparse_chain(recovery_tx)
    if (
        not locator_path.is_file()
        or locator_path.is_symlink()
        or _is_reparse(locator_path)
        or not recovery_tx.is_file()
        or recovery_tx.is_symlink()
        or _is_reparse(recovery_tx)
    ):
        raise RuntimeError(
            "fixed_recovery_artifact_not_ordinary"
        )
    if not 0 < locator_path.stat().st_size <= 4096:
        raise RuntimeError("run_locator_size_invalid")
    locator = json.loads(
        locator_path.read_text(encoding="utf-8")
    )
    if (
        not isinstance(locator, dict)
        or set(locator)
        != {
            "schemaVersion",
            "runId",
            "primaryTransactionPath",
        }
    ):
        raise RuntimeError(
            "run_locator_schema_mismatch"
        )
    if not isinstance(
        locator["primaryTransactionPath"],
        str,
    ):
        raise RuntimeError(
            "run_locator_primary_type_invalid"
        )
    primary = Path(
        locator["primaryTransactionPath"]
    )
    run_root = primary.parent
    if (
        locator["schemaVersion"] != 1
        or locator["runId"] != canonical_id
        or not primary.is_absolute()
        or primary.name != "transaction.json"
        or run_root.parent
        != contract.snapshots_root
        or not run_root.name.endswith(
            "-" + canonical_id
        )
    ):
        raise RuntimeError(
            "run_locator_boundary_mismatch"
        )
    if run_root.exists():
        _reject_reparse_chain(
            contract.snapshots_root
        )
        _reject_reparse_chain(run_root)
        _reject_reparse_chain(primary)
        snapshots_base = (
            contract.snapshots_root.resolve(
                strict=True
            )
        )
        if (
            not run_root.is_dir()
            or run_root.is_symlink()
            or _is_reparse(run_root)
            or run_root.resolve(strict=True).parent
            != snapshots_base
            or not primary.is_file()
            or primary.is_symlink()
            or _is_reparse(primary)
        ):
            raise RuntimeError(
                "primary_transaction_not_ordinary"
            )
    store = MirroredTransactionStore(
        primary_path=primary,
        recovery_path=(
            recovery_root / "transaction.json"
        ),
        storage_available=lambda path: path.exists(),
    )
    view = store.inspect_conservative()
    if view.record.run_id != canonical_id:
        raise RuntimeError(
            "run_locator_transaction_mismatch"
        )
    return (
        _layout_from_bound_root(run_root),
        recovery_root,
        store,
    )


def _assert_no_unfinished_fixed_runs(
    contract: HostContract,
) -> frozenset[Path]:
    c_by_id = {}
    c_root = contract.same_volume_recovery_root
    if c_root.exists():
        if (
            not c_root.is_dir()
            or c_root.is_symlink()
            or _is_reparse(c_root)
        ):
            raise RuntimeError(
                "fixed_recovery_root_not_ordinary"
            )
        for child in c_root.iterdir():
            try:
                child_id = str(uuid.UUID(child.name))
            except ValueError as error:
                raise RuntimeError(
                    "unknown_fixed_recovery_entry"
                ) from error
            if (
                child.name != child_id
                or child.is_symlink()
                or _is_reparse(child)
            ):
                raise RuntimeError(
                    "invalid_fixed_recovery_entry"
                )
            c_by_id[child_id] = child
    e_by_id = {}
    e_root = contract.snapshots_root
    if e_root.exists():
        if (
            not e_root.is_dir()
            or e_root.is_symlink()
            or _is_reparse(e_root)
        ):
            raise RuntimeError(
                "fixed_snapshots_root_not_ordinary"
            )
        for child in e_root.iterdir():
            if (
                child.is_symlink()
                or _is_reparse(child)
            ):
                raise RuntimeError(
                    "snapshot_reparse_entry"
                )
            parts = child.name.rsplit("-", 5)
            candidate = (
                "-".join(parts[-5:])
                if len(parts) >= 6
                else ""
            )
            try:
                child_id = str(uuid.UUID(candidate))
            except ValueError as error:
                raise RuntimeError(
                    "unknown_fixed_snapshot_entry"
                ) from error
            tx = child / "transaction.json"
            if (
                not child.is_dir()
                or not tx.is_file()
                or tx.is_symlink()
                or _is_reparse(tx)
            ):
                raise RuntimeError(
                    "snapshot_transaction_not_ordinary"
                )
            if child_id in e_by_id:
                raise RuntimeError(
                    "duplicate_snapshot_run_id"
                )
            e_by_id[child_id] = child
    if set(c_by_id) != set(e_by_id):
        raise RuntimeError(
            "prior_run_single_mirror_requires_recovery"
        )
    managed_active_paths = set()
    for child_id in sorted(c_by_id):
        layout, _, store = (
            _discover_fixed_existing(
                contract,
                child_id,
            )
        )
        if (
            layout.root
            != e_by_id[child_id].resolve(
                strict=True
            )
        ):
            raise RuntimeError(
                "prior_run_locator_e_mismatch"
            )
        store.assert_ready_for_new_run()
        current = store.read_equal().record
        if current.state is TxState.COMMITTED:
            candidates = [layout.active]
            presentation = (
                layout.root / "presentation"
            )
            if presentation.exists():
                candidates.append(presentation)
            for candidate in candidates:
                try:
                    managed = canonical_existing(
                        candidate
                    )
                except (OSError, ValueError) as error:
                    raise RuntimeError(
                        "committed_active_path_invalid"
                    ) from error
                if managed != candidate:
                    raise RuntimeError(
                        "committed_active_identity_mismatch"
                    )
                managed_active_paths.add(managed)
    return frozenset(managed_active_paths)


def _discover_fixed_local_trust_receipts(
    contract: HostContract,
) -> tuple:
    security = WindowsSecurityAdapter()
    receipts = []
    recovery_base = contract.same_volume_recovery_root
    if not recovery_base.exists():
        return ()
    for recovery_root in sorted(
        recovery_base.iterdir(), key=lambda item: item.name
    ):
        try:
            run_id = str(uuid.UUID(recovery_root.name))
            layout, exact_recovery, store = _discover_fixed_existing(
                contract, run_id
            )
            store.assert_ready_for_new_run()
            paths = (
                layout.root / "local-weixin-trust.json",
                exact_recovery / "local-weixin-trust.json",
                layout.root / "local-weixin-trust-evidence.json",
                exact_recovery / "local-weixin-trust-evidence.json",
            )
            present = tuple(os.path.lexists(path) for path in paths)
            if not any(present):
                continue
            if not all(present):
                continue
            receipts.append(
                verify_local_trust_artifacts(
                    primary_root=layout.root,
                    recovery_root=exact_recovery,
                    account_name=contract.account_id,
                    verify=security.verify_local_trust_artifact,
                )
            )
        except (
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            continue
    return tuple(receipts)


def run_fixed_preflight(
    contract: HostContract | None = None,
):
    contract = (
        fixed_host()
        if contract is None
        else require_fixed_host(contract)
    )
    managed_active_paths = (
        _assert_no_unfinished_fixed_runs(contract)
    )
    local_trust_receipts = (
        _discover_fixed_local_trust_receipts(contract)
    )
    return run_preflight(
        contract,
        WindowsHostAdapters.for_preflight(
            contract,
            managed_active_paths=managed_active_paths,
            local_trust_receipts=local_trust_receipts,
        ),
    )


def build_new_fixed_host_flow(
    *,
    validation_only: bool,
    refresh_mode: RefreshMode = RefreshMode.FULL,
    contract: HostContract | None = None,
) -> RefreshOrchestrator:
    if type(refresh_mode) is not RefreshMode:
        raise TypeError("refresh_mode_invalid")
    if (
        validation_only
        and refresh_mode is not RefreshMode.FULL
    ):
        raise RuntimeError("full_validation_mode_required")
    contract = (
        fixed_host()
        if contract is None
        else require_fixed_host(contract)
    )
    managed_active_paths = (
        _assert_no_unfinished_fixed_runs(contract)
    )
    local_trust_receipts = (
        _discover_fixed_local_trust_receipts(contract)
    )
    runtime_contract = (
        discover_fixed_runtime_contract(contract)
    )
    readonly_adapters = WindowsHostAdapters.for_preflight(
        contract,
        managed_active_paths=managed_active_paths,
        local_trust_receipts=local_trust_receipts,
    )
    readonly_preflight = run_preflight(
        contract, readonly_adapters
    )
    if not readonly_preflight.ok:
        raise RuntimeError(
            "fixed_readonly_preflight_blocked"
        )
    if (
        readonly_preflight.weixin.trustState
        == TrustState.TRIAL_REQUIRED.value
        and not validation_only
    ):
        raise RuntimeError("weixin_trial_requires_validation_only")
    trust_state = TrustState(
        readonly_preflight.weixin.trustState
    )
    runtime_weixin_identity = _runtime_weixin_identity(
        readonly_adapters
    )

    def revalidate_trial_identity():
        fresh_adapters = WindowsHostAdapters.for_preflight(
            contract,
            managed_active_paths=managed_active_paths,
            local_trust_receipts=local_trust_receipts,
        )
        fresh_report = run_preflight(
            contract, fresh_adapters
        )
        if (
            not fresh_report.ok
            or fresh_report.weixin.trustState
            != TrustState.TRIAL_REQUIRED.value
            or fresh_report.configSha256
            != readonly_preflight.configSha256
        ):
            raise RuntimeError(
                "trial_identity_revalidation_failed"
            )
        return _runtime_weixin_identity(fresh_adapters)
    vss = VssHelperClient(
        source_volume=contract.source_volume
    )
    validator = CopiedWeFlowValidatorBackend(
        formal_config=contract.config_path,
        formal_weflow=contract.formal_weflow,
        snapshots_root=contract.snapshots_root,
        capabilities=frozenset(
            readonly_preflight.weixin.capabilities
        )
    )
    if validation_only:
        process_gate = ValidationOnlyProcessGate()
        formal_ui = (
            ValidationOnlyFormalUiBackend()
        )
        security = ValidationOnlySecurityAdapter()
    else:
        process_gate = WindowsProcessGate(contract)
        formal_ui = WindowsFormalUiBackend(
            contract
        )
        security = WindowsSecurityAdapter()
    run_id = str(uuid.uuid4())
    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d-%H%M%S")
    allocated = allocate_refresh_version(
        snapshots_root=contract.snapshots_root,
        recovery_root=(
            contract.same_volume_recovery_root
        ),
        timestamp_utc=timestamp,
        run_id=run_id,
    )
    try:
        runtime_root = copy_install_verified(
            layout=allocated.layout,
            source=contract.formal_weflow.parent,
        )
        patch_copied_runtime(
            layout=allocated.layout,
            runtime_root=runtime_root,
        )
        dependencies = RefreshDependencies(
            contract=contract,
            layout=allocated.layout,
            store=allocated.store,
            vss=vss,
            validator=validator,
            formal_ui=formal_ui,
            process_gate=process_gate,
            security=security,
            preflight_adapters=WindowsHostAdapters(
                contract,
                allocated.layout,
                runtime_prepared=True,
                managed_active_paths=managed_active_paths,
                local_trust_receipts=local_trust_receipts,
            ),
            runtime_contract=runtime_contract,
            primary_backup_root=(
                allocated.layout.root
                / "config-backup"
            ),
            recovery_backup_root=(
                allocated.recovery_root
                / "config-backup"
            ),
            refresh_mode=refresh_mode,
            validation_only=validation_only,
            weixin_trust_state=trust_state,
            weixin_runtime_identity=runtime_weixin_identity,
            trial_identity_revalidator=(
                revalidate_trial_identity
            ),
            trust_security=WindowsSecurityAdapter(),
        )
        return RefreshOrchestrator(
            dependencies,
            run_id,
        )
    except BaseException:
        try:
            allocated.store.force_conservative_state(
                TxState.ROLLED_BACK
            )
        except BaseException:
            try:
                allocated.store.force_conservative_state(
                    TxState.RECOVERY_PENDING
                )
            except BaseException as persistence_error:
                raise RuntimeError(
                    "post_allocation_failure_not_persisted"
                ) from persistence_error
        raise


def build_existing_fixed_host_flow(
    run_id: str,
    *,
    status_only: bool = False,
    contract: HostContract | None = None,
) -> RefreshOrchestrator:
    contract = (
        fixed_host()
        if contract is None
        else require_fixed_host(contract)
    )
    layout, recovery_root, store = (
        _discover_fixed_existing(
            contract,
            run_id,
        )
    )
    if status_only:
        status_backend = RecoveryOnlyHostAdapters()
        vss = status_backend
        validator = status_backend
        formal_ui = status_backend
        process_gate = status_backend
        security = status_backend
    else:
        vss = VssHelperClient(
            source_volume=contract.source_volume
        )
        validator = CopiedWeFlowValidatorBackend(
            formal_config=contract.config_path,
            formal_weflow=contract.formal_weflow,
            snapshots_root=contract.snapshots_root,
        )
        formal_ui = WindowsFormalUiBackend(
            contract
        )
        process_gate = WindowsProcessGate(
            contract
        )
        security = WindowsSecurityAdapter()
    current = store.inspect_conservative().record
    refresh_mode = (
        RefreshMode.DATABASE_ONLY
        if (
            current.planned_files
            and current.presentation_manifest_sha256 is None
            and current.media_store_manifest_sha256 is None
        )
        else RefreshMode.FULL
    )
    dependencies = RefreshDependencies(
        contract=contract,
        layout=layout,
        store=store,
        vss=vss,
        validator=validator,
        formal_ui=formal_ui,
        process_gate=process_gate,
        security=security,
        preflight_adapters=(
            RecoveryOnlyHostAdapters()
        ),
        runtime_contract=None,
        primary_backup_root=layout.config_backup,
        recovery_backup_root=(
            recovery_root / "config-backup"
        ),
        refresh_mode=refresh_mode,
    )
    flow = RefreshOrchestrator(
        dependencies,
        str(uuid.UUID(run_id)),
    )
    flow.record_from_transaction()
    return flow


build_fixed_host_flow = build_new_fixed_host_flow
