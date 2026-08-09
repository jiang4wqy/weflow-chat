from contextlib import nullcontext
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

from weflow_chat.preflight import HostContract
from weflow_chat.security import SecurityMetadata
from weflow_chat.live import (
    _assert_no_unfinished_fixed_runs,
    _discover_fixed_local_trust_receipts,
    _discover_fixed_existing,
)
import weflow_chat.live as live
from weflow_chat.models import TxState
from weflow_chat.orchestrator import (
    RefreshStage,
    allocate_refresh_version,
)
from weflow_chat.windows_adapters import (
    FixedUserOperationMutex,
    RecoveryOnlyHostAdapters,
    WindowsFormalUiBackend,
    WindowsHostAdapters,
    WindowsProcessGate,
    WindowsSecurityAdapter,
    _classify_db_path_shape,
    _open_win32_mutex,
    _ps_json,
)


def _make_junction(link: Path, target: Path) -> None:
    powershell = Path(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command",
         "& { param($link,$target) $null=New-Item -ItemType Junction "
         "-Path $link -Target $target }",
         str(link), str(target)], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip("junction creation unavailable")


@pytest.mark.skipif(
    os.name != "nt",
    reason="requires Windows PowerShell encoding",
)
def test_ps_json_handles_localized_output_when_python_forces_utf8():
    script = (
        "@{value=[string]([char]0x7528)+[char]0x6237}|"
        "ConvertTo-Json -Compress"
    )
    child = (
        "import json;"
        "from weflow_chat.windows_adapters import _ps_json;"
        f"print(json.dumps(_ps_json({script!r}), ensure_ascii=True))"
    )
    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONPATH"] = str(
        Path(__file__).parents[2] / "src"
    )

    completed = subprocess.run(
        [sys.executable, "-B", "-c", child],
        cwd=Path(__file__).parents[2],
        env=environment,
        check=False,
        capture_output=True,
    )
    diagnostic = (
        completed.stdout + completed.stderr
    ).decode("utf-8", errors="replace")
    assert completed.returncode == 0, diagnostic
    assert (
        json.loads(completed.stdout.decode("ascii"))
        == {"value": "用户"}
    )


@pytest.mark.skipif(
    os.name != "nt",
    reason="requires Windows PowerShell arguments",
)
@pytest.mark.parametrize(
    "argument",
    [
        "bound-sentinel",
        "value with spaces",
        "value; throw 'argument_executed'",
        "value & Write-Error argument_executed",
    ],
)
def test_ps_json_binds_trailing_arguments_to_script_scope(
    argument,
):
    value = _ps_json(
        "@{value=[string]$args[0]}|"
        "ConvertTo-Json -Compress",
        argument,
    )
    assert value == {"value": argument}


def _create_allocator_roots(contract: HostContract) -> None:
    contract.snapshots_root.mkdir(parents=True)
    contract.same_volume_recovery_root.mkdir(parents=True)


def test_host_contract_uses_current_weixin_session_layout(tmp_path):
    contract = HostContract.for_test_root(tmp_path)
    assert contract.session_db == (
        contract.db_storage
        / "session"
        / "session.db"
    )


def test_weixin_identity_uses_loaded_version_dll_and_certificate(
    tmp_path,
    monkeypatch,
):
    contract = HostContract.for_test_root(tmp_path)
    contract.weixin_executable.parent.mkdir(parents=True)
    contract.weixin_executable.write_bytes(b"synthetic-executable")
    dll = contract.weixin_install_root / "4.1.12.26" / "Weixin.dll"
    dll.parent.mkdir(parents=True)
    dll.write_bytes(b"synthetic-dll")
    digest = hashlib.sha256(dll.read_bytes()).hexdigest().upper()
    certificate = "C" * 64
    responses = iter(
        (
            {"path": str(dll), "size": dll.stat().st_size},
            {
                "status": "Valid",
                "subject": "Tencent Technology",
                "dllStatus": "Valid",
                "dllSubject": "Tencent Technology",
                "dllCertificateSha256": certificate,
                "version": "4.1.12.26",
            },
            {"path": str(dll), "size": dll.stat().st_size},
        )
    )
    adapter = object.__new__(WindowsHostAdapters)
    adapter.contract = contract
    adapter._probe = lambda *args: next(responses)
    adapter._sha256 = lambda path: digest
    monkeypatch.setattr(
        "weflow_chat.windows_adapters._pe_architecture",
        lambda path: "x64",
    )

    identity = adapter._weixin_identity(
        [
            {
                "pid": 42,
                "parentPid": 1,
                "name": "Weixin.exe",
                "path": str(contract.weixin_executable),
                "commandLine": "",
                "creationTimeUtc": "2026-08-05T00:00:00Z",
            }
        ]
    )

    assert identity.dll_path == dll.resolve()
    assert identity.dll_version == "4.1.12.26"
    assert identity.dll_size == dll.stat().st_size
    assert identity.dll_sha256 == digest
    assert identity.dll_signer_certificate_sha256 == certificate


def test_db_path_shape_accepts_only_bound_managed_active_parent(
        tmp_path):
    contract = HostContract.for_test_root(tmp_path)
    active = (
        contract.snapshots_root
        / (
            "20260101-000000-"
            "33333333-3333-4333-8333-333333333333"
        )
        / "active"
    )
    rogue = contract.snapshots_root / "rogue" / "active"
    presentation = active.parent / "presentation"
    active.mkdir(parents=True)
    presentation.mkdir()
    rogue.mkdir(parents=True)
    contract.source_account.mkdir(parents=True)
    managed = frozenset(
        {active.resolve(), presentation.resolve()}
    )

    assert _classify_db_path_shape(
        str(active),
        contract=contract,
        managed_active_paths=managed,
    ) == "managed_active_parent"
    assert _classify_db_path_shape(
        str(presentation),
        contract=contract,
        managed_active_paths=managed,
    ) == "managed_active_parent"
    assert _classify_db_path_shape(
        str(rogue),
        contract=contract,
        managed_active_paths=frozenset({active.resolve()}),
    ) == "invalid"
    assert _classify_db_path_shape(
        str(contract.source_account),
        contract=contract,
        managed_active_paths=frozenset({active.resolve()}),
    ) == "account_dir_instead_of_parent"


def _mutex_contender(name, sddl, timeout_ms, results) -> None:
    try:
        with _open_win32_mutex(
                name=name, sddl=sddl, timeout_ms=timeout_ms):
            results.put("owned")
    except RuntimeError as error:
        results.put(str(error))


def test_host_contract_pins_executable_dll_and_dual_recount(tmp_path):
    contract = HostContract.for_test_root(tmp_path)
    assert contract.weixin_executable == contract.weixin_install_root / "Weixin.exe"
    assert contract.weixin_dll == (
        contract.weixin_install_root / "4.1.11.24" / "Weixin.dll")
    contract.db_storage.mkdir(parents=True)
    calls = []
    adapter = object.__new__(WindowsHostAdapters)
    adapter.contract = contract
    adapter._entry_reader = lambda root: calls.append(root) or (("session.db", 7, 1),)
    first = adapter.enumerate_source()
    second = adapter.enumerate_source()
    assert first.root == contract.db_storage
    assert first.entries == (("session.db", 7, 1),)
    assert first.rootIdentity == second.rootIdentity
    assert second.entries == first.entries
    assert calls == [contract.db_storage, contract.db_storage]


def test_prior_scan_blocks_e_nonterminal_when_c_mirror_is_missing(tmp_path):
    contract = HostContract.for_test_root(tmp_path)
    run_id = "33333333-3333-4333-8333-333333333333"
    run_root = contract.snapshots_root / f"20260721-120000-{run_id}"
    run_root.mkdir(parents=True)
    (run_root / "transaction.json").write_text("{}", encoding="utf-8")
    with pytest.raises(
            RuntimeError, match="prior_run_single_mirror_requires_recovery"):
        _assert_no_unfinished_fixed_runs(contract)


@pytest.mark.parametrize(
    "state,expected_count",
    [
        (TxState.COMMITTED, 2),
        (TxState.ROLLED_BACK, 0),
    ],
)
def test_prior_scan_returns_only_committed_active_paths(
        tmp_path, monkeypatch, state, expected_count):
    contract = HostContract.for_test_root(tmp_path)
    run_id = "33333333-3333-4333-8333-333333333333"
    recovery = contract.same_volume_recovery_root / run_id
    run_root = (
        contract.snapshots_root
        / f"20260721-120000-{run_id}"
    )
    recovery.mkdir(parents=True)
    run_root.mkdir(parents=True)
    (run_root / "transaction.json").write_text(
        "{}",
        encoding="utf-8",
    )
    active = run_root / "active"
    active.mkdir()
    presentation = run_root / "presentation"
    presentation.mkdir()
    store = SimpleNamespace(
        assert_ready_for_new_run=lambda: None,
        read_equal=lambda: SimpleNamespace(
            record=SimpleNamespace(state=state)
        ),
    )
    monkeypatch.setattr(
        live,
        "_discover_fixed_existing",
        lambda _contract, _run_id: (
            SimpleNamespace(
                root=run_root.resolve(),
                active=active.resolve(),
            ),
            recovery.resolve(),
            store,
        ),
    )

    managed = _assert_no_unfinished_fixed_runs(
        contract
    )

    assert len(managed) == expected_count
    assert (
        active.resolve() in managed
    ) is (state is TxState.COMMITTED)
    assert (
        presentation.resolve() in managed
    ) is (state is TxState.COMMITTED)


def test_local_trust_discovery_accepts_only_complete_verified_pair(
    tmp_path, monkeypatch
):
    contract = HostContract.for_test_root(tmp_path)
    run_id = "33333333-3333-4333-8333-333333333333"
    recovery = contract.same_volume_recovery_root / run_id
    run_root = (
        contract.snapshots_root
        / f"20260721-120000-{run_id}"
    )
    recovery.mkdir(parents=True)
    run_root.mkdir(parents=True)
    for root in (run_root, recovery):
        (root / "local-weixin-trust.json").write_text(
            "receipt", encoding="utf-8"
        )
        (root / "local-weixin-trust-evidence.json").write_text(
            "evidence", encoding="utf-8"
        )
    store = SimpleNamespace(assert_ready_for_new_run=lambda: None)
    monkeypatch.setattr(
        live,
        "_discover_fixed_existing",
        lambda _contract, _run_id: (
            SimpleNamespace(root=run_root.resolve()),
            recovery.resolve(),
            store,
        ),
    )
    monkeypatch.setattr(
        live,
        "WindowsSecurityAdapter",
        lambda: SimpleNamespace(
            verify_local_trust_artifact=lambda _path: None
        ),
    )
    expected = object()
    calls = []
    monkeypatch.setattr(
        live,
        "verify_local_trust_artifacts",
        lambda **values: calls.append(values) or expected,
    )

    assert _discover_fixed_local_trust_receipts(contract) == (
        expected,
    )
    assert calls[0]["primary_root"] == run_root.resolve()
    assert calls[0]["recovery_root"] == recovery.resolve()


@pytest.mark.parametrize("base_name", ["recovery", "snapshots"])
def test_existing_discovery_rejects_junction_in_fixed_base_chain(
        tmp_path, base_name):
    contract = HostContract.for_test_root(tmp_path / "contract")
    run_id = "33333333-3333-4333-8333-333333333333"
    _create_allocator_roots(contract)
    allocate_refresh_version(
        snapshots_root=contract.snapshots_root,
        recovery_root=contract.same_volume_recovery_root,
        timestamp_utc="20260721-120000", run_id=run_id)
    base = (contract.same_volume_recovery_root
            if base_name == "recovery" else contract.snapshots_root)
    target = tmp_path / f"real-{base_name}"
    base.rename(target)
    _make_junction(base, target)
    try:
        with pytest.raises(RuntimeError, match="reparse_chain"):
            _discover_fixed_existing(contract, run_id)
    finally:
        if base.exists():
            os.rmdir(base)


def test_post_allocation_constructor_failure_persists_terminal_run(
        tmp_path, monkeypatch):
    contract = HostContract.for_test_root(tmp_path / "contract")
    _create_allocator_roots(contract)
    runtime_steps = []

    class FailingAdapters:
        @classmethod
        def for_preflight(
                cls, contract, *,
                managed_active_paths=frozenset(),
                local_trust_receipts=()):
            return object()

        def __init__(
                self, contract, layout, *, runtime_prepared=False,
                managed_active_paths=frozenset(),
                local_trust_receipts=()):
            if not runtime_prepared:
                raise RuntimeError("runtime_not_declared")
            raise RuntimeError("adapter_construction_failed")

    monkeypatch.setattr(live, "WindowsHostAdapters", FailingAdapters)
    monkeypatch.setattr(
        live, "discover_fixed_runtime_contract", lambda contract: object())
    monkeypatch.setattr(
        live,
        "run_preflight",
        lambda contract, adapters: SimpleNamespace(
            ok=True,
            weixin=SimpleNamespace(
                trustState="builtin_trusted",
                capabilities=(
                    "stored-envelope-refresh",
                ),
            ),
        ),
    )
    monkeypatch.setattr(
        live, "VssHelperClient", lambda **_kwargs: object()
    )
    monkeypatch.setattr(
        live,
        "_runtime_weixin_identity",
        lambda adapters: object(),
    )
    monkeypatch.setattr(
        live,
        "CopiedWeFlowValidatorBackend",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        live,
        "copy_install_verified",
        lambda *, layout, source: (
            runtime_steps.append(("copy", layout.root))
            or layout.root / "runtime" / "WeFlow"
        ),
        raising=False,
    )
    monkeypatch.setattr(
        live,
        "patch_copied_runtime",
        lambda *, layout, runtime_root: runtime_steps.append(
            ("patch", layout.root, runtime_root)
        ),
        raising=False,
    )
    with pytest.raises(RuntimeError, match="adapter_construction_failed"):
        live.build_new_fixed_host_flow(
            validation_only=True,
            contract=contract,
        )
    assert runtime_steps[0][0] == "copy"
    assert runtime_steps[1] == (
        "patch",
        runtime_steps[0][1],
        runtime_steps[0][1] / "runtime" / "WeFlow",
    )
    recovery_runs = tuple(contract.same_volume_recovery_root.iterdir())
    assert len(recovery_runs) == 1
    locator = json.loads(
        (recovery_runs[0] / "run-locator.json").read_text(encoding="utf-8"))
    store = live.MirroredTransactionStore(
        primary_path=Path(locator["primaryTransactionPath"]),
        recovery_path=recovery_runs[0] / "transaction.json")
    assert store.inspect_conservative().record.state is TxState.ROLLED_BACK
    _assert_no_unfinished_fixed_runs(contract)


def test_existing_recovery_builder_does_not_read_formal_runtime(
        tmp_path, monkeypatch):
    contract = HostContract.for_test_root(tmp_path / "contract")
    run_id = "33333333-3333-4333-8333-333333333333"
    _create_allocator_roots(contract)
    allocate_refresh_version(
        snapshots_root=contract.snapshots_root,
        recovery_root=contract.same_volume_recovery_root,
        timestamp_utc="20260721-120000", run_id=run_id)
    monkeypatch.setattr(
        live, "discover_fixed_runtime_contract",
        lambda contract: (_ for _ in ()).throw(RuntimeError("formal_drift")))
    for name in (
            "VssHelperClient", "CopiedWeFlowValidatorBackend",
            "WindowsFormalUiBackend", "WindowsProcessGate",
            "WindowsSecurityAdapter", "RecoveryOnlyHostAdapters"):
        monkeypatch.setattr(live, name, lambda *args, **kwargs: object())
    flow = live.build_existing_fixed_host_flow(
        run_id, contract=contract
    )
    assert flow.dependencies.runtime_contract is None


def test_status_is_conservative_and_does_not_construct_vss(tmp_path, monkeypatch):
    contract = HostContract.for_test_root(tmp_path / "contract")
    run_id = "33333333-3333-4333-8333-333333333333"
    _create_allocator_roots(contract)
    allocated = allocate_refresh_version(
        snapshots_root=contract.snapshots_root,
        recovery_root=contract.same_volume_recovery_root,
        timestamp_utc="20260721-120000", run_id=run_id)
    old_recovery = allocated.store.recovery_path.read_bytes()
    allocated.store.record_shadow(
        expected=TxState.DISCOVERED,
        shadow_id="{11111111-1111-4111-8111-111111111111}",
        source_volume="F:\\")
    allocated.store.recovery_path.write_bytes(old_recovery)
    monkeypatch.setattr(
        live, "VssHelperClient",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("status must not verify VSS trust")))
    flow = live.build_existing_fixed_host_flow(
        run_id, status_only=True, contract=contract)
    assert (
        flow.record_from_transaction().stage
        is RefreshStage.RECOVERY_PENDING
    )


def test_e_offline_discovery_uses_c_and_only_writes_degraded_recovery(tmp_path):
    contract = HostContract.for_test_root(tmp_path)
    run_id = "33333333-3333-4333-8333-333333333333"
    _create_allocator_roots(contract)
    allocate_refresh_version(
        snapshots_root=contract.snapshots_root,
        recovery_root=contract.same_volume_recovery_root,
        timestamp_utc="20260721-120000", run_id=run_id)
    offline = tmp_path / "offline-e"
    contract.snapshots_root.rename(offline)
    _, _, restarted = _discover_fixed_existing(contract, run_id)
    recovered = restarted.force_conservative_state(TxState.ROLLED_BACK)
    assert recovered.mirror_degraded is True
    assert not restarted.primary_path.exists()
    assert restarted.recovery_path.is_file()


def test_fixed_mutex_uses_exact_per_user_name_acl_and_finite_wait():
    seen = []
    sid = "S-1-5-21-1000-2000-3000-1001"

    def opener(*, name, sddl, timeout_ms):
        seen.append((name, sddl, timeout_ms))
        return nullcontext("owned")

    lock = FixedUserOperationMutex(
        sid_reader=lambda: sid, opener=opener)
    with lock.acquire() as owned:
        assert owned == "owned"
    digest = hashlib.sha256(sid.encode("ascii")).hexdigest()[:32]
    assert seen == [(
        f"Local\\OpenAI.WeFlowRecovery.LiveMutation.v1.{digest}",
        f"D:P(A;;GA;;;SY)(A;;GA;;;{sid})", 5_000)]


@pytest.mark.skipif(os.name != "nt", reason="requires Win32 named mutexes")
def test_win32_mutex_excludes_a_real_second_process_and_releases():
    sid = _ps_json(
        "$s=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
        "@{sid=$s}|ConvertTo-Json -Compress")["sid"]
    name = (
        "Local\\OpenAI.WeFlowRecovery.Test."
        f"{uuid.uuid4()}")
    sddl = f"D:P(A;;GA;;;SY)(A;;GA;;;{sid})"
    context = multiprocessing.get_context("spawn")

    with _open_win32_mutex(name=name, sddl=sddl, timeout_ms=1_000):
        blocked_results = context.Queue()
        blocked = context.Process(
            target=_mutex_contender,
            args=(name, sddl, 200, blocked_results))
        blocked.start()
        blocked.join(5)
        if blocked.is_alive():
            blocked.terminate()
            blocked.join()
            pytest.fail("mutex contender did not finish")
        assert blocked.exitcode == 0
        assert blocked_results.get(timeout=1) == "operation_lock_timeout"

    released_results = context.Queue()
    released = context.Process(
        target=_mutex_contender,
        args=(name, sddl, 1_000, released_results))
    released.start()
    released.join(5)
    if released.is_alive():
        released.terminate()
        released.join()
        pytest.fail("released mutex contender did not finish")
    assert released.exitcode == 0
    assert released_results.get(timeout=1) == "owned"


def test_process_gate_uses_close_main_window_and_never_kills(tmp_path):
    seen = []

    def probe(script, *arguments):
        seen.append((script, arguments))
        return {"closed": True}

    gate = WindowsProcessGate(HostContract.for_test_root(tmp_path), probe=probe)
    assert gate.request_normal_close_and_wait(3.0)
    script = seen[0][0]
    assert "CloseMainWindow" in script
    assert "IsNullOrWhiteSpace" in script
    assert "--weflow-validator-request" in script
    assert "residual" in script
    assert "Stop-Process" not in script and "taskkill" not in script.casefold()


def test_process_gate_fails_closed_for_unreadable_or_validator_family(tmp_path):
    gate = WindowsProcessGate(
        HostContract.for_test_root(tmp_path),
        probe=lambda script, *arguments: {"closed": False})
    assert gate.request_normal_close_and_wait(0.1) is False


def test_formal_ui_launches_only_fixed_executable(tmp_path):
    contract = HostContract.for_test_root(tmp_path)
    contract.formal_weflow.parent.mkdir(parents=True)
    contract.formal_weflow.write_bytes(b"fixed-exe")
    active = tmp_path / "run" / "active"
    active.mkdir(parents=True)
    calls = []

    class Process:
        def poll(self):
            return None

    def popen(arguments, **options):
        calls.append((arguments, options))
        return Process()

    backend = WindowsFormalUiBackend(
        contract, popen=popen, sleeper=lambda seconds: None)
    assert backend.launch_and_require_account_open(active)
    assert calls[0][0] == [str(contract.formal_weflow)]


def test_security_acl_requires_exact_user_and_system_without_deny(tmp_path):
    root = tmp_path / "backup"
    root.mkdir()
    nested = root / "nested"
    nested.mkdir()
    payload = nested / "payload.bin"
    payload.write_bytes(b"payload")
    state = {"deny": False}
    acl_paths = []

    def probe(script, *arguments):
        if "WindowsIdentity" in script:
            return {"sid": "S-1-5-21-1000"}
        target = Path(arguments[0])
        acl_paths.append(target)
        inheritance = (
            "ContainerInherit, ObjectInherit"
            if target.is_dir()
            else "None"
        )
        rules = [
            {"sid": "S-1-5-21-1000", "type": "Allow",
             "rights": "FullControl",
             "inheritance": inheritance,
             "propagation": "None", "inherited": False},
            {"sid": "S-1-5-18", "type": "Allow",
             "rights": "FullControl",
             "inheritance": inheritance,
             "propagation": "None", "inherited": False},
        ]
        if state["deny"]:
            rules.append({"sid": "S-1-5-21-1000", "type": "Deny",
                          "rights": "Write", "inheritance": "None",
                          "propagation": "None", "inherited": False})
        return {"owner": "S-1-5-21-1000",
                "protected": True, "rules": rules}

    backend = WindowsSecurityAdapter(
        probe=probe, runner=lambda *args, **kwargs: SimpleNamespace(returncode=0),
        set_attributes=lambda path, attributes: True)
    backend.verify_restricted_backup_tree(root)
    assert set(acl_paths) == {root, nested, payload}
    state["deny"] = True
    with pytest.raises(RuntimeError, match="backup_acl_verification_failed"):
        backend.verify_restricted_backup_tree(root)


def test_security_restrict_uses_sid_grants_and_restore_is_exact(tmp_path):
    root = tmp_path / "backup"
    root.mkdir()
    commands = []
    probes = []

    def probe(script, *arguments):
        probes.append((script, arguments))
        if "WindowsIdentity" in script:
            return {"sid": "S-1-5-21-1000"}
        return {"ok": True}

    def runner(command, **options):
        commands.append(command)
        return SimpleNamespace(returncode=0)

    attributes = []
    backend = WindowsSecurityAdapter(
        probe=probe, runner=runner,
        set_attributes=lambda path, value: attributes.append((path, value)) or True)
    backend.restrict_backup_tree(root)
    assert all(
        Path(command[0]) == Path(
            r"C:\Windows\System32\icacls.exe")
        for command in commands)
    assert "*S-1-5-21-1000:(OI)(CI)F" in commands[1]
    assert "*S-1-5-18:(OI)(CI)F" in commands[1]
    assert "*S-1-5-21-1000" in commands[2]
    metadata = SecurityMetadata(32, "S-1-5-21-1000", "S-1-5-18", "O:SYG:SYD:P")
    backend.restore(root, metadata)
    assert probes[-1][1] == (str(root), metadata.dacl_sddl)
    assert attributes == [(str(root), 32)]


@pytest.mark.skipif(
    os.name != "nt",
    reason="requires Windows ACL roundtrip",
)
def test_security_restricted_backup_tree_roundtrips_on_windows(
        tmp_path,
):
    root = tmp_path / "backup"
    root.mkdir()
    (root / "payload.bin").write_bytes(b"payload")
    backend = WindowsSecurityAdapter()

    backend.restrict_backup_tree(root)
    backend.verify_restricted_backup_tree(root)


def test_security_rejects_reparse_before_acl_change(tmp_path):
    root = tmp_path / "backup"
    root.mkdir()
    (root / "target").mkdir()
    link = root / "link"
    _make_junction(link, root / "target")
    backend = WindowsSecurityAdapter(
        probe=lambda *args: {"sid": "S-1-5-21-1000"},
        runner=lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("acl mutation must not run")),
        set_attributes=lambda path, attributes: True)
    try:
        with pytest.raises(RuntimeError, match="backup_tree_reparse_entry"):
            backend.restrict_backup_tree(root)
    finally:
        if link.exists():
            os.rmdir(link)
