from contextlib import contextmanager
from types import SimpleNamespace

import pytest

import weflow_chat.desktop_chat_refresh as desktop_chat_refresh
import weflow_chat.desktop_refresh as desktop_refresh
from weflow_chat.desktop_refresh import run
from weflow_chat.orchestrator import RefreshMode, RefreshStage


class FakeLease:
    def __init__(self, events):
        self.events = events

    @contextmanager
    def acquire(self):
        self.events.append("lock_enter")
        try:
            yield
        finally:
            self.events.append("lock_exit")


class FakeProcessGate:
    def __init__(self, events, *, closes=True):
        self.events = events
        self.closes = closes

    def request_normal_close_and_wait(self, timeout_seconds):
        self.events.append(("normal_close", timeout_seconds))
        return self.closes


def _report(
    *,
    ok=True,
    reasons=(),
    warnings=(),
    trust_state="builtin_trusted",
):
    return SimpleNamespace(
        ok=ok,
        reasonCodes=tuple(reasons),
        warningCodes=tuple(warnings),
        sourceFileCount=17,
        sourceByteCount=4096,
        requiredFreeBytes=8192,
        weixin=SimpleNamespace(
            pid=4242,
            architecture="x64",
            dllVersion="4.1.11.24",
            dllSha256="A" * 64,
            trustState=trust_state,
        ),
        formalWeFlowPids=(),
        validatorPids=(),
        targetAccountMatches=1,
        sessionDbExists=True,
        currentDbPathShape=(
            "account_dir_instead_of_parent"
        ),
    )


def _run_with(
    *,
    report,
    input_fn,
    closes=True,
    output=None,
    events=None,
):
    events = [] if events is None else events
    output = [] if output is None else output
    lease = FakeLease(events)
    gate = FakeProcessGate(events, closes=closes)

    result = run(
        input_fn=input_fn,
        output_fn=output.append,
        lease_factory=lease.acquire,
        process_gate_factory=lambda: gate,
        preflight_fn=lambda: (
            events.append("preflight") or report
        ),
        flow_builder=lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("flow builder must not run")
        ),
        execute_fn=lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("refresh must not execute")
        ),
    )
    return result, events, output


def test_close_failure_stops_before_preflight_or_prompt():
    result, events, output = _run_with(
        report=_report(),
        input_fn=lambda prompt: (_ for _ in ()).throw(
            AssertionError("input must not be requested")
        ),
        closes=False,
    )
    assert result == 2
    assert events == [
        "lock_enter",
        ("normal_close", 30.0),
        "lock_exit",
    ]
    assert any(
        "WeFlow 无法正常关闭" in line
        for line in output
    )


def test_blocked_preflight_prints_chinese_reasons_without_start():
    report = _report(
        ok=False,
        reasons=(
            "config_not_regular_file",
            "insufficient_e_space",
        ),
        warnings=("old_upgrade_backup_missing",),
    )
    result, events, output = _run_with(
        report=report,
        input_fn=lambda prompt: (_ for _ in ()).throw(
            AssertionError("blocked preflight must not prompt")
        ),
    )
    rendered = "\n".join(output)
    assert result == 2
    assert events == [
        "lock_enter",
        ("normal_close", 30.0),
        "preflight",
        "lock_exit",
    ]
    assert (
        "配置文件不是普通文件 "
        "[config_not_regular_file]"
    ) in rendered
    assert (
        "E 盘可用空间不足 "
        "[insufficient_e_space]"
    ) in rendered
    assert (
        "未找到旧版升级备份 "
        "[old_upgrade_backup_missing]"
    ) in rendered
    assert "START" not in rendered


def test_every_preflight_reason_has_a_fixed_chinese_translation():
    reasons = (
        "config_hash_invalid",
        "config_not_regular_file",
        "current_db_path_shape_invalid",
        "formal_weflow_running",
        "historical_backup_contract_invalid",
        "host_adapter_contract_invalid",
        "host_contract_mismatch",
        "insufficient_e_space",
        "process_pid_contract_invalid",
        "run_root_collision",
        "session_db_missing",
        "source_enumeration_invalid",
        "source_recount_changed",
        "source_root_identity_changed",
        "source_volume_not_ntfs",
        "target_account_not_unique",
        "validator_process_residual",
        "vss_unsupported",
        "weixin_adapter_mismatch",
        "weixin_dll_hash_mismatch",
        "weixin_executable_mismatch",
        "weixin_process_identity_invalid",
        "weixin_signature_mismatch",
    )
    result, _events, output = _run_with(
        report=_report(
            ok=False,
            reasons=reasons,
        ),
        input_fn=lambda prompt: pytest.fail(
            "blocked preflight must not prompt"
        ),
    )
    rendered = "\n".join(output)
    assert result == 2
    assert "未识别的检查结果" not in rendered
    assert all(
        f"[{code}]" in rendered
        for code in reasons
    )


def test_successful_preflight_renders_redacted_summary_and_requires_start():
    prompts = []

    def cancel(prompt):
        prompts.append(prompt)
        return "取消"

    result, events, output = _run_with(
        report=_report(),
        input_fn=cancel,
    )
    rendered = "\n".join(output)
    assert result == 2
    assert events == [
        "lock_enter",
        ("normal_close", 30.0),
        "preflight",
        "lock_exit",
    ]
    assert "安全检查通过" in rendered
    assert "源文件数: 17" in rendered
    assert "源数据字节数: 4096" in rendered
    assert "微信进程 PID: 4242" in rendered
    assert "微信架构: x64" in rendered
    assert "微信 DLL 版本: 4.1.11.24" in rendered
    assert prompts == [
        "检查已通过。输入 START 开始复制和验证；"
        "输入其他内容取消: "
    ]


@pytest.mark.parametrize(
    "failure",
    [EOFError(), KeyboardInterrupt()],
)
def test_start_prompt_interruption_is_a_no_build_cancel(failure):
    def interrupted(_prompt):
        raise failure

    result, events, _output = _run_with(
        report=_report(),
        input_fn=interrupted,
    )
    assert result == 2
    assert events[-1] == "lock_exit"


def test_exact_start_builds_and_executes_refresh_inside_same_lease():
    events = []
    output = []
    lease = FakeLease(events)
    gate = FakeProcessGate(events)
    flow = object()
    result_record = SimpleNamespace(
        stage=RefreshStage.COMMITTED,
        runId="33333333-3333-4333-8333-333333333333",
        productionWriteCount=3,
    )

    def build(*, validation_only):
        events.append(("build", validation_only))
        return flow

    def execute(built, *, input_fn, output_fn):
        events.append(
            (
                "execute",
                built is flow,
                input_fn("confirm"),
            )
        )
        output_fn("cutover-notice")
        return result_record

    answers = iter(
        ["START", "CONFIRM synthetic"]
    )
    result = run(
        input_fn=lambda prompt: next(answers),
        output_fn=output.append,
        lease_factory=lease.acquire,
        process_gate_factory=lambda: gate,
        preflight_fn=lambda: (
            events.append("preflight")
            or _report()
        ),
        flow_builder=build,
        execute_fn=execute,
    )
    assert result == 0
    assert events == [
        "lock_enter",
        ("normal_close", 30.0),
        "preflight",
        ("build", False),
        ("execute", True, "CONFIRM synthetic"),
        "lock_exit",
    ]
    assert "正在准备验证副本，可能需要数分钟，请勿关闭窗口" in output
    assert "cutover-notice" in output


def test_trial_required_runs_validation_only_and_enrollment_is_success():
    events = []
    output = []
    prompts = []
    record = SimpleNamespace(
        stage=RefreshStage.ROLLED_BACK,
        runId="33333333-3333-4333-8333-333333333333",
        productionWriteCount=0,
        trustStatus="local_trust_enrolled",
    )

    def build(*, validation_only):
        events.append(("build", validation_only))
        return object()

    code = run(
        input_fn=lambda prompt: prompts.append(prompt) or "START",
        output_fn=output.append,
        lease_factory=FakeLease(events).acquire,
        process_gate_factory=lambda: FakeProcessGate(events),
        preflight_fn=lambda: _report(trust_state="trial_required"),
        flow_builder=build,
        execute_fn=lambda *args, **kwargs: record,
    )

    assert code == 0
    assert ("build", True) in events
    assert len(prompts) == 1
    assert "只复制、验证并安全回滚" in prompts[0]
    assert any("local_trust_enrolled" in line for line in output)


def test_database_only_desktop_entry_passes_fixed_mode_to_builder():
    events = []
    record = SimpleNamespace(
        stage=RefreshStage.COMMITTED,
        runId="33333333-3333-4333-8333-333333333333",
        productionWriteCount=3,
        trustStatus="not_required",
    )

    def build(*, validation_only, refresh_mode):
        events.append((validation_only, refresh_mode))
        return object()

    code = run(
        refresh_mode=RefreshMode.DATABASE_ONLY,
        input_fn=lambda _prompt: "START",
        output_fn=lambda _line: None,
        lease_factory=FakeLease([]).acquire,
        process_gate_factory=lambda: FakeProcessGate([]),
        preflight_fn=lambda: _report(),
        flow_builder=build,
        execute_fn=lambda *args, **kwargs: record,
    )

    assert code == 0
    assert events == [(False, RefreshMode.DATABASE_ONLY)]


def test_database_only_entry_stops_before_start_when_trial_is_required():
    prompts = []
    output = []

    code = run(
        refresh_mode=RefreshMode.DATABASE_ONLY,
        input_fn=lambda prompt: prompts.append(prompt) or "START",
        output_fn=output.append,
        lease_factory=FakeLease([]).acquire,
        process_gate_factory=lambda: FakeProcessGate([]),
        preflight_fn=lambda: _report(trust_state="trial_required"),
        flow_builder=lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("builder must not run")
        ),
        execute_fn=lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("refresh must not run")
        ),
    )

    assert code == 2
    assert prompts == []
    assert any("完整刷新入口完成本机验收" in line for line in output)


def test_builder_exception_is_redacted_and_releases_lease():
    events = []
    output = []
    lease = FakeLease(events)
    gate = FakeProcessGate(events)

    result = run(
        input_fn=lambda prompt: "START",
        output_fn=output.append,
        lease_factory=lease.acquire,
        process_gate_factory=lambda: gate,
        preflight_fn=lambda: _report(),
        flow_builder=lambda **kwargs: (_ for _ in ()).throw(
            RuntimeError(
                "SENSITIVE-KEY-AND-CHAT-SENTINEL"
            )
        ),
        execute_fn=lambda *args, **kwargs: (
            pytest.fail("execute must not run")
        ),
    )
    rendered = "\n".join(output)
    assert result == 2
    assert events[-1] == "lock_exit"
    assert "刷新未完成" in rendered
    assert "SENSITIVE-" not in rendered


@pytest.mark.parametrize(
    "fault_point",
    [
        "lease_factory",
        "lease_enter",
        "gate_factory",
        "normal_close",
        "preflight",
    ],
)
def test_pre_start_exceptions_are_redacted_and_release_lease(
    fault_point,
):
    events = []
    output = []
    sentinel = "SENSITIVE-KEY-CHAT-PATH-SENTINEL"

    @contextmanager
    def lease():
        events.append("lock_enter")
        if fault_point == "lease_enter":
            raise RuntimeError(sentinel)
        try:
            yield
        finally:
            events.append("lock_exit")

    def lease_factory():
        if fault_point == "lease_factory":
            raise RuntimeError(sentinel)
        return lease()

    class Gate:
        def request_normal_close_and_wait(
            self,
            timeout_seconds,
        ):
            if fault_point == "normal_close":
                raise RuntimeError(sentinel)
            return True

    def gate_factory():
        if fault_point == "gate_factory":
            raise RuntimeError(sentinel)
        return Gate()

    def preflight():
        if fault_point == "preflight":
            raise RuntimeError(sentinel)
        return _report()

    result = run(
        input_fn=lambda prompt: pytest.fail(
            "prompt must not be reached"
        ),
        output_fn=output.append,
        lease_factory=lease_factory,
        process_gate_factory=gate_factory,
        preflight_fn=preflight,
        flow_builder=lambda **kwargs: pytest.fail(
            "builder must not run"
        ),
        execute_fn=lambda *args, **kwargs: pytest.fail(
            "execute must not run"
        ),
    )

    assert result == 2
    assert sentinel not in "\n".join(output)
    assert any(
        "刷新未完成" in line
        for line in output
    )
    if fault_point in {
        "gate_factory",
        "normal_close",
        "preflight",
    }:
        assert events[-1] == "lock_exit"


def test_redacted_failure_survives_a_broken_output_boundary():
    result = run(
        output_fn=lambda message: (_ for _ in ()).throw(
            RuntimeError("SENSITIVE-OUTPUT-SENTINEL")
        ),
        lease_factory=lambda: (_ for _ in ()).throw(
            RuntimeError("SENSITIVE-LEASE-SENTINEL")
        ),
        process_gate_factory=lambda: pytest.fail(
            "gate must not run"
        ),
        preflight_fn=lambda: pytest.fail(
            "preflight must not run"
        ),
    )
    assert result == 2


@pytest.mark.parametrize(
    "stage",
    [
        RefreshStage.ROLLED_BACK,
        RefreshStage.RECOVERY_PENDING,
        RefreshStage.COMPATIBILITY_BLOCKED,
    ],
)
def test_only_committed_is_success_and_result_output_is_redacted(
    stage,
):
    output = []
    lease = FakeLease([])
    record = SimpleNamespace(
        stage=stage,
        runId="33333333-3333-4333-8333-333333333333",
        productionWriteCount=0,
        secret="SENSITIVE-KEY-CHAT-DATABASE",
    )
    result = run(
        input_fn=lambda prompt: "START",
        output_fn=output.append,
        lease_factory=lease.acquire,
        process_gate_factory=lambda: FakeProcessGate(
            []
        ),
        preflight_fn=lambda: _report(),
        flow_builder=lambda **kwargs: object(),
        execute_fn=lambda *args, **kwargs: record,
    )
    rendered = "\n".join(output)
    assert result == 2
    assert stage.value in rendered
    assert record.runId in rendered
    assert "SENSITIVE-" not in rendered


def test_main_accepts_no_arguments_and_never_echoes_rejected_values(
    monkeypatch,
    capsys,
):
    calls = []
    monkeypatch.setattr(
        desktop_refresh,
        "run",
        lambda: calls.append("run") or 0,
    )
    assert desktop_refresh.main([]) == 0
    assert calls == ["run"]
    assert (
        desktop_refresh.main(
            ["SENSITIVE-KEY-SENTINEL"]
        )
        == 2
    )
    assert calls == ["run"]
    captured = capsys.readouterr()
    assert "SENSITIVE-" not in (
        captured.out + captured.err
    )


def test_chat_refresh_main_is_fixed_database_only_and_rejects_arguments(
    monkeypatch,
    capsys,
):
    calls = []
    monkeypatch.setattr(
        desktop_chat_refresh,
        "run",
        lambda **kwargs: calls.append(kwargs) or 0,
    )

    assert desktop_chat_refresh.main([]) == 0
    assert calls == [{"refresh_mode": RefreshMode.DATABASE_ONLY}]
    assert desktop_chat_refresh.main(["SENSITIVE-PATH"]) == 2
    assert len(calls) == 1
    captured = capsys.readouterr()
    assert "SENSITIVE-" not in captured.out + captured.err
