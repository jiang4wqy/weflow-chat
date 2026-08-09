from contextlib import contextmanager
from types import SimpleNamespace

import pytest

import weflow_chat.cli as cli
import weflow_chat.live as live
from weflow_chat.orchestrator import RefreshMode


class FakeCrossProcessMutex:
    def __init__(self):
        self.held = False
        self.events = []

    @contextmanager
    def acquire(self, contender):
        if self.held:
            self.events.append(("timeout", contender))
            raise RuntimeError("operation_lock_timeout")
        self.held = True
        self.events.append(("enter", contender))
        try:
            yield
        finally:
            self.events.append(("release", contender))
            self.held = False


def test_task6_final_cli_dispatch_gate_reaches_live_composition(monkeypatch):
    expected = SimpleNamespace(ok=True)
    monkeypatch.setattr(live, "run_fixed_preflight", lambda: expected)
    args = cli.build_parser().parse_args(["preflight"])
    assert cli.dispatch(args) is expected
    monkeypatch.setattr(cli, "print_redacted_result", lambda result: None)
    monkeypatch.setattr(cli, "dispatch", lambda args: expected)
    assert cli.main(["preflight"]) == 0


def test_task6_refresh_dispatch_forces_mutating_composition(monkeypatch):
    flow = object()
    mutex = FakeCrossProcessMutex()
    seen = mutex.events
    monkeypatch.setattr(live, "fixed_operation_mutex",
                        lambda: mutex.acquire("refresh"))
    monkeypatch.setattr(
        live,
        "run_fixed_preflight",
        lambda: SimpleNamespace(
            ok=True,
            weixin=SimpleNamespace(trustState="builtin_trusted"),
        ),
    )
    def build(*, validation_only):
        seen.append(("build", validation_only))
        return flow
    def execute(built, input_fn):
        seen.append(("execute", input_fn))
        return built, input_fn
    monkeypatch.setattr(live, "build_new_fixed_host_flow", build)
    monkeypatch.setattr(cli, "execute_refresh", execute)
    result = cli.dispatch(
        cli.build_parser().parse_args(["refresh"]), input_fn="synthetic-input")
    assert result == (flow, "synthetic-input")
    assert seen == [
        ("enter", "refresh"), ("build", False),
        ("execute", "synthetic-input"), ("release", "refresh")]


def test_prior_media_dispatch_selects_only_the_fixed_hybrid_mode(
        monkeypatch):
    flow = object()
    seen = []
    monkeypatch.setattr(
        live,
        "fixed_operation_mutex",
        lambda: FakeCrossProcessMutex().acquire("prior-media"),
    )
    monkeypatch.setattr(
        live,
        "run_fixed_preflight",
        lambda: SimpleNamespace(
            ok=True,
            weixin=SimpleNamespace(trustState="builtin_trusted"),
        ),
    )

    def build(*, validation_only, refresh_mode):
        seen.append((validation_only, refresh_mode))
        return flow

    monkeypatch.setattr(live, "build_new_fixed_host_flow", build)
    monkeypatch.setattr(
        cli,
        "execute_refresh",
        lambda built, input_fn: built,
    )

    result = cli.dispatch(
        cli.build_parser().parse_args(["refresh-prior-media"])
    )

    assert result is flow
    assert seen == [(False, RefreshMode.PRIOR_MEDIA)]


@pytest.mark.parametrize(
    ("command", "expected", "locks"),
    [("status", "status", False), ("resume", "resume", True),
     ("rollback", "rollback", True)])
def test_task6_existing_dispatch_uses_fixed_guid_lookup(
        monkeypatch, command, expected, locks):
    run_id = "33333333-3333-4333-8333-333333333333"
    seen = []
    mutex = FakeCrossProcessMutex()
    def mutex_factory():
        if not locks:
            raise AssertionError("read-only status must not acquire mutation lock")
        return mutex.acquire(command)
    monkeypatch.setattr(live, "fixed_operation_mutex", mutex_factory)
    class ExistingFlow:
        def record_from_transaction(self): return "status"
        def resume(self): return "resume"
        def rollback_existing(self): return "rollback"
    monkeypatch.setattr(
        live, "build_existing_fixed_host_flow",
        lambda supplied, *, status_only=False: (
            seen.append((supplied, status_only)) or ExistingFlow()))
    args = cli.build_parser().parse_args([command, "--run-id", run_id])
    assert cli.dispatch(args) == expected
    assert seen == [(run_id, command == "status")]
    assert mutex.events == (
        [("enter", command), ("release", command)] if locks else [])


def test_two_process_contenders_allow_only_one_builder_to_enter(monkeypatch):
    mutex = FakeCrossProcessMutex()
    builder_calls = []
    contender = {"name": "process-a"}
    flow = object()
    monkeypatch.setattr(live, "fixed_operation_mutex",
                        lambda: mutex.acquire(contender["name"]))
    monkeypatch.setattr(
        live,
        "run_fixed_preflight",
        lambda: SimpleNamespace(
            ok=True,
            weixin=SimpleNamespace(trustState="builtin_trusted"),
        ),
    )
    def build(*, validation_only):
        builder_calls.append(validation_only)
        contender["name"] = "process-b"
        # Model a second process arriving while process A is between its
        # prior-run scan and allocation. It cannot enter this builder, so it
        # cannot allocate a run or touch VSS/formal config.
        assert cli.main(["refresh"]) == 2
        contender["name"] = "process-a"
        return flow
    monkeypatch.setattr(live, "build_new_fixed_host_flow", build)
    monkeypatch.setattr(cli, "execute_refresh",
                        lambda built, input_fn: built)
    assert cli.dispatch(cli.build_parser().parse_args(["refresh"])) is flow
    assert builder_calls == [False]
    assert mutex.events == [
        ("enter", "process-a"), ("timeout", "process-b"),
        ("release", "process-a")]


def test_builder_exception_releases_mutex_and_retry_can_enter(monkeypatch):
    mutex = FakeCrossProcessMutex()
    attempts = []
    flow = object()
    monkeypatch.setattr(live, "fixed_operation_mutex",
                        lambda: mutex.acquire("refresh"))
    monkeypatch.setattr(
        live,
        "run_fixed_preflight",
        lambda: SimpleNamespace(
            ok=True,
            weixin=SimpleNamespace(trustState="builtin_trusted"),
        ),
    )
    def build(*, validation_only):
        attempts.append(validation_only)
        if len(attempts) == 1:
            raise RuntimeError("builder_failed")
        return flow
    monkeypatch.setattr(live, "build_new_fixed_host_flow", build)
    monkeypatch.setattr(cli, "execute_refresh",
                        lambda built, input_fn: built)
    args = cli.build_parser().parse_args(["refresh"])
    with pytest.raises(RuntimeError, match="builder_failed"):
        cli.dispatch(args)
    assert cli.dispatch(args) is flow
    assert attempts == [False, False]
    assert mutex.events == [
        ("enter", "refresh"), ("release", "refresh"),
        ("enter", "refresh"), ("release", "refresh")]


@pytest.mark.parametrize("command", ["resume", "rollback"])
def test_recovery_commands_share_same_mutex_and_timeout_before_lookup(
        monkeypatch, command):
    mutex = FakeCrossProcessMutex()
    looked_up = []
    monkeypatch.setattr(live, "fixed_operation_mutex",
                        lambda: mutex.acquire(command))
    monkeypatch.setattr(
        live, "build_existing_fixed_host_flow",
        lambda run_id, **options: looked_up.append((run_id, options)))
    run_id = "33333333-3333-4333-8333-333333333333"
    with mutex.acquire("other-process"):
        with pytest.raises(RuntimeError, match="operation_lock_timeout"):
            cli.dispatch(cli.build_parser().parse_args(
                [command, "--run-id", run_id]))
    assert looked_up == []
