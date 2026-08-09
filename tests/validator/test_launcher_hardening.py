from dataclasses import replace
from pathlib import Path
import signal
import subprocess

import pytest

from weflow_chat.paths import RunLayout
from weflow_chat.validator.launcher import (
    ValidatorBlockedError,
    _build_validator_layout_for_test,
    _launch_validator_for_test,
)


RUN_ID = "00000000-0000-4000-8000-000000000001"


class _CompletedProcess:
    def wait(self, timeout):
        return 0


def _smoke_request(run_id=RUN_ID):
    return {"operation": "smoke", "runId": run_id}


@pytest.mark.parametrize(
    ("field", "relative"),
    [
        ("runtime_exe", Path("validator/validation/rogue.exe")),
        ("user_data_dir", Path("validation")),
        ("documents_dir", Path("active")),
    ],
)
def test_forged_validator_layout_never_reaches_runner(
    validator_layout, monkeypatch, field, relative
):
    forged = replace(
        validator_layout,
        **{field: validator_layout.run_root / relative},
    )
    runs = []
    monkeypatch.setattr(
        "weflow_chat.validator.launcher._write_request",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(ValidatorBlockedError):
        _launch_validator_for_test(
            layout=forged,
            request_payload=_smoke_request(),
            process_paths=(),
            verify_runtime=lambda layout: None,
            runner=lambda *args, **kwargs: (
                runs.append((args, kwargs)) or _CompletedProcess()
            ),
            reparse_check=lambda *args, **kwargs: None,
        )

    assert runs == []


@pytest.mark.parametrize(
    "payload",
    [
        {"operation": "arbitrary", "runId": RUN_ID},
        {
            "operation": "smoke",
            "runId": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        },
        {
            "operation": "validate-snapshot",
            "runId": RUN_ID,
            "area": "source",
        },
    ],
)
def test_invalid_request_values_are_rejected_before_publish_or_runner(
    validator_layout, payload
):
    runs = []

    with pytest.raises(ValidatorBlockedError):
        _launch_validator_for_test(
            layout=validator_layout,
            request_payload=payload,
            process_paths=(),
            verify_runtime=lambda layout: None,
            runner=lambda *args, **kwargs: (
                runs.append((args, kwargs)) or _CompletedProcess()
            ),
            reparse_check=lambda *args, **kwargs: None,
        )

    assert not validator_layout.request_path.exists()
    assert runs == []


def test_presentation_request_is_accepted_only_at_presentation_attempt(
    validator_layout, monkeypatch
):
    attempt = _build_validator_layout_for_test(
        layout=RunLayout.from_existing_root(validator_layout.run_root),
        area="presentation",
        run_id=RUN_ID,
        attempt_id="00000000-0000-4000-8000-000000000010",
        secure=lambda path: path.mkdir(parents=True, exist_ok=True),
    )
    runs = []
    monkeypatch.setattr(
        "weflow_chat.validator.launcher._write_request",
        lambda *args, **kwargs: None,
    )

    code = _launch_validator_for_test(
        layout=attempt,
        request_payload={
            "operation": "validate-snapshot",
            "runId": RUN_ID,
            "area": "presentation",
        },
        process_paths=(),
        verify_runtime=lambda layout: None,
        runner=lambda *args, **kwargs: (
            runs.append((args, kwargs)) or _CompletedProcess()
        ),
        reparse_check=lambda *args, **kwargs: None,
    )

    assert code == 0
    assert len(runs) == 1


def test_other_weflow_executable_path_fails_closed_before_runner(
    validator_layout, monkeypatch
):
    runs = []
    monkeypatch.setattr(
        "weflow_chat.validator.launcher._write_request",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(ValidatorBlockedError, match="^formal_weflow_running$"):
        _launch_validator_for_test(
            layout=validator_layout,
            request_payload=_smoke_request(),
            process_paths=(
                {
                    "Name": "WeFlow.exe",
                    "ExecutablePath": r"C:\Other\WeFlow\WeFlow.exe",
                },
            ),
            verify_runtime=lambda layout: None,
            runner=lambda *args, **kwargs: (
                runs.append((args, kwargs)) or _CompletedProcess()
            ),
            reparse_check=lambda *args, **kwargs: None,
        )

    assert runs == []


def test_post_spawn_path_error_still_reaps_child(
    validator_layout, monkeypatch
):
    class Process:
        def __init__(self):
            self.cleanup_started = False
            self.reaped = False

        def send_signal(self, value):
            assert value == signal.CTRL_BREAK_EVENT
            self.cleanup_started = True

        def terminate(self):
            self.cleanup_started = True

        def kill(self):
            self.cleanup_started = True

        def wait(self, timeout):
            assert self.cleanup_started
            self.reaped = True
            return 70

    process = Process()
    spawned = False

    def runner(*args, **kwargs):
        nonlocal spawned
        spawned = True
        return process

    def fail_after_spawn(*args, **kwargs):
        if spawned:
            raise OSError("synthetic_post_spawn_path_failure")

    monkeypatch.setattr(
        "weflow_chat.validator.launcher._write_request",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(
        (OSError, ValidatorBlockedError),
        match="synthetic_post_spawn_path_failure|validator_path_check_failed",
    ):
        _launch_validator_for_test(
            layout=validator_layout,
            request_payload=_smoke_request(),
            process_paths=(),
            verify_runtime=lambda layout: None,
            runner=runner,
            reparse_check=fail_after_spawn,
        )

    assert process.reaped is True


def test_stubborn_timeout_is_killed_and_reaped(
    validator_layout, monkeypatch
):
    class StubbornProcess:
        def __init__(self):
            self.actions = []
            self.reaped = False

        def wait(self, timeout):
            self.actions.append(("wait", timeout))
            if not any(action == "kill" for action, *_ in self.actions):
                raise subprocess.TimeoutExpired("validator", timeout)
            self.reaped = True
            return 70

        def send_signal(self, value):
            assert value == signal.CTRL_BREAK_EVENT
            self.actions.append(("signal", value))

        def terminate(self):
            self.actions.append(("terminate",))

        def kill(self):
            self.actions.append(("kill",))

    process = StubbornProcess()
    monkeypatch.setattr(
        "weflow_chat.validator.launcher._write_request",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(ValidatorBlockedError, match="^validator_timeout$"):
        _launch_validator_for_test(
            layout=validator_layout,
            request_payload=_smoke_request(),
            process_paths=(),
            verify_runtime=lambda layout: None,
            runner=lambda *args, **kwargs: process,
            reparse_check=lambda *args, **kwargs: None,
        )

    assert ("terminate",) in process.actions
    assert ("kill",) in process.actions
    assert process.reaped is True


def test_wait_oserror_still_reaps_child(
    validator_layout, monkeypatch
):
    class Process:
        def __init__(self):
            self.waits = 0
            self.signals = []
            self.reaped = False

        def wait(self, timeout):
            self.waits += 1
            if self.waits == 1:
                raise OSError("synthetic_wait_failure")
            self.reaped = True
            return 70

        def send_signal(self, value):
            self.signals.append(value)

        def terminate(self):
            raise AssertionError("signal wait should reap")

        def kill(self):
            raise AssertionError("signal wait should reap")

    process = Process()
    monkeypatch.setattr(
        "weflow_chat.validator.launcher._write_request",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(OSError, match="synthetic_wait_failure"):
        _launch_validator_for_test(
            layout=validator_layout,
            request_payload=_smoke_request(),
            process_paths=(),
            verify_runtime=lambda layout: None,
            runner=lambda *args, **kwargs: process,
            reparse_check=lambda *args, **kwargs: None,
        )

    assert process.signals == [signal.CTRL_BREAK_EVENT]
    assert process.reaped is True


def test_cleanup_wait_oserror_escalates_and_reaps(
    validator_layout, monkeypatch
):
    class Process:
        def __init__(self):
            self.waits = 0
            self.actions = []
            self.reaped = False

        def wait(self, timeout):
            self.waits += 1
            if self.waits <= 2:
                raise OSError(f"synthetic_wait_failure_{self.waits}")
            self.reaped = True
            return 70

        def send_signal(self, value):
            self.actions.append(("signal", value))

        def terminate(self):
            self.actions.append(("terminate",))

        def kill(self):
            self.actions.append(("kill",))

    process = Process()
    monkeypatch.setattr(
        "weflow_chat.validator.launcher._write_request",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(OSError, match="synthetic_wait_failure_1"):
        _launch_validator_for_test(
            layout=validator_layout,
            request_payload=_smoke_request(),
            process_paths=(),
            verify_runtime=lambda layout: None,
            runner=lambda *args, **kwargs: process,
            reparse_check=lambda *args, **kwargs: None,
        )

    assert process.actions[:2] == [
        ("signal", signal.CTRL_BREAK_EVENT),
        ("terminate",),
    ]
    assert process.reaped is True
