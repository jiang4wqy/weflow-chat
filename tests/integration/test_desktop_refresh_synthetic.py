from types import SimpleNamespace
import hashlib

from weflow_chat.cli import execute_refresh
from weflow_chat.desktop_refresh import run
from weflow_chat.orchestrator import RefreshStage


class _Lease:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _Gate:
    def request_normal_close_and_wait(
        self,
        timeout_seconds: float,
    ) -> bool:
        assert timeout_seconds == 30.0
        return True


def _passing_report():
    return SimpleNamespace(
        ok=True,
        sourceFileCount=4,
        sourceByteCount=4096,
        requiredFreeBytes=8192,
        weixin=SimpleNamespace(
            pid=1234,
            architecture="x64",
            dllVersion="4.1.11.24",
        ),
        warningCodes=(),
        reasonCodes=(),
    )


def _tree_hashes(root):
    return {
        path.relative_to(root).as_posix(): (
            hashlib.sha256(path.read_bytes()).hexdigest()
        )
        for path in root.rglob("*")
        if path.is_file()
    }


def _run_launcher(
    synthetic_refresh,
    *responses: str,
) -> tuple[int, list[str]]:
    answers = iter(responses)
    output: list[str] = []

    def builder(*, validation_only: bool):
        assert validation_only is False
        return synthetic_refresh.flow

    code = run(
        input_fn=lambda prompt: next(answers),
        output_fn=output.append,
        lease_factory=_Lease,
        process_gate_factory=_Gate,
        preflight_fn=_passing_report,
        flow_builder=builder,
        execute_fn=execute_refresh,
    )
    return code, output


def test_desktop_cancel_allocates_no_flow_and_writes_nothing(
    synthetic_refresh,
):
    before = (
        synthetic_refresh.faults.capture_formal_hashes()
    )
    live_source = (
        synthetic_refresh.flow.dependencies
        .contract.db_storage
    )
    source_before = _tree_hashes(live_source)
    built = []

    code = run(
        input_fn=lambda prompt: "CANCEL",
        output_fn=lambda message: None,
        lease_factory=_Lease,
        process_gate_factory=_Gate,
        preflight_fn=_passing_report,
        flow_builder=lambda **kwargs: built.append(kwargs),
        execute_fn=execute_refresh,
    )

    assert code == 2
    assert built == []
    assert (
        synthetic_refresh.faults.capture_formal_hashes()
        == before
    )
    assert _tree_hashes(live_source) == source_before
    synthetic_refresh.assert_no_real_host_paths_touched()


def test_desktop_start_and_confirm_commits_synthetic_refresh(
    synthetic_refresh,
):
    run_id = synthetic_refresh.flow.run_id
    code, output = _run_launcher(
        synthetic_refresh,
        "START",
        f"CONFIRM {run_id}",
    )

    assert code == 0
    assert (
        synthetic_refresh.flow.stage
        is RefreshStage.COMMITTED
    )
    assert any(run_id in line for line in output)
    assert any(
        "committed" in line.casefold()
        for line in output
    )
    synthetic_refresh.assert_source_unchanged()
    synthetic_refresh.assert_no_real_host_paths_touched()


def test_desktop_ui_rejection_rolls_back_synthetic_refresh(
    synthetic_refresh,
):
    before = (
        synthetic_refresh.faults.capture_formal_hashes()
    )
    code, output = _run_launcher(
        synthetic_refresh,
        "START",
        "REJECT",
    )

    assert code == 2
    assert (
        synthetic_refresh.flow.stage
        is RefreshStage.ROLLED_BACK
    )
    assert (
        synthetic_refresh.faults.capture_formal_hashes()
        == before
    )
    assert any(
        "rolled_back" in line.casefold()
        for line in output
    )
    synthetic_refresh.assert_source_unchanged()
    synthetic_refresh.assert_no_real_host_paths_touched()
