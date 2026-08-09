import argparse
from collections.abc import Callable
import json
import sys
import uuid

from weflow_chat.orchestrator import (
    RefreshMode,
    RefreshOrchestrator,
    RefreshStage,
    RunRecord,
)


class RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(
            2,
            f"{self.prog}: error: invalid_arguments\n",
        )


def parse_guid(value: str) -> str:
    return str(uuid.UUID(value))


def build_parser() -> argparse.ArgumentParser:
    parser = RedactedArgumentParser(
        prog="weflow-recovery"
    )
    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )
    sub.add_parser("preflight")
    sub.add_parser("refresh")
    sub.add_parser("refresh-prior-media")
    for name in ("resume", "rollback", "status"):
        command = sub.add_parser(name)
        command.add_argument(
            "--run-id",
            required=True,
            type=parse_guid,
        )
    return parser


def execute_refresh(
    flow: RefreshOrchestrator,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> RunRecord:
    try:
        snapshot = flow.prepare_snapshot()
        if snapshot.stage is not RefreshStage.SNAPSHOT_READY:
            return snapshot
        flow.validate_copies()
        if flow.stage is not RefreshStage.VALIDATED:
            return flow.record
        if flow.dependencies.validation_only:
            return flow.complete_validation_only()
        output_fn(
            json.dumps(
                {
                    "activeParent": str(
                        flow.layout.active
                    ),
                    "primaryBackupRoot": str(
                        flow.dependencies
                        .primary_backup_root
                    ),
                    "recoveryBackupRoot": str(
                        flow.dependencies
                        .recovery_backup_root
                    ),
                    "runId": flow.run_id,
                },
                sort_keys=True,
            )
        )
        prepared = flow.prepare_cutover()
        if prepared.stage is not RefreshStage.CONFIG_REPLACED:
            return prepared
        flow.launch_formal_for_ui()
        try:
            answer = input_fn(
                "Verify the latest chat, then type "
                f"CONFIRM {flow.run_id}: "
            )
        except (EOFError, KeyboardInterrupt):
            return flow.rollback(
                "ui_confirmation_rejected"
            )
        record = flow.record_ui_confirmation(answer)
        if record.stage is RefreshStage.UI_CONFIRMED:
            return flow.finalize()
        return record
    except BaseException as error:
        return flow.recover_after_exception(error)


def print_redacted_result(
    result: RunRecord | object,
) -> None:
    if isinstance(result, RunRecord):
        print(
            json.dumps(
                {
                    "runId": result.runId,
                    "stage": result.stage.value,
                    "productionWriteCount": (
                        result.productionWriteCount
                    ),
                    "trustStatus": result.trustStatus,
                },
                sort_keys=True,
            )
        )
        return
    print(
        json.dumps(
            {"status": getattr(result, "ok", False)},
            sort_keys=True,
        )
    )


def dispatch(
    args,
    *,
    input_fn=input,
) -> RunRecord | object:
    from weflow_chat.live import (
        build_existing_fixed_host_flow,
        build_new_fixed_host_flow,
        fixed_operation_mutex,
        run_fixed_preflight,
    )

    if args.command == "preflight":
        return run_fixed_preflight()
    if args.command == "status":
        flow = build_existing_fixed_host_flow(
            args.run_id,
            status_only=True,
        )
        return flow.record_from_transaction()
    if args.command in {
        "refresh",
        "refresh-prior-media",
        "resume",
        "rollback",
    }:
        with fixed_operation_mutex():
            if args.command in {
                "refresh",
                "refresh-prior-media",
            }:
                report = run_fixed_preflight()
                if not report.ok:
                    raise RuntimeError(
                        "fixed_readonly_preflight_blocked"
                    )
                builder_arguments = {
                    "validation_only": (
                        report.weixin.trustState
                        == "trial_required"
                    )
                }
                if args.command == "refresh-prior-media":
                    builder_arguments["refresh_mode"] = (
                        RefreshMode.PRIOR_MEDIA
                    )
                return execute_refresh(
                    build_new_fixed_host_flow(
                        **builder_arguments
                    ),
                    input_fn=input_fn,
                )
            flow = build_existing_fixed_host_flow(
                args.run_id
            )
            if args.command == "resume":
                return flow.resume()
            return flow.rollback_existing()
    raise RuntimeError("unknown_command")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = dispatch(args)
    except BaseException:
        return 2
    print_redacted_result(result)
    if isinstance(result, RunRecord):
        return (
            0
            if result.stage
            in {
                RefreshStage.COMMITTED,
                RefreshStage.ROLLED_BACK,
                RefreshStage.VALIDATED,
            }
            else 2
        )
    return (
        0
        if getattr(result, "ok", False) is True
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
