from __future__ import annotations

from collections.abc import Callable
import sys

from weflow_chat.orchestrator import (
    RefreshMode,
    RefreshStage,
)

_REASONS_ZH = {
    "config_hash_invalid": "配置文件哈希无效",
    "config_not_regular_file": "配置文件不是普通文件",
    "current_db_path_shape_invalid": "当前数据库路径结构不受支持",
    "formal_weflow_running": "正式 WeFlow 仍在运行",
    "historical_backup_contract_invalid": "历史备份记录无效",
    "host_adapter_contract_invalid": "主机检查适配器结果无效",
    "host_contract_mismatch": "当前主机不符合固定路径契约",
    "insufficient_e_space": "E 盘可用空间不足",
    "process_pid_contract_invalid": "进程 PID 检查结果无效",
    "run_root_collision": "目标运行目录已存在",
    "session_db_missing": "未找到 session.db",
    "source_enumeration_invalid": "源数据库枚举结果无效",
    "source_recount_changed": "两次源文件计数不一致",
    "source_root_identity_changed": "源数据库目录身份发生变化",
    "source_volume_not_ntfs": "微信数据卷不是 NTFS",
    "target_account_not_unique": "目标微信账号配置不唯一",
    "validator_process_residual": "存在残留验证器进程",
    "vss_unsupported": "当前系统不支持所需 VSS 操作",
    "weixin_adapter_mismatch": "微信版本或架构不受支持",
    "weixin_dll_hash_mismatch": "Weixin.dll 哈希不匹配",
    "weixin_executable_mismatch": "微信可执行文件路径不匹配",
    "weixin_process_identity_invalid": "微信主进程身份无效",
    "weixin_signature_mismatch": "微信数字签名不匹配",
}
_WARNINGS_ZH = {
    "old_upgrade_backup_missing": "未找到旧版升级备份",
}
_START_PROMPT = (
    "检查已通过。输入 START 开始复制和验证；"
    "输入其他内容取消: "
)
_TRIAL_START_PROMPT = (
    "当前微信版本需要首次本机验收。本次只复制、验证并安全回滚，"
    "不会修改正式 WeFlow；成功后登记本机信任。"
    "输入 START 继续；输入其他内容取消: "
)


def _message(
    code: str,
    translations: dict[str, str],
) -> str:
    return (
        f"{translations.get(code, '未识别的检查结果')} "
        f"[{code}]"
    )


def _render_preflight(report, output_fn) -> None:
    output_fn("WeFlow 微信数据连接安全检查")
    output_fn(f"源文件数: {report.sourceFileCount}")
    output_fn(f"源数据字节数: {report.sourceByteCount}")
    output_fn(f"所需可用字节数: {report.requiredFreeBytes}")
    output_fn(f"微信进程 PID: {report.weixin.pid}")
    output_fn(f"微信架构: {report.weixin.architecture}")
    output_fn(
        f"微信 DLL 版本: {report.weixin.dllVersion}"
    )
    trust_state = getattr(
        report.weixin, "trustState", "builtin_trusted"
    )
    output_fn(f"微信信任状态: {trust_state}")
    if trust_state == "trial_required":
        output_fn(
            "本次仅执行验收与本机登记，不进行正式配置切换"
        )
    for code in report.warningCodes:
        output_fn(
            _message(code, _WARNINGS_ZH)
        )
    for code in report.reasonCodes:
        output_fn(
            _message(code, _REASONS_ZH)
        )
    if report.ok:
        output_fn("安全检查通过")
    else:
        output_fn("安全检查未通过，未进行任何数据切换")


def _run_once(
    *,
    refresh_mode: RefreshMode = RefreshMode.FULL,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    lease_factory=None,
    process_gate_factory=None,
    preflight_fn=None,
    flow_builder=None,
    execute_fn=None,
) -> int:
    if type(refresh_mode) is not RefreshMode:
        raise TypeError("refresh_mode_invalid")
    default_process_gate = process_gate_factory is None
    default_preflight = preflight_fn is None
    default_flow_builder = flow_builder is None
    if lease_factory is None:
        from weflow_chat.live import (
            fixed_operation_mutex,
        )

        lease_factory = fixed_operation_mutex

    with lease_factory():
        contract = None
        if default_process_gate or default_preflight or default_flow_builder:
            from weflow_chat.host_discovery import initialize_host_contract

            contract = initialize_host_contract(
                input_fn=input_fn,
                output_fn=output_fn,
            )
        if default_process_gate:
            from weflow_chat.windows_adapters import WindowsProcessGate

            gate = WindowsProcessGate(contract)
        else:
            gate = process_gate_factory()
        if not gate.request_normal_close_and_wait(
            30.0
        ):
            output_fn(
                "WeFlow 无法正常关闭；"
                "未强制结束进程，刷新已停止"
            )
            return 2
        if default_preflight:
            from weflow_chat.live import run_fixed_preflight

            report = run_fixed_preflight(contract)
        else:
            report = preflight_fn()
        _render_preflight(report, output_fn)
        if not report.ok:
            return 2
        trial_required = (
            getattr(
                report.weixin,
                "trustState",
                "builtin_trusted",
            )
            == "trial_required"
        )
        if (
            trial_required
            and refresh_mode is not RefreshMode.FULL
        ):
            output_fn(
                "当前微信版本需要先使用完整刷新入口完成本机验收；"
                "聊天记录刷新尚未启动"
            )
            return 2
        try:
            response = input_fn(
                _TRIAL_START_PROMPT
                if trial_required
                else _START_PROMPT
            )
        except (EOFError, KeyboardInterrupt):
            output_fn("已取消，未创建快照或修改配置")
            return 2
        if response != "START":
            output_fn("已取消，未创建快照或修改配置")
            return 2
        if default_flow_builder or execute_fn is None:
            from weflow_chat.cli import (
                execute_refresh,
            )
            from weflow_chat.live import (
                build_new_fixed_host_flow,
            )

            flow_builder = flow_builder or build_new_fixed_host_flow
            execute_fn = (
                execute_fn
                or execute_refresh
            )
        output_fn(
            "正在准备验证副本，可能需要数分钟，请勿关闭窗口"
        )
        try:
            builder_arguments = {
                "validation_only": trial_required,
            }
            if refresh_mode is not RefreshMode.FULL:
                builder_arguments["refresh_mode"] = refresh_mode
            if default_flow_builder:
                builder_arguments["contract"] = contract
            flow = flow_builder(**builder_arguments)
            result = execute_fn(
                flow,
                input_fn=input_fn,
                output_fn=output_fn,
            )
        except BaseException:
            output_fn(
                "刷新未完成；错误详情已脱敏，"
                "请保留现有运行目录"
            )
            return 2
        trust_status = getattr(
            result, "trustStatus", "not_required"
        )
        output_fn(
            "刷新结果: "
            f"{result.stage.value}; "
            f"运行 ID: {result.runId}; "
            "正式配置写入次数: "
            f"{result.productionWriteCount}; "
            f"信任状态: {trust_status}"
        )
        return (
            0
            if (
                result.stage is RefreshStage.COMMITTED
                or (
                    trial_required
                    and result.stage is RefreshStage.ROLLED_BACK
                    and result.productionWriteCount == 0
                    and trust_status
                    == "local_trust_enrolled"
                )
            )
            else 2
        )


def run(
    *,
    refresh_mode: RefreshMode = RefreshMode.FULL,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    lease_factory=None,
    process_gate_factory=None,
    preflight_fn=None,
    flow_builder=None,
    execute_fn=None,
) -> int:
    try:
        return _run_once(
            refresh_mode=refresh_mode,
            input_fn=input_fn,
            output_fn=output_fn,
            lease_factory=lease_factory,
            process_gate_factory=process_gate_factory,
            preflight_fn=preflight_fn,
            flow_builder=flow_builder,
            execute_fn=execute_fn,
        )
    except BaseException:
        try:
            output_fn(
                "刷新未完成；错误详情已脱敏，"
                "请保留现有运行目录"
            )
        except BaseException:
            pass
        return 2


def main(argv: list[str] | None = None) -> int:
    supplied = (
        sys.argv[1:]
        if argv is None
        else argv
    )
    if supplied:
        print(
            "此桌面入口不接受任何参数",
            file=sys.stderr,
        )
        return 2
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
