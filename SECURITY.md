# Security policy

## Supported release

安全修复只面向最新发布的 `weflow-chat` 版本。运行时支持是精确身份合同，不是宽松版本范围：当前代码只接受 WeFlow `6.1.0` 和内置哈希/签名身份匹配的 Weixin x64 版本。版本字符串相同但文件哈希不同也会停止。

## Report a vulnerability

请通过 GitHub 仓库的私密 Security Advisory 报告漏洞。不要在公开 issue 中附加真实账号、完整路径、配置、数据库、媒体、日志、密钥信封、事务或信任回执。若无法提供脱敏复现，请先只描述固定错误码、受影响版本和操作阶段。

## Supply chain

- Release 只从 `v<semver>` 标签构建。
- CPython 与 Node 归档使用代码中固定的 HTTPS 地址和 SHA-256。
- Node 依赖由 `package-lock.json` 的完整性字段固定，并禁止安装脚本。
- Release ZIP、引导脚本和清单均发布 SHA-256。
- 一键安装命令先验证引导脚本，再由引导脚本验证 ZIP；校验失败时不会执行归档代码。

不要运行使用 `Invoke-Expression`、`iex`、远程脚本管道或未固定版本/哈希的第三方安装命令。

## Fail-closed behavior

未知或不受信的 WeFlow/Weixin、路径 reparse、事务分叉、镜像缺失、配置变化或验证失败都会阻止正式配置写入。工具不会通过扫描进程内存、绕过签名或自动信任本机未知版本来继续。
