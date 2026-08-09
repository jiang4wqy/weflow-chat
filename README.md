# weflow-chat

`weflow-chat` 是一个面向 Windows 10/11 x64 的非官方、源码可见工具。它从微信数据库的只读 VSS 快照生成经过隔离验证的新副本，再让用户人工检查并确认是否切换 WeFlow 的聊天数据库。

本项目不会扫描进程内存，也不能为从未初始化过的 WeFlow 提取首次密钥。开始前，WeFlow 必须已经成功打开过当前账号，并在本机配置中保存可用的 `safe:` 信封。

## 支持边界

- Windows 10/11 x64；不支持 ARM、32 位 Windows、macOS 或 Linux。
- WeFlow `6.1.0` 的精确受信运行时。
- 已内置身份的 Weixin `4.1.11.24` 和 `4.1.12.26` x64；任何哈希、签名或文件身份不匹配都会停止。
- 只刷新聊天数据库。不会下载或补抓头像、附件、朋友圈图片或视频。
- 刷新完全在本机离线处理；项目没有遥测、自动更新检查或错误上传。
- 不自动刷新，也不自动删除历史快照。每次更新聊天记录都由用户启动桌面快捷方式。

## 安装

正式 Release 会附带 `install-command.txt`。复制其中完整的一行到 Windows PowerShell 5.1 运行即可。该命令固定版本，先下载并校验引导脚本 SHA-256，再由引导脚本下载并校验 Release ZIP；ZIP 校验通过前不会执行包内代码。

不要使用 `Invoke-Expression`、`iex` 或“下载后直接管道执行”的命令。仓库内的 [install.ps1](install.ps1) 只接受 HTTPS 归档地址、固定版本和 64 位 SHA-256。

安装到当前用户的 `%LOCALAPPDATA%\Programs\WeFlowChat`，并创建桌面快捷方式“刷新 WeFlow 聊天记录”。Release 自带 Python 3.12 和 Node 24，不修改系统 Python、系统 Node、WeFlow、Weixin 或微信数据目录。

首次使用 VSS 前，需要单独以管理员身份运行安装目录中的：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\vss-helper\Install-WeFlowVssTrustRoot.ps1
```

这是一次性的信任根初始化 UAC。日常刷新在创建和删除本次工具拥有的 VSS 影子副本时仍会出现受控 UAC。

## 手动刷新

1. 正常退出正在运行的 WeFlow；不要强制结束进程。
2. 双击桌面“刷新 WeFlow 聊天记录”。
3. 首次运行按提示选择微信账号目录与固定 NTFS 存储卷。
4. 检查脱敏预检结果，输入完全一致的 `START`。
5. WeFlow 打开新副本后，检查最新聊天和时间。
6. 确认无误后输入窗口给出的 `CONFIRM <run-id>`；拒绝、关闭窗口或异常会回滚旧配置。

以后有新聊天数据时重复上述过程。程序不会自动感知或定时同步。

高级恢复命令只接受界面给出的规范运行 UUID：

```powershell
weflow-chat status <run-id>
weflow-chat resume <run-id>
weflow-chat rollback <run-id>
```

如果使用正式安装包，请通过其内置 Python 运行 `-m weflow_chat.cli`；普通用户应优先使用桌面快捷方式。

## 朋友圈照片为何显示“已删除”

本项目只复制本机已经存在的数据库和可用媒体引用。朋友圈服务器内容、已过期缓存、发送方撤回或本机从未完整下载的文件不会因为数据库刷新而重新出现。本项目不联网补抓这些内容，也不承诺把朋友圈媒体永久保存在本机。

## 安全与许可

- 只处理你依法有权访问的数据，并自行遵守适用法律和第三方软件条款。
- 未知版本只允许脱敏、只读的兼容检查，不会替换正式配置。
- 发生错误时不要手工删除快照或事务文件，先使用 `status` 或 `rollback`。
- 项目不是微信、Weixin 或 WeFlow 官方产品，也未获得其背书。
- 本项目采用限制性源码可见许可证，不是 OSI 批准的开源软件；详见 [LICENSE](LICENSE)。

更多信息见 [PRIVACY.md](PRIVACY.md)、[SECURITY.md](SECURITY.md) 和 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## English install summary

Windows 10/11 x64 only. Use the single, version-pinned command from a GitHub Release's `install-command.txt`. It verifies the bootstrap script and Release ZIP before executing package code, installs bundled Python 3.12 and Node 24 per-user, and creates a no-argument desktop shortcut. WeFlow must already contain a working `safe:` envelope. Refresh is manual and offline; unsupported runtime identities fail closed.
