# Privacy

`weflow-chat` 在用户自己的 Windows 电脑上离线处理数据。刷新阶段不发起网络请求，不包含遥测、广告、自动更新、崩溃上传或远程日志。

## 本机读取

为完成刷新，程序只读检查 WeFlow/Weixin 的受支持运行时身份、WeFlow 当前账号选择器与已有 `safe:` 信封、微信数据库目录、磁盘与进程状态。它不扫描进程内存，不提取首次密钥，也不读取无关账号。

## 本机保存

- `%LOCALAPPDATA%\WeFlowChat\settings.json`：用户选择的源账号目录和数据存储根；权限应仅允许当前用户与 SYSTEM。
- 用户选择的 `WeFlowChatData`：不可变快照副本、脱敏清单和事务状态。
- `%APPDATA%\WeFlowChat\Recovery`：配置同卷的恢复事务与备份。
- `%PROGRAMDATA%\WeFlowRecovery\shadows`：仅含 VSS 所有权 journal，不含聊天内容。

历史快照不会自动清理，避免在恢复证据尚未确认时误删数据。用户应在确认不再需要恢复后自行管理存储空间。

## 不记录和不上传

普通输出不得包含账号 ID、联系人、消息正文、时间线内容、媒体文件名、完整本机路径、密钥信封、解密密钥、命令行、环境变量或真实配置内容。仓库和 Release 不包含任何真实聊天、媒体、设置、事务、日志或信任回执。

安装命令会访问 GitHub Release、python.org、nodejs.org 和 npm 官方 registry 取得经过固定哈希或 lockfile integrity 校验的安装材料。刷新本身不需要联网。
