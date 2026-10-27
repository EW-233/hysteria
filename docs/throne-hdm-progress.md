# Throne 原生迁移开发索引（2026-10-27）

本轮按用户要求先改代码。以 GitHub 最新正式版 Throne 1.3.2 及其锁定的 sing-box、sing-quic 为基线，未部署新客户端、未改服务器、未创建 PR。

实际代码位于相邻仓库，分支均为 `codex/hy2-post-auth-migration`：

| 仓库路径 | 提交 | 内容 |
| --- | --- | --- |
| `D:/code/web/Throne-hdm` | `503ea62`、`08b99b0`、`42b6058` | 节点编辑、持久化、配置生成、分享及去重；本地 workspace、构建脚本和依赖校验 |
| `D:/code/web/sing-box-hdm` | `cc02ae74` | handshake_migration 配置、参数传递及 detour 互斥 |
| `D:/code/web/sing-quic-hdm` | `1577e14` | HTTP 233 后更换 UDP socket 与数据端口、保留同一 QUIC 会话及测试 |

完整说明：`D:/code/web/Throne-hdm/docs/handshake-migration.md`。

已通过真实本地 QUIC 集成测试（plain/Salamander/Gecko/Chrome、并发 TCP、UDP、单次 TLS 握手），认证拒绝、切换拨号失败、数据端口黑洞、deadline 与关闭并发测试，以及 Windows Go 1.26.3 race 三轮。Throne workspace 的实际依赖图也通过测试。

已编译完整 GUI 和 `D:/code/web/Throne-hdm/build/ThroneCore-hdm.exe`，使用完整 Windows 功能标签；构建信息位于同目录 `hdm-build-info.json`，三份源码 dirty 均为 false。

已补齐 Qt 6.11.2 静态 SDK 和 OpenSSL，使用 Ninja/MSVC 构建 Throne 1.3.2-hdm.0.3.2。应用、Windows ICO、托盘状态图标均替换为用户提供的灰狼少女红色徽章头像。独立空配置启动、核心 IPC、迁移开关显示及端口启用状态检查通过；未启动公网流量或 TUN。

独立客户端：`D:/code/web/Throne-hdm/build/Throne-HDM-1.3.2-hdm.0.3.2-windows-x64.zip`，含配套 GUI、内核、libcronet.dll、updater.exe、许可证、使用说明和 SHA256 清单。实际实验配置另存 `D:/code/web/Throne-hdm/build/US13-HDM-test.private.json`，含443→8443迁移节点和443普通对照节点，不进入源码提交或压缩包。已安装的旧客户端保持原样；公网 TUN、网页测速及长期使用待用户手动验证。

用户截图：实验客户端 98.12/4.76 Mbps，原 Throne 100.81/5.14 Mbps，选用了不同测速服务器，因此不据此判断性能差异。用户提供的 26061 普通 HY2 节点仍作为对照；不能与 443→8443 的另一服务实例混搭端口。实际认证信息不写入仓库。
