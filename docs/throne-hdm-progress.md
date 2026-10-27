# Throne 原生迁移开发索引（2026-10-27）

本轮按用户要求先改代码。以 GitHub 最新正式版 Throne 1.3.2 及其锁定的 sing-box、sing-quic 为基线，未部署新客户端、未改服务器、未创建 PR。

实际代码位于相邻仓库，分支均为 `codex/hy2-post-auth-migration`：

| 仓库路径 | 提交 | 内容 |
| --- | --- | --- |
| `<workspace>/Throne-hdm` | `503ea62`、`08b99b0` | 节点编辑、持久化、配置生成、分享及去重；本地 workspace、构建脚本和依赖校验 |
| `<workspace>/sing-box-hdm` | `cc02ae74` | handshake_migration 配置、参数传递及 detour 互斥 |
| `<workspace>/sing-quic-hdm` | `1577e14` | HTTP 233 后更换 UDP socket 与数据端口、保留同一 QUIC 会话及测试 |

完整说明：`<workspace>/Throne-hdm/docs/handshake-migration.md`。

已通过真实本地 QUIC 集成测试（plain/Salamander/Gecko/Chrome、并发 TCP、UDP、单次 TLS 握手），认证拒绝、切换拨号失败、数据端口黑洞、deadline 与关闭并发测试，以及 Windows Go 1.26.3 race 三轮。Throne workspace 的实际依赖图也通过测试。

已编译 `<workspace>/Throne-hdm/build/ThroneCore-hdm.exe`，使用完整 Windows 功能标签；构建信息位于同目录 `hdm-build-info.json`，三份源码 dirty 均为 false。此文件是内核构建验证产物，不代表已交付完整 GUI 客户端。

GUI 修改和 XML 检查已完成，CMake 配置因缺少 Qt6 开发包停止，新的 Throne.exe 尚未编译。后续补齐 Qt6 开发依赖，构建 GUI 与此内核配套的独立客户端包，再进行真实环境测试。

用户截图：实验客户端 98.12/4.76 Mbps，原 Throne 100.81/5.14 Mbps，选用了不同测速服务器，因此不据此判断性能差异。用户提供的 26061 普通 HY2 节点仍作为对照；不能与 443→8443 的另一服务实例混搭端口。实际认证信息不写入仓库。
