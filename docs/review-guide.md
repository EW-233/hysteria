# 源码审核说明

本仓库保留 Hysteria 上游历史，以 `fb25dc852ebbc70658e67889f411887a82b7c281` 为开发基线。审核自有改动可运行：

```sh
git diff fb25dc852ebbc70658e67889f411887a82b7c281..main
```

## 审核范围

- 原 UDP 握手迁移：`app/cmd/client_migration.go`、`extras/transport/udphop/`、`core/client/`。
- WSS 握手中继：`app/cmd/client_worker_hdm.go`、`extras/transport/workerhdm/`。
- TCP/UDP Bridge 与长度帧：`extras/bridge/tcpudp/`、`extras/transport/packetframe/`。
- Worker 接入控制与资源限制：`workers/hdm/index.mjs`。
- 构建、部署、回滚及验收工具：`scripts/hdm/`，示例配置：`examples/worker-hdm/`。

请重点检查认证成功前后的换路时序、会话与密钥连续性、重连和取消、并发读写与 Close/deadline、Worker 鉴权与流量限制、固定后端约束、配置兼容性以及测试覆盖缺口。

## 设计和验证记录

- [原 UDP 迁移设计](hdm-design.md)、[使用说明](hdm-usage.md)、[验证记录](hdm-validation.md)。
- [中继设计](worker-hdm-design.md)、[本地验收](worker-hdm-local.md)、[公网验收及局限](worker-hdm-cloudflare.md)。
- Throne、sing-box、sing-quic 的相邻检出只在进度文档中引用；本仓库不包含其修改源码。

## 本地检查

需要 Go 1.26 系列工具链和支持 `node --test` 的 Node.js。仓库根目录已提供 `go.work`。

```sh
go test ./app/cmd ./core/client ./extras/transport/udphop ./extras/transport/workerhdm ./extras/transport/packetframe ./extras/bridge/tcpudp
node --test workers/hdm/index.test.mjs
```

公网验收需要自行配置服务端、Worker 和认证信息；不会由上述检查命令部署服务。运行 `smoke-worker-live.py` 时必须显式传入 `--config` 和 `--expected-egress`；运行抓包分析时必须传入 `--server`。不要把真实配置、令牌或抓包加入 Git。

## 隐私处理与证据边界

公开历史中的 `192.0.2.10` 和 `192.0.2.20` 分别代指维护服务器和实验服务器，`hdm.example.com`、`YOUR_SUBDOMAIN` 与 `<workspace>` 等均是占位符。部署记录中的这些地址经过替换，不能直接照抄运行，也不能将占位符当作实测地址。

13 个个人开发提交在发布副本中完成历史脱敏，提交 SHA 与私人开发检出不同。上游历史和作者归属保持原样；测试中的虚拟身份与上游许可证署名保留。源码审核并不等于对所有第三方依赖、生产部署和公网抗干扰能力的完整认证。
