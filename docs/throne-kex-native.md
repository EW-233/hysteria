# Throne 原生 KEX 测试包

本轮目标是把已验证的带外握手客户端编入 ThroneCore，使用 Throne 原有 TUN、DNS、路由和自定义节点功能。GUI 沿用已换用户头像的 1.3.2-hdm.0.3.2，原生核心版本为 1.14-kex.0.9.0。

## 结构与行为

- 原生出站类型为 `hysteria2-kex`，通过 sing-box 的出站注册表注册。正常运行保留 GUI 和核心两个进程，无 ExtraCore、内部 SOCKS 桥或独立 KEX 客户端。
- 首次实际流量触发一次 HTTPS KEX。后续 TCP 流与 UDP 会话共用同一条直连 QUIC 连接；检查配置不会访问握手入口。
- HTTPS 和 UDP 都经过宿主直连拨号器，支持 TUN 的物理接口识别。个人测试包沿用已验证的本机源 IPv4 绑定；换网后应调整或删除自定义节点中的 `inet4_bind_address`。
- 握手失败、会话断开、网络接口变化均不自动重连或降级。停止并重新启动节点后才能创建新出站。
- 单次调用取消只终止该调用；停止出站才关闭共享连接。建立时限默认 20 秒，不限制成功后的连接寿命。
- 设备私钥与 Worker 接入令牌仅进入个人测试包数据库，不提交源码。配置解码失败不回显原始配置。

## 可复现构建

依赖相邻的 `Throne-hdm`、`sing-box-hdm`、`sing-quic-hdm` 仓库，具体提交写入构建记录。Go 固定为 1.26.3，QUIC 补丁按 SHA256 新建隔离目录；不会覆盖原有 `go.work`、修改全局模块缓存。

```powershell
python scripts/hdm/build-throne-kex.py
python scripts/hdm/package-throne-kex.py --config C:/Users/668/.codex/secrets/hdm-cloudflare/kex-client.json
```

构建输出在 `build/throne-kex`，打包输出必须是新目录。脚本验证原 GUI 清单、原生核心哈希、数据库完整性和节点回读结果，并写出整包 SHA256 清单。`packaged-live.json` 从最终数据库回读生成，仅用于本机验收，不公开。

## 验证记录与边界

初版原生适配器本地 race 测试通过：12 条并发 TCP 只执行一次 KEX、20 次 UDP 回显、UDP 读截止到期后恢复、取消单条 TCP 不关闭共享连接、失败不重试、网络变化后停止。

首次通过 Throne 实际 `Check/Create` 流程创建原生出站，公网 trace 下载 233 字节耗时 3758 ms（含首次建立），5 MB 下载 2860 ms，SOCKS5 UDP DNS 回复 61 字节、160 ms。此验收使用本机随机端口入站，不启动 GUI、不创建第二个 TUN。

生命周期审计确认的 3 个 P2 已修复：接收结束主动清理 UDP 适配器、把会话关闭及写截止取消传到 QUIC DATAGRAM 入队等待、TCP 建连取消时中断写方向。新增接口不改变线上协议，服务端无需更新。

修复后的 QUIC 队列 race 连续 5 轮通过，core/client 与 Throne UDP 适配器 race 各连续 3 轮通过；普通非实验客户端构建与修改包 go vet 通过。最终隔离 workspace 下，kexoutbound 与 boxmain 全包 race 通过（3.527 秒、2.338 秒），完整核心编译成功。TUN/DNS/路由组合仅做 Check 校验，未创建实际虚拟网卡。包内节点的公网验收结果追加于下方。此前 UDP 间歇性超时仍是观察项；该包不承诺解决用户截图中的速度差距。GUI 操作、原生版 TUN 路由接管、睡眠恢复和长时间使用由本轮用户实测继续验证。

## 最终个人包验收（2026-10-29）

- 交付：`build/throne-kex/Throne-KEX-0.9.0-windows-x64.zip`，59,848,703 字节。
- ZIP SHA256：`fe4530af7d20cfbdcc8f2f0a338c85adfb1d7965e63dafae817eb6abe8da0ec4`。
- 构建来源：dual-hy2 `d44f89a0`、Throne `030808f1`、sing-box `cc02ae74`、sing-quic `1577e148`。两个仓库原有未提交 `go.work.sum` 保留，构建使用独立 workspace。
- QUIC 补丁 SHA256：`9dd3ef2a52e8e69316da0ed4f0e824736848c8b9a1485d4ed79bee704a34d7a3`。
- 原生核心在源码提交后重新构建；这一轮跳过已通过的本地回归，因此 build-info 的 `tests_run:false` 表示本次构建调用未重复测试，不表示之前未测试。
- 包内文件哈希、ZIP 完整性、SQLite integrity_check 和原生 custom 节点回读全部通过。包内无 ExtraCore 二进制，节点、TUN、系统代理均默认不启动。

公网验收使用从最终数据库回读生成的 `packaged-live.json`。首次请求在约 8 秒后于 `https_exchange` 阶段超时，没有自动重试；与此前成功的节点逐字段比较一致。随后分别对主、备用入口执行绑定物理 IPv4 的 HTTPS 检查，均完成 TLS 并收到 Worker 对 GET `/k` 的预期 405。该检查不带接入令牌。

手动重新运行测试、创建新会话后：一次 KEX 成功，trace 233 字节耗时 2941 ms（含建立）；5,000,000 字节下载耗时 2873 ms；UDP DNS 回复 61 字节，UDP 子测试约 170 ms，完整测试通过。结束测试时的 stream canceled 日志来自主动清理。未因此更换入口、协议参数或开启自动重试。

第一次 HTTPS 超时的根因仍未确定，保留日志 `build/throne-kex/packaged-live-test.log`；成功日志为 `packaged-live-test-second.log`。这证明最终节点可用，不等于长时间稳定性已验证。未启动用户 GUI 或第二个 TUN；下一步由用户退出旧客户端后，在新包里启用 TUN 手测。

## 本机入站端口冲突修正（2026-10-29）

用户 GUI 启动在 DNS 入站之后失败。现场查到原测试包的固定 `127.0.0.1:2082` 被 `wslrelay.exe` 占用；绑定测试返回 Windows 10048，5533 可用。此前公网验收替换了测试入站为随机端口，因此漏掉了交付默认值与本机服务的冲突。

打包脚本改为 `random_inbound_port=true`，沿用 GUI 已有的每次启动选择可用端口功能；首次在设置里勾选“随机端口”并保存也会立即选择新端口。核心二进制与协议参数未改。未停止 WSL、已有 Throne 或修改正在运行的 GUI 数据库；窗口工具 native pipe 不可用，现有客户端需用户修改该选项或使用新包。

修正版：`build/throne-kex/Throne-KEX-0.9.0-portfix-windows-x64.zip`。
SHA256：`ddb7f225a9c8cc2e4f9d2b676f0ac66f6202069dc59211d1f6a8917cf868dcb1`。
新包 SQLite 完整性、随机端口设置及全文件哈希验证通过；保留原包以便回溯。原生版 TUN 实际运行仍待用户继续手测。
