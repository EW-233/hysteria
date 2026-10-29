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
