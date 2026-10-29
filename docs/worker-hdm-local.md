# Worker HDM 本地 PoC（M1）

> 提交标识说明：本页项目提交 SHA 已映射为身份改写后的等价文件树提交；原构建时的 SHA 记录仅保留在本机。

## 行为和边界

认证之前：CLI → 本地 TCP Bridge → 独占 UDP socket → 唯一 HY2 监听器。
HTTP 233 之后：同一个 CLI QUIC Transport 切换至新的 UDP socket → 同一个监听器。
不重新建立 QUIC/TLS，不重新发起认证。旧 TCP 通路最多保留五秒接收迟到数据。
Bridge 不识别 233，不持有内部 TLS 密钥，只搬运帧中的数据报。

本版本是本地 M1，不包含 Cloudflare Worker、WebSocket、VPC/Tunnel 部署。
未来只考虑 Free 套餐；现在无需账号、域名或 Cloudflare API token。
跨源 IP 测试用 127.0.0.1 → 127.0.0.2，不能据此宣称 VPS 公网迁移已验证。

状态日志 `data path unverified` 只表示本地 socket 安装成功。可用性测试在
关闭 Bridge 后检查完整业务应答；生产代码没有标准 QUIC PATH 验证/ACTIVE 状态。
不支持自动回退，直连黑洞由 QUIC 超时处理。不要将此 PoC 当成已完成的 M4。

## 构建和本机试用

在仓库根目录运行 PowerShell：

```powershell
./scripts/hdm/build-worker.ps1
```

产物位于 `build/worker-hdm/`：Windows amd64 和 Linux amd64 的 CLI、Bridge，
另有 `SHA256SUMS`、`build-info.json`。原 `build/hdm/` 产物不受影响。

在三个终端分别执行（仅本地实验，样例使用公开测试证书并跳过证书验证）：

```powershell
./build/worker-hdm/hysteria-worker-windows-amd64.exe server -c examples/worker-hdm/server.yaml
./build/worker-hdm/hdm-bridge-windows-amd64.exe -listen 127.0.0.1:18080 -target 127.0.0.1:24443
./build/worker-hdm/hysteria-worker-windows-amd64.exe client -c examples/worker-hdm/client.yaml
```

客户端提供 `http://127.0.0.1:18081` HTTP 代理。停止 Bridge 后新业务请求仍应
通过直连 UDP 工作；若客户端本身断线并重建，必须先重新启动 Bridge。
上面的 24443 可以改成 443；Bridge 的固定目标和客户端 `server` 必须指向同一实例。
本阶段无需 Linux 双端口重定向。

## 配置语义

| 配置 | 含义 |
| --- | --- |
| transport.type: tcpBridge | 显式启用本地实验；默认 udp 保持原样 |
| server | 最终直连 UDP 目标；仍按原规则设置 SNI，可显式配置 tls.sni |
| transport.tcpBridge.address | 必填，字面量回环 TCP IP:port |
| connectTimeout | TCP 拨号上限，默认 5s |
| handshakeTimeout | TCP 连接建立后的中继硬时限，默认 10s；不含拨号时间 |

不与 realm、mimic、端口范围、定时 hopping 或旧 handshakeMigration 同时启用。
混淆顺序仍为 QUIC → obfs → 路径切换器；plain、Salamander 和 Gecko 都经过验证。
每次连接生成新的工厂、TCP 会话和独立迁移状态。

Bridge 只允许回环 TCP 监听和固定回环 UDP 目标。帧格式为 uint16 大端长度加
原始数据报，长度 1..2048；帧错误、半关闭、EOF 均结束本次会话。
每会话默认最多 1 MiB 双向数据报、15s 硬生命周期、每方向 5s 空闲时间，
全 Bridge 最多 64 个会话，可通过命令行参数调整。Stats.Bytes 统计通过预算检查的
数据报字节，不是网卡流量。限制不能被解释为“已经识别认证并只允许握手”。

## 阶段变更

- 新增 `extras/bridge/tcpudp`、`extras/transport/packetframe` 和 `extras/cmd/hdm-bridge`：
  有界的双向桥与可执行入口；没有新依赖。
- `extras/transport/udphop` 复用初始化、接收队列、一次切换和旧 socket 回收；
  仅新增中继模式对当前路径读错误的报告和旧路径错误隔离。
- 新增 `extras/transport/workerhdm`：将 TCP 帧封装为 PacketConn，保持逻辑目标，
  串行收发并限制握手时长。
- `app/cmd/client.go` 与 `client_worker_hdm.go`：校验新配置、使用原 OnAuthenticated，
  在全部混淆 wrapper 外隐藏 UDP syscall 能力，避免将 TCP 当作 UDP 初始化。
- 更新配置解析 fixture；新增单元和集成测试、构建脚本与示例。
- core、QUIC 依赖版本、HY2 wire format 均未修改。

## 测试证据

定向 Windows race 测试使用 Go 1.26.3；WSL Linux 使用已有 Go 1.26.0 工具链。
主要命令（在 Windows 上先设置 `$env:GOTOOLCHAIN='go1.26.3'`）：

```text
go test -race ./extras/transport/packetframe ./extras/bridge/tcpudp ./extras/transport/workerhdm ./extras/transport/udphop ./app/cmd -run 'Test(Frames|Bridge|PacketConn|RelaySwitch|PostAuth|RecvLoop|WorkerHDM|HandshakeMigration|ClientConfig$)' -count=1 -timeout=120s
```

| 检查 | 已获得的结果 |
| --- | --- |
| 两字节帧、短写、粘包、截断、零/超大长度 | 通过 |
| 16 并发会话各 10 次回显，不串包 | 通过 |
| 并发/字节/硬时限/空闲约束、回收 | 通过 |
| 握手端 EOF、静默超时、认证拒绝 | 通过 |
| 源 IP 从 127.0.0.1 变为 127.0.0.2 | 六种 obfs/Chrome 组合通过 |
| 中继关闭后 4 条并发 TCP 流及 HY2 UDP | 通过；每连接 TLS=1、Authenticator=1 |
| 完整 CLI 工厂的 HTTP/HTTPS 上传和回显下载 | 三种 obfs 组合通过 |
| 切换中继续原 TCP Stream、原 UDP Session | 通过 |
| 首两个直连数据报丢弃 | 六组合通过 |
| 连续 100 次新连接，每次重新通过桥握手 | 100/100；TLS=100、Authenticator=100、桥 TCP=100 |
| 直连路径 QUIC v1 Initial（plain 模式） | 0；混淆模式不以原始包头判断 |
| 直连全黑洞 | 关闭 ChromeParrot、QUIC idle=4s 时有界失败，无重握手 |
| 100 次切换/Close 并发、旧路径 EOF | race/goleak 通过 |
| 默认配置、旧定时 hopping、旧双端口 HDM | 回归通过 |

Authenticator 调用计数不是逐条 HTTP 233 抓包计数；没有导出 TLS key 或独立
pcap。本次证据来自真实 socket 的包头观察、认证/TLS 回调计数和原业务流连续性。

测试曾发现：TCP 半帧超时被 quic-go 视为 Temporary，接收循环退出后握手清理卡住。
已将中继模式的不可恢复读错误包装为永久错误，并保留底层错误链；新增静默桥测试
验证 50ms 握手限额在 2s 内失败。此修复不改变原 UDP hopping 的超时处理。

修复后 Windows 对上述五个 extras/cmd 包及 core/client 的完整 `go test -race`
均通过（app/cmd 18.794s）。没有运行或声称整个 core 集成压力测试套件通过。
HTTP 初版测试的服务端在读完请求体前写响应，受到 HTTP/1 默认非全双工行为影响；
已修正测试端为先读完整请求体再回显，生产转发代码未为此修改。

### 已构建程序验收

`74180a9` 构建出版本 `0.4.2-worker-local` 的 Windows/Linux amd64 CLI 和 Bridge，
两平台启动检查均通过。随后执行：

```powershell
python -X utf8 -B scripts/hdm/smoke-worker.py
```

脚本启动独立的真实 server、Bridge、client 进程以及本地 HTTP/HTTPS 回显服务，
使用临时端口，结束后回收全部测试进程。实测结果：

| 阶段 | HTTP 上传并回显 | HTTPS 上传并回显 |
| --- | --- | --- |
| 认证后 | 122,880 字节一致 | 122,880 字节一致 |
| Bridge 进程退出后 | 151,552 字节一致 | 151,552 字节一致 |

客户端日志仅出现一次认证后切换。报告与日志在 `build/worker-hdm/smoke/`，
SHA256 校验和与构建来源在 `build/worker-hdm/`。这是一项功能验收，不是吞吐基准。
WSL 的 Linux 定向 race 测试及追加的 HTTP/HTTPS、半关闭测试亦通过。

## 后续尚未验证

- Cloudflare 免费账户上的 Worker WSS、VPC/Tunnel、独立 token 和各项实际限额。
- VPS 公网跨 IP/NAT、真实 MTU、延迟和长连接可靠性；本地回环不是这些测试的替代。
- 生产路径确认机制、明确的迁移失败超时、回退策略和用户可见状态。
- 1000 次统计、A/B/C/D 性能基准、远程抓包、服务端重启场景及封锁测试。
- 基于认证源 IP 的外部策略兼容性；认证初始地址是 Bridge 地址。

方案调整是把最小 CLI 适配提前到 M1，先证明同一 QUIC 会话可跨路径，再实现 Worker。
没有提前引入 M2 的云配置或把未验证路径标记成 ACTIVE。
