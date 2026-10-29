# Worker KEX 短连接 TLS 转发组件

日期：2026-10-28。本组件仅转发不透明握手载荷，不依赖 `kex` 包，不处理 UDP 数据面。
本次没有部署、修改运行服务或提交 commit。

## 文件与接入 API

- `core/internal/kexrelay/server.go`：TLS 服务、并发限额、超时、取消与关闭。
- `core/internal/kexrelay/wire.go`：有界协议编解码、共享上游凭据验证。
- `core/internal/kexrelay/server_test.go`、`wire_test.go`：真实 TLS、协议和生命周期测试。
- `extras/worker-kex/worker.mjs`：Cloudflare Worker 生产入口。
- `extras/worker-kex/relay.mjs`：可测试的请求处理和协议实现。
- `extras/worker-kex/relay.test.mjs`：Worker 单测及 Go TLS 互通测试。
- `extras/worker-kex/wrangler.toml`：配置示例，不包含秘密。
- `extras/worker-kex/package.json`：无第三方依赖的 Node 测试入口。

Go 包路径为 `github.com/apernet/hysteria/core/v2/internal/kexrelay`，遵守 Go 的 internal 可见性限制，供 core 内主线程代码接入：

```go
// Handler 必须响应取消，不能把秘密写入日志。
type Handler func(context.Context, []byte) ([]byte, error)

func NewServer(Config, Handler) (*Server, error)
func (*Server) Serve(context.Context, net.Listener) error
func (*Server) Close() error
func WriteRequest(io.Writer, []byte, []byte) error // 凭据、载荷
func ReadResponse(io.Reader) ([]byte, error)
```

`Config` 字段：

| 字段 | 语义与默认值 |
| --- | --- |
| `TLSConfig *tls.Config` | 必填；须有证书或证书回调；克隆配置并将最低协议版本至少设为 TLS 1.2 |
| `Credential []byte` | 必填；恰好 32 字节，构造时复制 |
| `ReadTimeout time.Duration` | TLS 握手与完整请求读取共享绝对截止时间，默认 5 秒 |
| `WriteTimeout time.Duration` | 完整响应写入截止时间，默认 5 秒 |
| `HandlerTimeout time.Duration` | 处理函数的 context 截止时间，默认 5 秒 |
| `MaxConnections int` | 包括尚未完成 TLS 握手的连接，默认 128 |

超时和连接限额的零值使用默认值，负值拒绝。TLSConfig 的引用内容与回调返回配置在运行时不得进行不安全修改；证书回调仍由调用者负责。

接入示意（配置与 listener 由主线程创建，处理函数可包装现有握手入口）：

```go
// 将独立配置与不透明握手函数接入 TLS 转发入口。
relay, err := kexrelay.NewServer(kexrelay.Config{
    TLSConfig:     tlsConfig,
    Credential:    upstreamCredential, // 将 UPSTREAM_TOKEN 的十六进制串解码为 32 字节
    MaxConnections: 128,
}, func(ctx context.Context, request []byte) ([]byte, error) {
    return handleHandshake(ctx, request)
})
if err != nil {
    return err
}
defer relay.Close()
return relay.Serve(ctx, tcpListener)
```

`Serve` 接收普通 TCP listener，在内部包装 TLS，并接管 listener；不要传入已经包装 TLS 的 listener。
只能调用一次 `Serve`。父 context 取消会关闭监听和活跃连接，并取消处理函数；显式 `Close` 幂等。
`Serve` 等所有连接处理函数退出后返回；主动关闭返回 `ErrServerClosed`，父 context 取消返回对应 context 错误。

处理函数须遵守 context 取消契约。超时会立即关闭连接，但 Go 无法强行终止不配合的函数；该函数未返回时仍占用并发名额，并阻止 `Serve` 返回。
不为处理函数另建可被遗弃的执行协程。处理期间不另读客户端数据；客户端断开可能直到处理结果写入时才被发现，处理 context 仍有独立上限。

## 固定协议 KXRF v1

只允许在 TLS 中传输，所有多字节整数为大端。长度只计算握手载荷，不包含头或凭据。

| 字节偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 4 | ASCII `KXRF`，十六进制 `4b 58 52 46` |
| 4 | 1 | 版本，固定 `01` |
| 5 | 1 | 消息类型，请求 `01`，响应 `02` |
| 6 | 1 | 状态，请求固定 `00`；响应见下表 |
| 7 | 1 | 保留字节，固定 `00` |
| 8 | 4 | 载荷字节数，uint32 大端 |

请求：`12 字节头 || 32 字节原始上游凭据 || 1～16384 字节载荷`。
成功响应：`12 字节头 || 1～16384 字节载荷`。
错误响应：仅 12 字节头，长度为零，无凭据、载荷或错误文本。
最大请求线上长度为 16428 字节，最大响应为 16396 字节。

响应状态：

| 值 | Go 常量 | 含义 |
| --- | --- | --- |
| 0 | `StatusOK` | 成功 |
| 1 | `StatusInvalid` | 魔数、版本、类型、保留位、长度或截断不合法 |
| 2 | `StatusUnauthorized` | 上游共享凭据不匹配 |
| 3 | `StatusHandler` | 处理失败、panic、响应为空或响应超长 |
| 4 | `StatusTimeout` | TLS 建立后读取请求超时，尽力返回 |

TLS 握手失败、处理超时、取消、并发限额或写入失败可能直接关闭连接，没有错误帧。
错误响应都是尽力发送；客户端不能依赖总能读到状态码。
`ReadResponse` 将有效错误帧转为 `*RemoteError`（公开 `Status` 字段）；非法本地输入使用 `ErrFrame` 或 `ErrCredential`。

每条连接只读取一个请求、最多调用一次处理函数、写一个响应后关闭。
流水发送的后续帧不会被处理。Go `ReadResponse` 只读一帧，调用者负责关闭连接；Worker 还会等待 EOF，并拒绝响应尾随字节、第二个响应、截断或超长。

长度先校验后分配。上游凭据始终为 32 字节，使用 `crypto/subtle.ConstantTimeCompare` 比较。
本组件不打印请求、响应、凭据或处理函数错误；处理函数自身的日志策略由主线程负责。

## Worker 接口与配置

客户端仅使用 `POST /k`，头部为 `Authorization: Bearer <CLIENT_TOKEN>`，body 为原始握手载荷。
成功返回 HTTP 200、`application/octet-stream` 和原始响应；所有响应设置 `Cache-Control: no-store`。
不会从 URL、查询参数、HTTP body 或客户端请求头选择上游地址。

环境变量：

| 名称 | 要求 |
| --- | --- |
| `CLIENT_TOKEN` | Worker secret；独立随机 32 字节的 64 位十六进制编码 |
| `UPSTREAM_TOKEN` | 另一份 Worker secret；独立随机 32 字节的 64 位十六进制编码 |
| `UPSTREAM_HOST` | 固定完整 DNS 主机名，DNS-only；证书必须与该主机名匹配 |
| `UPSTREAM_PORT` | 固定整数端口，1～65535 |
| `TIMEOUT_MS` | 整个请求的绝对超时，1～30000 毫秒，默认 5000 |

两个 secret 接受大小写十六进制，解码后若相同则配置失败。客户端 Bearer 不透传给上游；请求帧只携带解码后的 `UPSTREAM_TOKEN`。
客户端凭据使用 WebCrypto HMAC 签名/验证做固定长度标签比较，将比较交给原生密码实现，避免用 JavaScript/JIT 循环鉴权。用于比较的 HMAC key 是固定公开值，不是部署凭据；实际认证秘密仍为 CLIENT_TOKEN。Go 上游使用 `crypto/subtle` 恒定时间比较原始凭据。
禁止 IP 字面量、单标签主机名和 localhost；代码无法检查 DNS 控制台的代理开关，DNS-only 仍是配置方必须满足的条件。

生产入口直接导入：

```js
import { connect } from 'cloudflare:sockets';
// hostname 与 port 只来自固定部署配置，TLS 从连接开始即开启。
const socket = connect({ hostname, port }, { secureTransport: 'on' });
```

每次请求只调用一次 `connect`，观察 `opened` / `closed`，写入一次完整帧，读到一帧和 EOF 后关闭 socket；无连接池、重试、WebSocket、CONNECT 或任意目标代理。
不提前关闭 writable，避免半关闭策略影响待读取响应。任何失败或取消都调用 `socket.close()`，并取消 reader / writer、释放流锁。

上传逐块计数并使用固定容量缓冲区，不信任 Content-Length；超过 16 KiB 立即取消上传。
响应头到齐后立即校验声明长度，响应累计也有 16396 字节上限。整体超时覆盖上传、TLS 建连、写入、响应和 EOF；提供的 `request.signal` 触发取消时退出。

客户端错误统一为固定文本，不包含上游状态细节、异常消息、地址或秘密：

| HTTP 状态 | 场景 |
| --- | --- |
| 400 | 空载荷 |
| 401 | 客户端 Bearer 缺失或无效 |
| 404 / 405 | 路径或方法错误 |
| 408 | 客户端取消 |
| 413 | 声明或实际上传过长（非法 Content-Length 也拒绝） |
| 500 | 配置不完整、地址非法、凭据相同 |
| 502 | 上游失败、TLS 失败、协议错误、上游拒绝 |
| 504 | 整体超时或有效上游超时错误帧 |

## 官方 API 核对记录与验证范围

2026-10-28，主线程通过本机 SSH CONNECT 中继成功获取 Cloudflare 官方 TCP sockets 正文，保存为 `build/kex/cloudflare-tcp-sockets.html`。本轮已读取该本地快照，完成下列 API 与约束核对；此前网络失败导致的“未完成官方页面正文核验”限制已解除。

- `connect` 接受包含 `hostname` 与 `port` 的目标地址；`secureTransport: 'on'` 从连接开始使用 TLS，默认值 `off` 不启用 TLS。
- Socket 提供 `readable`、`writable`、`opened`、`closed`；连接或关闭发生错误时，相应 Promise 可能拒绝。
- `socket.close()` 强制关闭读写两侧；`allowHalfOpen` 默认 `false`，读侧收到 EOF 时写侧自动关闭。
- 出站 TCP 连接禁止访问 Cloudflare IP 段；localhost、私网地址也属于禁止目标，端口 25 被禁止，不能连接回当前 Worker。
- Socket 必须在请求等 handler 内创建，不能在全局作用域创建并跨请求共享；每条打开的 Socket 占用运行时并发连接额度。

因此，上游需要使用解析到实际公网源站、未经过 Cloudflare 代理的主机名，并提供匹配该主机名的可信 TLS 证书。代码中的端口格式校验允许 1～65535，但 Cloudflare 运行时仍会拒绝端口 25。

本地快照对应的官方资料地址：

```text
https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/
```

主线程补充的实验进展：当前 Cloudflare token 没有 DNS 读写权限，源站实验使用 `186-241-106-13.sslip.io` 申请 Let's Encrypt 证书；主线程已在服务器使用 `getent` 确认该名称指向自有 VPS。独立 Worker `hy2-kex-poc` 正准备部署。该解析结果与部署进展来自主线程，本轮没有重新查询 DNS、申请证书或执行部署。

官方 API 正文核验已经完成；Cloudflare 线上运行时与公网链路验收仍需以实际部署后的结果为准。本组件交付时的 Node Socket 适配器仅验证本地行为及真实 Go TLS 协议互通，不代表已完成 Worker 公网验收。

## 测试

从仓库根目录运行：

```text
go test ./core/internal/kexrelay -count=1 -v
go test -race ./core/internal/kexrelay -count=1
go vet ./core/internal/kexrelay
node --test extras/worker-kex/relay.test.mjs
```

Go 测试动态生成临时 CA 和匹配主机名的证书，用真实 TLS 连接且验证证书；覆盖 16 KiB、未知版本、凭据错误、截断、超长、处理错误和 panic、读取/握手/处理/写入超时、取消、关闭、并发名额回收、握手阶段限额及流水两帧只处理一次。
写入超时同时用 `net.Pipe` 和真实 TLS 验证，避免内核发送缓冲使测试误通过。

Worker 测试覆盖固定目标与凭据隔离、流式大小、每个异步阶段的超时/取消、错误不泄漏、无重试、关闭、非法及多响应、提前拒绝超长头。
Go 的 `TestWorkerInterop` 自动启动 Node 测试，注入临时 CA 和回环服务，验证 Worker 协议逻辑与真实 Go TLS 服务互通。
单独运行 Node 测试时该互通项跳过；机器未安装 Node 时 Go 互通项也跳过，不应把跳过视为互通验证通过。


本次本地结果：`go test -race ./core/internal/kexrelay -count=1 -v` 通过，未报告数据竞争；其中 Node 的 15 项测试全部通过且无跳过，包含真实 Go TLS 互通。`go vet ./core/internal/kexrelay` 与 Worker 入口语法检查通过。


## 外部 QUIC 路径审计修复交接（2026-10-28）

以下修复位于隔离 fork `build/kex/quic-go`，由主线程生成最终 patch/manifest；本轮没有生成补丁清单、提交或执行部署。

- 新增 `Conn.AllowExternalPeerKeyUpdate(ctx)`：客户端验证认证 READY 后、发送 READY_ACK 前调用，事件由连接主循环处理。仅开放对端 key update 解密，不关闭确认通道、不提前开放业务，也不允许本端主动发起更新。待路径验证阶段仍拒绝 phase 1。服务端保持 READY_ACK 后 Confirm→START，客户端保持 START 后 Confirm。
- 外部连接关闭后的处理器绑定已验证远端地址和本地路径信息；异源不回复且不消耗重发退避计数，同源保留 CLOSE 重发。普通 QUIC 关闭行为保持原有语义。
- 候选路径保存通过 AEAD 的收包 `packetInfo`；探测回复、路径胜出后的普通发送和关闭重发均使用该信息。底层不提供 OOB 的平台仍受原有 PacketConn 能力限制；本轮多地址验证使用真实 AEAD 收包与发送参数断言，没有宣称完成跨平台真实多网卡验收。

生产文件共六处：`external_path.go`、`external_kex.go`、`connection.go`、`closed_conn.go`、`transport.go`、`internal/handshake/external_kex.go`。
新增测试文件：`external_path_test.go`；扩展测试文件：`closed_conn_test.go`、`internal/handshake/external_kex_test.go`。

Go 1.26.3 Windows 本地验证全部通过：

```text
go test -race . ./internal/handshake -run 'TestExternal|TestClosedLocalConnection' -count=1 -timeout=60s
go test -race . -run 'TestClosedLocalConnection|TestPacketHandler|TestTransport' -count=1 -timeout=60s
go vet . ./internal/handshake
```

回归覆盖：100 次真实 AEAD 接入解密后服务端实际发出 phase 1，客户端经 READY 许可仍可读取 START；许可前拒绝早期更新；许可本身不确认握手或允许主动更新；取消与路径门控；真实 UDP 关闭后异源无回复；同源仍重发且使用验证时本地地址；不同候选路径的 packetInfo 隔离及伪造包不能覆盖路径信息。

主线程补充验收进展：接入新 API 后端到端 race 通过（约 14.7 秒）；公网绑定物理源 IP 后首次 probe 成功，连接约 3.27 秒，TCP 与 DNS 均通过。这些结果由主线程提供，最终补丁重部署及阻断入口验收由主线程继续执行。
