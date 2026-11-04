# 已验证外部 QUIC 的 HY2 业务适配

本适配器仅在 `kex_poc` build tag 下编译。实现和测试限定在 `core/client/external*.go`、`core/server/external*.go`，不修改普通客户端、服务器和认证路径。

## 责任边界

上层负责 Noise、身份与权限绑定、UDP 路径验证、反放大、连接租约、撤销和可靠 READY_ACK/START。适配器接收上层提供的 `*quic.Conn` 和权限快照，不自行执行这些步骤，也不发送 auth POST、构造 HTTP 233、伪造 TLS 状态或重拨连接。

权限结构是受信调用方的输入，不是可供网络对端直接提交的认证证明。调用方必须确保权限属于当前连接；`Principal` 必须非空白，启用 UDP 必须有双向 QUIC DATAGRAM 能力。适配器只读取 DATAGRAM 能力，不依赖 TLS 握手状态。

## 固定 API

```go
// client 包
type ExternalPolicy struct {
     Principal  string
     UDPEnabled bool
     Rx         uint64
     RxAuto     bool
}

func NewExternalClient(
     conn *quic.Conn, config *Config, policy ExternalPolicy,
 ) (Client, *HandshakeInfo, error)

// server 包
type ExternalPolicy struct {
     Principal   string
     UDPEnabled  bool
     ClientMaxRx uint64
}

func PrepareExternalSession(
     conn *quic.Conn, config *Config, policy ExternalPolicy,
 ) (*ExternalSession, error)

func (*ExternalSession) Serve() error
func (*ExternalSession) ServeContext(context.Context) error
func (*ExternalSession) Close() error
func (*ExternalSession) UDPEnabled() bool
func (*ExternalSession) Context() context.Context
```

带宽单位均为字节/秒。客户端构造保留普通 `NewClient` 的三返回值形式，第二项包含最终 UDP 开关、发送带宽和实际远端地址；不填造 ECH 成功状态。

## 接入顺序与资源归属

1. 上层完成外部连接的身份验证和路径验证，取得双方权限快照。
2. 服务器调用 `PrepareExternalSession(conn, config, policy)`。此时仅校验业务配置、填默认值、准备处理器；不会接受业务流、启动 UDP 会话管理器、拨号或记录在线事件。
3. 上层读取 `session.UDPEnabled()`，将与本地禁用配置取交集后的权限绑定到控制协议。服务器接收带宽和自动探测设置也应与传给客户端的 Rx/RxAuto 一致。
4. 上层完成可靠 READY_ACK/START，停止自己的业务流和 DATAGRAM 接收循环；已经接受的控制流必须自行收尾，不能交给业务分发器。
5. 服务器调用阻塞式 `session.Serve()` 或 `ServeContext(ctx)`。客户端调用 `NewExternalClient` 并使用返回的现有 `Client.TCP/UDP` 接口。
6. 上层通过 `Close()`、取消 ServeContext 或关闭连接 Context 终止会话，并最终释放自己拥有的 Transport/PacketConn。

构造失败不关闭传入连接。构造成功后，适配器负责业务连接的关闭，但不拥有底层 Transport/PacketConn，也不关闭服务器 `Config.Cleanup`。调用方必须在业务退出后释放这些资源；它们可能由其他连接共享。

客户端包装现有 `clientImpl`，直接复用 TCP/UDP。因为现有普通 `clientImpl.Close()` 对 tr/pktConn 没有 nil 检查，包装层覆盖 Close，仅幂等关闭 QUIC 连接并清理 UDP 会话，不调用普通 Close。

服务器 Serve/ServeContext 共用一次性激活标记，再次调用返回 `ErrExternalSessionStarted`。准备后先 Close，或者传入已经取消的 Context，不产生在线/离线事件。激活后各记录一次在线、Connect，以及对应的离线、Disconnect。Serve 退出会等待其 TCP 处理器和 UDP 主循环收尾；正常本地关闭通常也返回 QUIC 关闭错误，由上层按关闭原因处理。

出站 TCP/UDP 资源绑定到连接 Context，取消时主动关闭，包括请求回填或出站写入阻塞的连接。现有 Outbound 接口不接受 Context，无法中断尚未返回的自定义 Dial；其结果若在取消后才返回，会立即关闭。自定义 Outbound 和 RequestHook 必须自行保证有限阻塞时间，否则 Serve 的最终收尾仍可能等待它们。

## 业务行为与配置

TCP 通过 AcceptStream 接收，使用 quicvarint 读取帧类型，仅对 `protocol.FrameTypeTCPRequest` 调用现有 `h.handleTCPRequest`。地址解析仍使用现有 `protocol.ReadTCPRequest`，复用 RequestHook、Outbound、流量统计和双向复制。未知帧仅重置对应流，不创建 HTTP/3 服务。

UDP 复用原会话管理器，包括分片、重组、RequestHook、CheckUDP、空闲清理与流量统计。实际权限是外部 UDPEnabled 与服务器 DisableUDP 的交集。客户端禁用时 UDP() 返回错误；服务器禁用时不创建 UDP 会话管理器，若对端绕过客户端 API 发送 DATAGRAM，则以协议错误关闭连接，不能触发 UDP 出站。

配置使用浅拷贝，调用方字段不会被填默认值。已有 Outbound、RequestHook、logger 仍是共享接口对象，需遵守原有并发约定。

| 配置 | 外部构造行为 |
| --- | --- |
| 客户端 CongestionConfig | 规范化控制器类型与 BBR profile，默认 BBR |
| 客户端 FastOpen、BandwidthConfig | 按现有 TCP 和带宽语义使用 |
| 客户端 ConnFactory、ServerAddr、Auth、TLS、QUIC 握手配置、OnAuthenticated | 不用于建立连接或旧认证回调；不会重新拨号 |
| 服务器 CongestionConfig | 规范化并填默认值 |
| 服务器 Outbound | 缺省使用原默认出站 |
| 服务器 UDPIdleTimeout | 缺省 60 秒；非零需在 2–600 秒范围 |
| 服务器 BandwidthConfig | 非零 MaxTx/MaxRx 至少 65536，与普通路径一致 |
| 服务器 TLS、Authenticator、监听 Conn | 不要求设置，也不伪造 |
| QUIC 传输窗口、stream 数量、idle timeout、DATAGRAM 上限 | 连接创建时由上层设置，适配器不追溯修改 |

客户端 RxAuto 为 true 时忽略本地 MaxTx，使用配置的拥塞控制器；否则沿用现有服务器 Rx 与本地 MaxTx 选择逻辑，最终非零使用 Brutal，零使用配置的拥塞控制器。特别是本地 MaxTx 为零时保持现有带宽探测语义。

服务器 IgnoreClientBandwidth 为 true 时使用配置的拥塞控制器；否则用 ClientMaxRx，并按非零服务器 MaxTx 收紧。最终非零使用 Brutal，零使用配置的拥塞控制器。

## 测试与当前边界

适配层测试通过 fork 的真实外部密钥 QUIC 回环入口构造连接，TLS.HandshakeComplete 保持 false，然后连接本机真实 TCP/UDP 目标。测试覆盖：

- 激活前已经排队的 TCP/UDP 不触发出站、在线或 Connect。
- FastOpen 和普通 TCP，服务端主动问候及双向负载。
- 3000 字节 UDP 双向分片/重组；沿用现有 HY2 4096 字节消息缓冲限制。
- UDP 权限与本地配置取交集、禁用拒绝、缺少 DATAGRAM 能力时构造失败。
- 未知流类型重置后，合法 TCP 仍能使用。
- Principal 与配置校验、带宽上限和自动探测组合。
- 重复 Serve、并发 Close、激活前取消、Context 资源清理、迟到 Dial 结果释放。
- 身份与流量日志、在线/离线各一次、关闭业务连接后 PacketConn 仍可用。

这些测试没有替代主线程的 Noise + UDP 路径 + READY_ACK/START 端到端 harness。主线程另行验证真实握手和控制服务关闭后的数据面持续运行。

开发时在旧回环 fork 发现两个传输层边界：外部客户端 sentFirstPacket 未更新可令 CloseWithError 不发 CONNECTION_CLOSE；16 字节 CID 下 SendDatagram 的 payload 估算可能不足以扣除 packet number 和 DATAGRAM 帧开销，满尺寸分片在打包时被丢弃。它们不在适配器修改范围内。测试显式使用 InitialPacketSize=1200、MaxDatagramFrameSize=1100，并验证两端本地关闭；不以此声称远端关闭传播及最大尺寸 DATAGRAM 已修复。网络 fork 的修复及相关验证由主线程维护。

Windows 上使用已安装的 Go 1.26.3，避免已观察到的 Go 1.26.0 大流量 race 运行时异常。验证命令：

```powershell
$env:GOTOOLCHAIN = 'go1.26.3'
$env:GOWORK = (Resolve-Path build/kex/go.work).Path
go -C core test -race -tags kex_poc ./client ./server -count=1 -timeout=120s
go -C core vet -tags kex_poc ./client ./server

# 普通构建继续使用正式依赖，不包含适配器。
$env:GOWORK = 'off'
go -C core test ./client ./server -count=1 -timeout=120s
```
