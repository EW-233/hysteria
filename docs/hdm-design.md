# Hysteria2 Handshake-to-Data Migration：第一阶段源码审计

> 公开副本中的服务器地址、域名及本机路径已脱敏；详情见 [源码审核说明](review-guide.md)。

> 后续最小实现已完成；使用与部署见 [hdm-usage.md](hdm-usage.md)，实际测试记录见 [hdm-validation.md](hdm-validation.md)。以下保留第一阶段审计时的结论。

## 1. 结论与任务定位

本阶段交付源码审计、修改定位和验证设计；尚未实现 HDM，也未验证 UDP 443 → 8443 的实际迁移。

首个开发里程碑仍是：官方 CLI 在固定服务端 IP 上通过握手端口完成 QUIC/TLS 和 HY2 HTTP 233 认证，然后仅切换一次底层 UDP 路径，继续使用同一个 QUIC 连接传输 TCP Stream 和 HY2 UDP Datagram。

现有代码提供了可复用的路径：保持同一个 `udpHopPacketConn`、`quic.Transport`、`quic.Conn`，在包装内部替换 UDP socket 与真实目标端口。服务端使用 Hysteria 自己的 quic-go fork；它通过 `DisablePathManager` 直接接受已解密的 1-RTT 数据报所携带的新客户端地址，而不是完成标准 QUIC 路径验证。因此实现具有源码依据，但“socket 已切换”“收到新 socket 的数据报”和“QUIC 已验证路径”必须分别记录。

本阶段没有发现必须修改 HY2 wire format、TLS 或认证协议的理由。跨 IP 握手中继仍需独立 PoC；本审计不能作为其可用性证明。

## 2. 审计基线与复现环境

| 项目 | 本次实际值 |
| --- | --- |
| 初始工作区 | `<workspace>/dual-hy2`，为空，无 Git 仓库 |
| 检出来源 | `https://github.com/HyNetwork/hysteria.git`，组织名是 `HyNetwork` |
| 官方分支 | `master` |
| 审计提交 | `fb25dc852ebbc70658e67889f411887a82b7c281` |
| 最近标签描述 | `app/v2.13.0-2-gfb25dc8` |
| 本地审计分支 | `hdm-audit` |
| Go | `go1.26.0 windows/amd64` |
| 工作区模块 | `go.work` 中的 `app`、`core`、`extras`，均要求 Go 1.26.0 |
| QUIC 实际依赖 | `github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c` |
| QUIC 模块校验和 | `h1:cxK8qTA0YCsj68A7zLYDCfPgMTOyt3ePkHh+oXEmYU0=` |

`core/go.mod`、`extras/go.mod` 与 `app/go.mod` 锁定同一个 fork 版本；`go.work` 没有替换到其他 QUIC 实现。依赖通过 `go mod download -json github.com/apernet/quic-go` 实际下载并阅读。通用 quic-go 文档检索未成功返回内容，本审计以锁定的 fork 源码为依据。

下文行号均相对于上述官方提交；后续代码修改后应重新定位。

## 3. 实际调用链

```text
app/cmd/client.go: runClient
  → client.NewReconnectableClient(config.Config, connectedFunc, lazy)
  → core/client/reconnect.go: reconnect()
  → app/cmd/client.go: clientConfig.Config()
      → fillServerAddr()                 解析 IP、握手端口、TLS SNI
      → fillConnFactory()                设置延迟打开的 singleUseConnFactory
  → core/client/client.go: NewClient()
      → Config.verifyAndFill()
      → clientImpl.connect()
          → ConnFactory.New(ServerAddr)
              → socketOptions.ListenUDP()
                或 udphop.NewUDPHopPacketConn(...)
              → wrapObfs(innerConn)
          → quic.Transport{Conn: pktConn}
          → http3.Transport.Dial → tr.DialEarly(...)
          → HTTP POST https://hysteria/auth
          → RoundTrip() → 检查 HTTP 233
          → 解析认证响应、设置拥塞控制、关闭响应 body
          → 【拟新增：可选的认证后 transport 切换触发点】
          → 保存 pktConn / tr / conn，创建客户端 UDP session manager
      → 返回 Client 与 HandshakeInfo
  → connectedFunc() 通知 CLI 已连接
  → Client.TCP() / Client.UDP() 复用上述 conn
```

关键位置：

- `app/cmd/client.go:127`：`clientConfigTransportUDP`，已有固定与范围 hop interval。
- `app/cmd/client.go:247`：`fillServerAddr()`；固定端口返回 `*net.UDPAddr`，端口并集/范围返回 `*udphop.UDPHopAddr`。
- `app/cmd/client.go:273`：`fillConnFactory()`；按地址类型选择 socket，再套 obfs。
- `app/cmd/client.go:622`：配置生成；realm 分支会提前进入 `realmConfig()`，绕过常规 transport 构造。
- `app/cmd/client.go:853`：CLI 的可重连客户端入口。
- `app/cmd/client.go:1278`：`singleUseConnFactory`；每份工厂只允许打开一次。
- `core/client/config.go:21,93`：公开配置和 `ConnFactory` 边界。
- `core/client/client.go:69–181`：连接、认证和初始化的完整过程。
- `core/server/server.go:54–85`：服务端 QUIC 配置及唯一监听 transport。
- `core/internal/protocol/http.go:20`：`StatusAuthOK = 233`。

### 认证时序

`NewClient()` 同步调用 `connect()`；只有 `rt.RoundTrip(req)` 成功且状态码等于 233，才会返回成功。非 233 与请求错误都会关闭已建立的 QUIC 连接、transport 和 packet conn。

虽然使用 `DialEarly`，此处认证请求是普通 HTTP POST。锁定依赖的 `http3/client.go:271–291` 在发送普通请求前等待 `HandshakeComplete()`，不走 GET/HEAD 的 0-RTT 特例。因此认证成功触发点晚于 TLS 握手完成。TLS 握手完成和客户端收到 `HANDSHAKE_DONE` 的 QUIC 握手确认仍是不同事件；后者与切换附近的包序需要抓包验证。

现有 `connectedFunc` 发生在 `NewClient()` 返回后，参数也不暴露底层 conn。把迁移直接放到该 CLI 通知中，不利于统一失败清理；优先在 core 认证成功分支增加可选钩子。

## 4. UDP hopping 的实际行为

### 创建、切换和关闭

`extras/transport/udphop/conn.go`：

1. `NewUDPHopPacketConn()`（63）规范化 interval，创建全部同 IP 的目标端口地址，调用 `ListenUDPFunc()` 打开一个本地 socket。
2. 初始 `addrIndex` 随机选择，并非固定第一个端口；同时启动当前 socket 的 `recvLoop` 与定时 `hopLoop`。
3. 全零 interval 会被规范化为 30 秒；不能把零 interval 当成“关闭定时器”。最短 interval 为 5 秒。
4. `hop()`（172）持有 `connMutex` 写锁，先创建新 socket；失败时保留原路径，但不向调用者返回错误。
5. 创建成功后关闭更早的 `prevConn`，把 `currentConn` 移为 `prevConn`，安装新 socket，恢复 buffer/deadline，启动新接收循环，再随机选择目标端口。随机结果可以和前一次相同。
6. 两个 socket 的接收循环投递到同一个、容量为 1024 的 `recvQueue`；排队满时丢弃普通数据报。
7. `Close()`（256）在同一写锁下关闭前后两个 socket、关闭 `closeChan`，重复关闭返回 nil。`ReadFrom()` 和定时循环可由 `closeChan` 解除等待。

定时 hopping 的旧 socket 一般保留到下一次 hop 或整体 Close。一次性切换没有“下一次 hop”，必须明确旧 socket 保留策略；不能直接假设它会自动回收。

另一个已有生命周期风险：`recvLoop()` 的 timeout 分支（134）直接阻塞写入 `recvQueue`，没有监听 `closeChan`。如果队列已满且上层停止读取，关闭 socket 也不能解除这个 channel send。手动模式的生命周期重构需覆盖该情况；本阶段只记录源码风险，尚未注入复现或修复。

### 为什么底层切换不直接销毁 QUIC 会话

- `WriteTo()`（245）忽略 QUIC 传入的真实目标地址，始终写入 `currentConn` 和 `Addrs[addrIndex]`。
- `ReadFrom()`（227）忽略实际报文源地址，统一返回构造时的逻辑 `Addr`，使上层持续看到同一个 peer。
- QUIC transport 一直读取同一个包装对象，不会因为内部 socket 变化重新调用 Dial；TCP Stream、UDP session manager 与 TLS 状态仍属于原 `quic.Conn`。
- 服务端按 QUIC destination Connection ID 找到现有连接；接收新源地址的数据后，其 fork 会更新回包地址。

这是“不主动重建 QUIC”的机制说明。数据端口不通、转发到不同进程、丢包或旧包乱序仍可能导致连接中断，必须用集成测试证明实际连续性。

### obfs 包装顺序

构造顺序是先创建 UDP/hop，再调用 `wrapObfs()`。发送方向：

```text
QUIC → 可选 Salamander/Gecko obfs → UDP hop → 本地 UDP socket
```

接收方向相反。`extras/obfs/conn.go:56` 产生的包装只代理现有 `PacketConn` 和部分 UDP 方法，不会自动暴露新增的手动切换方法。因此不能只对 core 收到的最外层 `pktConn` 做 `PostAuthSwitcher` 类型断言，否则 obfs 开启时会失效。

包装没有实现 quic-go 的完整 `OOBCapablePacketConn`（缺少 `ReadMsgUDP/WriteMsgUDP`）；依赖的 `sys_conn.go:56–98` 会走 `basicConn` 收发路径，不会绕过包装直接用 OOB/GSO 发送。保留这项性质，并验证新 socket 的 buffer、deadline、平台 socket 选项和 DF/PMTU 行为。

## 5. QUIC、CID、NAT rebinding 与路径验证

以下证据来自固定的 [apernet/quic-go a10df75c260c](https://github.com/apernet/quic-go/tree/a10df75c260c)：

| 问题 | 源码证据与结论 |
| --- | --- |
| `DisablePathManager` 的作用 | `interface.go:195–197` 明确说明是为 HY2 hopping 直接更换 remote addr；`connection.go:1291–1294` 实施该逻辑 |
| 新地址是否需先通过 TLS 解密 | `connection.go:1190–1294` 先解密 short-header 包、过滤重复包并处理 frame，之后才进入服务端地址变化分支；任意伪造 UDP 包不会因此直接改变服务端路径 |
| 是否执行标准 PATH 验证 | 上述分支直接 `ChangeRemoteAddr` 后返回，跳过 path manager 的 `PATH_CHALLENGE/PATH_RESPONSE` 与正常迁移处理 |
| 客户端地址视角 | `connection.go:1284–1286` 对客户端直接返回；此外 hop 包装会隐藏实际 peer 地址变化 |
| 连接如何按 CID 找到 | `transport.go:586–615` 解析 destination CID，通过 packet handler map 分派已有连接，不依赖客户端源端口保持不变 |
| 默认客户端 CID | `core/client/client.go:106–112` 默认启用 ChromeParrot，使用 `ZeroLengthConnectionIDGenerator`；这是客户端发出的源 CID，即服务端回包的 destination CID，不能与客户端发往服务端的 destination CID 混为一谈 |
| 服务端 CID | `core/server/server.go:67` 未设置自定义 CID generator；服务端 transport 的通常默认 CID 长度由 fork 决定（`transport.go:433–436`） |
| 标准迁移 API | fork 有 `Conn.AddPath()`、`Path.Probe()`、`Path.Switch()`；`AddPath()` 检查 peer 的迁移限制。它不是已有 hopping 所用机制，也不能仅因 API 存在就认为能直接接入本方案 |

固定 IP 双端口方案实际上同时改变客户端本地 UDP socket/源端口和服务端目标端口。两个外部端口必须最终到达同一个服务端 QUIC transport / CID 路由实例；运行两个独立 HY2 进程不满足条件。

重要边界：

- 当前服务端绕过路径管理分支没有正常分支的“仅最高编号非探测包才切换路径”判断。尚未处理过的延迟旧路径包可能让回包地址暂时切回旧源端口。保留旧 socket 可接住部分回包，但不能据此承诺无损。
- 默认客户端零长度 CID 在这个“单一逻辑 transport 内换 socket”的模型中有源码依据；它不等价于标准迁移 API、跨 IP 中继或其他 QUIC 实现的兼容性保证。必须覆盖 ChromeParrot 默认/关闭两种配置。
- NAT/REDIRECT 反向映射可能让新 socket 的回包来自 8443，也可能由测试转发器表现为其他源端口；不能只靠返回端口判断是否完成迁移。
- `quic.Conn.LocalAddr()` 在依赖 `send_conn.go:40–64` 中缓存了创建时地址，`HandshakeInfo.ServerAddr` 也是逻辑握手地址；它们不适合作为物理路径迁移证据。
- 当前模式不能报告“QUIC PATH 验证成功”，也不能自动继承标准迁移中的拥塞控制/PMTU 重置语义。

## 6. 第二阶段的最小修改设计

### 配置与边界

沿用提案的 `transport.udp.handshakeMigration`，当前版本尚不识别该功能。建议 `enabled` 默认 false；只有启用时才执行 HDM 校验和构造。

- `server` 表示握手目标；单次连接内 DNS 只解析一次，复制同一个 IP/IPv6 zone 并替换为 `dataPort`。允许域名固定解析到该次连接的一个 IP，不允许为数据端口再次独立解析或接受其他 data IP。
- 需要保证严格静态 IP 时使用 IP 字面量配合 `tls.sni`。正常重连重新调用配置工厂时，域名可能解析到不同 IP，不能宣称跨连接固定。
- 校验握手端口和 `dataPort` 均在 1–65535，且不同；拒绝握手端口并集/范围。
- 与 `hopInterval`、`minHopInterval`、`maxHopInterval` 全部互斥；手动模式完全不启动 `hopLoop`。
- `trigger` 缺省或 `auth_success` 才有效；其他值直接配置错误。
- HDM 第一版拒绝 realm 及 mimic 组合；realm 绕过常规工厂，mimic 当前按单个目标 ip:port 设置匹配，不能让配置看似生效却仅部分处理。
- 分享 URI 暂不扩展协议；需要说明 HDM 参数不会随现有 URI 导出，保留原 URI 行为。

### transport 复用

保留 `NewUDPHopPacketConn` 及定时 hopping 行为。增加独立手动构造入口，强制初始握手目标，不走随机初始端口；复用现有字段、收发循环和队列。

从 `hop()` 提取持锁的 socket 安装原语，接收明确目标并返回错误。定时调用者保持原来的失败跳过和随机目标策略；手动调用者只尝试一次，记录结果，并让重复调用返回同一结果，不再创建 socket。`Close()`、切换和可选恢复共享互斥保护。

保留完整原 socket 和原目标端口，创建失败不得覆盖它们。成功后最多保留两个 socket；明确旧 socket 是保留至 Close，还是在有依据的过渡窗口后回收。回退只允许一次，不产生新的定时重试。

接收数据结构需携带 socket 的 generation/路径标记，才有办法区分旧 socket 回包与新 socket 回包。当前 `udpPacket.Addr` 在上抛时会被丢弃，单纯观察 `ReadFrom()` 不能区分。

### 认证触发与模块边界

优先给 `core/client.Config` 增加可空的窄回调，例如 `OnAuthenticated func(context.Context) error`。准确签名在最小实现时确定，但不得让 core import extras。

CLI 在每次配置生成时建立独立的 holder/闭包；`singleUseConnFactory.Open` 构造手动 transport 时把切换能力写入 holder，再调用现有 `wrapObfs()`。回调引用内层手动对象，避免扩散修改所有 obfs 包装。holder 的可见性与调用同步必须明确，不使用全局状态。

在 `core/client/client.go` 检查 233、解析响应、设置拥塞控制并关闭 body 之后，保存/返回 client 之前调用钩子。回调报错且无法回退时，沿现有错误分支关闭 conn、transport、packet conn；回调成功仅表示完成相应本地操作，不表示远端可达。

`reconnect.go` 通常无需更改：CLI 每次重连通过 `config.Config()` 获得新工厂与新 holder，所以每个新 QUIC 连接都从握手端口开始。不要复用上一个连接的“一次性已切换”状态。core 直接调用者若复用 CLI 的单次工厂，原有 API 就会报 already used，这不应伪装成 HDM 重试。

### 路径状态与 fallback 的真实能力

建议记录以下相互独立的事实，而不是把一个布尔值称作迁移成功：

| 事件/状态 | 能说明什么 | 不能说明什么 |
| --- | --- | --- |
| `AUTHENTICATED` | 收到并确认 233 | 数据端口可达 |
| `SWITCHING` | 已安装新 socket/目标 | 已发出数据报 |
| `DATA_SENT` | 新 socket 的 `WriteTo` 成功 | 对端收到、回复或路径验证 |
| `RESPONSE_SEEN` | 新 socket 收到目标相关数据报 | 数据报通过 QUIC AEAD；标准 PATH 验证完成 |
| 应用数据验证通过 | 原 Stream/UDP Session 在新路径继续收发 | 所有网络与异常条件都可靠 |
| `FALLBACK_SELECTED` | 本地恢复原 socket/端口 | 原路径已恢复可用 |
| 回退后数据验证通过 | 原会话在原路径恢复业务 | 服务端重启后能保存原会话 |
| `ERROR/CLOSED` | 失败或关闭，释放资源 | 应自动重新迁移 |

**远端黑洞自动回退是尚未解决的技术门槛。** 现有 hopping 没有可靠路径确认或主动探测 API；新 socket 创建失败可以立即保留原路径，`WriteTo` 失败也可有界处理，但 UDP 写成功无法判断端口不可达。仅收到一个原始 UDP 回包也不是经过认证的 QUIC 证明。

第二阶段可以先完成 `fallback: false` 的最小本地闭环；若尚未实现完整语义，必须拒绝 `fallback: true` 并明确说明限制，不能静默忽略或宣称黑洞回退已支持。若同时实现 true，必须先完成带期限的确认/恢复设计，验证闲置连接没有首包、伪造回包、旧路径迟到包、ICMP 错误和 Close 的行为。不能新增伪 HY2 Datagram、重复认证、额外 TLS 握手，或以无限重试代替确认。

普通客户端业务在 `NewClient()` 返回后才建立，因此“已有 TCP/UDP 会话跨切换”需要测试专门延后一次性 primitive 的调用，在同一个连接先打开业务后再切换；不能拿认证时切换后新建业务替代这项验证。

### 预计修改文件

| 文件 | 用途 |
| --- | --- |
| `extras/transport/udphop/conn.go` | 提取 socket 安装原语、手动构造与一次性切换、并发和资源管理 |
| `extras/transport/udphop/conn_test.go` | 原有 hopping 回归和手动生命周期、故障注入、Close 竞态 |
| `app/cmd/client.go` | 配置解析/校验、固定握手地址、工厂 holder、realm/mimic 组合检查 |
| `app/cmd/client_test.go` | HDM 配置、默认关闭、互斥、工厂与 obfs 接线测试 |
| `app/cmd/client_test.yaml` | 配合已有 `assertAllFieldsSet` 覆盖新增配置字段 |
| `core/client/config.go` | 可选认证后钩子；保留已有 ConnFactory 与 Client 接口 |
| `core/client/client.go` | 233 后调用钩子、失败清理 |
| core 新增认证钩子集成测试 | 233/拒绝认证/回调错误/未配置行为的真实 client-server 验证 |
| extras 新增 HDM 集成测试 | 可引用 core 与 udphop，连接真实服务端并模拟双端口/丢包/不可达，不给 core 测试引入 extras 依赖环 |
| `docs/hdm-design.md` 和后续使用/实验记录 | 实现边界、配置、抓包与基准数据 |

初步不需要修改 `extras/obfs/conn.go`、`core/server/server.go`、`core/client/reconnect.go` 或 quic-go 依赖。若 PoC 证明这些假设不成立，先记录证据再调整范围。

## 7. 已执行的第一阶段检查

以下均针对未修改的官方基线，不能证明 HDM 已实现。测试命令从仓库根目录执行，`-count=1` 避免测试缓存。

```powershell
go test ./extras/transport/udphop -count=1

go test ./core/client ./core/internal/integration_tests -run '^Test(UDPSessionManager|ClientServer(BadAuth|UDPDisabled|TCPEcho|UDPEcho|HandshakeInfo|ChromeParrot|ClientShutdown|ServerShutdown|TCPClose))$' -count=1 -timeout 3m -v

go test ./app/cmd -run '^Test(SingleUseConnFactory|ClientTransportUDPHopIntervalConfig|ClientConfig|ClientConfigUnmarshal)$' -count=1 -timeout 3m -v

go test -race ./extras/transport/udphop ./core/client -count=1 -timeout 3m

$auditBinary = Join-Path ([System.IO.Path]::GetTempPath()) 'hdm-audit-fb25dc8-hysteria.exe'
go build -o $auditBinary ./app
& $auditBinary version
```

| 检查 | 结果 | 范围 |
| --- | --- | --- |
| udphop 现有单元测试 | 通过 | 接收 timeout、hop 继承 deadline、interval 校验、随机 interval 范围；4 个顶层测试 |
| core client 与选定集成测试 | 通过 | 1 个 UDP session 单测、9 个真实 client-server 顶层测试；含 ChromeParrot 默认/关闭、认证失败、TCP/UDP Echo、HandshakeInfo、TCP Close、双方关闭 |
| CLI 选定配置测试 | 通过 | `TestClientConfig`、`TestSingleUseConnFactory`、`TestClientTransportUDPHopIntervalConfig`；3 个顶层测试 |
| race 检查 | 通过 | 现有 udphop 与 client 单测，不覆盖尚未实现的手动切换，也未覆盖队列满时的 timeout 关闭风险 |
| Windows CLI 构建与 version 启动 | 通过 | 普通 `go build` 未注入发布元数据，version 显示 Unknown 属预期；二进制仍不支持 HDM |
| HDM 双端口、抓包、100/1000 次与吞吐基准 | 未执行 | 功能尚未实现 |

早先一次 `-run 'Test(Smoke|Close|ChromeParrot)'` 匹配不到实际测试名称，输出为 `[no tests to run]`，不计作验证；随后已按实际名称执行上述用例。CLI 正则中的 `TestClientConfigUnmarshal` 也不存在，实际通过的是表内三个测试。

依赖下载/测试自动调整的 `go.work.sum` 在收尾恢复到基线，不作为本阶段变更；没有升级依赖。仓库现有 CI 在 Ubuntu 上运行全模块测试，本阶段的 Windows 定向基线检查不能代替该 CI。

本阶段实际新增文件只有 `docs/hdm-design.md`，用于固定审计证据、调用链、预计修改范围与验证门槛；没有修改 Go 源码或配置 fixture。上表实际执行的测试与构建均通过，没有测试失败；未执行项保持未验证。

## 8. 后续本地验证与证据要求

1. 单测先验证手动模式固定初始目标、无 hop timer、233 后仅一次调用、未认证不切换、重复调用不分配、打开 socket 失败、关闭后调用、并发 Close，以及上限两个 socket 的完整释放。
2. Go 集成测试使用两个独立 UDP 目标入口和同一个 HY2 服务端实例；测试用转发器只是本地确定性工具，不能当作第四阶段中继 PoC。测试监听动态端口，避免照搬现有 `serverConn()` 固定 14514 导致并行冲突。
3. 确认 core 连接构造/Dial 只发生一次、服务端只接受一个 QUIC 连接；既统计实际 auth HTTP 请求数，也统计 `Authenticator` 调用。服务端对重复 auth 请求可直接重发 233，单独统计 authenticator 一次不足以排除重复认证。
4. 在应用层校验完整内容和 session 标识：HTTP/HTTPS、单连接上传/下载、多路 TCP、HY2 UDP、已经建立的流/会话跨切换。注入短暂丢包、数据端口黑洞、服务端重启、客户端主动关闭、切换/关闭竞态。
5. 服务端重启会丢失 TLS/QUIC 会话，应验证失败有界释放，以及下一次新建连接重新从握手端口开始；不能要求重启后保留原 session。
6. Linux 上用独立测试环境验证 UDP 443 和 8443 通过 REDIRECT/DNAT 进入同一监听实例；抓取客户端外部接口和服务端入口，两端覆盖同一次连接。第一阶段没有配置主机防火墙、启动 WSL 或操作远程 VPS。
7. 保存原始 pcap、使用的网络规则和配置、源码 SHA、测试工具版本及逐次结果。无 obfs 模式先验证 data port 没有新的 Initial；若旧 Initial 重传到 data port，应单独辨别其属于旧连接重传还是新 Dial，不能把两者合并统计。obfs 模式需结合内部计数/解混淆证据，单凭外部抓包无法直接解析 QUIC 包型。
8. `go test -race`、适当的 `goleak` 和 socket 关闭计数共同检查生命周期；已有 race 通过不能证明未来手动模式没有竞态。
9. 100 次迁移完成基本功能验收，再建立 A/B/C 对照并扩展到 1000 次。记录连接/迁移/业务成功率、P50/P95/P99、上传/下载、CPU/内存/丢包/重传和失败恢复时间。D 组需等待独立跨 IP PoC；99.5% 和吞吐损失 5% 是目标，不填成实测结果。

## 9. 本阶段方案调整与未验证假设

相对初始提案的必要细化：

- 增补当前源码已有的 `minHopInterval/maxHopInterval` 互斥校验。
- 增补默认 ChromeParrot 零长度客户端 CID、Gecko obfs、realm 和 mimic 的兼容性边界。
- 选择每连接可选回调加内层 transport holder，规避 obfs 隐藏接口问题；没有要求 core 直接依赖 extras。
- 不预设现有 fork 会做标准路径验证；远端黑洞回退与可靠确认作为第二阶段明确门槛，最小成功路径可先使用 `fallback: false`。

仍需验证：同 IP 双端口/NAT 下完整会话连续性、切换时握手确认与迟到包的影响、数据端口不可达的有界恢复、一次性模式的旧 socket 回收、不同平台的 socket/PMTU 行为、obfs 后真实双端口收发，以及目标 Linux 环境是否具备所需监听和抓包条件。

跨 IP 握手中继、远程实测、抗检测效果与性能目标均无本阶段实验结论。后续 PR 创建及合并须另获用户授权；本阶段仅形成可审阅的本地审计提交。
