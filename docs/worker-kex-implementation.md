# Worker KEX：第一阶段实现记录

> 提交标识说明：本页项目提交 SHA 已映射为身份改写后的等价文件树提交；原构建时的 SHA 记录仅保留在本机。

日期：2026-10-28。本文记录 0.6.0 的本地实验握手与待接入状态。
后续的隔离 QUIC 回环实现及 B2 状态映射见 [外部密钥 PoC](worker-kex-quic-poc.md)，
接入租约与授权状态见 [接入组件](worker-kex-admission.md)。正常构建仍未接入新数据面。
设计依据：`worker-kex-design.md`。新增代码位于 `core/internal/kex`。

## 本轮交付与边界

已实现真实 Noise IK 双向握手、设备公钥登记与撤销、严格的二进制载荷、方向密钥派生、
请求去重、有限期 pending、并发与容量限制，以及可注入拨号器的单次 HTTPS 交换。
本地 TLS 集成测试使用临时生成的密钥、回环地址与测试证书，不读取现有节点凭据。

**返回 Result 仅表示带外握手成功，不表示 UDP 可达或 HY2 已连接。**
0.6.0 阶段 Broker 没有 ACTIVE 转换接口；后续增加了接入租约和活动授权管理，
目前仅在隔离回环实验中导入 quic-go 密钥，尚无公网业务接入。
现有 HY2 客户端、服务器与 Throne 运行路径都没有调用本包。

尚未实现：Worker 转发脚本、VPS 原始 TCP/TLS 长度帧入口、UDP 密钥确认/路径验证/READY、
QUIC 传输参数语义校验、reset token、HTTP/3 业务接入、Throne 原生出站与设备管理 UI。
没有生成可供日常使用的新客户端，没有部署或替换任何运行服务。

## 文件职责

| 文件 | 用途 |
| --- | --- |
| `types.go` | 配置、权限、密钥与待接入结果 |
| `wire.go` | 固定版本、规范二进制载荷和长度检查 |
| `handshake.go` | IK 初始化、一次性响应消费、会话绑定与派生 |
| `server.go` | 设备登记、原子去重、pending 配额和回收 |
| `http.go` | 单次 HTTPS 客户端与不自行监听的联调处理器 |
| `*_test.go` | 身份、请求绑定、容量、生命周期、TLS 与模糊测试 |
| `testdata/noise-ik.json` | flynn/noise v1.1.0 发布的 IK 测试向量 |
| `testdata/LICENSE.flynn-noise` | 测试向量的上游许可证 |

## B1：实验性的编码与密钥导出规则

固定依赖 `github.com/flynn/noise v1.1.0`，不修改该库，不自行实现 Noise DH/AEAD。
此规则是本项目的实验性组合，不是 Noise 标准 exporter 或 TLS 握手；测试通过不等于独立密码学审计通过。

### 外层与 prologue

整个消息上限 16384 字节。前四字节为 ASCII `HKX1`，第五字节为消息类型：请求 1、响应 2。
后续为对应的 Noise 消息。版本未知、类型错位或超过上限直接拒绝。
套件固定为 `Noise_IK_25519_ChaChaPoly_SHA256`，没有算法协商或自动降级。

Noise prologue 的字节内容为：

```text
ASCII("HY2-KEX\0HKX1\0Noise_IK_25519_ChaChaPoly_SHA256\0")
|| uint16_be(len(service_id)) || UTF8(service_id)
```

其中 `\0` 表示一个零字节，不是反斜杠与数字 0 两个字节。
service_id 为 1～128 字节合法 UTF-8，不包含空白/ASCII 控制字符；两端必须完全相同。
服务器静态公钥由 IK 的预消息绑定，客户端静态公钥在消息 1 中传递并验证后用于设备查询。

### 加密载荷

固定字段直接拼接；变长字段使用两字节大端长度。整数为大端，布尔值只接受 0 或 1。
不允许尾随字节、重复字段或非规范地址表示；地址必须是无 zone 的具体 IP:port，端口非零。
私网/回环地址允许本地实验，部署配置仍需显式指定目标。

请求字段顺序：

1. request_id（16 字节随机非零值）。
2. created_at（8 字节正 Unix 秒数）。
3. client_cid（16 字节随机非零值）。
4. udp_address（长度 + 规范文本，最多 128 字节）。
5. max_rx（8 字节）。
6. client_transport_parameters（长度 + 原始字节，1～4096 字节）。

响应字段顺序：

1. request_id（16 字节）。
2. request_hash（32 字节，对整个带外请求含外层头做 SHA-256）。
3. session_id（16 字节随机非零值）。
4. server_cid（16 字节随机非零值，不等于 client_cid）。
5. pending_lifetime_ms（8 字节，1～10000）。
6. udp_address（长度 + 规范文本）。
7. principal（长度 + 1～128 字节文本）。
8. udp_enabled、rx_auto（各 1 字节）。
9. rx（8 字节，rx_auto 为真时必须为 0）。
10. server_transport_parameters（长度 + 1～4096 字节）。

本阶段传输参数只做长度/完整性绑定，不能将任意字节串描述为合法 QUIC 参数。
参数语义、策略版本与 reset token 等尚未接入的字段加入时，需要明确更新实验版本；不能静默修改 HKX1。

### 导出构造

完成第二条 Noise 消息后，取得 `ChannelBinding()` 的最终 32 字节握手摘要 H。
按 Noise Split 顺序，K1 是 initiator → responder 的 32 字节秘密，K2 是反方向秘密。
两端按相同顺序取得原始 Split key。它们从不直接作为 QUIC 包密钥，不再用于 Noise transport 加密或 REKEY。

```text
C = HKDF-SHA256(
    IKM  = K1,
    salt = H,
    info = ASCII("HY2-KEX/HKX1/QUICv1/client/traffic-secret"),
    L    = 32)
S = HKDF-SHA256(
    IKM  = K2,
    salt = H,
    info = ASCII("HY2-KEX/HKX1/QUICv1/server/traffic-secret"),
    L    = 32)
```

H 用作上下文绑定而非秘密来源。HKDF 包含 Extract 和 Expand；不会把公开摘要直接当密钥。
派生结果只作为后续 QUIC v1 适配的候选 traffic secret；本阶段没有实现 `quic key/iv/hp/ku` 使用路径。
相应的密码套件常量、key update 和握手确认仍需 B2 验证，不能仅凭输出长度相同就认定已兼容。

代码通过 `UnsafeKey()` 获取 Split key，限制在单个导出函数内使用；没有使用 `UnsafeNewCipherState()` 恢复状态。
对自己持有的私钥/临时密钥切片及过期 traffic secret 做尽力清零。Noise 内部状态与 Go 堆副本不能保证被主动擦除。
后续独立审计仍应检查导出组合、长期密钥泄露边界及库选择；本轮只完成工程实现和测试向量验证。

### 独立 HKDF 向量

`TestExporterVector` 的预期值由 Python 标准库 `hmac`/`hashlib` 计算，不调用 Go 实现。
IK 的公开上游向量另外验证实际库的套件与 Split 方向，避免仅靠双端一致性掩盖同一种错误。
固定向量输入为 K = `00 01 ... 1f`、H = 32 个 `a5` 字节；两个标签分别测试。

## 会话与重放规则

- 客户端的 Finish 无论成功还是失败都消费握手对象；同一对象无法再接受响应。
- 服务端在加密操作前限制并发；设备验证、额度检查、响应构造与记录提交在同一互斥区中完成。
- 同设备与 request_id 下，只允许完全相同的请求摘要命中缓存。重复请求返回原响应，不延长 pending 或去重记录寿命。
- pending 默认全局 128、每设备 2；去重记录默认 4096；加密请求并发默认 8。设备登记最多 1024 项。
- pending 有效期 10 秒。服务端每秒清理过期状态，收到请求时也清理；实际内存回收可能晚至下一个清理周期。
- 请求时间最多落后 60 秒、超前 30 秒；去重记录保留 150 秒。满容量时拒绝新请求，不提前驱逐有效去重记录。
- 丢弃、过期或撤销会清除 pending 秘密与响应缓存，但保留去重记录，旧请求不能立即重新分配状态。
- 撤销设备后不允许覆盖登记恢复启用；首版应换新设备密钥。活动会话撤销尚无实现，因为尚未创建活动会话。
- Close 幂等，清理 pending、CID 索引、设备和去重记录，并等待回收协程退出。
- 不持久化 pending、密钥或包号。重启后重新处理旧请求必须生成新秘密与新随机标识；不能恢复旧连接。

客户端从服务器声明的 lifetime 中减去本地握手总耗时，保守计算剩余等待时间，不依赖服务器墙上时钟。
未来 UDP 适配必须再次检查服务器真实截止时间；Result 的存在不能授权过期会话接入。

## HTTPS 行为与部署前提

Exchange 只允许 `https://.../k`，禁止凭据型 URL、查询串、fragment、自动重定向和关闭证书校验。
使用专用 HTTP/1.1 transport、正常 TLS 验证、不读取环境代理，支持核心传入 DialContext。
一次调用仅发一次 POST；禁用连接复用与可重放 GetBody，不循环重试、不开替代连接路径。
超时默认 8 秒；context 取消立即结束。完整读取有界响应后关闭响应体与专用 transport。
DNS、TLS、连接/响应、HTTP 状态错误按类别返回，不携带访问令牌或上游错误正文。

HTTP 处理器要求 Bearer 令牌，使用固定长度摘要比较，限制方法、路径、媒体类型与请求长度。
响应标记 no-store。它只供回环 TLS 测试或后续受保护入口使用，不会自行监听公网。
如果实际挂到服务器，外层还必须设置 TLS、连接数量、读头/读体/写回时限；本包不替代那些限制。
现在的 HTTP 令牌在本地直连测试中模拟入口凭据，未来 Worker 入口令牌与 VPS 上游凭据必须分开。

## 验证与复现

在 `core` 目录执行，使用 `GOWORK=off` 避免改动已有工作区校验和文件：

```powershell
$env:GOWORK = 'off'
go test -race ./internal/kex -count=5 -timeout=120s
go vet ./internal/kex
go test ./internal/kex -run=^$ -fuzz=FuzzWireDecoders -fuzztime=15s -parallel=4 -timeout=60s
go test ./client ./server ./internal/protocol ./internal/integration_tests -short -count=1 -timeout=120s
```

测试覆盖未知/撤销设备、错误服务器密钥、service_id/UDP 目标错配、时间窗、响应篡改、
已认证但字段错误的响应、并发重放、请求 ID 冲突、配额耗尽、去重记录过期、并发关闭和取消。
真实回环 TLS 测试核对证书、禁止重定向、请求次数、socket 回收、错误响应、超长响应及取消。
`goleak` 检查包测试结束后的协程泄漏；模糊测试检查畸形输入和规范编码一致性。
这些结果仅适用于握手包，不代表 UDP 数据面、Throne 或公网验证完成。

## 本轮实测结果

- `go test -race ./internal/kex -count=5 -timeout=120s`：通过，包含公开 IK 向量、HTTPS 联调、自动回收和泄漏检查。
- `go vet ./internal/kex`：通过。
- 15 秒、4 worker 的解析器模糊测试：完成 1,473,300 次执行，无失败。
- 现有 `client`、`server`、`internal/protocol` 单测：通过。
- `internal/integration_tests` 回归：未全部通过，`TestClientServerUDPStress` 的四组场景均收到 0 个 UDP 回包。
- 使用 `git archive` 导出未改动的 `6105c17` 提交，在独立临时目录、`GOWORK=off` 下运行同一 UDP 压测，复现相同的四组失败。
  该失败在本轮实现前的代码上也存在，根因尚未确定，不把它归因于环境，也不把本次回归写成全部通过。
- 不用这组压力测试替代用户此前公网 DNS 间歇超时的诊断，两者是否相关仍未知。

## 后续进度

独立本地注入 PoC 已完成，详见 [外部密钥 PoC](worker-kex-quic-poc.md)。以下公网/业务步骤仍待实现。


1. 已完成：quic-go 外部握手回环构造、B2 本地状态映射与注入 PoC。
2. 接入短包头控制、双向确认、按路径反放大与 READY，验证 key update、CID 轮换和失败回收。
3. 已增加 pending 独占租约、两步激活与权限复核组件；仍需逐包公网适配和 HY2 初始化接入。
4. 最后接入同进程 VPS 入口、Worker 与 ThroneCore；每一阶段独立提交和验收。


## 0.8.0：真实路径与业务实验

新增 `core/kexpoc` 统一管理 Noise 接入、外部 QUIC、路径与 READY 确认、原生 HY2 TCP/UDP 业务。`app/cmd/kex-poc` 提供独立 server/client/probe 与显式 TUN 模式。`extras/worker-kex` 使用短 TLS 帧连接同进程源站入口，不需要 WSS/Bridge/Tunnel。所有接入/生命周期改动仍隔离在 `kex_poc` 构建与固定补丁工作区。

详见 [真实网络验收](worker-kex-network-acceptance.md)、[HY2 适配](worker-kex-hy2-adapter.md)、[Worker relay](worker-kex-relay.md)、[测试 CLI](worker-kex-test-cli.md)。构建脚本按补丁哈希选择新目录，保留原实验工作区，无需先清理旧补丁。
