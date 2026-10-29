# Worker KEX：外部密钥 QUIC 回环 PoC

日期：2026-10-28。对应 P1 与 B2 的本地数据面验证。
设计依据：[设计](worker-kex-design.md)；Noise 编码与导出规则见[基础实现](worker-kex-implementation.md)。

## 已实现的链路

回环 HTTPS POST `/k` → 真实 Noise IK → 双方各自取得方向密钥及认证绑定的 QUIC 参数 →
独立 QUIC Transport 导入 → UDP 短包头可靠流与双向 DATAGRAM。
测试随后关闭 HTTPS 服务，数据面仍可传输。没有发送原 HY2 认证 POST，也没有构造假 233。
这只是 QUIC 数据面实验，还未初始化 HY2 代理业务。

**这个入口仅接受回环地址，不能用于公网部署。**
未实现公网 pending CID 分派、双向路径挑战、按路径反放大、READY、活动权限复核或 Throne 出站。
回环测试预先知道对端 socket 地址，以已知本地路径预算建立连接，不能据此声称通过地址验证。
正常构建没有引用该 fork，也不会调用带 `kex_poc` 标签的测试。

## B2 本地状态映射

| 项目 | 本地实验的处理 | 边界 |
| --- | --- | --- |
| 加密层 | 仅安装 QUIC v1 ChaCha20Poly1305 的 1-RTT read/write secret | Initial、Handshake、0-RTT 密钥均不可用；收到 CRYPTO 拒绝 |
| TLS | 不运行 TLS，不填造协商结果 | `ConnectionState().TLS.HandshakeComplete` 始终为 false |
| 参数 | 在 Noise 载荷中绑定真实 wire.TransportParameters | 验证 CID、版本及支持范围；拒绝未实现的 preferred address、初始 reset token 等 |
| 握手完成 | 导入参数/密钥后关闭内部 handshakeCompleteChan | 只表示本地安装完成，不表示业务可用 |
| 包号空间 | 丢弃 Initial/Handshake 包号空间，从新的应用空间开始 | 每个全新 Transport 只允许导入一次，避免密钥/包号复用 |
| 丢包恢复 | 复用 sentPacketHandler、流控与 PTO | ackhandler 内部的 confirmed 用于应用空间 PTO；不等于外部协议确认 |
| 协议确认 | 只有显式 ConfirmExternalLoopback 才确认 crypto 状态 | 普通 ACK 不提前确认；该调用仅是测试钩子，不能当作公网 READY |
| 密钥更新 | 复用 updatableAEAD 和 quic ku | 显式确认前禁止新 key phase；已验证更新丢包、旧包乱序和连续两轮更新 |
| CID | 固定 16 字节初始 CID，复用已有 CID 管理与轮换逻辑 | 没有对初始 stateless reset token 的支持，尚未验证公网轮换 |
| 来源地址 | 固定回环对端，丢弃其它来源及所有长包头 | 仅验证不会被重放包切换路径；尚无候选路径验证与迁移 |
| 生命周期 | 父 context 取消触发关闭，使用原有 idle timeout 与关闭流程 | Close 后 AEAD 仍可生成 CONNECTION_CLOSE，避免上游关闭顺序产生空指针 |

ExternalLoopbackParameters 按本次 CID 生成参数。KEX 的 ParameterBuilder 是有界纯函数，
客户端此时还不知道服务端 CID，peer 传零；服务端生成自己 CID 后同时知道两端 CID。
固定参数与 builder 只能选择一种。builder 错误不会预留 pending 状态。

## 可复现的实验依赖

固定 `github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c`，
模块校验和 `h1:cxK8qTA0YCsj68A7zLYDCfPgMTOyt3ePkHh+oXEmYU0=`。
补丁在 `scripts/hdm/quic-kex.patch`；manifest 记录变更前后文件 SHA-256。
脚本只在本仓库 build 子目录复制并应用补丁，使用独立 go.work，不修改全局模块缓存或正常构建的依赖。
已存在的目录只有在 marker、文件哈希和 workspace 一致时才能复用；未知文件不覆盖。
Windows 应用补丁明确关闭 git autocrlf；补丁自身固定 LF。
上游 Windows 两个测试仍用旧 newConn 签名，补丁只补齐其第三个参数，未改变生产 socket 实现。

在仓库根目录执行：

```powershell
python scripts/hdm/prepare-kex-quic.py
$env:GOWORK = (Resolve-Path build/kex-poc/go.work).Path
go -C core test -race -tags kex_poc ./internal/kex -count=5 -timeout=120s
go -C build/kex-poc/quic-go test -race . ./internal/handshake -run '^TestExternal' -count=5 -timeout=120s
go -C build/kex-poc/quic-go test . ./internal/handshake -short -count=1 -timeout=120s
go -C core test ./client ./server ./internal/protocol -count=1 -timeout=60s
go -C core vet -tags kex_poc ./internal/kex
```

正常依赖的 KEX 检查：

```powershell
$env:GOWORK = 'off'
go -C core test -race ./internal/kex -count=3 -timeout=60s
go -C core vet ./internal/kex
```

## 验证结果与保留问题

上述 race、vet、回环 KEX→QUIC、fork 根包/handshake 短测及现有 client/server/protocol 单测通过。
同一补丁已在新的隔离目录重建并运行回环测试；准备脚本重复执行只校验并复用。
测试直接记录发送包，断言短包头与固定 bit；包括超过初始窗口的流数据、双向 DATAGRAM、每五包丢一包、
参数错配、重复导入、父 context 取消、idle 回收与其它来源重放。
测试不读取现有节点密钥，不连接 VPS，不替换 Throne 或运行中的客户端。

原有 UDPStress 四组收零回包的问题在未改动的 27b9909 上也复现，仍未定位；
本阶段未重新运行那组测试，也未把它与早前公网 DNS 间歇超时归为同因。
此处通过的范围不包括公网接入、HY2 业务、TUN 路由或长期使用。

## 后续接入

先实现有限期 pending 的独占移交与激活时权限复核，再实现经过认证的 UDP 来源选择、
每路径预算、挑战响应及可靠 READY。验证通过后才接 HY2 业务状态与 Worker 短 TLS 入口。
Throne 原生出站还需统一相关依赖、接入核心拨号/取消路径并完成 TUN 验收。
