# Cloudflare 握手中继实验

新增 `transport.type: worker`：客户端通过验证公网证书的 WSS 连接 Worker，二进制消息逐个承载 QUIC 数据报。Worker 通过固定 Tunnel 的 VPC Network 连接 VPS 回环 `127.0.0.1:18080`，复用长度帧 TCP/UDP Bridge。

认证仍由最终 HY2 服务端完成；客户端收到 HTTP 233 后调用已有 `SwitchAfterAuth`，同一 QUIC/TLS 会话切换到配置 `server` 的直连 UDP。Worker 无法解密内部流量，也无法识别 233。切换日志只确认本地换路，业务收发测试才确认数据路径。

## 客户端配置

```yaml
server: 192.0.2.20:8443
auth: REPLACE_WITH_EXPERIMENTAL_HY2_PASSWORD
tls:
  sni: hdm.test
  ca: server.crt
transport:
  type: worker
  worker:
    url: wss://hdm-handshake.YOUR_SUBDOMAIN.workers.dev/hdm/connect
    token: REPLACE_WITH_SEPARATE_RANDOM_WORKER_TOKEN
    connectTimeout: 8s
    handshakeTimeout: 10s
socks5:
  listen: 127.0.0.1:11808
http:
  listen: 127.0.0.1:11809
```

Worker 接入令牌至少32字符，与 Cloudflare 管理 API Token、HY2 密码相互独立。公网只允许 WSS，明文 WS 只允许字面量回环地址以便测试。拒绝 URL 账号、查询参数、片段及其他路径。不支持端口跳跃、原 UDP 握手迁移或 mimic 组合。

## Worker 与 Bridge 限制

Worker 固定后端，不接受目标参数；每包1–2048字节，双向累计最多1MiB，写队列最多64KiB，生命周期15秒，空闲5秒。WebSocket 出站由平台缓冲，累计流量限额也约束每会话缓冲上界。Bridge 在单实例内严格限制64并发，Worker 全局内存不承担跨实例限流。Worker 不提供业务回退通道。

源码 `workers/hdm/index.mjs`；部署参考 `wrangler.example.jsonc`，Tunnel UUID 由私有部署状态提供。接入令牌使用 Secret 绑定 `HDM_TOKEN`，VPC Network 绑定 `HDM_VPC`。Bridge 仅监听回环，公网无需开放 TCP Bridge 端口。

Cloudflare Workers VPC 当前 Beta 免费，仍受 Workers Free 配额限制；部署不得升级付费。依据官方 VPC Networks 文档及 workers-sdk 上传绑定实现（2026-10-27核查）。

## 验证

- `node --test workers/hdm/index.test.mjs` 验证帧拆分/合并、消息类型、流量/排队/超时限制、鉴权及清理。
- `go test ./extras/transport/workerhdm ./app/cmd -run 'TestWS|TestWorkerHDM'` 验证真实 HY2 WSS 迁移、三种混淆、单次 TLS/认证及断桥后 TCP/UDP。
- `go test -race ...` 检查并发路径。
- 公网部署与结果另在本文件记录，完成前不将本地测试视为公网验收。

## 断连行为

WSS/Tunnel/Bridge 在认证前断开，当前连接失败；认证后业务依赖直连 UDP。直连 UDP 黑洞不会自动回到 Worker，由 QUIC 超时结束。新的连接需要重新完成 WSS 握手。已有 Throne 未移植这一模式，先用独立 CLI 验证。
