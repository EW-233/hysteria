# Cloudflare 握手中继实验

新增 `transport.type: worker`：客户端通过验证公网证书的 WSS 连接 Worker，二进制消息逐个承载 QUIC 数据报。Worker 通过固定 Tunnel 的 VPC Network 连接 VPS 回环 `127.0.0.1:18080`，复用长度帧 TCP/UDP Bridge。

认证仍由最终 HY2 服务端完成；客户端收到 HTTP 233 后调用已有 `SwitchAfterAuth`，同一 QUIC/TLS 会话切换到配置 `server` 的直连 UDP。Worker 无法解密内部流量，也无法识别 233。切换日志只确认本地换路，业务收发测试才确认数据路径。

## 客户端配置

```yaml
server: 186.241.106.13:8443
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


## 2026-10-27 公网部署与验收（UTC−7）

服务器管理全部通过 `43.252.41.230` 的 SSH 会话内 nc 中继连接 `186.241.106.13:45222`，私钥保持在本机。

- `hdm-cloudflared.service`：cloudflared 2026.10.5，官方资产 SHA256 校验通过；HTTP/2连接，4条健康Tunnel连接。
- `hdm-bridge.service`：仅监听 `127.0.0.1:18080`，固定转发到实验HY2 `127.0.0.1:443`。
- `hysteria-hdm.service`：更新独立实验实例，直连数据目标为 `186.241.106.13:8443`，沿用原8443→443重定向。
- 原普通HY2 `sb-us.service`（26061/UDP）持续运行；未修改中继服务器上的mieru。
- Worker `hdm-handshake.wlai28353.workers.dev`：health=200，未鉴权连接=401，带目标参数请求=404。
- VPC Network直接绑定Tunnel UUID已实测可访问回环Bridge；未配置公网Bridge入口或DNS记录。Tunnel API返回warp-routing.enabled=false，该直接绑定链路仍正常，不将这个字段伪报为已启用。

公网验收通过WSS完成认证，等待16秒（超过中继15秒硬生命周期），服务器回环Bridge建立连接数为0，继续使用同一客户端完成IPv4出口检查、SOCKS5 UDP DNS和5,000,000字节下载。该次下载1.843秒，约21.7Mbps，仅为连通性粗测，不代表吞吐上限。

抓包中回环接口含4个QUIC Initial包；公网8443入口收到1029个短头包，未见QUIC Initial。捕获期间还存在较早测试会话的5个保活包，新会话源端口40313贡献1024包。客户端日志只有1次认证连接和1次迁移。仅截取128字节包头；不通过CID字节直接宣称匹配，因为QUIC可轮换连接ID。

验收时用户原Throne TUN仍开启，Windows路由显示先经过throne-tun；服务器看到国内来源IP。此结果证明该环境中的WSS认证后UDP业务可用，但**不能替代关闭原TUN后的独立直连验收**。个人交付包建议用户先关闭原TUN，再启动CLI和独立代理浏览器手测。

曾尝试主动停用实验Tunnel/Bridge的命令被自动审批拒绝（只返回blocked by policy）。本轮没有执行该停服测试，改为上述硬生命周期到期+回环连接归零验收。客户端与浏览器代理手测不需要管理员权限。

## 构建、交付与回滚

`build-worker.ps1` 默认Go1.26.3；Go1.26.0在Windows race运行中曾发生运行时崩溃，1.26.3的相关race测试通过。四个相关包完整测试通过，Worker模拟测试覆盖2026运行时默认Blob行为，并在accept前显式指定ArrayBuffer。

`package-worker.py`生成个人客户端包，含真实配置、CA、启动脚本和独立Edge代理测试脚本；输出只在忽略的build目录，不包含Cloudflare管理密钥或SSH私钥。HTTP代理11809，SOCKS5代理11808。默认不启动TUN、不修改系统代理。

部署使用 `cloudflare-worker.py`、两个systemd单元及 `install-worker.sh`。安装前上传SHA256SUMS与二进制；回滚脚本 `rollback-worker.sh` 停用新增实验服务并恢复 `/opt/hysteria-hdm/hysteria.before-worker-wss`，保留Cloudflare资源与凭据。执行停服/回滚须符合当前会话授权及审批要求。

运行配置包含独立Worker接入令牌。Cloudflare管理令牌保存在Git外受限目录；其到期不等于已部署Worker自动下线。CLI认证前入口失效会连接失败，认证后UDP故障仍由QUIC超时结束，无自动fallback。


## 0.5.2 Windows CMD / TUN 包（2026-10-28）

使用 `package-worker-tun.py` 生成个人TUN包。用户完整解压后双击 `start-tun.cmd`，脚本通过Windows UAC启动管理员CMD；未授权则停止。启动前检查已有TUN/VPN，避免叠加测试。此包使用内核原生TUN及内置Wintun，取消HTTP/SOCKS监听。

新增可选 `transport.worker.dialIP`，仅改变TCP拨号目标IP，保留WSS URL域名、Host及TLS证书验证。CMD每次启动先解析Worker IPv4，再把该IP和服务器UDP IP加入TUN排除路由，然后写入运行时JSON。一个进程的重连继续使用固定IP，防止DNS变化导致WSS回流到TUN；下次运行CMD重新解析。管理中继和局域网同样保留直连。

`prepare-tun.ps1 -PrepareOnly`仅生成配置，不创建网卡、不改路由、不申请管理员权限，可用于打包验证。实际TUN启动由用户运行CMD完成。窗口内按Ctrl+C触发客户端已有的正常退出和TUN路由清理；异常强杀不保证同等清理。

验收包括固定IP仍保留Host/SNI、拒绝不可信TLS证书、配置字段解析、迁移相关race测试、CMD辅助脚本语法及生成配置路由检查。公网测试仅验证新增固定IP拨号与原服务端兼容；不会把不开TUN的测试视为Windows路由接管已验收。
