# 带外握手真实网络验收

日期：2026-10-28。实验客户端版本：0.8.0-kex-poc。

## 本轮实现

独立 `kex_poc` 构建将设备 Noise 握手、共享 UDP Transport 的 CID 登记、逐来源路径挑战、反放大预算、可靠 READY 控制流和原生 HY2 TCP/UDP 业务连接起来。Worker 每次建连使用一个短 TLS 上游请求；不使用 WSS、Tunnel 或 Bridge。

控制流固定为客户端双向 stream 0，53 字节控制帧绑定 session ID 与 Noise 摘要：HELLO → READY → READY_ACK+FIN → START+FIN。收到 READY 的客户端先允许接收对端更新后的密钥，然后发送 ACK；主动密钥更新和业务返回仍等待 START。服务端收到 ACK 后确认并发送 START，避免早期密钥更新让 START 无法解密。

## 已有本地证据

- Go 1.26.3 / Windows，重建隔离补丁工作区后核心 KEX、编排、relay 和 HY2 适配的 race 测试通过两次。
- 真实 UDP socket 覆盖首个双向探测/响应丢失、认证前预算、未知 CID/无效 AEAD/长包头静默丢弃、异源重放、超时和取消。
- HTTPS 入口关闭后，同连接约 5.5 MB TCP 和 20 次 700 字节 UDP 回显成功；超过 10 秒待接入期限仍可传输。
- 两条连接共享服务端 Transport，设备撤销能结束已有业务。
- Worker 15 项 Node 测试包含实际 Go TLS 帧服务互通。

## 审计修订

子智能体审计指出四项真实代码风险：READY 前后密钥更新的确认顺序、关闭处理器向未验证来源重发 CLOSE、多地址源站回复未携带本地 packetInfo、Dial 配置早退泄漏 socket。四项均已修复；新增测试真实触发 100 次接入解密后 phase 1 START、关闭异源静默、多路径本地元数据隔离和配置早退 socket 回收。最终从补丁重建工作区，核心五包 race 与 fork 根包/handshake 的 short race 回归全部通过。CLI 普通/race 和双平台构建通过。

Go 1.26.0 的 Windows race 大流量测试曾出现 internal/poll 栈损坏崩溃；1.26.3 多次测试通过。本轮固定 1.26.3，不把工具链差异称为已经完全证明的根因。

## 公网实验部署

- 独立 Cloudflare Worker：`hy2-kex-poc`，入口 `kex.kkbk.info`。
- 自有 VPS：`186.241.106.13`；UDP 28443、短 TLS relay 18443；首次启动的诊断 HTTPS 18444 在最终部署时关闭。
- 同进程服务：`hy2-kex-experiment.service`，路径 `/opt/hy2-kex-experiment`。
- 源站使用指向该 VPS 的临时映射域名及受信任 TLS 证书；Cloudflare token 缺少 DNS 写权限，因此尚未改成自有源站子域名。
- 设备密钥、接入令牌和真实配置均保存在仓库外，不属于公开源码/通用发布包。
- 旧 hysteria-hdm、hdm-bridge、hdm-cloudflared 保持运行；本实验不依赖它们。

首次未绑定接口的本机探测失败；检查发现另一个 Throne TUN 正在接管路由。绑定物理网卡地址的 HTTPS 检查正常，因此后续直连验收需要显式绑定物理来源，不能把现有代理转发当作成功。

## 公网结果

首次成功 probe：建连 3265 ms，HTTPS 状态 200，UDP DNS 成功。该首轮用于确认 Worker→源站→直接 UDP 链路。

审计修正版在独立公网服务上完成两轮持续传输验证。每轮只启动一个客户端、只进行一次 KEX；之后使用临时 INPUT 规则拒绝实验 TCP 18443，等待 16 秒（超过 pending 10 秒期限）再测试，结束前确认拒绝规则仍在，最后恢复防火墙。远端预设自动恢复计时器防止意外退出遗留规则。

| 项目 | 第一轮 | 第二轮 |
| --- | --- | --- |
| 入口不可用后 5,000,000 字节下载 | 成功，2.654 秒，15.07 Mbps | 成功，2.597 秒，15.40 Mbps |
| 同连接 UDP DNS | 18/20 成功 | 19/20 成功 |
| 同连接 VPS 回环 UDP 回显 | 未测试 | 18/20 成功 |
| 业务前后 relay 存活 TCP 连接 | 均为 0 | 均为 0 |
| 抓包中的 relay TCP 建连流 | 1 | 1 |
| 双向 UDP 抓包数量 | 6,110 | 6,161 |
| UDP 长包头 | 0 | 0 |
| 每个方向首包 | 短包头 | 短包头 |
| 退出前同一客户端进程仍运行 | 是 | 是 |

抓包只截取 96 字节，不记录密钥或业务正文。IPv4 UDP 来源是本地运营商公网地址，不是中继或旧代理服务器；绑定源地址只是一项配置，实际直连结论由 VPS 抓包支持。只能从抓包认定长/短包头，不能直接从受头保护的字节断言 key phase。

VPS HTTPS 出口实际采用其 IPv6 `2a0e:df80:a:1::11a`，已与 VPS 地址核对。第一轮脚本只接受 VPS IPv4，将正常 IPv6 出口误判为失败；原始结果保留，第二轮校验已更正。两轮总体 `ok=false` 均保留，因为 UDP 并非全数成功，不把“TCP 跑通”改写成所有验收通过。

UDP 进一步对照：

- VPS 本机直接向 1.1.1.1 查询 DNS：20/20 成功。
- 第二轮 HY2 回显的两个超时 ID，VPS 回环服务都收到并回复了；问题在回复之后的发送/回程/本机接收路径，尚不能精确归因。
- 使用另一临时端口、独立随机凭据的原始 UDP 回显（不经过 QUIC/HY2）：首轮 14/20 成功，VPS 日志确认 20 个请求均收到并回复；后续一轮 20/20 成功。说明间歇超时能独立于新握手复现，不足以单独归因于 KEX，也不足以排除 HY2 的其它问题。

本地证据文件（位于忽略的 build 目录，不随公开源码发布）：`build/kex/public-acceptance/{report.json,headers.json,client.log}`、`build/kex/public-acceptance-2/`、`build/kex/dns-server-baseline.json`、`build/kex/raw-udp-baseline*.json`、`build/kex/echo-server.log`。源码验证日志：`final-core-test.log`、`final-fork-test.log`、`worker-go-interop.log`。

结论：一次短 HTTPS 带外握手后，用短包头直接接入 VPS 并持续承载 HY2 TCP/UDP，在公网已证明可行。UDP 稳定性、TUN 实际路由和长期使用仍是独立验收项；上述 5 MB 数字仅为连通性/吞吐粗测，不能当作带宽上限。

## 范围与限制

当前是独立实验 CLI/TUN 包。ThroneCore 原生出站尚未集成，因此没有交付去除 ExtraCore 的新 Throne 客户端。本协议替换 QUIC 的 TLS 握手，需要配套客户端与服务端，不能导入普通 hysteria2 分享链接。

不自动重试 KEX、不自动重连、不回退普通 HY2/WSS/备用节点。网络切换、睡眠恢复与长期运行尚未验收；原旧 UDPStress 基线也有失败，不能据此宣称全仓库回归全绿。


## 交付包复测与清理

实现提交 `df955545a6b7c0992c4873cf6b78ffe638c4797e` 后重新构建，二进制和构建清单均指向该提交；唯一保留的工作区改动为原有 `go.work.sum`。最终 Linux 二进制 SHA256：`dae5ed1a534b9c6ba184468e85f48ba91fdab86535e5f7bee8ef0ea520474dce`，已与服务器文件校验一致。

从实际交付 Windows 包运行 probe：建连 2136 ms，HTTPS 200（533 ms），该次单个 UDP DNS 未返回，整体在 30 秒截止时以 `udp_failed` 退出。保留 `build/kex/final-package-probe.json`；没有重试到成功后覆盖这个失败结果。此结果再次说明交付包可完成握手与 TCP，但 UDP 仍不能视为稳定可用。

临时 UDP 对照进程、额外诊断 HTTPS 监听、测试防火墙规则/恢复计时器、抓包进程与本地管理 CONNECT 代理已结束。独立 `hy2-kex-experiment` 及三项原有服务保持 active，实验仅监听 UDP 28443 和 TCP 18443。

本机私密测试包：`build/kex-cli/KEX-0.8.0-manual-test.zip`，包含真实设备配置；不提交、不公开发布。TUN 启动需要用户关闭已有 Throne TUN 后手动提权测试；本轮未启动第二个 TUN。

## 2026-10-29 用户浏览器 TUN 测速反馈

用户报告新路线已经在普通浏览器中完成测速。两张截图同为 VPS 出口，但选择了不同测速服务器，因此只能作为连通性与性能待排查记录，不能据此认定差异来自随机波动或 KEX 握手。

| 项目 | 新 KEX 测试 | 常规 Throne |
| --- | --- | --- |
| 下行 | 18.38 Mbps | 110.21 Mbps |
| 上行 | 7.51 Mbps | 9.12 Mbps |
| 空闲延迟 | 169 ms | 169 ms |
| 下载负载延迟 | 176 ms | 351 ms |
| 上传负载延迟 | 3135 ms | 641 ms |
| 测速服务器 | Docomo Pacific / Los Angeles | Frontier / Los Angeles |
| 结果 ID | 1984543149 | 1984543950 |

下一阶段改为 Throne 原生出站，让用户在相同 GUI/TUN 环境下对照；首版沿用已验证的协议参数，不同时更换拥塞算法。实验源码采用 BBR standard 并关闭 GSO，常规 Throne 当时的实际拥塞与相关参数尚未核实。
