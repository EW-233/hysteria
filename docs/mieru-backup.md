# mieru 备用服务部署记录

部署日期：2026-10-27。服务器：192.0.2.10，openEuler 24.03 LTS，x86_64。

## 已部署设置

- 官方服务端 mita 3.39.0，发布于 2026-10-23；RPM 的 SHA256 已与 GitHub release digest 核对。
- 安装包 SHA256：614833abd440dbeb89723f90c930f9d2abe9f79992076bcf2985f5986a85e0d3。
- 公网监听：192.0.2.10:32061，同时 TCP/UDP；既有443和其它服务保持原样。
- 用户 backup，密码为独立生成的32字节随机值，不写入本文或Git。
- MTU 1400，DNS策略 PREFER_IPv4，日志 INFO，未指定自定义流量模式或用户流量配额。
- systemd 单元 mita.service，以 mita 用户运行，已启用开机自启。
- firewalld public 区已分别添加32061/tcp与32061/udp的运行时及永久规则，无全局重载。
- 服务器已有 TCP BBR 和正常 NTP，本次未更改内核拥塞控制。

## 客户端交付

本地私人文件在 build/mieru-backup 下，均被 Git 忽略：

- Throne-Mieru-backup.private.json：可导入的两个 sing-box outbound。
- Throne-Mieru-links.private.txt：对应的两条 mierus:// 简单分享链接。
- server.private.json：服务端原始设置。

Throne 使用“程序 → 添加文件中的配置档”导入JSON。优先选 Relay230-Mieru-TCP，Relay230-Mieru-UDP 作为对照。两个节点的多路复用均为 MULTIPLEXING_LOW。导入文件不包含测试专用的网卡绑定参数，可使用 Throne 的正常 TUN 出站处理。备用节点需要手动选择，本次没有配置自动故障切换。

## 参数说明

| 参数 | 可选值与含义 | 当前选择 |
| --- | --- | --- |
| transport | TCP或UDP，指客户端到服务器的外层传输；两者都可代理TCP和UDP业务 | TCP优先，另备UDP节点 |
| server/server_port | 服务器地址及监听端口，两端需匹配 | 192.0.2.10:32061 |
| server_ports | 多个端口范围；每次建立新底层连接时选择，不是HY2认证后迁移 | 未设置 |
| username/password | 双方匹配的身份凭据，同时参与密钥派生 | 独立账户backup |
| multiplexing | OFF关闭；LOW/MIDDLE/HIGH逐步增加复用旧底层连接的倾向，非固定并发数 | LOW |
| traffic_pattern | 编码后的流量模式，调节TCP分片、Nonce、填充等；两端可以独立设置发送模式。增强设置会带来延迟或带宽开销，具体字段随版本变化 | 留空使用默认 |
| mtu | 官方客户端UDP载荷上限1280–1400，两端应一致；TCP外层不使用该参数。当前Throne mieru配置未暴露MTU字段 | 1400 |
| dns.dualStack | USE_FIRST_IP、PREFER_IPv4、PREFER_IPv6、ONLY_IPv4、ONLY_IPv6，控制服务端选用地址族 | PREFER_IPv4 |
| loggingLevel | INFO正常运行，DEBUG排障时增加日志 | INFO |
| users.quotas | 设置一个或多个天数/兆字节额度 | 未设配额 |
| allowPrivateIP/allowLoopbackIP | 服务端用户是否可访问私有IP或本机回环地址 | 默认禁止 |
| userHintIsMandatory | 是否要求客户端提供新版用户提示以加快用户查找；旧客户端可能不支持 | 默认false |

mieru直接使用自身加密协议，本配置不需要TLS证书、SNI或Reality公钥。服务器使用较新的3.39.0，当前Throne内嵌mieru库为3.33.0；本次验证覆盖默认流量模式。官方新版的0-RTT、低熵模式等不能假定都能在此Throne页面中配置。

## 已完成验证

用Throne workspace的同一份sing-box及mieru 3.33.0依赖构建独立CLI测试内核，绑定本机物理网卡（以太网）；没有修改用户正在运行的Throne或系统路由。

- TCP/UDP外层均完成真实HTTPS请求，出口IP均为192.0.2.10。
- TCP连接本地源地址确认为物理网卡地址，远端为192.0.2.10:32061。
- 通过TCP外层和UDP外层的SOCKS5 UDP关联分别查询公共DNS成功，收到有效A记录。
- 同一个Cloudflare 1MiB文件：TCP用时0.738105秒，UDP用时16.212485秒。这是单次连通性下载样本，不是完整带宽、长期稳定性或抗干扰结论。
- systemctl restart mita 后自动恢复RUNNING，随后TCP外层HTTPS及UDP业务转发均成功。
- 所有本地测试内核已终止；服务端保留运行。

## 维护

查看状态：systemctl status mita；mita status。
查看日志：journalctl -u mita -n 100 --no-pager。
重新启动：systemctl restart mita。
服务端配置目录：/etc/mita；原始部署文件位于仅root可读目录 /root/mieru-backup-20261027。

需要停用时使用 systemctl disable --now mita，再分别删除 public 区的32061/tcp、32061/udp运行时及永久规则；无需改动其它服务。

官方版本对应文档保存在 build/mieru-src/docs 下：server-install.zh_CN.md、client-install.zh_CN.md、traffic-pattern.zh_CN.md、protocol.zh_CN.md。源码tag v3.39.0，对应commit bcd14b88d0fb7e7707bb80e5d7f6c33675d26c06。
