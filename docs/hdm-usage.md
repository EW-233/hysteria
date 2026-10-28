# HDM 实验版使用与部署

> 公开副本中的服务器地址、域名及本机路径已脱敏；详情见 [源码审核说明](review-guide.md)。

## 当前范围

实现固定服务端 IP、两个 UDP 端口的单次迁移。客户端先在握手端口完成 TLS 和 HTTP 233 认证，然后在同一个 QUIC transport 内切换本地 socket 和目标端口。默认关闭，不改变 HY2 协议格式。

只支持 `trigger: auth_success`（可省略），数据端口须在 1–65535 且不同于握手端口。握手端口不能是列表或范围；与 hopInterval、minHopInterval、maxHopInterval、realm、mimic 互斥。支持 plain、Salamander、Gecko。重连时重新生成配置和工厂，从握手端口开始。

`fallback: true` 明确报错，当前没有远端黑洞自动回退。认证回调返回成功仅表示本地 socket 切换成功；日志中的 `data path not yet verified` 不能当作端到端验证。收到 UDP 包也不等价于 QUIC PATH 验证。服务端依赖当前 Hysteria QUIC fork 的 DisablePathManager 行为。

旧 socket 保留 **5 秒**接收迟到包，然后关闭；客户端 Close 会取消回收定时器。限制旧路径保留期，避免旧路径保活持续掩盖数据端口黑洞。没有定时重复切换，也不会自动恢复旧路径。ChromeParrot 默认开启，在锁定依赖中会覆盖客户端 maxIdleTimeout 为 **30 秒**；因此不能承诺设置 4 秒后默认模式就在 4 秒内失败。关闭 ChromeParrot 的黑洞测试使用 4 秒 QUIC 空闲超时。

两端口必须进入同一个 QUIC 实例。两个独立 HY2 服务分别监听两个端口不能实现此功能。跨 IP 中继、跨进程迁移、其他 QUIC 实现及 sing-box 服务端的兼容性尚未验证。

## 构建

在仓库根目录运行：

```powershell
./scripts/hdm/build.ps1
```

输出位于 `build/hdm/`：Windows amd64 客户端、Linux amd64/arm64 可执行文件、SHA256SUMS 和 build-info.json。构建默认使用通过 Windows 迁移竞态测试的 Go 1.26.3 工具链，可通过 `-Toolchain` 显式指定；不升级项目依赖。二进制版本标记为实验版；未提交的源码会标注 dirty。

## 服务器准备

服务器需要 systemd、nftables、OpenSSL、ss。先确认架构、现有 UDP 监听、nftables 规则、主机防火墙和云安全组。443 已被现有 UDP 服务占用时改用两组空闲端口，不能直接覆盖当前服务。

将匹配架构的二进制、SHA256SUMS 和两个 shell 脚本通过可信 SSH 上传。以下命令中的散列取自构建输出，不要原样执行占位文本：

```bash
sudo bash install-server.sh ./hysteria-hdm-linux-amd64 443 8443 <该二进制的SHA256>
```

脚本校验散列并拒绝覆盖现有实验安装或已占用端口，创建：

- `/opt/hysteria-hdm/hysteria`：独立二进制。
- `/etc/hysteria-hdm/config.yaml`：服务端配置及独立随机密码。
- `/etc/hysteria-hdm/server.crt`、`server.key`：有效期 30 天、SNI 为 hdm.test 的实验自签证书。
- `hysteria-hdm.service`：独立服务，握手端口是唯一 QUIC 监听。
- `hysteria-hdm-ports.service` 和 `inet hysteria_hdm`：将数据端口 REDIRECT 到握手端口。

脚本不配置云安全组或主机 filter 链。需要允许外部进入两个 UDP 端口；REDIRECT 后 filter 链看到的端口可能已经是握手端口，须按现有防火墙检查。规则仅覆盖进入服务器的流量，不覆盖服务器自己 OUTPUT 到本机的测试。

部署后检查：

```bash
systemctl status hysteria-hdm.service hysteria-hdm-ports.service
journalctl -u hysteria-hdm.service -n 60 --no-pager
ss -lunp
nft list table inet hysteria_hdm
```

监听列表只看到握手端口属正常现象，数据端口由 NAT 处理。脚本中的服务启动检查不等于远程数据路径测试成功。

回滚：

```bash
sudo bash rollback-server.sh
```

回滚停止并禁用两个实验单元，移除实验 NAT 表；保留二进制、证书和配置便于诊断。不会刷新全局规则集。再次运行安装脚本会因已有安装而拒绝覆盖，需要先检查现有实验文件并按实际情况处理。

## 客户端与 Throne

通过可信 SSH 取回 `/etc/hysteria-hdm/client.yaml` 和 `server.crt`，填写实际 IP，并保证 CA 路径正确。密码文件和服务器私钥不能提交到 Git。模板见 `scripts/hdm/client.example.yaml`。

```powershell
./build/hdm/hysteria-hdm-windows-amd64.exe client -c <本地实验配置路径>
```

本地已发现 `<client-directory>/Throne/Throne.exe` 和 `ThroneCore.exe`。ThroneCore 的构建信息显示其依赖 Throneproj/sing-box 和 sing-quic；官方 Hysteria CLI 与 GUI/ThroneCore 不是可互换的程序。当前尚未构建或覆盖 Throne.exe，也未修改运行中的 Throne 数据库。

官方 Throne 源码的 ExtraCore 接口可通过本地 SOCKS 接入 CLI。配置草案见 `scripts/hdm/throne-extracore.example.json`：

- 可执行文件：本次构建的 Hysteria Windows CLI。
- 参数：`client -c %s`，由 Throne 写临时配置并替换 %s。
- SOCKS 地址：127.0.0.1:18480，与 YAML 一致。
- CA 使用绝对路径，避免临时配置位置导致证书路径失效。

该模板按当前上游源码核对，尚未在本地已安装的旧版 Throne 中完成导入和运行验证。若要求原生 Hysteria 节点编辑器直接支持迁移，需要继续修改 Throne 配置生成和相应内核，随后编译并备份替换本地程序；本仓库的改动不会自动传递给 ThroneCore。

## 真实环境验收顺序

1. 先使用独立实验端口，通过 CLI 的 SOCKS 测试 HTTPS、上传、下载和 UDP。
2. 用同一节点配置将 enabled 分别设为 false/true 做 A/B，对比多次成功率和吞吐；不要把本地回环数据当作公网速度。
3. 同时在客户端和服务器抓包。首轮使用 plain，按两 UDP 端口过滤，确认数据端口没有新 QUIC Initial。混淆模式的外部包型不能直接按 QUIC 解析。
4. 测试服务端重启、丢包、数据端口封锁及重新连接；记录实际超时、是否重新认证和新连接的握手目标。
5. 再接入 Throne 做正常使用和测速，保存软件版本、源码提交、配置参数、pcap 与结果。

远程吞吐、长时间稳定性、双端实际 443→8443 抓包、服务端重启与 Throne 原生替换尚待真实环境执行。分享 URI 不包含新增 HDM 参数。只有这些验收完成且获得授权后才创建 PR。

## Windows 原生 TUN 手动测试

现有 Windows 二进制包含 TUN 和 Wintun 支持。可从已配置的独立客户端目录生成 TUN 包：

```powershell
python scripts/hdm/package-tun.py build/hdm/hdm-client-windows-0.2.1 build/hdm/hdm-client-windows-tun-0.2.1
```

输出目录必须不存在。脚本复制二进制、CA 证书和构建信息，生成迁移及对照配置、管理员启动脚本、校验清单和 ZIP。源配置必须使用明确的 IPv4 服务器地址；真实密码只进入本地输出文件，不能提交到仓库。

退出其他 VPN、旧 HDM 客户端，关闭残留系统代理和浏览器代理插件，然后右键 `start-tun-hdm.cmd` 以管理员身份运行。浏览器流量经 TUN 进入实验连接，可直接使用网页版 Speedtest。确认网页出口为服务器出口后开始测速；停止客户端，再使用 `start-tun-baseline.cmd` 对照，保持同一个测速节点。

路由接管公网 IPv4 和全球单播 IPv6，排除服务器 IP 和本地网络以避免路由环路。保留系统 DNS 配置；局域网 DNS 查询仍走局域网，因此不提供 DNS 防泄漏保证。Ctrl+C 正常退出时关闭 TUN 并清理其路由。打包不会启动客户端；管理员权限、驱动加载和网页测速仍需实际验收。
