# Worker KEX 测试 CLI

日期：2026-10-28。此 CLI 是带 build tag 的独立测试入口，复用 core/v2/kexpoc 和 app/internal/socks5、app/internal/tun。默认应用依赖、常规入口和运行服务均不受影响。

## 构建与产物

在仓库根目录执行：

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/hdm/build-kex-poc.ps1
~~~

脚本固定 GOTOOLCHAIN=go1.26.3。这是本实验已经验证的版本，不表示最新版本。主线程已确认 Windows Go 1.26.0 的 race 大流量测试会触发 internal/poll WriteToInet4 崩溃，相同核心测试在 Go 1.26.3 下连续三轮通过。

默认先调用 prepare-kex-quic.py --output build/kex-network，再将 GOWORK 设置为该目录中的 go.work；所有构建带 kex_poc 标签，不改默认 go.work、go.mod 或模块缓存中的源代码。准备脚本校验固定依赖、补丁及 manifest；目录内容不匹配时会拒绝覆盖，需要主线程完成最终补丁准备。

最终补丁尚未落地时，可显式使用主线程当前维护的临时工作区：

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/hdm/build-kex-poc.ps1 -Workspace build/kex/go.work
~~~

此参数跳过准备脚本，构建的是指定工作区，应结合 build-info.json 确认来源。脚本先运行 CLI 测试，再构建 Windows/Linux amd64，并生成：

- build/kex-cli/windows-amd64/kex-poc.exe
- build/kex-cli/linux-amd64/kex-poc
- build/kex-cli/kex-poc-windows-amd64.zip
- build/kex-cli/kex-poc-linux-amd64.zip
- build/kex-cli/SHA256SUMS 和 build-info.json

压缩包仅包含程序、无凭据示例、本文档，以及 Windows 启动器。打包显式列举文件，不会收录输出目录中另行放入的真实配置、证书或密钥。Linux 解压后执行 chmod +x kex-poc。构建脚本恢复调用前的进程环境变量，不自动运行服务端、代理或 TUN。

## 配置与密钥

所有私钥和令牌从 JSON 文件读取，没有命令行秘密参数；正常日志和 probe JSON 不打印配置、URL、秘密或底层错误正文。JSON 限制 1 MiB，拒绝未知字段及尾随第二个对象；证书文件相对路径以配置文件目录为基准。

在解压目录生成两份独立密钥材料：

~~~powershell
.\kex-poc.exe keygen -out server-keys.json
.\kex-poc.exe keygen -out device-keys.json
~~~

文件包含 private_key_hex、public_key_hex、relay_credential_hex、access_token。私钥、公钥和 relay 凭据均为 32 字节的 64 位 hex；令牌也独立随机生成。已有文件会被拒绝覆盖，标准输出只包含 keygen_written 成功状态。Unix 创建权限为 0600；Windows 继承目录 ACL，使用只允许测试人员访问的目录保存这些文件。两份文件不应直接充当客户端或服务端配置，它们是供本地编辑配置时使用的密钥材料。

复制 client.example.json 为 client.json，server.example.json 为 server.json，然后在本地编辑器填入：

| 字段 | 客户端 | 服务端 |
| --- | --- | --- |
| service_id | 与服务端相同的服务标识 | 同左 |
| private_key_hex | device-keys.json 的私钥 | server-keys.json 的私钥 |
| server_public_key_hex | server-keys.json 的公钥 | 不使用 |
| udp_address | VPS 对外公布的明确 IP:端口 | 与客户端相同的公布地址 |
| udp_listen | 不使用 | 本机监听地址，如 0.0.0.0:20443；默认使用 udp_address |
| max_rx | 客户端接收带宽上限，字节/秒；0 使用默认行为 | 不使用 |
| devices[].public_key_hex | 不使用 | 登记 device-keys.json 的公钥 |
| devices[].principal | 不使用 | 设备身份，例如 test-device |
| devices[].udp_enabled | 不使用 | 是否允许 HY2 UDP |
| devices[].rx_auto / rx | 不使用 | 接收带宽策略；rx_auto=true 时 rx 必须为 0 |

当前核心要求同一服务端实例内所有设备的 rx_auto/rx 一致；CLI 用该策略填充 HY2.IgnoreClientBandwidth 和 HY2.BandwidthConfig.MaxRx，并在不一致时拒绝启动。不同设备仍可分别控制 UDPEnabled。

udp_address 必须是实际单播 IP 地址，IPv6 写作 [地址]:端口，不接受域名、未指定地址或 zone。服务端通常通过 udp_listen 绑定 0.0.0.0 或 ::，通过 udp_address 公布 VPS 外网地址；存在端口映射时两者可以不同。

HTTPS 和 relay 配置：

| 字段 | 用途 |
| --- | --- |
| https.endpoint | 客户端握手地址，必须为 https://域名[:端口]/k，不允许用户凭据、查询参数或片段 |
| https.access_token | 客户端发送的 Bearer token；直连时须与服务端相同，Worker 模式须与 Worker CLIENT_TOKEN 相同 |
| https.ca_pem | 客户端可选 CA PEM 文本，含换行转义；追加到系统信任库，不是路径 |
| https.entry_ip | 可选固定 HTTPS 入口 IP；保留 endpoint 域名的 SNI 和证书验证 |
| https.listen | 可选的标准 HTTPS 测试入口，如 0.0.0.0:8443；空值关闭 |
| https.cert_file / key_file | 服务端 TLS 证书链与私钥路径；HTTPS 和 relay 共用，relay 单独开启也必须填写 |
| relay.listen | 可选的短 TLS 帧入口，如 0.0.0.0:9443；空值关闭 |
| relay.credential_hex | 恰好 32 字节 hex，与 Worker UPSTREAM_TOKEN 的 64 位 hex 对应 |

服务端至少开启一个入口。HTTPS 与 relay 同时启用时必须使用不同 TCP 端口。示例中的 8443 是标准 HTTPS，9443 是 relay；Worker 的 UPSTREAM_PORT 必须配置成实际 relay 端口，不能照搬其它示例的 HTTPS 端口。relay 不是 HTTP 服务，不接受 fetch 的 HTTP 请求。

## 三条联调路径

1. 直连：CLI 的 https.endpoint 指向 VPS 的标准 HTTPS /k。适合验证 KEX、UDP 数据面及证书配置。
2. Cloudflare fetch 实验：标准 HTTPS handler 可以作为 fetch 的上游；该实验需由主线程配置对应 Worker 和令牌转发。
3. 最终 Worker：CLI 向 Worker HTTPS /k 发请求；Worker 用短 TLS 帧转发到 VPS relay.listen。CLIENT_TOKEN 验证客户端请求，UPSTREAM_TOKEN 对应 relay.credential_hex；这两个秘密独立生成。VPS 的标准 HTTPS 入口可以留作测试，也可以关闭。

三种路径的数据面均直接走 VPS UDP。CLI 只实现到入口的标准 HTTPS；Worker 到 VPS 的短 TLS 帧由 Worker 与 relay 完成。CA PEM 和 entry_ip 只影响 CLI 到 HTTPS 入口的连接，Worker 到 relay 的信任和域名设置由 Worker 配置负责。

## 启动与单连接行为

Linux 服务端示例：

~~~sh
./kex-poc server -config server.json
~~~

普通 Windows 客户端：

~~~powershell
.\kex-poc.exe client -config client.json -timeout 20s
~~~

连接成功后监听 127.0.0.1:1089，支持 SOCKS5 TCP 与 UDP；UDP 是否可用取决于登记策略。程序只创建一条 KEX/HY2 连接，不自动重拨，不回退到普通 HY2 握手。首次连接失败、连接中断或本地服务异常均退出。timeout 只限制首次连接建立；成功后可持续使用到用户中断或远端关闭。

可双击 start-kex-poc.cmd，读取启动器旁边的 client.json。启动器放在 scripts/hdm 时也能找到 build/kex-cli/windows-amd64/kex-poc.exe，但配置仍放在启动器旁边。程序退出后窗口暂停，便于查看脱敏错误。

## 可选 TUN

~~~powershell
.\kex-poc.exe client -config client.json -tun
~~~

TUN 非默认，需要管理员权限。双击 start-kex-poc-tun.cmd 会在需要时请求 UAC，然后以可见窗口运行；构建和测试不调用它。用 Ctrl+C 结束，以便现有 tun.Server 关闭网卡和回收路由。

CLI 在 TUN 启动前完成 HTTPS 入口解析和唯一一次连接建立。没有 entry_ip 时解析全部入口 IP，优先选择 IPv4 并固定本次 HTTPS 拨号地址；显式 entry_ip 则直接使用该地址。两者始终保留 endpoint 主机名作为 TLS SNI 和校验身份，不支持跳过证书验证。

TUN 自动排除 VPS UDP 地址以及解析得到的所有 HTTPS 入口地址，IPv4 用 /32，IPv6 用 /128；其余 IPv4/IPv6 默认路由进入 TUN。默认网卡名 kex-poc，MTU 1400，地址 172.31.255.1/30 和 fdfe:dcba:9876::1/126，可通过 tun.name、mtu、ipv4、ipv6 修改。现有 TUN 实现保留系统 DNS 设置，DNS 流量随路由转发；Windows 的 Wintun 代码随当前 sing-tun 依赖内嵌，不由打包脚本另行下载驱动。

client_connected 事件仅确认连接建立和 SOCKS5 监听成功；tun_requested=true 表示已请求启动 TUN，并非网卡或路由配置完成证明。TUN 启动失败会退出且执行清理。本文测试不启动系统 TUN，实际网卡、系统路由及 DNS 接管由主线程后续验证。

## Probe 与结果

通过同一连接发起 HTTP(S) GET，并可额外发送固定 example.com A 查询：

~~~powershell
.\kex-poc.exe probe -config client.json -url https://example.com/ -dns 1.1.1.1:53 -timeout 20s
~~~

默认 URL 是 https://example.com/。只验证 TCP 时不传 -dns；只验证 UDP 时传 -url "" -dns 1.1.1.1:53。DNS 目标必须是明确 IP:端口，可使用 [IPv6]:53。timeout 覆盖入口解析、建连、TCP 和 UDP 的总时间，超时关闭这唯一一条连接以中断阻塞。

TCP 请求经 client.TCP 建立，统计响应正文的字节数与时间；仅 HTTP 2xx 算成功，不自动跟随重定向，也不读取环境中的 HTTP_PROXY。HTTPS 目标本身使用系统根证书校验；https.ca_pem 仅用于 KEX 入口。UDP 通过 client.UDP 发送随机 ID 的固定问题，校验响应来源、ID、响应标志、opcode、问题及成功状态，并拒绝截断响应。

成功时 stdout 输出一个 JSON 对象，例如（数值仅示意）：

~~~json
{"ok":true,"connect_ms":120,"elapsed_ms":350,"tcp":{"ok":true,"status":200,"bytes":1256,"elapsed_ms":180},"udp":{"ok":true,"bytes":61,"response_id":12345,"elapsed_ms":50}}
~~~

错误时退出码非零；完成连接尝试后的结果仍输出到 stdout，并带 connect_failed、tcp_failed 或 udp_failed。命令参数/配置无法读取等前置错误只向 stderr 输出固定中文错误 JSON。URL、令牌、私钥、响应正文及底层错误不进入输出。JSON 中 bytes 不包含协议握手与网络包开销。

## 已执行检查与交接边界

本地 CLI 测试包括：密钥仅写文件且禁止覆盖、配置和参数错误脱敏、IPv4/IPv6 入口排除、固定入口 IP 保留 SNI、真实 HTTPS→Noise→UDP path→READY→TCP/DNS、错误令牌只握手一次、DNS 错误 ID/源地址拒绝与超时退出。

单独执行测试：

~~~powershell
$env:GOTOOLCHAIN = 'go1.26.3'
$env:GOWORK = (Resolve-Path 'build/kex/go.work').Path
# 最终补丁准备好后，改为 build/kex-network/go.work。
go test -count=1 -timeout 90s -tags kex_poc ./app/cmd/kex-poc
# race 需可用的 C 编译器和 CGO_ENABLED=1。
$env:CGO_ENABLED = '1'
go test -race -count=1 -timeout 90s -tags kex_poc ./app/cmd/kex-poc
~~~

本次交付不部署、不 commit、不启动 TUN。Windows 与 Linux 编译、Windows 启动校验和本地回环测试由本任务验证；Linux 实机运行、VPS 外网 UDP、Cloudflare Worker、真实证书以及 TUN 的最终测试由主线程完成。临时工作区构建通过不代表尚未生成的最终 patch/manifest 已验证。
