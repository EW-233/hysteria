# HDM 实现验证记录

日期：2026-10-27。功能提交：`da49645`（0.2.0 认证后UDP迁移）。本记录覆盖本地验证及部署准备，不代表远程 VPS 或 Throne 实际运行验收。

## 修改范围与原因

| 文件 | 作用 |
| --- | --- |
| core/client/config.go、client.go | 增加可空认证成功回调，仅在 HTTP 233 后调用；失败释放 QUIC、transport 和 socket。 |
| extras/transport/udphop/conn.go、migration.go | 复用现有接收队列和 socket 安装；增加固定初始目标、一次性切换、5 秒旧路径回收；修复满队列 timeout 通知阻塞关闭。 |
| app/cmd/client.go、client_migration.go | 配置解析、互斥校验、每连接 holder；穿过混淆包装调用内层切换。 |
| 对应测试及配置 fixture | 验证配置、失败释放、双端口真实 QUIC 数据收发、重复迁移及竞态。 |
| extras/go.mod | 将现有工作区使用的 goleak 1.3.0 声明为 extras 测试直接依赖；未升级协议依赖。 |
| scripts/hdm、docs/hdm-usage.md | 构建、独立服务器安装与回滚、客户端配置、Throne 外部核心接入草案。 |

## 通过的检查

| 检查 | 结果与限制 |
| --- | --- |
| Windows 普通测试 | app/cmd、extras/transport/udphop、core/client 全包通过。 |
| Linux Go 1.26.0 race | udphop、obfs、core/client、app/cmd 四个包完整通过。 |
| Windows Go 1.26.3 race | TestHandshakeMigration 全组通过，构建默认使用此工具链。 |
| 原有核心定向集成测试 | Linux 的错误认证、UDP 禁用、TCP/UDP echo、ChromeParrot 开关通过。 |
| 六种迁移组合 | plain、Salamander、Gecko × ChromeParrot 开/关；四路并发 TCP、完整负载校验、UDP 回显通过，注入数据路径初始两包丢失。 |
| 连续连接 | 100/100；每次新配置均先访问握手入口；共 100 次 TLS、100 次 Authenticator 调用；plain 数据入口 Initial 计数为 0。 |
| 已有会话连续性 | 已打开 TCP 流的连续数据跨切换完整；同一 HY2 UDP 会话切换前后回显成功。 |
| 黑洞端口 | 关闭 ChromeParrot、QUIC 空闲超时设为 4 秒，测试在 15 秒总期限内失败；没有自动回退或新握手。 |
| 生命周期 | 重复/并发触发仅创建两个 socket；创建失败只尝试一次；关闭竞态循环 100 次；认证失败不切换；回调失败后的写操作返回 net.ErrClosed；transport goleak 检查通过。 |
| 构建 | Windows amd64、Linux amd64、Linux arm64 交叉构建成功。Windows 和 WSL amd64 启动及新增配置校验通过；arm64 未运行。 |
| 脚本和格式 | Bash 语法检查、PowerShell AST 解析、JSON 模板解析、gofumpt v0.12.0 和 git diff --check 通过。服务器安装脚本尚未在真实主机执行。 |

测试入口是两个真实回环 UDP socket，由测试 PacketConn 合并到同一个服务端 QUIC transport，并按客户端来源选择回包入口。它验证完整协议收发，不替代 Linux REDIRECT、运营商 NAT 或远程抓包。Initial 统计检查 plain 模式数据入口包头；混淆模式没有据此宣称外部 QUIC 包型可见。

Authenticator 计数不是原始 HTTP auth 请求计数；结合 TLS 次数、入口包型和业务连续性可支持当前单会话实现，但本轮没有单独抓取每一条 HTTP 233 认证请求。

## 失败、修复与剩余风险

- 初版配置 fixture 未覆盖新增字段，补齐后通过。测试日志未初始化和测试监听器缺少错误透传/UDP 接口的问题已修正。
- 黑洞测试促使旧路径策略从“保留到 Close”改为“最多 5 秒”；同时发现 ChromeParrot 固定 30 秒空闲超时，修正了测试对 4 秒配置的假设。旧路径回收不表示新路径已验证。
- Windows Go 1.26.0 完整迁移 race 曾出现 0xc0000005 运行时异常，没有把它记作通过。Linux Go 1.26.0 与 Windows Go 1.26.3 的迁移 race 通过；该运行时异常的根因尚未单独定位。
- 扩展 Windows 回归中的原有 TestClientServerUDPStress 失败。使用 `git archive HEAD core` 导出的修改前审计基线、关闭 go.work 后，small 子测试同样出现 0/200 回包。该失败可在未引入 HDM 的基线复现，本轮未修改该压力测试，也未宣称完整仓库 CI 全绿。

## 复现命令

```powershell
go test ./app/cmd ./extras/transport/udphop ./core/client -count=1 -timeout=90s
$env:GOTOOLCHAIN="go1.26.3"
go test -race ./app/cmd -run "^TestHandshakeMigration" -count=1 -timeout=120s
./scripts/hdm/build.ps1
```

```bash
go test -race ./extras/transport/udphop ./extras/obfs ./core/client ./app/cmd -count=1 -timeout=120s
bash -n scripts/hdm/install-server.sh
bash -n scripts/hdm/rollback-server.sh
```

日志和二进制保存在被 Git 忽略的 `build/hdm/`，包括 linux-race-tests.log、windows-tests.log、windows-race-go1.26.3.log、linux-regression-tests.log、SHA256SUMS 和 build-info.json。以最终 SHA256SUMS 和 build-info.json 识别产物。

## 尚待真实环境完成

服务器 IP/SSH 入口尚未明确；本机 SSH config 读取被文件权限拒绝。本轮没有向历史记录中的主机猜测部署。安装脚本、独立服务和回滚材料已准备，远程监听、防火墙与安全组仍需现场确认。

Throne 安装位于 <client-directory>/Throne。ThroneCore 内嵌的 sing-box/sing-quic 没有本次 CLI 修改。已核对官方源码 ExtraCore 接口并准备模板；尚未构建/替换 Throne.exe、ThroneCore.exe，也未修改当前运行配置。

后续完成实际 443→8443 NAT 与双端抓包、HTTPS 和吞吐 A/B、服务端重启、长期正常使用及 Throne 接入，再按用户授权创建 PR。没有抗检测效果或公网速度结论。
