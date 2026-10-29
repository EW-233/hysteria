# Worker KEX：代码审计记录

日期：2026-10-28。用户要求子智能体审计代码质量；本轮由同一个独立子智能体分两阶段只读审计。

## 第一阶段：外部密钥 QUIC 回环

范围：quic-kex.patch 及其生成的 external_kex.go、connection.go、internal/handshake/external_kex.go，
以及 KEX→QUIC 回环测试和 ParameterBuilder 变更。
检查参数与 CID 绑定、确认前后的密钥状态、短包头与来源拒绝分支、取消和关闭顺序。
子智能体运行 External QUIC、密钥更新及带 kex_poc 标签的 KEX 回环相关测试，未发现可确认、可行动的问题。
这一阶段的子智能体没有额外运行 race；主线程已单独运行相关 race 测试。

## 第二阶段：接入租约与状态管理

范围：admission.go、admission_test.go 及 server.go、types.go、quic_poc_test.go 的本轮变更。
检查一次接管/一次材料交接、原始截止时间、父取消、撤销与 Commit 竞态、激活中额度、
CID 占用及去重记录、逐地址预算和证明绑定。
子智能体运行带 kex_poc 标签的 KEX race 测试一轮，通过，未发现可确认、可行动的问题。
没有修改文件，审计不会扩大为对公网部署或完整 QUIC 协议的合规结论。

## 主线程验证与边界

正常依赖的 KEX race 测试五轮、隔离 fork 下带标签 KEX→QUIC race 测试五轮及 vet 均通过。
fork 根包/handshake 的短测、External 系列 race 测试与已有 client/server/protocol 单测通过，
固定依赖补丁全新重建后再次验证 KEX→QUIC。
此外在 Windows 上以 GOOS=linux、GOARCH=amd64、CGO_ENABLED=0 构建了带标签的 KEX 测试二进制及 fork 根包测试二进制，
只证明 Linux/amd64 编译通过，尚未在 Linux 上执行这些测试。

原有 UDPStress 在基线复现的失败仍保留，未将整套集成回归写为全部通过。
源码审计没有覆盖新的公网适配、真实收发预算、READY 或 Throne/TUN；这些功能尚未实现。
现有 CryptoSetup 与 Noise→QUIC 密钥导出仍是实验组合，本记录不替代密码学审查。
