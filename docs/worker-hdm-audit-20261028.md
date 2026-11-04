# WSS迁移代码质量审计（2026-10-28）

用户要求启动独立子智能体审计。审计覆盖迁移收发、断线恢复、Worker边界、部署及Throne打包；审计阶段只读，没有访问真实凭据或服务器。以下为确认的问题和本轮处理。

| 严重级别 | 问题 | 处理 |
| --- | --- | --- |
| P1 | WSS迁移后的UDP仍被中继永久读错误策略处理；Windows WSAEMSGSIZE可终止接收，随后QUIC关闭可能等待队列 | 将错误策略绑定到初始中继；UDP超长报文继续接收；队列读期限独立唤醒 |
| P2 | 重连丢弃旧客户端时没有关闭socket/transport（既有代码问题） | 连接归属在锁内切换，锁外释放；并发旧错误不清除新连接，关闭后的迟到连接被回收 |
| P2 | 重复部署仅enable --now，已运行Bridge/Tunnel不会加载新二进制或参数 | 显式restart；本轮未在服务器执行 |
| P2 | 对多个单元一次is-active会在仅部分服务正常时成功 | 逐个is-active --quiet，任何失败退出 |

## 验证

- Windows真实UDP socket接收4096字节报文后，仍能接收下一条正常报文。
- 底层接收已退出时，逻辑读期限可唤醒ReadFrom，真实quic.Transport.Close能够返回。
- 迁移后过期期限清除/重设，后续UDP数据恢复；不会读到队列中的陈旧超时。
- udphop、workerhdm、packetframe竞态测试通过；应用层WorkerHDM与HandshakeMigration集成竞态测试通过。
- 重连并发、资源释放及关闭场景新增9组回归；core/client全包-race -count=10与go vet通过，子智能体复核P1未发现新的确定遗漏。

## 剩余限制

Throne包使用ExtraCore而非sing-box原生WSS；实际Throne TUN路由接管、网络切换、睡眠恢复与长期使用仍需手测。启动入口健康检查不能证明WSS升级或UDP迁移成功，仍需观察认证日志和实际业务。已有UDP DNS间歇超时不能仅凭本次代码修复认定已解决。UDP故障不自动回退Worker是当前设计。
