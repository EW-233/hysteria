# Worker KEX：接入租约与路径状态组件

日期：2026-10-28。基于 0.6.1 的[外部密钥 QUIC 回环 PoC](worker-kex-quic-poc.md)。
本阶段实现同进程握手结果向单个数据面的所有权交接、授权生命周期和路径预算组件。
**尚未把路径状态组件接入 QUIC 的逐包 AEAD、PATH_RESPONSE 解析和最终 UDP 写出钩子。**
因此这不是可用的公网 UDP 接入服务器，不能通过移除回环限制来部署。

## 所有权与时限

同进程可信分派器调用 `Broker.ClaimPending(serverLifetime, serverCID)`，只允许接管一次。
接管不选择第一个 UDP 来源，也不释放 pending 名额或改变原来的 10 秒截止时间。
`TakeMaterial()` 只能读取一次方向密钥、双方参数/CID、Noise 绑定、设备权限和客户端 MaxRx。
参数返回副本，Broker 内的方向密钥随交接清零；调用者在 QUIC 导入后负责清除自己的副本。
这不是保证 Go 运行时内存不存在副本的承诺。

Claim 的父 Context 应来自服务器/数据面的生命周期。单次 HTTPS 请求的 Context 会在响应后取消，
不能用它作为随后直连数据面的生命周期。租约 Context 在父取消、pending 截止、设备撤销、
Discard、租约关闭或 Broker 关闭时取消；传输适配必须关闭自己持有的 QUIC 和业务资源。
Broker 不执行任意业务关闭回调，也不在持锁时运行网络 I/O。
接管后的 pending 使用可停止计时器；激活后停止该计时器，活动连接不会被原 pending 期限误关。

当前回环 PoC 已使用 Claim/TakeMaterial 取代直接读取 Broker 的私有 map，服务器 QUIC 使用租约 Context。
测试结束关闭租约，断言待接入服务器连接随之取消。该 PoC 仍使用本地确认钩子；
未将回环流回显冒充真实 PATH_CHALLENGE/PATH_RESPONSE 或 READY。

## 路径状态的可信输入约定

| 接口 | 允许输入的来源 | 状态作用 |
| --- | --- | --- |
| RecordAuthenticatedDatagram | 已成功 AEAD 解密的实际 UDP 数据报来源与线长，每报一次 | 最多跟踪两个候选；分别累计接收预算 |
| PathChallenge | 已登记候选地址 | 为该路径提供系统随机 8 字节挑战，重传保持同值 |
| ReserveSend | 最终 UDP 写出前的实际来源/目的地址与线长 | 未验证路径最多发送自身收到字节的三倍；发送失败不退预算 |
| VerifyPathResponse | 已解密数据报中的 PATH_RESPONSE 及其实际来源 | 仅匹配当前来源自己的挑战才产生 PathProof；首个成功来源原子胜出 |

三倍预算必须覆盖 ACK、探测、PTO、关闭报文及所有控制发送，不能只限制应用流。
候选地址之间不能共享预算，HTTPS 字节和 AEAD 无效数据不能增加预算。
计数使用饱和边界，避免三倍乘法回绕。取胜后清除其它候选，旧候选不能改写胜出的路径。
PathProof 内部绑定具体租约与来源，不能拿另一个会话或自己拼装的证明来激活。

这些接口是可信适配边界，不是密码验证器。调用它们时如果传入伪造来源、未验证密文或流重组后的猜测来源，
组件本身无法挽救调用者的错误。特别是不能从可靠控制流的重组消息推断 PATH_RESPONSE 的 UDP 来源。
现在单测在该边界模拟可信事件，只验证状态与预算算法，不代表真实网络反放大已经成立。

## 两步激活与撤销竞态

`BeginActivation(proof)` 检查原截止时间、父取消、当前设备权限、一次性材料交接、路径证明和容量，
随后占用一个激活中的名额。并发 Begin 只有一个成功。业务初始化在锁外执行，失败时关闭租约回滚。
`Activation.Commit()` 在初始化成功后再次检查同一组生命周期/权限条件，成功才转为活动授权状态。
撤销与 Commit 使用同一把锁：撤销先发生则提交拒绝；提交先发生则撤销取消活动租约。
初始化和 Commit 之间撤销设备，不能留下活动授权。

活动名额默认全局 128、每设备 8，可通过 `MaxActive`、`MaxActivePerDevice` 调整；
激活中的预留也计入额度。待接入与活动额度分别计算，Stats 单独给出 Pending、Activating、Active 和 ReplayRecords。
活动 CID 保留在分派索引中防止碰撞，关闭后释放；握手去重缓存被清除响应但保留拒绝重放的记录。
去重记录回收不关闭仍然活动的会话。

Commit 只完成服务器授权状态变更，不负责发送 READY。后续适配必须先完成双向密钥/路径确认和业务初始化，
再 Commit 并发送可靠 READY；发送失败关闭租约。客户端在验证 READY 前不能向用户显示连接成功。
尚未接入 HY2 业务初始化，因此本阶段测试的 Active 是授权管理器状态，不能称为可代理业务的连接。

## 验证结果与复现

仓库根目录执行正常依赖的状态测试：

```powershell
$env:GOWORK = 'off'
go -C core test -race ./internal/kex -count=5 -timeout=120s
go -C core vet ./internal/kex
```

包含隔离 QUIC 回环的测试：

```powershell
python scripts/hdm/prepare-kex-quic.py
$env:GOWORK = (Resolve-Path build/kex-poc/go.work).Path
go -C core test -race -tags kex_poc ./internal/kex -count=5 -timeout=120s
go -C core vet -tags kex_poc ./internal/kex
```

已通过五轮带标签 race 测试与 vet，包含所有原 KEX 测试、真实 Noise→QUIC 回环和以下新测试：

- 32 路并发接管只有一个所有者，一次性材料交接不延长期限且不共享可变参数。
- 两候选预算隔离、第三候选拒绝、挑战跨来源/跨会话拒绝、先到候选不能永久抢占。
- 并发激活最多一次、预留计入容量、全局/单设备额度分别限制。
- 接管后、初始化中和活动时撤销；Commit 与撤销并发时最终没有残留活动授权。
- Commit 重新核对超时、权限、父取消和 Broker 关闭；关闭幂等且按设备隔离。
- 截止计时器无需调用 Stats 即可取消 pending，活动会话越过旧期限仍存活。
- 去重记录到期后活动 CID 仍保留，活动关闭后释放 CID。

未新增公网监听、Worker 资源或 Throne 可执行文件，也未部署或替换运行服务。
下一步是实现真正的 pending CID 数据报分派、候选路径逐包解密/验证和发送预算钩子，
再接可靠控制流/READY、HY2 初始化、Worker 上游和 Throne 原生出站。

补充构建检查：GOOS=linux、GOARCH=amd64、CGO_ENABLED=0 的 KEX（kex_poc 标签）与 fork 根包测试二进制编译通过，
尚未在 Linux 上执行。两阶段子智能体的只读审计结果见 [审计记录](worker-kex-audit-20261028.md)。
