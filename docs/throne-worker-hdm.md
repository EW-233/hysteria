# Throne WSS迁移试用包

2026-10-28，本包复用用户头像版Throne 1.3.2-hdm.0.3.2 GUI及配套ThroneCore，采用ExtraCore调用Hysteria 0.5.6-worker-tun，独立交付版本0.5.6。没有把WSS协议重新移植到sing-box；Throne负责TUN、DNS、分流和进程生命周期，Hysteria负责WSS认证与同一QUIC会话的UDP迁移。

## 构建及启动

运行 `python scripts/hdm/package-throne-worker.py`。输入是已校验的相邻Throne构建包和build目录内个人配置，输出为新的私有目录和ZIP，不覆盖原Throne。生成器从配套GUI源码读取建表语句，仅预置一个节点与独立路由，不复制用户数据库。首次不开TUN、系统代理或自动连接，协议注册及文件关联自动注册关闭。

每次用 `start-throne.cmd` 启动。准备脚本拒绝当前已有Throne或TUN，尝试HTTPS DNS与包内缓存候选IP，再通过Windows自带curl的`--resolve`保留域名/SNI并进行正常TLS证书验证，要求`/health`返回`ok`。没有`-k`或跳过证书验证；过期DNS缓存仅作为候选地址，不会跳过在线检查。支持Windows PowerShell 5的WSS默认端口解析差异。

启动成功后生成本次 `worker-client.json`，仅监听本机18480 SOCKS5端口；CA写入当前目录绝对路径。GUI节点使用相对外部程序和配置路径，移动目录后重新运行启动器即可。Throne混合代理端口2082。默认全局代理、私有网段直连；Throne原有外部核心进程直连规则以及入口/服务器IP直连规则避免递归转发。

启动器只在Throne启动前刷新配置，程序运行期间固定IP。网络变化或重连失败时应停止节点、退出Throne、重新运行启动器。认证后UDP故障不会自动回退Worker。外部核心异常退出时由Throne停止节点；不宣称无缝断线恢复。

## 验证范围

- 预置SQLite结构、节点和路由通过Throne实际加载，核心IPC成功。
- 使用隔离数据库和随机本机端口启动真实GUI/ThroneCore/外部核心，不设置系统代理、不启动TUN。
- TCP出口为186.241.106.13，SOCKS UDP DNS成功；等待16秒后TCP出口不变，UDP查询再次成功。
- 测试完成终止自己创建的测试进程，用户原Throne未关闭。
- 桌面操作工具的原生管道不可用，因此未进行新包可见界面点击及TUN接管验收；这部分留给用户手测。

此前原生CMD包的UDP DNS短测存在间歇性超时，Throne这轮成功不能证明长期稳定。用户先日常使用，记录异常时间、连接恢复和TUN切换情况。

包内含个人接入凭据，不适合公开上传；Cloudflare管理密钥与SSH私钥不进入交付。


## 审计后的核心修订

0.5.6包含独立审计确认的UDP接收与重连回收修复。初始中继的不可恢复帧错误策略不再作用到迁移后的UDP；Windows超长数据报被丢弃，接收继续。逻辑读期限独立于底层接收协程，使QUIC Transport关闭能够唤醒队列。失效旧客户端摘下后释放资源，并避免迟到旧错误影响新连接。

服务端协议不变，本轮只交付客户端；部署脚本的重复部署重启及逐服务状态检查修复不在真实服务器执行。
