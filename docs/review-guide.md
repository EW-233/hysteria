# 源码审核与本地配置

本仓库保留 Hysteria 上游历史与许可证。实验功能以独立提交维护：master 与 codex/worker-hdm-local 提供当前 Worker/KEX 功能，codex/hdm-handshake-migration 保留较早的握手迁移方案。

## 本地部署参数

- Cloudflare KEX 脚本需要显式传入 --secrets、--zone、--origin、--worker-host、--server-ip；配置目录应位于 Git 外。
- Cloudflare WSS 脚本需要 --secrets。复制脚本到其他环境时应使用独立配置目录。
- 公网测试需要 --config 与 --expected-egress；抓包分析需要 --server。
- Throne 打包支持重复传入 --direct-ip，额外管理地址由操作者配置。
- TUN 启动准备脚本支持 -DirectIP 地址数组。
- Android 打包需要 --signing-dir。更新既有安装必须沿用原签名密钥，不能随意生成替代密钥。

文档中的 example.com、文档保留网段和相对路径均为示例，不可当作实际部署参数。旧测试包应重新构建，校验值以本次构建清单为准。

## 发布检查

提交前检查作者和提交者身份，并检查待发布的全部分支、文档、构建信息及压缩包。配置、令牌、私钥、个人节点和抓包应留在 Git 外；不要发布本机路径或私人基础设施标识。保留上游及第三方许可证、作者归属和依赖校验值。
