#!/bin/sh
# 上传构建文件、校验清单、服务单元及独立 Tunnel 令牌后，部署实验实例。
set -eu
cd /opt/hdm-worker
sha256sum --check --ignore-missing SHA256SUMS
chmod 600 /etc/hdm-worker/tunnel-token.txt
install -m 755 hdm-bridge-linux-amd64 /opt/hdm-worker/hdm-bridge
install -m 644 hdm-bridge.service /etc/systemd/system/hdm-bridge.service
install -m 644 hdm-cloudflared.service /etc/systemd/system/hdm-cloudflared.service
# 保留首次部署前的实验服务二进制，独立于普通 HY2 实例。
backup=/opt/hysteria-hdm/hysteria.before-worker-wss
if ! test -f "$backup"; then cp -p /opt/hysteria-hdm/hysteria "$backup"; fi
install -m 755 hysteria-worker-linux-amd64 /opt/hysteria-hdm/hysteria.next
mv /opt/hysteria-hdm/hysteria.next /opt/hysteria-hdm/hysteria
systemctl daemon-reload
if ! systemctl restart hysteria-hdm.service; then
  cp -p "$backup" /opt/hysteria-hdm/hysteria.rollback
  mv /opt/hysteria-hdm/hysteria.rollback /opt/hysteria-hdm/hysteria
  systemctl restart hysteria-hdm.service
  exit 1
fi
# 已运行的服务也必须重新加载新二进制和启动参数。
systemctl enable hdm-bridge.service hdm-cloudflared.service
systemctl restart hdm-bridge.service hdm-cloudflared.service
# is-active接受多个单元时任意一个active即可成功，因此必须逐个验收。
for unit in hysteria-hdm hdm-bridge hdm-cloudflared; do
  systemctl is-active --quiet "$unit"
done
