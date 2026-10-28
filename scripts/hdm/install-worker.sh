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
systemctl enable --now hdm-bridge.service hdm-cloudflared.service
systemctl is-active hysteria-hdm hdm-bridge hdm-cloudflared
