#!/bin/sh
# 回滚实验实例并停用新增回环桥与 Tunnel；不删除云端资源或本地凭据。
set -eu
backup=/opt/hysteria-hdm/hysteria.before-worker-wss
test -f "$backup"
systemctl disable --now hdm-cloudflared.service hdm-bridge.service
cp -p "$backup" /opt/hysteria-hdm/hysteria.rollback
mv /opt/hysteria-hdm/hysteria.rollback /opt/hysteria-hdm/hysteria
systemctl restart hysteria-hdm.service
systemctl is-active hysteria-hdm
