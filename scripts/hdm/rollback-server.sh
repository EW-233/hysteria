#!/usr/bin/env bash
# 撤销本项目独立服务和 NAT 表；保留配置、证书及二进制以便诊断。
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo '需要 root 权限' >&2; exit 1; }
systemctl disable --now hysteria-hdm.service hysteria-hdm-ports.service
if nft list table inet hysteria_hdm >/dev/null 2>&1; then
 nft delete table inet hysteria_hdm
fi
echo '实验服务已停止，实验端口重定向已移除；配置与二进制保留。'
