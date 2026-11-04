#!/usr/bin/env bash
# 部署独立实验服务：两个 UDP 入口进入同一个 HY2 监听实例。
set -euo pipefail
umask 077
if [[ $# -ne 4 ]]; then
  echo "用法: sudo bash install-server.sh <Linux二进制> <握手端口> <数据端口> <SHA256>" >&2
  exit 2
fi
binary=$(realpath "$1")
handshake=$2
data=$3
expected=$4
[[ $EUID -eq 0 ]] || { echo '需要 root 权限' >&2; exit 1; }
for p in "$handshake" "$data"; do
  [[ $p =~ ^[1-9][0-9]{0,4}$ ]] && ((p <= 65535)) || { echo '端口必须在 1..65535' >&2; exit 1; }
done
[[ $handshake != "$data" ]] || { echo '两个端口不能相同' >&2; exit 1; }
[[ $expected =~ ^[0-9a-fA-F]{64}$ ]] || { echo '必须提供 SHA256' >&2; exit 1; }
for command in sha256sum openssl ss nft systemctl install realpath; do command -v "$command" >/dev/null; done
actual=$(sha256sum "$binary" | cut -d ' ' -f 1)
[[ ${actual,,} == ${expected,,} ]] || { echo '二进制 SHA256 不符' >&2; exit 1; }
# 拒绝覆盖既有安装或占用端口，避免影响现有代理服务。
for path in /opt/hysteria-hdm /etc/hysteria-hdm /etc/systemd/system/hysteria-hdm.service /etc/systemd/system/hysteria-hdm-ports.service; do
  [[ ! -e $path ]] || { echo "已存在，停止安装: $path" >&2; exit 1; }
done
for p in "$handshake" "$data"; do
  [[ -z $(ss -H -lun "sport = :$p") ]] || { echo "UDP 端口被占用: $p" >&2; exit 1; }
done
if nft list table inet hysteria_hdm >/dev/null 2>&1; then echo '实验 NAT 表已存在' >&2; exit 1; fi
nft_bin=$(command -v nft)
systemctl is-system-running >/dev/null || [[ $(systemctl is-system-running) == degraded ]]
chmod +x "$binary"
"$binary" version >/dev/null

# 创建独立凭据和证书；秘密仅保存在 root 可读的配置文件中。
install -d -m 700 /etc/hysteria-hdm
install -d -m 755 /opt/hysteria-hdm
install -m 755 "$binary" /opt/hysteria-hdm/hysteria
openssl req -x509 -newkey rsa:3072 -nodes -days 30 -subj /CN=hdm.test -addext subjectAltName=DNS:hdm.test -keyout /etc/hysteria-hdm/server.key -out /etc/hysteria-hdm/server.crt >/dev/null 2>&1
password=$(openssl rand -hex 32)
cat > /etc/hysteria-hdm/config.yaml <<EOF
listen: :$handshake
tls:
  cert: /etc/hysteria-hdm/server.crt
  key: /etc/hysteria-hdm/server.key
auth:
  type: password
  password: "$password"
EOF
cat > /etc/hysteria-hdm/client.yaml <<EOF
# 通过可信 SSH 通道取回本文件和 server.crt，填写服务端 IP。
server: SERVER_IP:$handshake
auth: "$password"
tls:
  sni: hdm.test
  ca: server.crt
transport:
  type: udp
  udp:
    handshakeMigration:
      enabled: true
      dataPort: $data
      trigger: auth_success
      fallback: false
socks5:
  listen: 127.0.0.1:18480
EOF
unset password
cat > /etc/hysteria-hdm/ports.nft <<EOF
# 仅重定向实验数据端口，不刷新已有防火墙规则。
table inet hysteria_hdm {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    udp dport $data counter redirect to :$handshake
  }
}
EOF
nft -c -f /etc/hysteria-hdm/ports.nft
cat > /etc/systemd/system/hysteria-hdm-ports.service <<EOF
[Unit]
Description=Hysteria HDM experimental UDP redirect
After=network-online.target
Before=hysteria-hdm.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$nft_bin -f /etc/hysteria-hdm/ports.nft
ExecStop=$nft_bin delete table inet hysteria_hdm
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/hysteria-hdm.service <<'EOF'
[Unit]
Description=Hysteria HDM experimental server
Wants=network-online.target
Requires=hysteria-hdm-ports.service
After=network-online.target hysteria-hdm-ports.service
[Service]
Type=simple
ExecStart=/opt/hysteria-hdm/hysteria server -c /etc/hysteria-hdm/config.yaml
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/hysteria-hdm.service /etc/systemd/system/hysteria-hdm-ports.service
# 启动失败只停止本次实验服务并撤销本次 NAT 表，保留文件便于诊断。
rollback_on_error() {
 systemctl disable --now hysteria-hdm.service hysteria-hdm-ports.service >/dev/null 2>&1 || true
 if nft list table inet hysteria_hdm >/dev/null 2>&1; then nft delete table inet hysteria_hdm; fi
 echo '实验启动失败，已停止服务并撤销实验 NAT；配置保留在 /etc/hysteria-hdm' >&2
}
trap rollback_on_error ERR
systemctl daemon-reload
systemctl enable --now hysteria-hdm-ports.service hysteria-hdm.service
systemctl is-active --quiet hysteria-hdm.service
trap - ERR
printf '实验服务已启动；握手 UDP %s，数据 UDP %s。请核查主机防火墙及云安全组。
' "$handshake" "$data"
printf '客户端配置及证书位于 /etc/hysteria-hdm，请通过可信 SSH 取回；不要把秘密提交到 Git。
'
