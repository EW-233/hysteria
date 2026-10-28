"""使用现有免费账户部署独立握手 Tunnel/Worker；凭据只从 Git 外受限目录读取。"""
import argparse
import json
import secrets
from pathlib import Path
import requests

parser = argparse.ArgumentParser()
parser.add_argument("action", choices=["tunnel", "deploy", "status"])
parser.add_argument("--secrets", type=Path, default=Path.home() / ".codex/secrets/hdm-cloudflare")
args = parser.parse_args()
config = json.loads((args.secrets / "credentials.json").read_text(encoding="utf-8"))
base = "https://api.cloudflare.com/client/v4/accounts/" + config["accountId"]
client = requests.Session()
client.headers["Authorization"] = "Bearer " + config["apiToken"]
state_file = args.secrets / "worker-state.json"
state = json.loads(state_file.read_text()) if state_file.exists() else {}

def api(method, path, **kwargs):
    response = client.request(method, base + path, timeout=45, **kwargs)
    body = response.json()
    if not response.ok or not body.get("success"):
        # 错误响应也不输出完整请求、头部或秘密内容。
        raise RuntimeError(f"Cloudflare {method} {path}: HTTP {response.status_code}; " + str(body.get("errors")).replace(config["apiToken"], "[redacted]"))
    return body.get("result")

def save():
    state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

if args.action == "tunnel":
    name = "hdm-us13-handshake"
    if not state.get("tunnelId"):
        tunnels = api("GET", "/cfd_tunnel", params={"is_deleted": "false", "name": name})
        existing = [t for t in tunnels if t["name"] == name]
        tunnel = existing[0] if existing else api("POST", "/cfd_tunnel", json={"name": name, "config_src": "cloudflare"})
        state["tunnelId"] = tunnel["id"]
        state["tunnelName"] = name
        save()
    tid = state["tunnelId"]
    api("PUT", f"/cfd_tunnel/{tid}/configurations", json={"config": {"ingress": [{"service": "http_status:404"}]}})
    token = api("GET", f"/cfd_tunnel/{tid}/token")
    (args.secrets / "tunnel-token.txt").write_text(token, encoding="utf-8")
    secret_file = args.secrets / "worker-token.txt"
    if not secret_file.exists(): secret_file.write_text(secrets.token_urlsafe(48), encoding="utf-8")
    print("Tunnel prepared:", tid, "(token saved privately)")
elif args.action == "deploy":
    tid = state["tunnelId"]
    metadata = {"main_module": "index.mjs", "compatibility_date": "2026-10-27", "bindings": [
        {"type": "vpc_network", "name": "HDM_VPC", "tunnel_id": tid},
        {"type": "secret_text", "name": "HDM_TOKEN", "text": (args.secrets / "worker-token.txt").read_text().strip()},
    ]}
    module = Path(__file__).resolve().parents[2] / "workers/hdm/index.mjs"
    with module.open("rb") as source:
        api("PUT", "/workers/scripts/hdm-handshake", files={"metadata": (None, json.dumps(metadata), "application/json"), "index.mjs": ("index.mjs", source, "application/javascript+module")})
    api("POST", "/workers/scripts/hdm-handshake/subdomain", json={"enabled": True, "previews_enabled": False})
    subdomain = api("GET", "/workers/subdomain")["subdomain"]
    state["workerURL"] = f"https://hdm-handshake.{subdomain}.workers.dev"
    save()
    print("Worker deployed:", state["workerURL"])
else:
    if state.get("tunnelId"):
        tunnel = api("GET", "/cfd_tunnel/" + state["tunnelId"])
        print("Tunnel:", tunnel.get("status"), "connectors:", len(tunnel.get("connections") or []))
    print("Worker:", state.get("workerURL", "not deployed"))
