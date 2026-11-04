"""公网验收：独立 CLI 经 WSS 认证，中继硬超时后继续测试同一会话。"""
import argparse
import json
import os
import secrets
import socket
import subprocess
import time
from pathlib import Path
import requests
import yaml

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument("--config", type=Path, required=True)
p.add_argument("--expected-egress", required=True, help="预期出口 IPv4 地址")
a = p.parse_args()
out = ROOT / "build/worker-hdm/public-smoke"
out.mkdir(exist_ok=True)

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def receive(s, n):
    data = b""
    while len(data) < n:
        part = s.recv(n-len(data))
        if not part: raise ConnectionError("SOCKS closed")
        data += part
    return data

def udp_check(port):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as tcp:
        tcp.sendall(bytes.fromhex("050100")); assert receive(tcp,2) == bytes.fromhex("0500")
        tcp.sendall(bytes.fromhex("05030001000000000000"))
        head = receive(tcp,4); assert head[1] == 0 and head[3] == 1
        addr = receive(tcp,6)
        host = socket.inet_ntoa(addr[:4]); endpoint = ("127.0.0.1" if host == "0.0.0.0" else host, int.from_bytes(addr[4:],"big"))
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.settimeout(15)
            qid = secrets.token_bytes(2)
            query = qid + bytes.fromhex("01000001000000000000") + b"\x07example\x03com\x00" + bytes.fromhex("00010001")
            udp.sendto(bytes.fromhex("00000001010101010035") + query,endpoint)
            reply,_ = udp.recvfrom(4096)
            assert reply[:4] == bytes.fromhex("00000001")
            answer = reply[10:]
            assert answer[:2] == qid and answer[2]&128 and answer[3]&15 == 0
            return len(answer)

config = yaml.safe_load(a.config.read_text(encoding="utf-8"))
assert config["transport"]["type"].lower() == "worker"
http_port,socks_port = free_port(),free_port()
while http_port == socks_port: socks_port=free_port()
config["http"]={"listen":f"127.0.0.1:{http_port}"}
config["socks5"]={"listen":f"127.0.0.1:{socks_port}"}
ca = config.get("tls",{}).get("ca")
if ca and not Path(ca).is_absolute(): config["tls"]["ca"]=str((a.config.resolve().parent/ca).resolve())
path=out/"client.yaml"
path.write_text(yaml.safe_dump(config,sort_keys=False),encoding="utf-8")
with (out/"client.log").open("wb") as log:
    cli=ROOT/"build/worker-hdm/hysteria-worker-windows-amd64.exe"
    process=subprocess.Popen([str(cli),"client","-c",str(path)],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0)
    try:
        end=time.monotonic()+40
        while True:
            if process.poll() is not None: raise RuntimeError("CLI exited; see client.log")
            try:
                with socket.create_connection(("127.0.0.1",http_port),timeout=.1): break
            except OSError:
                if time.monotonic()>end: raise TimeoutError("proxy not ready")
                time.sleep(.1)
        session=requests.Session();session.trust_env=False
        session.proxies={"http":f"http://127.0.0.1:{http_port}","https":f"http://127.0.0.1:{http_port}"}
        def tcp_check():
            r=session.get("https://api.ipify.org",timeout=20);r.raise_for_status()
            assert r.text.strip()==a.expected_egress
            return r.text.strip()
        result={"egressBefore":tcp_check(),"udpDNSBefore":udp_check(socks_port)}
        print("WSS authenticated; TCP and UDP passed",flush=True)
        # 认证已完成，继续等待16秒，覆盖Worker和Bridge的15秒硬生命周期。
        end=time.monotonic()+16
        while time.monotonic()<end: time.sleep(.2)
        result.update(egressAfter=tcp_check(),udpDNSAfter=udp_check(socks_port))
        start=time.monotonic()
        r=session.get("https://speed.cloudflare.com/__down?bytes=5000000",timeout=40);r.raise_for_status();assert len(r.content)==5000000
        elapsed=time.monotonic()-start
        result.update(downloadBytes=len(r.content),downloadSeconds=round(elapsed,3),Mbps=round(len(r.content)*8/elapsed/1e6,2))
        text=(out/"client.log").read_text(encoding="utf-8")
        assert text.count("connected to server")==1 and text.count("switched to direct UDP")==1
        result["authenticatedSessions"]=1
        (out/"results.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
        print(json.dumps(result),flush=True)
    finally:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill();process.wait()
