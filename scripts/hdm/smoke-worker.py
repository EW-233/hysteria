"""使用已构建 Windows CLI 验证本地中继退出后的 HTTP/HTTPS，所有进程均在退出时回收。"""

import http.client
import http.server
import json
import pathlib
import socket
import ssl
import subprocess
import threading
import time


ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "build" / "worker-hdm"
EVIDENCE = OUT / "smoke"


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Echo(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    processes, logs, origins, threads = [], [], [], []
    cli = str(OUT / "hysteria-worker-windows-amd64.exe")
    cert = ROOT / "core/internal/integration_tests/test.crt"
    key = ROOT / "core/internal/integration_tests/test.key"
    udp_port, bridge_port, proxy_port = free_port(socket.SOCK_DGRAM), free_port(), free_port()

    # JSON 是 YAML 的子集；路径和端口由当前测试确定，不接触用户现有配置。
    server_config = {"listen": f"127.0.0.1:{udp_port}", "tls": {"cert": str(cert), "key": str(key)},
                     "auth": {"type": "password", "password": "local-smoke-only"}}
    client_config = {"server": f"127.0.0.1:{udp_port}", "auth": "local-smoke-only",
                     "tls": {"insecure": True}, "transport": {"type": "tcpBridge", "tcpBridge": {
                         "address": f"127.0.0.1:{bridge_port}"}}, "http": {"listen": f"127.0.0.1:{proxy_port}"}}
    for name, config in (("server", server_config), ("client", client_config)):
        (EVIDENCE / f"{name}.json").write_text(json.dumps(config), encoding="utf-8")

    def start(name, args):
        log = (EVIDENCE / f"{name}.log").open("wb")
        logs.append(log)
        process = subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        processes.append(process)
        return process

    def ready(port):
        end = time.monotonic() + 10
        while time.monotonic() < end:
            if any(p.poll() is not None for p in processes):
                raise RuntimeError("本地测试进程提前退出，见 smoke 日志")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.05)
        raise TimeoutError(f"监听端口未就绪：{port}")

    try:
        start("server", [cli, "server", "-c", str(EVIDENCE / "server.json")])
        bridge = start("bridge", [str(OUT / "hdm-bridge-windows-amd64.exe"),
                                  "-listen", f"127.0.0.1:{bridge_port}", "-target", f"127.0.0.1:{udp_port}"])
        ready(bridge_port)
        start("client", [cli, "client", "-c", str(EVIDENCE / "client.json")])
        ready(proxy_port)
        for secure in (False, True):
            origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo)
            if secure:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert, key)
                origin.socket = ctx.wrap_socket(origin.socket, server_side=True)
            origins.append(origin)
            thread = threading.Thread(target=origin.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)

        results = []
        for stage in ("after_auth", "after_bridge_exit"):
            if stage == "after_bridge_exit":
                bridge.terminate()
                bridge.wait(timeout=5)
            for secure, origin in zip((False, True), origins):
                host, port = origin.server_address
                if secure:
                    # 仅测试端点使用仓库测试证书；该选项不会写入用户配置。
                    conn = http.client.HTTPSConnection("127.0.0.1", proxy_port, timeout=10,
                                                       context=ssl._create_unverified_context())
                    conn.set_tunnel(host, port)
                    url = "/"
                else:
                    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
                    url = f"http://{host}:{port}/"
                try:
                    body = (stage + ":application-payload").encode() * 4096
                    conn.request("POST", url, body)
                    response = conn.getresponse()
                    received = response.read()
                    if response.status != 200 or received != body:
                        raise AssertionError("HTTP/HTTPS 数据完整性检查失败")
                    results.append({"stage": stage, "protocol": "HTTPS" if secure else "HTTP", "bytes": len(body)})
                finally:
                    conn.close()
        client_log = (EVIDENCE / "client.log").read_text(encoding="utf-8")
        switches = client_log.count("tcpBridge switched to direct UDP")
        if switches != 1:
            raise AssertionError(f"预期仅认证切换一次，实际 {switches}")
        report = {"success": True, "switches": switches, "requests": results}
        (EVIDENCE / "result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report))
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for origin in origins:
            origin.shutdown()
            origin.server_close()
        for thread in threads:
            thread.join(timeout=5)
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
