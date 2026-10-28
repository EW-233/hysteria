"""打包个人 WSS 试用客户端；实际凭据只写入忽略的 build 目录。"""
import hashlib
import json
import shutil
import zipfile
from pathlib import Path
import yaml

root=Path(__file__).resolve().parents[2]
base=root/"build/worker-hdm"
version=json.loads((base/"build-info.json").read_text(encoding="utf-8"))["version"]
out=base/("client-"+version)
out.mkdir(exist_ok=True)
shutil.copy2(base/"hysteria-worker-windows-amd64.exe",out/"hysteria.exe")
config=yaml.safe_load((base/"live/client.yaml").read_text(encoding="utf-8"))
shutil.copy2(config["tls"]["ca"],out/"server.crt")
config["tls"]["ca"]="server.crt"
(out/"client.yaml").write_text(yaml.safe_dump(config,allow_unicode=True,sort_keys=False),encoding="utf-8")
(out/"start.cmd").write_bytes(b'@echo off\r\ncd /d "%~dp0"\r\nhysteria.exe client -c client.yaml\r\npause\r\n')
# 独立浏览器配置目录避免影响用户已有会话；通过显式 HTTP 代理测试网页。
(out/"browser-test.ps1").write_text('$ErrorActionPreference = \'Stop\'\n$edgePaths = @("${env:ProgramFiles(x86)}\\Microsoft\\Edge\\Application\\msedge.exe", "$env:ProgramFiles\\Microsoft\\Edge\\Application\\msedge.exe")\n$edge = $edgePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1\nif (-not $edge) { throw \'Microsoft Edge not found. Set a browser HTTP proxy to 127.0.0.1:11809 manually.\' }\n$profile = Join-Path $PSScriptRoot \'browser-profile\'\n& $edge "--user-data-dir=$profile" \'--proxy-server=http://127.0.0.1:11809\' \'--disable-quic\' \'--no-first-run\' \'https://www.speedtest.net/\'\n',encoding="utf-8-sig")
(out/"README.txt").write_text("""个人实验客户端：WSS握手，认证后UDP迁移

1. 建议先关闭原Throne的TUN，以隔离真实直连测试；SSH管理仍由开发工具经中继进行。
2. 双击start.cmd，等待connected to server和代理端口监听成功，保持窗口开启。
3. SOCKS5为127.0.0.1:11808，HTTP代理为127.0.0.1:11809。
4. PowerShell运行 powershell -ExecutionPolicy Bypass -File .\browser-test.ps1，可启动独立Edge配置打开Speedtest。
   如果浏览器不能启动，可在专用浏览器配置中手动设置HTTP代理。
5. 测试结束关闭专用浏览器和客户端窗口，然后按需要恢复Throne。

本包是CLI实验版，不是Throne替换版，也不会设置系统代理或创建TUN。无需管理员权限。
关闭原TUN后若WSS连接失败，请保留错误日志；此前自动验收时原Throne TUN处于开启状态，尚未证明关闭后WSS入口可达。
日志中的switched只代表本地换路；网页加载/下载成功才证明数据收发。
没有自动回退到Worker的功能。UDP阻断时等待QUIC超时；再次连接需重新走WSS。
配置包含个人Worker接入令牌与HY2密码，请勿公开分享本包。它不包含Cloudflare管理API密钥或SSH私钥。
""",encoding="utf-8-sig")
files=sorted(x for x in out.iterdir() if x.is_file() and x.name!="SHA256SUMS")
(out/"SHA256SUMS").write_text("".join(hashlib.sha256(x.read_bytes()).hexdigest()+"  "+x.name+"\n" for x in files),encoding="utf-8")
archive=base/(out.name+".zip")
with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED) as z:
    for x in out.iterdir():
        if x.is_file(): z.write(x,arcname=out.name+"/"+x.name)
print("Client directory:",out)
print("Client archive:",archive)
print("Archive SHA256:",hashlib.sha256(archive.read_bytes()).hexdigest())
