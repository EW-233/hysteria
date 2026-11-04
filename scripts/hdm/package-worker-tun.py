"""生成双击CMD启动的个人WSS原生TUN客户端，不自动改变本机网络。"""
import argparse
import hashlib
import json
import shutil
import zipfile
from pathlib import Path
import yaml

root=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser()
p.add_argument("--config",type=Path,default=root/"build/worker-hdm/live/client.yaml")
a=p.parse_args()
base=root/"build/worker-hdm"
info=json.loads((base/"build-info.json").read_text(encoding="utf-8"))
out=base/("client-tun-"+info["version"])
# 不覆盖已有用户包中的日志、浏览器资料或运行时配置。
out.mkdir(exist_ok=False)
config=yaml.safe_load(a.config.read_text(encoding="utf-8"))
assert config["transport"]["type"].lower()=="worker"
ca=Path(config["tls"]["ca"])
if not ca.is_absolute(): ca=a.config.resolve().parent/ca
shutil.copy2(ca,out/"server.crt")
shutil.copy2(base/"live/worker-bootstrap.json",out/"worker-bootstrap.json")
config["tls"]["ca"]="server.crt"
for key in ("socks5","http","tun"): config.pop(key,None)
config["transport"]["worker"].pop("dialIP",None)
(out/"client-base.json").write_text(json.dumps(config,ensure_ascii=False,indent=2),encoding="utf-8")
for source,target in ((base/"hysteria-worker-windows-amd64.exe","hysteria.exe"),(base/"build-info.json","build-info.json"),(root/"scripts/hdm/prepare-worker-tun.ps1","prepare-tun.ps1"),(root/"scripts/hdm/start-worker-tun.cmd","start-tun.cmd")):
    shutil.copy2(source,out/target)
(out/"README.txt").write_text("""WSS握手后UDP迁移：Windows原生TUN测试包

1. 完整解压，先退出Throne和其他VPN/TUN，关闭浏览器代理插件及旧系统代理。
2. 双击start-tun.cmd，在Windows管理员权限提示中选择“是”。不必手动运行PowerShell。
3. 保持黑色窗口开启，等待connected to server及TUN初始化完成，确认没有随后报错。
4. 用平时的浏览器打开网页版Speedtest，先确认出口属于实验服务器，再测速。
5. 停止时在黑色窗口按Ctrl+C。程序正常退出会关闭TUN并清理自身添加的路由。
   不建议直接强杀进程；若意外退出后网络异常，先检查是否仍有客户端运行。
6. 测试结束可重新开启原Throne。

本包接管公网IPv4和全球单播IPv6的TCP/UDP，未启用HTTP/SOCKS监听，不修改系统代理。
启动时解析并固定本次Worker IPv4，排除Worker、HY2服务器和管理中继，避免TUN环路；TLS仍校验Worker原域名。
保留局域网访问和系统当前DNS设置，不承诺DNS防泄漏。
每次重新运行CMD优先查询加密DNS；不可用时使用7天有效期的服务器核实缓存，过期则停止。Worker入口本身必须在关闭原代理后可达。
客户端先经WSS/Worker/Tunnel认证，收到HTTP233后同一QUIC会话切换到UDP8443。
UDP被阻断时没有Worker自动回退；看到切换日志不代表业务已收到回包，以网页实际访问为准。

程序内置Wintun支持，无需单独下载DLL。开启TUN需要UAC授权。
本次使用已验证的自有域名入口；加密DNS不可达时回退到包内已核实IP属于正常提示。
本机直连已通过WSS认证、UDP迁移及临时代理TCP/UDP测试；实际TUN路由和浏览器测速仍需手测。

本包包含个人Worker令牌及HY2密码，请勿公开分享；不含Cloudflare管理API密钥或SSH私钥。
""",encoding="utf-8-sig")
(out/"SHA256SUMS").write_text("".join(hashlib.sha256(f.read_bytes()).hexdigest()+"  "+f.name+"\n" for f in sorted(out.iterdir()) if f.is_file()),encoding="utf-8")
archive=base/(out.name+".zip")
with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED) as z:
    for f in out.iterdir():
        if f.is_file(): z.write(f,out.name+"/"+f.name)
print("TUN directory:",out)
print("TUN archive:",archive)
print("SHA256:",hashlib.sha256(archive.read_bytes()).hexdigest())
