"""从已配置的 Windows 客户端生成原生 TUN 包，不启动程序或修改系统路由。"""
import argparse
import hashlib
import ipaddress
from pathlib import Path
import re
import shutil
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='已有客户端目录，包含 client.yaml 和 server.crt')
    parser.add_argument('output', type=Path, help='新建的 TUN 客户端目录')
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    config = (source / 'client.yaml').read_text(encoding='utf-8-sig')
    match = re.search(r'^server:\s*(\d+\.\d+\.\d+\.\d+):\d+\s*$', config, re.M)
    if not match:
        raise ValueError('当前打包脚本要求 server 使用明确的 IPv4 地址')
    server_ip = str(ipaddress.IPv4Address(match.group(1)))
    if re.search(r'^tun:', config, re.M):
        raise ValueError('源配置已有 TUN，请先核对，避免重复配置')
    config, count = re.subn(r'^(\s*ca:)\s*.*$', r'\1 server.crt', config, flags=re.M)
    if count != 1:
        raise ValueError('需要唯一的 CA 配置')
    baseline, count = re.subn(r'^(\s*enabled:)\s*true[ \t]*$', r'\1 false', config, flags=re.M)
    if count != 1:
        raise ValueError('需要唯一且已启用的迁移配置')

    # 排除服务器及本地网络，防止外层 QUIC 再次进入 TUN，同时保留局域网访问。
    tun = f'''
tun:
  name: hdm-tun
  mtu: 1500
  timeout: 5m
  address:
    ipv4: 100.100.100.101/30
    ipv6: fd00:4844:4d::1/126
  route:
    ipv4: [0.0.0.0/0]
    ipv6: ["2000::/3"]
    ipv4Exclude:
      - {server_ip}/32
      - 127.0.0.0/8
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 169.254.0.0/16
      - 224.0.0.0/4
'''
    # 输出目录必须不存在，防止覆盖用户的配置和运行日志。
    output.mkdir(parents=True, exist_ok=False)
    for name in ('hysteria-hdm.exe', 'server.crt', 'build-info.json'):
        shutil.copy2(source / name, output / name)
    for name, text in (('client-tun.yaml', config), ('client-tun-baseline.yaml', baseline)):
        (output / name).write_text(text.rstrip() + '\n' + tun, encoding='utf-8')

    # 用户右键以管理员身份运行；脚本本身不触发提权、不修改持久系统设置。
    for mode, filename in (('hdm', 'client-tun.yaml'), ('baseline', 'client-tun-baseline.yaml')):
        script = f'''@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -Command "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ exit 1 }}"
if errorlevel 1 (
  echo Please right-click this script and choose Run as administrator.
  pause
  exit /b 1
)
echo Close other VPN and HDM clients first. Keep this window open.
echo Press Ctrl+C to stop the client and remove its TUN routes.
hysteria-hdm.exe client -c {filename}
set "result=%errorlevel%"
echo Exit code: %result%
pause
exit /b %result%
'''
        (output / f'start-tun-{mode}.cmd').write_bytes(script.replace('\n', '\r\n').encode('ascii'))
    readme = f'''HDM Windows x64 原生 TUN 客户端

启动方法
1. 完整解压。退出 Throne、其他 VPN 和旧的 HDM 客户端，并关闭浏览器代理插件及残留系统代理。
2. 右键 start-tun-hdm.cmd，选择“以管理员身份运行”，保持窗口打开。
3. 查看窗口是否有连接或 TUN 初始化错误。正常后打开网页版 Speedtest 测试。
4. 先确认网页显示的出口 IP 为服务器出口，再开始测速。网页显示的服务商和位置仅供辅助判断。
5. 测试期间不要同时运行其他下载或内置测速脚本。
6. 停止时在客户端窗口按 Ctrl+C；程序正常退出时会关闭 TUN 并清理其路由。

对照测试
停止迁移模式，再右键以管理员身份运行 start-tun-baseline.cmd。
两种模式必须分开运行。选择同一个网页测速服务器，各测几次以便比较。
迁移模式：{server_ip} UDP443 完成认证后切换到 UDP8443。
对照模式：始终使用同一服务器 UDP443。
测速走向：浏览器 -> 本机 hdm-tun -> 实验 HY2 连接 -> 服务器 -> 测速节点。

路由与 DNS
此包接管公网 IPv4 和全球单播 IPv6 的 TCP/UDP；服务器 IP 与局域网保留直连，避免路由环路。
保留系统当前 DNS 设置。若 DNS 是局域网路由器，DNS 查询仍走局域网；本包不宣称 DNS 防泄漏。
如果网页无法解析，请检查系统 DNS 或浏览器安全 DNS 配置，并把错误日志发回排查。
异常强制终止后如网络未恢复，先确认客户端已退出，必要时重启系统，不要手动清空全部路由。

构建与验证
使用已构建的 0.2.1-hdm 二进制及其内置 TUN/Wintun 支持，无需另行下载 DLL。
此包只新增配置与启动脚本；构建信息见 build-info.json，文件校验见 SHA256SUMS。
未自动启动 TUN，管理员权限、驱动加载、网页连通性和公网速度需在你的机器上手动验收。
节点认证信息已配置好，配置和压缩包不要公开上传。
'''
    (output / '使用说明.txt').write_text(readme, encoding='utf-8-sig')
    files = sorted(p for p in output.iterdir() if p.is_file())
    manifest = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files)
    (output / 'SHA256SUMS').write_text(manifest, encoding='utf-8')
    archive = output.with_suffix('.zip') if not output.suffix else output.parent / (output.name + '.zip')
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as z:
        for path in sorted(output.iterdir()):
            z.write(path, f'{output.name}/{path.name}')
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for path in output.iterdir():
            assert z.read(f'{output.name}/{path.name}') == path.read_bytes()
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    Path(str(archive) + '.sha256').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    print(f'Created: {archive}\nBytes: {archive.stat().st_size}\nSHA256: {digest}')


if __name__ == '__main__':
    main()
