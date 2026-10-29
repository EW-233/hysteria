"""制作带个人 KEX 节点的独立 Throne 包；真实凭据仅写入 ignored build 目录。"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_database(path, source, outbound):
    # 从配套 GUI 的源码提取结构，创建全新数据库，避免带入原客户端的私人节点。
    # 启用 GUI 自带的随机监听端口，避免固定 2082 与 WSL 或其他本机代理冲突。
    profile = {'name':'US13 · HTTPS握手 / UDP直连', 'type':'custom', 'subtype':'outbound',
               'config':json.dumps(outbound,ensure_ascii=False)}
    with sqlite3.connect(path) as db:
        for name in ('SettingsRepo.cpp','GroupsRepo.cpp','ProfilesRepo.cpp','RoutesRepo.cpp'):
            code = (source/'src/database'/name).read_text(encoding='utf-8')
            statements = re.findall(r'CREATE TABLE IF NOT EXISTS .*?\n\s*\)',code,re.S)
            if not statements:
                raise ValueError('配套 GUI 数据库结构缺失：'+name)
            for sql in statements:
                db.execute(sql)
        db.execute('INSERT INTO groups(id,name,profiles_json,scroll_last_profile) VALUES(0,?,?,1)',('KEX原生测试','[1]'))
        db.execute('INSERT INTO groups_order(group_id,display_order) VALUES(0,0)')
        db.execute('INSERT INTO profiles(id,type,name,gid,outbound_json) VALUES(1,?,?,0,?)',('custom',profile['name'],json.dumps(profile,ensure_ascii=False)))
        db.execute('INSERT INTO route_profiles(id,name,default_outbound_id) VALUES(1,?,-1)',('KEX全局（局域网直连）',))
        addresses = [outbound['server'],outbound['https']['entry_ip'],'43.252.41.230']
        cidrs = [str(ipaddress.ip_network(ip)) for ip in addresses]
        db.execute('INSERT INTO route_rules(route_profile_id,rule_order,name,type,ip_cidr_json,outbound_id) VALUES(1,0,?,0,?,-2)',('握手入口和服务端直连',json.dumps(cidrs)))
        db.execute('INSERT INTO route_rules(route_profile_id,rule_order,name,type,ip_is_private,outbound_id) VALUES(1,1,?,0,1,-2)',('局域网直连',))
        settings = {'language':'2','current_group':'0','current_route_id':'1','remember_id':'1',
                    'remember_enable':'false','system_proxy_enabled':'false','tun_mode_enabled':'false',
                    'url_scheme_auto_register':'false','file_assoc_auto_register':'false',
                    'inbound_address':'127.0.0.1','inbound_socks_port':'2082','random_inbound_port':'true','vpn_ipv6':'true',
                    'enable_tun_routing':'true','core_box_api_port':'-9091','core_box_api_secret':secrets.token_hex(24),
                    'sub_auto_update':'-30','remote_dns':'https://1.1.1.1/dns-query','dns_final_out':'remote',
                    'log_level':'info','log_file_level':'info','route_auto_update':'-1440'}
        db.executemany('INSERT INTO settings(key,value) VALUES(?,?)',settings.items())
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('数据库完整性检查失败')
        restored = json.loads(json.loads(db.execute('SELECT outbound_json FROM profiles WHERE id=1').fetchone()[0])['config'])
        if restored != outbound:
            raise ValueError('节点序列化回读不一致')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--throne-source',type=Path,default=ROOT.parent/'Throne-hdm')
    parser.add_argument('--config',type=Path,required=True,help='本机私密 CLI KEX JSON')
    parser.add_argument('--output-name',default='Throne-KEX-0.9.0-windows-x64')
    args = parser.parse_args()
    source = args.throne_source.resolve()
    gui = source/'build/Throne-HDM-1.3.2-windows-x64'
    base = ROOT/'build/throne-kex'
    out = (base/args.output_name).resolve()
    if out.parent != base.resolve():
        raise ValueError('输出必须位于 build/throne-kex 下')
    info = json.loads((base/'build-info.json').read_text(encoding='utf-8'))
    if sha(base/'ThroneCore.exe') != info['core_sha256']:
        raise ValueError('核心与构建记录不一致')
    # 复用已换头像的 GUI，验证其清单；核心始终使用本轮原生构建。
    for line in (gui/'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines():
        digest,name = line.split('  ',1)
        item = (gui/name).resolve()
        if not item.is_relative_to(gui.resolve()) or sha(item) != digest:
            raise ValueError('GUI包校验失败：'+name)
    config = json.loads(args.config.read_text(encoding='utf-8-sig'))
    server,port = config['udp_address'].rsplit(':',1)
    server = str(ipaddress.ip_address(server.strip('[]')))
    outbound = {k:config[k] for k in ('service_id','private_key_hex','server_public_key_hex','https')}
    outbound.update(type='hysteria2-kex',server=server,server_port=int(port))
    if config.get('bind_address'):
        addr = ipaddress.ip_address(config['bind_address'])
        outbound['inet4_bind_address' if addr.version == 4 else 'inet6_bind_address'] = str(addr)
    if 'max_rx' in config:
        outbound['max_rx'] = config['max_rx']
    noise_version = re.search(r'github.com/flynn/noise (v[^\s]+)', (ROOT/'core/go.mod').read_text()).group(1)
    cache = Path(subprocess.check_output(['go','env','GOMODCACHE'],text=True).strip())
    noise_license = cache/'github.com/flynn'/('noise@'+noise_version)/'LICENSE'
    quic_license = ROOT/'build'/('kex-network-'+info['quic_patch_sha256'][:12])/'quic-go/LICENSE'
    for license_path in (noise_license,quic_license):
        if not license_path.is_file(): raise ValueError('缺少依赖许可证：'+str(license_path))
    out.mkdir(exist_ok=False)
    for name in ('Throne.exe','libcronet.dll','updater.exe'):
        shutil.copy2(gui/name,out/name)
    shutil.copy2(base/'ThroneCore.exe',out/'ThroneCore.exe')
    shutil.copytree(gui/'licenses',out/'licenses')
    shutil.copy2(ROOT/'LICENSE.md',out/'licenses/Hysteria-LICENSE.md')
    shutil.copy2(noise_license,out/'licenses/flynn-noise-LICENSE.txt')
    shutil.copy2(quic_license,out/'licenses/apernet-quic-go-LICENSE.txt')
    (out/'config').mkdir()
    create_database(out/'config/throne.db',source,outbound)
    # 从最终数据库回读节点生成验收配置，避免测试用节点与交付节点发生偏差。
    with sqlite3.connect(out/'config/throne.db') as db:
        node = json.loads(json.loads(db.execute('SELECT outbound_json FROM profiles WHERE id=1').fetchone()[0])['config'])
    node['tag'] = 'kex-out'
    live = {'log':{'level':'info'},'outbounds':[node], 'route':{'final':'kex-out','auto_detect_interface':True}}
    (base/'packaged-live.json').write_text(json.dumps(live,ensure_ascii=False,indent=2),encoding='utf-8')
    info['gui'] = json.loads((gui/'package-info.json').read_text(encoding='utf-8'))['gui']
    info['gui_version'] = '1.3.2-hdm.0.3.2'
    info['private_config_included'] = True
    info['native_outbound'] = 'hysteria2-kex'
    (out/'build-info.json').write_text(json.dumps(info,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (out/'start-throne.cmd').write_text('@echo off\r\ncd /d "%~dp0"\r\necho Please exit your other Throne and CLI TUN client first.\r\npause\r\nstart "" "%~dp0Throne.exe"\r\n',encoding='ascii')
    (out/'使用说明.txt').write_text('''Throne KEX 原生测试包 0.9.0

1. 先退出原来的 Throne，以及之前 CMD 启动的 KEX TUN 客户端。
2. 完整解压到新目录；双击 Throne.exe（或 start-throne.cmd）。不要覆盖旧客户端。
3. 启动预置的 US13 · HTTPS握手 / UDP直连 节点，然后启用 Throne 的 TUN 模式。
   如出现管理员权限提示，请确认；本包默认不自动启动节点、不改系统代理。
   本地 SOCKS/HTTP 入站使用随机可用端口，当前端口以 GUI 显示为准。
4. 在普通浏览器打开 Speedtest。对比时请手动选择与常规 Throne 相同的测速服务器。
5. 若失败，停止后重新启动节点；本实验版不自动重连、不降级为普通 HY2。

KEX 已编入 ThroneCore。运行时保留正常的 GUI + 核心，不需要额外 kex-poc/hysteria-worker 进程。
HTTPS 只用于建立会话，业务直连服务器 UDP 28443；不使用 WSS、Tunnel 或 Bridge。
沿用已验证的 BBR 参数，本包没有承诺修复测速差距。UDP 仍有待观察的间歇性超时。
GUI 继续显示原有版本，自定义出站可能不显示完整协议名称；核心版本和源码见 build-info.json。
目前绑定打包时的本机物理 IPv4。换 Wi-Fi、网卡或地址后，请在自定义节点 JSON 中调整
inet4_bind_address，或删掉该字段后停止并重启节点，让 TUN 的自动接口识别接管。
请勿使用内置升级覆盖实验核心；后续使用新实验包升级。

此包包含你的设备私钥和 Worker 接入令牌，只供本人测试，不要公开分享。
不含 Cloudflare 管理密钥、SSH 私钥或服务端私钥。
''',encoding='utf-8-sig')
    files = sorted(p for p in out.rglob('*') if p.is_file())
    (out/'SHA256SUMS.txt').write_text(''.join(sha(p)+'  '+p.relative_to(out).as_posix()+'\n' for p in files),encoding='utf-8')
    archive = Path(str(out)+'.zip')
    if archive.exists():
        raise ValueError('归档已存在，拒绝覆盖')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(out.rglob('*')):
            if p.is_file(): z.write(p,out.name+'/'+p.relative_to(out).as_posix())
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None: raise ValueError('归档校验失败')
    print('Package:',out)
    print('Archive:',archive)
    print('SHA256:',sha(archive))


if __name__ == '__main__':
    main()
