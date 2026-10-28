"""生成预置WSS迁移节点的独立Throne包；只写新目录，不读取用户原客户端数据库。"""
import argparse
import hashlib
import json
import re
import secrets
import shutil
import sqlite3
import zipfile
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]


def create_database(destination, source, profile, addresses):
    # 复用配套GUI源码的建表语句，避免复制已有数据库中的节点或个人设置。
    with sqlite3.connect(destination) as db:
        for name in ('SettingsRepo.cpp', 'GroupsRepo.cpp', 'ProfilesRepo.cpp', 'RoutesRepo.cpp'):
            code = (source / 'src/database' / name).read_text(encoding='utf-8')
            statements = re.findall(r'CREATE TABLE IF NOT EXISTS .*?\n\s*\)', code, re.S)
            if not statements:
                raise ValueError('未找到配套数据库结构：' + name)
            for statement in statements:
                db.execute(statement)
        db.execute("INSERT INTO groups(id,name,profiles_json,scroll_last_profile) VALUES(0,?,?,1)", ('WSS迁移试用', '[1]'))
        db.execute('INSERT INTO groups_order(group_id,display_order) VALUES(0,0)')
        db.execute('INSERT INTO profiles(id,type,name,gid,outbound_json) VALUES(1,?,?,0,?)', ('extracore', profile['name'], json.dumps(profile,ensure_ascii=False)))
        db.execute('INSERT INTO route_profiles(id,name,default_outbound_id) VALUES(1,?,-1)', ('HDM全局（局域网直连）',))
        db.execute("INSERT INTO route_rules(route_profile_id,rule_order,name,type,ip_cidr_json,outbound_id) VALUES(1,0,?,0,?,-2)", ('握手入口和服务端直连', json.dumps([ip+'/32' for ip in addresses])))
        settings = {
            'language':'2', 'current_group':'0', 'current_route_id':'1', 'remember_id':'1',
            'remember_enable':'false', 'system_proxy_enabled':'false', 'tun_mode_enabled':'false',
            'url_scheme_auto_register':'false', 'file_assoc_auto_register':'false',
            'inbound_address':'127.0.0.1', 'inbound_socks_port':'2082',
            'vpn_ipv6':'true', 'enable_tun_routing':'true', 'core_box_api_port':'-9091',
            'core_box_api_secret':secrets.token_hex(24), 'sub_auto_update':'-30',
            'remote_dns':'https://1.1.1.1/dns-query', 'dns_final_out':'remote',
            'log_level':'info', 'log_file_level':'info', 'route_auto_update':'-1440',
        }
        db.executemany('INSERT INTO settings(key,value) VALUES(?,?)', settings.items())
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--throne-source', type=Path, default=ROOT.parent/'Throne-hdm')
    parser.add_argument('--gui-package', type=Path)
    parser.add_argument('--config', type=Path, default=ROOT/'build/worker-hdm/live/client.yaml')
    parser.add_argument('--version', default='0.5.6')
    args = parser.parse_args()
    source = args.throne_source.resolve()
    gui = args.gui_package or source/'build/Throne-HDM-1.3.2-windows-x64'
    base = ROOT/'build/worker-hdm'
    out = base/('Throne-Worker-HDM-'+args.version+'-windows-x64')
    info = json.loads((base/'build-info.json').read_text(encoding='utf-8'))
    config = yaml.safe_load(args.config.read_text(encoding='utf-8-sig'))
    if config['transport']['type'] != 'worker':
        raise ValueError('要求WSS Worker配置')
    # 先校验配套GUI包，随后只拷贝明确列出的程序和许可证。
    for line in (gui/'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines():
        digest, name = line.split('  ',1)
        item = (gui/name).resolve()
        if not item.is_relative_to(gui.resolve()) or hashlib.sha256(item.read_bytes()).hexdigest() != digest:
            raise ValueError('GUI包校验失败：'+name)
    out.mkdir(exist_ok=False)
    for name in ('Throne.exe','ThroneCore.exe','libcronet.dll','updater.exe'):
        shutil.copy2(gui/name,out/name)
    shutil.copytree(gui/'licenses',out/'licenses')
    shutil.copy2(ROOT/'LICENSE.md',out/'licenses/Hysteria-LICENSE.md')
    shutil.copy2(base/'hysteria-worker-windows-amd64.exe',out/'hysteria-worker.exe')
    ca = Path(config['tls']['ca'])
    if not ca.is_absolute(): ca = args.config.resolve().parent/ca
    shutil.copy2(ca,out/'server.crt')
    shutil.copy2(base/'live/worker-bootstrap.json',out/'worker-bootstrap.json')
    config['tls']['ca']='server.crt'
    for key in ('tun','http','socks5'): config.pop(key,None)
    config['transport']['worker'].pop('dialIP',None)
    (out/'client-base.json').write_text(json.dumps(config,ensure_ascii=False,indent=2),encoding='utf-8')
    for name,target in [('prepare-throne-worker.ps1','prepare-throne.ps1'),('start-throne-worker.cmd','start-throne.cmd')]:
        shutil.copy2(ROOT/'scripts/hdm'/name,out/target)
    profile = {'name':'US13 · WSS握手后UDP直连', 'type':'extracore', 'socks_address':'127.0.0.1', 'socks_port':18480,
               'extra_core_path':'../hysteria-worker.exe', 'extra_core_args':'client -c ../worker-client.json', 'extra_core_conf':'', 'no_logs':False}
    (out/'config').mkdir()
    bootstrap = json.loads((out/'worker-bootstrap.json').read_text())
    server = config['server'].rsplit(':',1)[0]
    create_database(out/'config/throne.db',source,profile,[*bootstrap['ipv4'],server,'43.252.41.230'])
    metadata = {'packageVersion':args.version,'hysteria':info,'throne':json.loads((gui/'package-info.json').read_text(encoding='utf-8')),'integration':'Throne ExtraCore SOCKS5 TCP/UDP; TUN owned by Throne'}
    (out/'build-info.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'使用说明.txt').write_text("""Throne WSS握手后UDP迁移日常试用包

1. 完整解压到可写目录，保留全部文件；先从托盘退出旧Throne，并关闭CMD/TUN测试客户端。
2. 每次双击start-throne.cmd。它重新检查入口证书与可达性，写入配置，然后打开Throne。
3. 节点已预置：US13 · WSS握手后UDP直连。选中节点并启动，等待日志出现connected to server，再在Throne开启TUN，按提示授权管理员权限。
4. 初次打开不自动连接、不自动开启系统代理或TUN。平常在Throne里切换、停止节点和查看日志。
5. 要停止接管网络，关闭TUN、停止节点；从托盘退出可一并关闭外部核心。

界面保留用户头像图标，GUI仍显示1.3.2-hdm.0.3.2；交付包及Hysteria核心版本见build-info.json。
此版由Throne管理TUN、DNS与分流，Hysteria外部核心完成WSS认证及同一QUIC会话迁移。
不是sing-box原生WSS实现。默认全局代理、局域网直连；外部核心及入口/服务端流量直连以避免循环。
本机代理端口2082，内部SOCKS端口18480；均只监听127.0.0.1。不要同时开多个测试包。
移动目录后必须重新运行start-throne.cmd，更新CA绝对路径。不要只复制Throne.exe，也不要直接用旧HDM节点代替此节点。

加密DNS不可用时会尝试缓存IP，每个候选地址必须通过当前域名的TLS证书及/health检查。
缓存到期不直接放行：成功重新验证TLS才可继续；所有入口不可达时停止启动，保留原配置。
程序运行期间固定入口IP；网络切换后如不能恢复，请停止节点、退出Throne并重新运行start-throne.cmd。
UDP故障不会自动回退Worker承载业务。已有连接可能中断，新连接由核心重新握手；外部核心异常退出会停止节点。
此前UDP DNS短测存在间歇性超时，仍需日常验证。若出现问题，请保留发生时间及Throne日志，勿公开真实配置。

本包包含个人Worker令牌和HY2密码，请勿公开分享；不含Cloudflare管理密钥及SSH私钥。
""",encoding='utf-8-sig')
    files = sorted(p for p in out.rglob('*') if p.is_file())
    (out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(out).as_posix()+'\n' for p in files),encoding='utf-8')
    archive = Path(str(out)+'.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(out.rglob('*')):
            if p.is_file(): z.write(p,out.name+'/'+p.relative_to(out).as_posix())
    with zipfile.ZipFile(archive) as z: assert z.testzip() is None
    print('Throne package:',out)
    print('Archive:',archive)
    print('SHA256:',hashlib.sha256(archive.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
