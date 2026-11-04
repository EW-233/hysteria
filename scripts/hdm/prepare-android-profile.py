"""生成 Android TUN 配置；真实令牌仅写入 ignored 构建目录。"""
import argparse
import ipaddress
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def android_profile(config):
    # 只选取跨平台字段，不能继承 Windows 的源地址、网卡或 CLI TUN 配置。
    host, port = config['udp_address'].rsplit(':', 1)
    host = str(ipaddress.ip_address(host.strip('[]')))
    outbound = {k: config[k] for k in ('service_id', 'private_key_hex', 'server_public_key_hex', 'https')}
    outbound.update(type='hysteria2-kex', tag='kex-out', server=host, server_port=int(port))
    if 'max_rx' in config:
        outbound['max_rx'] = config['max_rx']
    return {
        'log': {'level':'info', 'timestamp':True},
        'dns': {'servers':[{'type':'https','tag':'remote','server':'1.1.1.1','server_port':443,
                            'path':'/dns-query','tls':{'enabled':True,'server_name':'cloudflare-dns.com'},
                            'detour':'kex-out'}], 'final':'remote', 'strategy':'prefer_ipv4'},
        'inbounds':[{'type':'tun','tag':'tun-in','address':['172.19.0.1/30','fdfe:dcba:9876::1/126'],
                     'mtu':1400,'auto_route':True,'strict_route':True,'stack':'gvisor','dns_mode':'hijack'}],
        'outbounds':[outbound, {'type':'direct','tag':'direct'}],
        'route':{'auto_detect_interface':True, 'default_domain_resolver':'remote',
                 'rules':[{'action':'sniff'},{'protocol':'dns','action':'hijack-dns'},
                          {'ip_is_private':True,'outbound':'direct'}], 'final':'kex-out'}
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    args=parser.parse_args()
    config=json.loads(args.config.read_text(encoding='utf-8'))
    output=ROOT/'build/android-kex/Example-KEX-Android.private.json'
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(android_profile(config),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Android profile generated; contents withheld.')


if __name__=='__main__':
    main()
