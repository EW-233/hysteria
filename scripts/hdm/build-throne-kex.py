"""构建原生 KEX ThroneCore；隔离 workspace，不修改 GUI 仓库原有依赖文件。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TAGS = 'kex_poc,with_clash_api,with_gvisor,with_quic,with_wireguard,with_utls,with_dhcp,with_tailscale,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0,with_purego,with_naive_outbound'


def run(args, env=None):
    subprocess.run([str(x) for x in args], cwd=ROOT, env=env, check=True)


def revision(path):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(path), *args], text=True, encoding='utf-8').strip()
    return {'commit': git('rev-parse', 'HEAD'), 'status': git('status', '--short')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--throne-source', type=Path, default=ROOT.parent/'Throne-hdm')
    parser.add_argument('--sing-box', type=Path, default=ROOT.parent/'sing-box-hdm')
    parser.add_argument('--sing-quic', type=Path, default=ROOT.parent/'sing-quic-hdm')
    parser.add_argument('--version', default='0.9.0')
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--skip-tests', action='store_true', help='仅用于本轮相同源码测试已经通过后的重新打包')
    args = parser.parse_args()
    source, box, sq = [p.resolve() for p in (args.throne_source, args.sing_box, args.sing_quic)]
    env = dict(os.environ, GOTOOLCHAIN='go1.26.3')
    patch_hash = hashlib.sha256((ROOT/'scripts/hdm/quic-kex.patch').read_bytes()).hexdigest()
    fork = ROOT/'build'/('kex-network-'+patch_hash[:12])
    run([sys.executable, ROOT/'scripts/hdm/prepare-kex-quic.py', '--output', fork], env)
    out = ROOT/'build/throne-kex'
    out.mkdir(parents=True, exist_ok=True)
    # Windows 的 Go 模块路径匹配使用原生规范化；同盘使用相对路径避免绝对路径分隔符差异。
    def quote(path):
        try:
            value = os.path.relpath(path, out).replace('\\', '/')
        except ValueError:
            value = str(path)
        return json.dumps(value)
    workspace = 'go 1.26.0\n\nuse (\n '+quote(source/'core')+'\n '+quote(ROOT/'core')+'\n)\n'
    for mod, path in [('github.com/sagernet/sing-box', box), ('github.com/sagernet/sing-quic', sq), ('github.com/apernet/quic-go', fork/'quic-go')]:
        workspace += '\nreplace '+mod+' => '+quote(path)+'\n'
    (out/'go.work').write_text(workspace, encoding='utf-8', newline='\n')
    env['GOWORK'] = str(out/'go.work')
    if args.prepare_only:
        print('GOWORK='+env['GOWORK'])
        return
    if not args.skip_tests:
        # race 覆盖本地真实 QUIC 会话；不会访问公网，也不创建 TUN。
        test_env = dict(env, CGO_ENABLED='1')
        test_env.pop('KEX_NATIVE_LIVE_CONFIG', None)
        run(['go', '-C', source/'core', 'test', '-race', '-tags', 'kex_poc,with_quic,with_gvisor,with_clash_api,with_utls', './internal/kexoutbound', './internal/boxmain', '-count=1', '-timeout=90s'], test_env)
    binary = out/'ThroneCore.exe'
    flags = '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14-kex.'+args.version+' -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0'
    run(['go', '-C', source/'core', 'build', '-trimpath', '-ldflags', flags, '-tags', TAGS, '-o', binary, '.'], dict(env, CGO_ENABLED='0'))
    info = {'version':args.version, 'go':'go1.26.3', 'tags':TAGS, 'quic_patch_sha256':patch_hash,
            'repositories':{name:revision(path) for name,path in [('dual-hy2',ROOT),('Throne',source),('sing-box',box),('sing-quic',sq)]},
            'core_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(), 'tests_run':not args.skip_tests}
    (out/'build-info.json').write_text(json.dumps(info,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Built:',binary)


if __name__ == '__main__':
    main()
