"""构建 Android 原生 KEX 核心；使用隔离源码副本，不改正在使用的桌面核心。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'build/android-kex'
TAGS = 'kex_poc,with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_purego,badlinkname,tfogo_checklinkname0'


def run(args, cwd=ROOT, env=None):
    subprocess.run([str(x) for x in args], cwd=cwd, env=env, check=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--skip-tests', action='store_true')
    parser.add_argument('--target', default='android/arm64,android/amd64')
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    box_source = ROOT.parent / 'sing-box-hdm'
    box = OUT / 'sing-box'
    throne = ROOT.parent / 'Throne-hdm'
    adapter = throne / 'core/internal/kexoutbound'
    patch_hash = sha(ROOT / 'scripts/hdm/quic-kex.patch')
    quic = ROOT / 'build' / ('kex-network-' + patch_hash[:12])
    run([sys.executable, ROOT / 'scripts/hdm/prepare-kex-quic.py', '--output', quic])
    if not box.exists():
        run(['git', 'clone', '--no-hardlinks', box_source, box])
    expected = subprocess.check_output(['git', '-C', str(box_source), 'rev-parse', 'HEAD'], text=True).strip()
    actual = subprocess.check_output(['git', '-C', str(box), 'rev-parse', 'HEAD'], text=True).strip()
    if expected != actual:
        raise RuntimeError('隔离核心版本不同，请使用新的构建目录')
    # 复用已经验收的桌面适配器；逐文件记录哈希，避免两套协议实现漂移。
    dest = box / 'protocol/kexoutbound'
    dest.mkdir(exist_ok=True)
    hashes = {}
    for source in sorted(adapter.glob('*.go')):
        shutil.copy2(source, dest / source.name)
        hashes[source.name] = sha(source)
    config = box / 'experimental/libbox/config.go'
    original = subprocess.check_output(['git', '-C', str(box), 'show', 'HEAD:experimental/libbox/config.go']).decode()
    original = original.replace('"github.com/sagernet/sing-box/option"', '"github.com/sagernet/sing-box/option"\n "github.com/sagernet/sing-box/protocol/kexoutbound"')
    original = original.replace('return box.Context(ctx, include.InboundRegistry(), include.OutboundRegistry(),', 'outboundRegistry := include.OutboundRegistry()\n kexoutbound.Register(outboundRegistry)\n return box.Context(ctx, include.InboundRegistry(), outboundRegistry,')
    config.write_text(original, encoding='utf-8')
    def quote(path):
        return json.dumps(os.path.relpath(path, OUT).replace('\\', '/'))
    workspace = 'go 1.26.0\n\nuse (\n '+quote(box)+'\n '+quote(ROOT/'core')+'\n)\n'
    workspace += '\nreplace github.com/sagernet/sing-quic => '+quote(ROOT.parent/'sing-quic-hdm')+'\n'
    workspace += '\nreplace github.com/apernet/quic-go => '+quote(quic/'quic-go')+'\n'
    (OUT / 'go.work').write_text(workspace, encoding='utf-8')
    tools = OUT / 'tools'
    tools.mkdir(exist_ok=True)
    sdk = Path(os.environ['ANDROID_HOME'])
    env = dict(os.environ, GOTOOLCHAIN='go1.26.3', GOWORK=str(OUT/'go.work'), GOBIN=str(tools),
               ANDROID_NDK_HOME=str(sdk/'ndk/28.0.13004108'), CGO_ENABLED='1')
    env['PATH'] = str(tools)+os.pathsep+env['PATH']
    # 只做编译/本地回环测试，不访问实际节点，也不创建宿主机 TUN。
    if args.prepare_only:
        print('GOWORK='+env['GOWORK'])
        return
    if not args.skip_tests:
        run(['go', 'test', '-ldflags=-checklinkname=0', '-tags', TAGS, './protocol/kexoutbound', '-count=1', '-timeout=90s'], box, env)
    run(['go', 'install', 'github.com/sagernet/gomobile/cmd/gomobile', 'github.com/sagernet/gomobile/cmd/gobind'], box, env)
    aar = OUT / 'libbox.aar'
    flags = '-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=1.14-kex.0.11.0'
    run([tools/'gomobile.exe', 'bind', '-o', aar, '-target', args.target, '-androidapi', '24',
         '-javapkg=io.nekohasekai', '-libname=box', '-trimpath', '-buildvcs=false',
         '-ldflags', flags, '-tags', TAGS, './experimental/libbox'], box, env)
    revisions = {name:subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()
                 for name,path in [('dual-hy2',ROOT),('Throne',throne),('sing-quic',ROOT.parent/'sing-quic-hdm')]}
    info = {'repositories':revisions, 'ndk':'28.0.13004108', 'version':'0.11.0', 'go':'go1.26.3', 'target':args.target, 'tags':TAGS,
            'sing_box_commit':expected, 'adapter_sha256':hashes, 'quic_patch_sha256':patch_hash,
            'aar_sha256':sha(aar), 'tests_run':not args.skip_tests}
    (OUT/'build-info.json').write_text(json.dumps(info,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Built:', aar)


if __name__ == '__main__':
    main()
