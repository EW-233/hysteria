"""使用本机独立签名构建 APK，并交付配置、许可证及来源清单。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'build/android-kex'


def run(args, cwd=ROOT, env=None):
    subprocess.run([str(a) for a in args],cwd=cwd,env=env,check=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def revision(path):
    return subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT.parent/'sing-box-for-android-kex')
    parser.add_argument('--java-home',type=Path,default=Path('C:/Program Files/Android/Android Studio/jbr'))
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--package-only',action='store_true',help='仅打包已经构建和签名的 APK')
    parser.add_argument('--signing-dir',type=Path,required=True,help='Git 外的原有签名目录；更新安装须沿用同一密钥')
    args=parser.parse_args()
    source=args.source.resolve()
    sdk=Path(os.environ['ANDROID_HOME'])
    env=dict(os.environ,JAVA_HOME=str(args.java_home),GOTOOLCHAIN='go1.26.3')
    # 签名私钥及口令保持在用户私密目录；不写入源码或交付包。
    private=args.signing_dir.resolve()
    private.mkdir(parents=True,exist_ok=True)
    key=private/'greywolf-kex.p12'
    metadata=private/'signing.json'
    if not metadata.exists():
        metadata.write_text(json.dumps({'password':secrets.token_urlsafe(32),'alias':'greywolf-kex'}),encoding='utf-8')
    signing=json.loads(metadata.read_text(encoding='utf-8'))
    if not key.exists():
        keyenv=dict(env,KEX_SIGN_PASSWORD=signing['password'])
        run([args.java_home/'bin/keytool.exe','-genkeypair','-keystore',key,'-storetype','PKCS12',
             '-storepass:env','KEX_SIGN_PASSWORD','-alias',signing['alias'],'-keyalg','RSA','-keysize','3072',
             '-validity','10000','-dname','CN=GreyWolf KEX Local Build'],env=keyenv)
    props={'sdk.dir':sdk.as_posix(),'KEYSTORE_FILE':key.as_posix(),'KEYSTORE_PASS':signing['password'],
           'ALIAS_NAME':signing['alias'],'ALIAS_PASS':signing['password']}
    (source/'local.properties').write_text(''.join(k+'='+v+'\n' for k,v in props.items()),encoding='utf-8')
    if not args.package_only:
        (source/'app/libs').mkdir(exist_ok=True)
        shutil.copy2(OUT/'libbox.aar',source/'app/libs/libbox.aar')
        run([source/'gradlew.bat',':app:assembleOtherRelease','--console=plain','--max-workers=4'],cwd=source,env=env)
    run([sys.executable,ROOT/'scripts/hdm/prepare-android-profile.py','--config',args.config],env=env)
    # 校验实际导入文件经过移动端注册表后可构建，且不会主动访问握手入口。
    box=OUT/'sing-box'
    shutil.copy2(ROOT/'scripts/hdm/android-libbox_test.go',box/'experimental/libbox/android_kex_test.go')
    checkenv=dict(env,GOWORK=str(OUT/'go.work'),ANDROID_KEX_CHECK_CONFIG=str(OUT/'Example-KEX-Android.private.json'))
    info=json.loads((OUT/'build-info.json').read_text(encoding='utf-8'))
    if digest(OUT/'libbox.aar')!=info['aar_sha256'] or digest(source/'app/libs/libbox.aar')!=info['aar_sha256']:
        raise RuntimeError('AAR 与来源清单不一致')
    run(['go','test','-ldflags=-checklinkname=0','-tags',info['tags'],'./experimental/libbox',
         '-run','TestAndroidKEXProfileOffline','-count=1'],cwd=box,env=checkenv)
    delivery=OUT/'GreyWolf-KEX-0.11.0-android'
    delivery.mkdir(exist_ok=False)
    info['android_gui_commit']=revision(source)
    info['repositories']={name:revision(path) for name,path in [('dual-hy2',ROOT),('Throne',ROOT.parent/'Throne-hdm'),('sing-quic',ROOT.parent/'sing-quic-hdm')]}
    elf_results=[]
    info['application_id']='dev.greywolf.kex'
    info['profile_check']='passed; no network handshake'
    info['device_runtime_tested']=False
    info['private_profile_included']=True
    for path in sorted((source/'app/build/outputs/apk/other/release').glob('GreyWolf-KEX-0.11.0-*.apk')):
        abi='universal' if 'universal' in path.name else ('arm64-v8a' if 'arm64-v8a' in path.name else 'x86_64')
        output=delivery/f'GreyWolf-KEX-0.11.0-{abi}.apk'
        shutil.copy2(path,output)
        with zipfile.ZipFile(output) as archive:
            if archive.testzip(): raise RuntimeError('APK ZIP 完整性失败')
            found={name.split('/')[1] for name in archive.namelist() if name.startswith('lib/') and name.endswith('.so')}
            core_abis={name.split('/')[1] for name in archive.namelist() if name.startswith('lib/') and name.endswith('/libbox.so')}
            expected={'arm64-v8a','x86_64'} if abi=='universal' else {abi}
            if found!=expected or core_abis!=expected: raise RuntimeError('APK 原生架构不完整或混入未支持架构')
            # 所有原生依赖都须满足 16 KiB 页对齐，不能只检查自建的 Go 核心。
            elfdir=OUT/'elf-check'; elfdir.mkdir(exist_ok=True)
            readelf=sdk/'ndk/28.0.13004108/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe'
            for name in archive.namelist():
                if not name.startswith('lib/') or not name.endswith('.so'): continue
                extracted=elfdir/name.replace('/','_')
                extracted.write_bytes(archive.read(name))
                text=subprocess.check_output([str(readelf),'-lW',str(extracted)],encoding='utf-8')
                alignments=[int(line.split()[-1],16) for line in text.splitlines() if line.strip().startswith('LOAD')]
                if not alignments or min(alignments)<16384: raise RuntimeError('原生依赖不满足 16 KiB 对齐：'+name)
                elf_results.append({'apk':output.name,'library':name,'min_load_alignment':min(alignments)})
        manifest=subprocess.check_output([str(sdk/'build-tools/37.0.0/aapt2.exe'),'dump','badging',str(output)],encoding='utf-8')
        for expected in ["name='dev.greywolf.kex'","versionName='0.11.0'","minSdkVersion:'24'","application-label:'灰狼 KEX'"]:
            if expected not in manifest: raise RuntimeError('安装包身份或系统版本校验失败')
        with (delivery/f'{abi}-signature.txt').open('w',encoding='utf-8') as log:
            subprocess.run([str(sdk/'build-tools/37.0.0/apksigner.bat'),'verify','--verbose','--print-certs',str(output)],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        run([sdk/'build-tools/37.0.0/zipalign.exe','-c','-P','16','4',output],env=env)
    (delivery/'native-library-verification.json').write_text(json.dumps(elf_results,indent=2)+'\n',encoding='utf-8')
    if len(list(delivery.glob('*.apk')))!=3: raise RuntimeError('缺少预期 APK')
    shutil.copy2(OUT/'Example-KEX-Android.private.json',delivery/'Example-KEX-Android.private.json')
    licenses=delivery/'licenses'; licenses.mkdir()
    for path,name in [(source/'LICENSE','Android-GUI-LICENSE.txt'),(box/'LICENSE','sing-box-LICENSE.txt'),(ROOT/'LICENSE.md','Hysteria-LICENSE.md')]:
        shutil.copy2(path,licenses/name)
    (delivery/'build-info.json').write_text(json.dumps(info,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    shutil.copy2(ROOT/'docs/android-kex.md',delivery/'使用说明.md')
    (delivery/'SHA256SUMS.txt').write_text(''.join(digest(p)+'  '+p.relative_to(delivery).as_posix()+'\n' for p in sorted(delivery.rglob('*')) if p.is_file()),encoding='utf-8')
    archive=Path(str(delivery)+'-private.zip')
    if archive.exists(): raise RuntimeError('交付归档已存在')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(delivery.rglob('*')):
            if p.is_file(): z.write(p,delivery.name+'/'+p.relative_to(delivery).as_posix())
    print('Delivery:',delivery)
    print('Archive SHA256:',digest(archive))


if __name__=='__main__':
    main()
