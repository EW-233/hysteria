"""为已检出的 SFA 1.14.2 源码设置实验包身份及用户指定图标。"""
import argparse
from pathlib import Path
from PIL import Image


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--icon', type=Path, required=True)
    args=parser.parse_args()
    root=args.source
    def edit(path, transform):
        file=root/path
        file.write_text(transform(file.read_text(encoding='utf-8')),encoding='utf-8')
    edit('app/build.gradle.kts', lambda s: s.replace('applicationId = "io.nekohasekai.sfa"','applicationId = "dev.greywolf.kex"').replace('base.archivesName.set("SFA-${versionName}")','base.archivesName.set("GreyWolf-KEX-${versionName}")').replace('include("armeabi-v7a", "arm64-v8a", "x86", "x86_64")','include("arm64-v8a", "x86_64")'))
    edit('app/build.gradle.kts',lambda s:s.replace('storeFile = file("release.keystore")','storeFile = file(getProps("KEYSTORE_FILE").ifEmpty { "release.keystore" })'))
    edit('app/src/main/java/io/nekohasekai/sfa/bg/VPNService.kt',lambda s:s.replace('        protect(fd)','        // 保护失败时停止拨号，避免握手流量重新进入 VPN。\n        check(protect(fd)) { "无法保护 VPN 出站套接字" }').replace('.setSession("sing-box")','.setSession("灰狼 KEX")'))
    edit('app/build.gradle.kts',lambda s:s if '**/armeabi-v7a/**' in s else s.replace('            useLegacyPackaging = true','            useLegacyPackaging = true\n            // 核心仅支持 64 位，通用包也必须排除依赖中附带的 32 位库。\n            excludes += setOf("**/armeabi-v7a/**", "**/x86/**")'))
    (root/'version.properties').write_text('VERSION_CODE=1100\nVERSION_NAME=0.11.0\nGO_VERSION=go1.26.3\n',encoding='utf-8')
    edit('app/src/main/res/values/strings.xml',lambda s:s.replace('<string name="app_name" translatable="false">sing-box</string>','<string name="app_name" translatable="false">灰狼 KEX</string>'))
    edit('app/src/main/AndroidManifest.xml',lambda s:s.replace('android:allowBackup="true"','android:allowBackup="false"'))
    def vendor(s):
        s=s.replace('override val hasCustomUpdate = true','// 实验核心通过手动安装新实验包更新，避免上游包覆盖。\n    override val hasCustomUpdate = false')
        start=s.index('    override fun checkUpdateAsync():')
        end=s.index('    override suspend fun verifySilentInstallMethod',start)
        return s[:start]+'''    override fun checkUpdateAsync(): UpdateInfo? = null

    override fun scheduleAutoUpdate() {
        // 本测试包不调度上游自动更新。
    }

'''+s[end:]
    edit('app/src/other/java/io/nekohasekai/sfa/vendor/Vendor.kt',vendor)
    # 生成各屏幕密度的图标，保留原始图片；自适应图标留出裁切安全区。
    im=Image.open(args.icon).convert('RGBA')
    side=min(im.size); left=(im.width-side)//2; top=(im.height-side)//2
    im=im.crop((left,top,left+side,top+side))
    for density,size in [('mdpi',48),('hdpi',72),('xhdpi',96),('xxhdpi',144),('xxxhdpi',192)]:
        im.resize((size,size),Image.Resampling.LANCZOS).save(root/f'app/src/main/res/mipmap-{density}/ic_launcher.png')
    fg=Image.new('RGBA',(432,432),(30,30,35,255))
    fg.alpha_composite(im.resize((288,288),Image.Resampling.LANCZOS),(72,72))
    (root/'app/src/main/res/drawable-nodpi').mkdir(exist_ok=True)
    fg.save(root/'app/src/main/res/drawable-nodpi/kex_launcher.png')
    (root/'app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml').write_text('''<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@drawable/kex_launcher" />
</adaptive-icon>
''',encoding='utf-8')
    print('已设置独立身份、图标和更新策略。')


if __name__=='__main__':
    main()
