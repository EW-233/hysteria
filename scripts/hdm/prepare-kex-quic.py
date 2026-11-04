#!/usr/bin/env python3
"""准备隔离的 QUIC 外部握手实验；校验固定依赖和补丁，不改全局模块缓存。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args: list[str], cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(args, cwd=cwd, env=env, text=True, encoding="utf-8", capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result.stdout


def verify_files(folder: Path, manifest: dict, state: str) -> None:
    for name, entry in manifest["files"].items():
        path = folder / name
        expected = entry[state]
        if expected is None:
            if path.exists():
                raise RuntimeError(f"unexpected preexisting file: {name}")
        elif not path.is_file() or digest(path) != expected:
            raise RuntimeError(f"refusing modified or mismatched file: {name}")


def workspace(folder: Path) -> str:
    # Go workspace 路径使用引号与正斜杠，支持包含空格的 Windows 工作区。
    paths = [os.path.relpath(ROOT / name, folder).replace("\\", "/") for name in ("core", "app", "extras")]
    entries = "\n".join(" " + json.dumps(p, ensure_ascii=False) for p in paths)
    return "go 1.26.0\n\nuse (\n" + entries + "\n)\n\nreplace github.com/apernet/quic-go => ./quic-go\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="build/kex-network", help="仓库 build 内的独立实验目录")
    args = parser.parse_args()
    folder = (ROOT / args.output).resolve()
    build = (ROOT / "build").resolve()
    if not folder.is_relative_to(build) or folder == build:
        raise RuntimeError("output must be a child of this repository's build directory")
    patch = HERE / "quic-kex.patch"
    manifest = json.loads((HERE / "quic-kex-manifest.json").read_text(encoding="utf-8"))
    patch_hash = digest(patch)
    marker = folder / "prepared.json"
    if folder.exists():
        if not marker.is_file() or json.loads(marker.read_text(encoding="utf-8")) != {"patch_sha256": patch_hash, "manifest": manifest}:
            raise RuntimeError("existing experiment differs; use a new output directory; nothing was overwritten")
        verify_files(folder / "quic-go", manifest, "after")
        if (folder / "go.work").read_text(encoding="utf-8") != workspace(folder):
            raise RuntimeError("existing workspace was modified; nothing was overwritten")
        print(f"Verified existing experiment: {folder}")
        return
    env = dict(os.environ, GOWORK="off")
    module = manifest["module"] + "@" + manifest["version"]
    # 显式下载固定版本，使用 Go 的校验和数据库；不通过未知镜像关闭校验。
    with tempfile.TemporaryDirectory(prefix="hy2-kex-mod-") as probe:
        download = json.loads(run(["go", "mod", "download", "-json", module], Path(probe), env))
    if download.get("Sum") != manifest["sum"] or download.get("Version") != manifest["version"]:
        raise RuntimeError("pinned module checksum/version mismatch")
    source = Path(download["Dir"])
    verify_files(source, manifest, "before")
    folder.parent.mkdir(parents=True, exist_ok=True)
    folder.mkdir()
    # 失败时保留诊断目录，绝不递归删除用户目录或覆盖未知文件。
    target = folder / "quic-go"
    shutil.copytree(source, target)
    for path in target.rglob("*"):
        if path.is_file():
            path.chmod(path.stat().st_mode | stat.S_IWRITE)
    relative = target.relative_to(ROOT).as_posix()
    run(["git", "-c", "core.autocrlf=false", "apply", "--check", "--directory=" + relative, str(patch)], ROOT, env)
    run(["git", "-c", "core.autocrlf=false", "apply", "--directory=" + relative, str(patch)], ROOT, env)
    verify_files(target, manifest, "after")
    (folder / "go.work").write_text(workspace(folder), encoding="utf-8", newline="\n")
    marker.write_text(json.dumps({"patch_sha256": patch_hash, "manifest": manifest}, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Prepared external-handshake experiment: {folder}")
    print(f"GOWORK={folder / 'go.work'}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        raise SystemExit(f"Preparation failed: {error}")
