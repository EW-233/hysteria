# 构建隔离 KEX 实验 CLI；仅复制无凭据示例，不改变默认工作区依赖。
param(
    [string]$Version = '0.8.0-kex-poc',
    [string]$Workspace = ''
)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$outputDir = Join-Path $projectRoot 'build/kex-cli'
$originalEnv = @{}
foreach ($name in @('GOWORK', 'GOTOOLCHAIN', 'GOOS', 'GOARCH', 'CGO_ENABLED', 'GOFLAGS')) {
    $originalEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location $projectRoot
try {
    # 固定已验证的补丁版本，避免 Go 1.26.0 在 Windows race UDP 大流量测试中的崩溃。
    $env:GOTOOLCHAIN = 'go1.26.3'
    $env:GOFLAGS = ''
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    if ([string]::IsNullOrWhiteSpace($Workspace)) {
        # 按补丁内容隔离，更新后自动使用新目录，保留旧实验而不要求手动清理。
        $patchHash = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'quic-kex.patch') -Algorithm SHA256).Hash.ToLowerInvariant().Substring(0, 12)
        $workspaceDir = "build/kex-network-$patchHash"
        & python (Join-Path $PSScriptRoot 'prepare-kex-quic.py') --output $workspaceDir
        if ($LASTEXITCODE -ne 0) { throw '隔离 QUIC 工作区准备失败；请确认最终补丁与 manifest 已更新' }
        $Workspace = Join-Path $projectRoot ($workspaceDir + '/go.work')
    } elseif (-not [IO.Path]::IsPathRooted($Workspace)) {
        $Workspace = Join-Path $projectRoot $Workspace
    }
    $env:GOWORK = (Resolve-Path -LiteralPath $Workspace).Path
    $goVersion = (& go env GOVERSION).Trim()
    if ($LASTEXITCODE -ne 0 -or $goVersion -ne 'go1.26.3') { throw '需要已验证的 Go 1.26.3 工具链' }
    $revision = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw '读取 Git 版本失败' }
    $dirtyPaths = @(& git status --porcelain)
    $dirty = $dirtyPaths.Count -gt 0
    $builtAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

    # 常规测试先覆盖配置脱敏、路由排除、真实回环 TCP/DNS；race 独立运行需 C 编译器。
    & go test -count=1 -timeout 90s -tags kex_poc ./app/cmd/kex-poc
    if ($LASTEXITCODE -ne 0) { throw 'KEX CLI 测试失败' }
    $outputs = @()
    foreach ($target in @('windows', 'linux')) {
        $env:GOOS = $target
        $targetDir = Join-Path $outputDir "$target-amd64"
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        $suffix = if ($target -eq 'windows') { '.exe' } else { '' }
        $binary = Join-Path $targetDir "kex-poc$suffix"
        & go build -mod=readonly -trimpath -tags kex_poc -ldflags "-s -w -X main.version=$Version" -o $binary ./app/cmd/kex-poc
        if ($LASTEXITCODE -ne 0) { throw "$target CLI 构建失败" }
        Copy-Item -LiteralPath (Join-Path $projectRoot 'app/cmd/kex-poc/examples/client.example.json') -Destination $targetDir -Force
        Copy-Item -LiteralPath (Join-Path $projectRoot 'app/cmd/kex-poc/examples/server.example.json') -Destination $targetDir -Force
        Copy-Item -LiteralPath (Join-Path $projectRoot 'docs/worker-kex-test-cli.md') -Destination $targetDir -Force
        $packageFiles = @($binary, (Join-Path $targetDir 'client.example.json'), (Join-Path $targetDir 'server.example.json'), (Join-Path $targetDir 'worker-kex-test-cli.md'))
        if ($target -eq 'windows') {
            foreach ($launcher in @('start-kex-poc.cmd', 'start-kex-poc-tun.cmd')) {
                Copy-Item -LiteralPath (Join-Path $PSScriptRoot $launcher) -Destination $targetDir -Force
                $packageFiles += Join-Path $targetDir $launcher
            }
            & $binary version
            if ($LASTEXITCODE -ne 0) { throw 'Windows CLI 启动验证失败' }
        }
        # 精确列出打包文件，避免误打包用户后来放入的真实 client.json、密钥或证书。
        $archive = Join-Path $outputDir "kex-poc-$target-amd64.zip"
        Compress-Archive -LiteralPath $packageFiles -DestinationPath $archive -Force
        $outputs += $binary, $archive
    }
    $manifest = foreach ($file in $outputs) {
        $relative = $file.Substring($outputDir.Length + 1).Replace('\', '/')
        '{0}  {1}' -f (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
    }
    [IO.File]::WriteAllLines((Join-Path $outputDir 'SHA256SUMS'), $manifest, [Text.UTF8Encoding]::new($false))
    $info = @{ version=$Version; commit=$revision; dirty=$dirty; dirtyPaths=$dirtyPaths; patchSHA256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'quic-kex.patch') -Algorithm SHA256).Hash.ToLowerInvariant(); builtAt=$builtAt; go=$goVersion; tag='kex_poc'; workspace=$env:GOWORK } | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $outputDir 'build-info.json'), $info, [Text.UTF8Encoding]::new($false))
    Write-Host "构建与打包完成：$outputDir"
} finally {
    Pop-Location
    foreach ($name in $originalEnv.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalEnv[$name], 'Process')
    }
}
