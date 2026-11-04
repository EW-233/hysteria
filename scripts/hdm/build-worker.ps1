# 构建 WSS 握手中继实验的 CLI 和 Bridge，保留原 HDM 构建目录。
param([string]$Version = '0.5.6-worker-tun', [string]$Toolchain = 'go1.26.3')
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$outputDir = Join-Path $projectRoot 'build/worker-hdm'
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
$originalEnv = @{}
foreach ($name in @('GOOS', 'GOARCH', 'CGO_ENABLED', 'GOTOOLCHAIN')) {
    $originalEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location $projectRoot
try {
    $revision = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw '无法读取 Git 提交' }
    $dirty = [bool](git status --porcelain)
    $buildRevision = if ($dirty) { "$revision-dirty" } else { $revision }
    $env:GOTOOLCHAIN = $Toolchain
    $env:CGO_ENABLED = '0'
    $goVersion = (& go env GOVERSION).Trim()
    if ($LASTEXITCODE -ne 0) { throw '工具链不可用' }
    $quicVersion = (& go list -m -f '{{.Version}}' github.com/apernet/quic-go).Trim()
    if ($LASTEXITCODE -ne 0) { throw '无法读取 QUIC 依赖版本' }
    $builtAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $pkg = 'github.com/apernet/hysteria/app/v2/cmd'
    $outputs = @()
    foreach ($target in @(@('windows', 'amd64'), @('linux', 'amd64'))) {
        $env:GOOS = $target[0]
        $env:GOARCH = $target[1]
        $suffix = if ($env:GOOS -eq 'windows') { '.exe' } else { '' }
        $cli = Join-Path $outputDir "hysteria-worker-$env:GOOS-$env:GOARCH$suffix"
        $bridge = Join-Path $outputDir "hdm-bridge-$env:GOOS-$env:GOARCH$suffix"
        $flags = "-s -w -X $pkg.appVersion=$Version -X $pkg.appCommit=$buildRevision -X $pkg.appDate=$builtAt -X $pkg.appType=experimental -X $pkg.appToolchain=$goVersion -X $pkg.libVersion=$quicVersion -X $pkg.appPlatform=$env:GOOS -X $pkg.appArch=$env:GOARCH"
        & go build -trimpath -ldflags $flags -o $cli ./app
        if ($LASTEXITCODE -ne 0) { throw 'CLI 构建失败' }
        & go build -trimpath -ldflags '-s -w' -o $bridge ./extras/cmd/hdm-bridge
        if ($LASTEXITCODE -ne 0) { throw 'Bridge 构建失败' }
        $outputs += $cli, $bridge
    }
    $manifest = foreach ($path in $outputs) {
        '{0}  {1}' -f (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(), (Split-Path $path -Leaf)
    }
    [IO.File]::WriteAllLines((Join-Path $outputDir 'SHA256SUMS'), $manifest, [Text.UTF8Encoding]::new($false))
    $info = @{ version=$Version; commit=$revision; dirty=$dirty; builtAt=$builtAt; go=$goVersion } | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $outputDir 'build-info.json'), $info, [Text.UTF8Encoding]::new($false))
    & (Join-Path $outputDir 'hysteria-worker-windows-amd64.exe') version
    if ($LASTEXITCODE -ne 0) { throw 'CLI 启动验证失败' }
    & (Join-Path $outputDir 'hdm-bridge-windows-amd64.exe') -h
    if ($LASTEXITCODE -ne 0) { throw 'Bridge 启动验证失败' }
} finally {
    Pop-Location
    foreach ($name in $originalEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $originalEnv[$name], 'Process') }
}
