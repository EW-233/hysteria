# 构建 Windows 客户端及两种 Linux 架构，写入版本信息和 SHA256 清单。
param([string]$Version = '0.2.1-hdm', [string]$Toolchain = 'go1.26.3')
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$outputDir = Join-Path $projectRoot 'build/hdm'
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
$originalEnv = @{}
foreach ($name in @('GOOS','GOARCH','CGO_ENABLED','GOTOOLCHAIN')) { $originalEnv[$name] = [Environment]::GetEnvironmentVariable($name,'Process') }
Push-Location $projectRoot
try {
    $revision = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw '无法读取 Git 提交' }
    $dirty = [bool](git status --porcelain)
    $buildRevision = if ($dirty) { "$revision-dirty" } else { $revision }
    $buildDate = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $pkg = 'github.com/apernet/hysteria/app/v2/cmd'
    $env:GOTOOLCHAIN = $Toolchain
    $goVersion = (& go env GOVERSION).Trim()
    if ($LASTEXITCODE -ne 0) { throw '工具链不可用' }
    $quicVersion = (& go list -m -f '{{.Version}}' github.com/apernet/quic-go).Trim()
    if ($LASTEXITCODE -ne 0) { throw '无法读取 QUIC 依赖版本' }
    $env:CGO_ENABLED = '0'
    $outputs = @()
    foreach ($target in @(@('windows','amd64'), @('linux','amd64'), @('linux','arm64'))) {
        $env:GOOS = $target[0]
        $env:GOARCH = $target[1]
        $filename = "hysteria-hdm-$($target[0])-$($target[1])"
        if ($env:GOOS -eq 'windows') { $filename += '.exe' }
        $path = Join-Path $outputDir $filename
        $flags = "-s -w -X $pkg.appVersion=$Version -X $pkg.appCommit=$buildRevision -X $pkg.appDate=$buildDate -X $pkg.appType=experimental -X $pkg.appToolchain=$goVersion -X $pkg.libVersion=$quicVersion -X $pkg.appPlatform=$env:GOOS -X $pkg.appArch=$env:GOARCH"
        & go build -trimpath -ldflags $flags -o $path ./app
        if ($LASTEXITCODE -ne 0) { throw "构建失败: $filename" }
        $outputs += $path
    }
    $manifest = foreach ($path in $outputs) { '{0}  {1}' -f (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(), (Split-Path $path -Leaf) }
    [IO.File]::WriteAllLines((Join-Path $outputDir 'SHA256SUMS'), $manifest, [Text.UTF8Encoding]::new($false))
    @{ version=$Version; commit=$revision; dirty=$dirty; builtAt=$buildDate; go=(& go version) } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputDir 'build-info.json') -Encoding utf8NoBOM
    & (Join-Path $outputDir 'hysteria-hdm-windows-amd64.exe') version
    if ($LASTEXITCODE -ne 0) { throw 'Windows 二进制启动验证失败' }
} finally {
    Pop-Location
    foreach ($name in $originalEnv.Keys) { [Environment]::SetEnvironmentVariable($name,$originalEnv[$name],'Process') }
}
