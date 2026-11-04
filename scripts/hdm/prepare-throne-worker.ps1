# 刷新Throne外部核心配置，验证WSS入口后固定本次IP；不创建TUN或修改系统代理。
param([switch]$PrepareOnly)
$ErrorActionPreference = 'Stop'
try {
    if (-not $PrepareOnly) {
        if (@(Get-Process Throne -ErrorAction SilentlyContinue).Count -gt 0) { throw '请先从托盘完全退出正在运行的Throne，再启动此独立测试包。' }
        $other = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' -and ($_.Name -match '(?i)tun' -or $_.InterfaceDescription -match '(?i)wintun|wireguard') })
        if ($other.Count -gt 0) { throw '请先关闭CMD测试包和其他VPN/TUN，避免叠加。' }
        # 防止旧外部核心残留占用内部端口，启动前给出可操作的错误。
        $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 18480)
        try { $probe.Start() } catch { throw '内部SOCKS端口18480已被占用，请先关闭旧测试核心。' }
        finally { $probe.Stop() }
    }
    $config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'client-base.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $worker = [Uri]$config.transport.worker.url
    if ($worker.Scheme -ne 'wss' -or $worker.UserInfo -or $worker.Query -or $worker.Fragment) { throw 'Worker地址必须为不带用户信息、查询参数或片段的WSS地址。' }
    # Windows PowerShell 5的Uri可能不识别WSS默认端口，显式补齐443。
    $workerPort = if ($worker.Port -lt 1) { 443 } else { $worker.Port }
    $cachePath = Join-Path $PSScriptRoot 'worker-bootstrap.json'
    $cache = Get-Content -LiteralPath $cachePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($cache.host -ne $worker.DnsSafeHost) { throw '入口缓存域名与配置不一致。' }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $addresses = @()
    foreach ($resolver in @('https://1.1.1.1/dns-query', 'https://1.0.0.1/dns-query')) {
        $response = $null; $reader = $null
        try {
            $request = [Net.HttpWebRequest]::Create($resolver + '?name=' + [Uri]::EscapeDataString($worker.DnsSafeHost) + '&type=A')
            $request.Accept = 'application/dns-json'; $request.Proxy = $null
            $request.Timeout = 4000; $request.ReadWriteTimeout = 4000
            $response = $request.GetResponse()
            $reader = [IO.StreamReader]::new($response.GetResponseStream())
            $answer = $reader.ReadToEnd() | ConvertFrom-Json
            if ($answer.Status -eq 0) { $addresses = @($answer.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { $_.data }) }
            if ($addresses.Count -gt 0) { break }
        } catch { Write-Host "加密DNS暂不可用：$resolver" }
        finally { if ($reader) { $reader.Dispose() }; if ($response) { $response.Dispose() } }
    }
    # 缓存仅提供候选IP；即使DNS缓存过期，也必须重新通过域名TLS验证及健康检查。
    if ($addresses.Count -eq 0) { Write-Host '使用入口缓存，并重新验证域名证书及可达性。' }
    $addresses = @(@($addresses) + @($cache.ipv4) | Select-Object -Unique)
    $curl = Join-Path $env:SystemRoot 'System32/curl.exe'
    if (-not (Test-Path -LiteralPath $curl)) { throw '缺少Windows自带curl.exe，无法验证WSS入口。' }
    $workerIP = $null
    foreach ($candidate in $addresses) {
        $ip = $null
        if (-not [Net.IPAddress]::TryParse([string]$candidate, [ref]$ip)) { continue }
        if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { continue }
        $bytes = $ip.GetAddressBytes()
        if ($bytes[0] -eq 0 -or $bytes[0] -eq 10 -or $bytes[0] -eq 127 -or $bytes[0] -ge 224 -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) { continue }
        $mapping = '{0}:{1}:{2}' -f $worker.DnsSafeHost, $workerPort, $ip
        $health = 'https://{0}:{1}/health' -f $worker.DnsSafeHost, $workerPort
        $body = & $curl --silent --fail --noproxy '*' --proto '=https' --connect-timeout 4 --max-time 6 --resolve $mapping $health
        if ($LASTEXITCODE -eq 0 -and ($body -join "`n").Trim() -eq 'ok') { $workerIP = $ip.ToString(); break }
        Write-Host "入口不可达，尝试下一IP：$ip"
    }
    if (-not $workerIP) { throw '所有WSS入口的TLS/健康检查均失败；保留旧配置，请检查网络后重试。' }
    $config.transport.worker | Add-Member -NotePropertyName dialIP -NotePropertyValue $workerIP -Force
    $config.tls.ca = Join-Path $PSScriptRoot 'server.crt'
    foreach ($name in @('tun', 'http', 'socks5')) { $config.PSObject.Properties.Remove($name) }
    $config | Add-Member -NotePropertyName socks5 -NotePropertyValue @{listen='127.0.0.1:18480'} -Force
    $runtime = Join-Path $PSScriptRoot 'worker-client.json'
    [IO.File]::WriteAllText($runtime, ($config | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
    Write-Host "配置就绪：WSS入口 $($worker.DnsSafeHost) -> $workerIP；UDP目标 $($config.server)"
    if ($PrepareOnly) { Write-Host '仅准备配置：没有启动Throne或TUN。' }
    exit 0
} catch {
    Write-Host ('启动准备失败：' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
