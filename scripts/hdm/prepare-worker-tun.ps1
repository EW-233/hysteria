# CMD启动前检查权限和路由依赖，生成只用于本次运行的TUN配置。
param([switch]$PrepareOnly)
$ErrorActionPreference = 'Stop'
try {
    $basePath = Join-Path $PSScriptRoot 'client-base.json'
    $config = Get-Content -LiteralPath $basePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $PrepareOnly -and -not $isAdmin) {
        Write-Host 'TUN需要管理员权限，请在UAC窗口中选择“是”。'
        $entry = Join-Path $PSScriptRoot 'start-tun.cmd'
        Start-Process -FilePath $env:ComSpec -Verb RunAs -WindowStyle Normal -WorkingDirectory $PSScriptRoot -ArgumentList ('/d /c ""{0}""' -f $entry)
        exit 20
    }
    if (-not $PrepareOnly) {
        # 同时运行多个TUN会影响出口判断，也可能让握手请求绕回原代理。
        $other = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' -and ($_.Name -match '(?i)tun' -or $_.InterfaceDescription -match '(?i)wintun|wireguard') })
        if ($other.Count -gt 0) { throw ('请先关闭已有TUN/VPN，再启动此包：' + (($other | ForEach-Object Name) -join ', ')) }
    }
    $worker = [Uri]$config.transport.worker.url
    if ($worker.Scheme -ne 'wss') { throw '此包要求Worker使用WSS。' }
    # 系统DNS可能返回错误地址；先查询HTTPS DNS，再使用打包时核实的短期缓存。
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $addresses = @()
    foreach ($resolver in @('https://1.1.1.1/dns-query', 'https://1.0.0.1/dns-query')) {
        $reply = $null; $reader = $null
        try {
            $query = $resolver + '?name=' + [Uri]::EscapeDataString($worker.DnsSafeHost) + '&type=A'
            $request = [Net.HttpWebRequest]::Create($query)
            $request.Accept = 'application/dns-json'
            $request.Proxy = $null
            $request.Timeout = 4000; $request.ReadWriteTimeout = 4000
            $reply = $request.GetResponse()
            $reader = [IO.StreamReader]::new($reply.GetResponseStream())
            $answer = $reader.ReadToEnd() | ConvertFrom-Json
            if ($answer.Status -eq 0) {
                $addresses = @($answer.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { ([Net.IPAddress]::Parse($_.data)).ToString() } | Select-Object -Unique)
            }
            if ($addresses.Count -gt 0) { break }
        } catch { Write-Host "加密DNS暂不可用：$resolver" }
        finally { if ($reader) { $reader.Dispose() }; if ($reply) { $reply.Dispose() } }
    }
    if ($addresses.Count -eq 0) {
        $bootstrap = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'worker-bootstrap.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($bootstrap.host -ne $worker.DnsSafeHost -or [DateTimeOffset]::UtcNow -gt [DateTimeOffset]::Parse($bootstrap.validUntil)) { throw '入口缓存不匹配或已过期，请更新入口配置。' }
        $addresses = @($bootstrap.ipv4 | ForEach-Object { ([Net.IPAddress]::Parse($_)).ToString() })
        Write-Host '加密DNS未返回可用结果，使用打包时通过服务器核实的入口IP；TLS证书仍正常验证。'
    }
    if ($addresses.Count -eq 0) { throw '没有可用Worker入口IP。' }
    $workerIP = [Net.IPAddress]::Parse($addresses[0]).ToString()
    $serverHost = ($config.server -split ':')[0]
    $serverIP = [Net.IPAddress]::Parse($serverHost)
    if ($serverIP.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw '当前TUN包要求服务器使用IPv4地址。' }
    # 固定本次WSS拨号IP以避免重连时DNS变化造成路由环路，证书仍按URL域名验证。
    $config.transport.worker | Add-Member -NotePropertyName dialIP -NotePropertyValue $workerIP -Force
    $exclude4 = @("$serverIP/32", "$workerIP/32", '43.252.41.230/32', '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '224.0.0.0/4') | Select-Object -Unique
    $tun = [ordered]@{
        name = 'hdm-worker-tun'; mtu = 1500; timeout = '5m'
        address = @{ ipv4 = '100.100.100.101/30'; ipv6 = 'fd00:4844:4d::1/126' }
        route = @{ ipv4 = @('0.0.0.0/0'); ipv6 = @('2000::/3'); ipv4Exclude = @($exclude4); ipv6Exclude = @('::1/128', 'fc00::/7', 'fe80::/10') }
    }
    $config | Add-Member -NotePropertyName tun -NotePropertyValue $tun -Force
    # 本包只开TUN，避免占用普通代理包的SOCKS/HTTP监听端口。
    $config.PSObject.Properties.Remove('socks5')
    $config.PSObject.Properties.Remove('http')
    $runtime = Join-Path $PSScriptRoot 'client-tun.runtime.json'
    [IO.File]::WriteAllText($runtime, ($config | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
    Write-Host "配置就绪。Worker直连IP：$workerIP；服务器UDP目标：$($config.server)"
    if ($PrepareOnly) { Write-Host '仅生成配置：未创建TUN、未改变路由、未申请提权。' }
    exit 0
} catch {
    Write-Host ('启动准备失败：' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
