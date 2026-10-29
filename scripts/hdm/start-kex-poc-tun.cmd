@echo off
setlocal
cd /d "%~dp0"
rem 用户双击时才请求提权；标签分支确保取消时返回非零状态。
powershell.exe -NoProfile -Command "$p = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 }; exit 1"
if not errorlevel 1 goto run_client
if /i "%~1"=="--elevated" goto elevation_denied
set "KEX_LAUNCHER=%~f0"
powershell.exe -NoProfile -Command "try { Start-Process -FilePath $env:KEX_LAUNCHER -ArgumentList '--elevated' -Verb RunAs -ErrorAction Stop } catch { Write-Host 'Elevation cancelled or failed.'; exit 1 }"
if errorlevel 1 goto elevation_failed
exit /b 0

:elevation_denied
echo Administrator privileges were not granted.
pause
exit /b 1

:elevation_failed
echo Elevation cancelled or failed.
pause
exit /b 1

:run_client
set "KEX_BIN=%~dp0kex-poc.exe"
if not exist "%KEX_BIN%" set "KEX_BIN=%~dp0..\..\build\kex-cli\windows-amd64\kex-poc.exe"
set "KEX_CONFIG=%~dp0client.json"
if not exist "%KEX_CONFIG%" (
  echo Missing client.json. Copy client.example.json and fill credentials locally.
  pause
  exit /b 1
)
if not exist "%KEX_BIN%" (
  echo Missing kex-poc.exe. Run build-kex-poc.ps1 first.
  pause
  exit /b 1
)
echo TUN is opt-in. Keep this window open; use Ctrl+C for route cleanup.
"%KEX_BIN%" client -config "%KEX_CONFIG%" -tun
set "KEX_RESULT=%errorlevel%"
echo Client exited with code %KEX_RESULT%.
pause
exit /b %KEX_RESULT%
