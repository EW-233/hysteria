@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0prepare-tun.ps1"
set "prepResult=%errorlevel%"
if "%prepResult%"=="20" exit /b 0
if not "%prepResult%"=="0" (
  pause
  exit /b %prepResult%
)
echo Keep this window open. Press Ctrl+C for graceful shutdown and TUN cleanup.
echo Wait for TUN initialization, then test in your normal browser.
hysteria.exe client -c client-tun.runtime.json
set "runResult=%errorlevel%"
echo Client exited with code %runResult%.
pause
exit /b %runResult%
