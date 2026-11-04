@echo off
setlocal
cd /d "%~dp0"
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
echo SOCKS5: 127.0.0.1:1089. Press Ctrl+C to close. No automatic reconnect.
"%KEX_BIN%" client -config "%KEX_CONFIG%"
set "KEX_RESULT=%errorlevel%"
echo Client exited with code %KEX_RESULT%.
pause
exit /b %KEX_RESULT%
