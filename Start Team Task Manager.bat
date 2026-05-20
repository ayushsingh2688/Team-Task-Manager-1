@echo off
setlocal
title Start Team Task Manager

set "APP_DIR=%~dp0"
set "APP_URL=http://localhost:3000"

cd /d "%APP_DIR%"

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed or is not available in PATH.
  echo Please install Node.js 20 or newer, then run this file again.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='SilentlyContinue'; $appDir = '%APP_DIR%'; $url = '%APP_URL%'; $isRunning = $false; try { Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 | Out-Null; $isRunning = $true } catch { $isRunning = $false }; if (-not $isRunning) { Start-Process -FilePath 'node' -ArgumentList 'server.js' -WorkingDirectory $appDir -WindowStyle Minimized; Start-Sleep -Seconds 2 }; Start-Process $url"

echo Team Task Manager is opening in your browser.
echo If it does not open, go to %APP_URL%
timeout /t 3 >nul
