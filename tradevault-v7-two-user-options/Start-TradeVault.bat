@echo off
title TradeVault Server
cd /d "%~dp0"
echo.
echo ==========================================
echo        TradeVault Server Starting
echo ==========================================
echo.
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed or not in PATH.
  echo Install Node.js 20+ and try again.
  pause
  exit /b 1
)
echo Starting TradeVault on http://localhost:3000
echo Keep this window OPEN while using the app.
echo.
start "" http://localhost:3000
node server.js
echo.
echo TradeVault server stopped.
pause
