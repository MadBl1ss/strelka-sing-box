@echo off
chcp 65001 >nul
cd /d "%~dp0"
where pwsh >nul 2>&1
if %errorlevel%==0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-servers.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-servers.ps1"
)
