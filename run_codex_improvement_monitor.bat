@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_codex_improvement_monitor.ps1" %*
exit /b %ERRORLEVEL%
