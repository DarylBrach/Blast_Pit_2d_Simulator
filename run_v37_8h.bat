@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_v37_8h.ps1" %*
exit /b %ERRORLEVEL%
