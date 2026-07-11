@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" tmp_2d_simulator_v35.py %*
) else (
  python tmp_2d_simulator_v35.py %*
)
exit /b %errorlevel%
