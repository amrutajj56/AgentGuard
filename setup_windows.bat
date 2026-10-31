@echo off
setlocal
cd /d "%~dp0"

echo ==========================================
echo AgentGuard - Windows setup
echo ==========================================

where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher 'py' was not found.
  echo Install Python 3.10 or newer from https://www.python.org/downloads/
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 goto failed
)

.venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 goto failed
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto failed

echo.
echo Setup complete. Double-click run_windows.bat to start AgentGuard.
pause
exit /b 0

:failed
echo.
echo Setup failed. Read the error above and check your Python installation/internet connection.
pause
exit /b 1
