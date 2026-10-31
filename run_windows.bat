@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo Environment not found. Run setup_windows.bat first.
  pause
  exit /b 1
)

REM Local demo defaults. Change these before first launch if desired.
if not defined AGENTGUARD_SECRET set "AGENTGUARD_SECRET=local-demo-secret-change-before-sharing-2026"
if not defined AGENTGUARD_ADMIN_EMAIL set "AGENTGUARD_ADMIN_EMAIL=admin@agentguard.local"
if not defined AGENTGUARD_ADMIN_PASSWORD set "AGENTGUARD_ADMIN_PASSWORD=ChangeMe123!"

echo Starting AgentGuard at http://127.0.0.1:8000
echo Admin email: %AGENTGUARD_ADMIN_EMAIL%
echo Press CTRL+C to stop the server.
.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
pause
