@echo off
setlocal EnableExtensions
title Phantom SOAR - Backend (FastAPI :8000)
cd /d "%~dp0"
call "%~dp0scripts\dev_env.bat"
rem 0.0.0.0 lets a Wazuh VM post webhooks to this machine; use 127.0.0.1 for local-only.
if not defined BACKEND_HOST set "BACKEND_HOST=0.0.0.0"

rem --- Virtualenv (created on first run, refreshed when requirements change) ---
if exist ".venv\Scripts\python.exe" goto :deps
echo [setup] Creating virtualenv in .venv ...
python -m venv .venv
if errorlevel 1 goto :error

:deps
copy /b /y "backend\requirements.txt"+"backend\requirements-dev.txt" ".venv\requirements.new" >nul
fc /b ".venv\requirements.new" ".venv\requirements.installed" >nul 2>&1
if not errorlevel 1 goto :secret
echo [setup] Installing backend dependencies ...
".venv\Scripts\python.exe" -m pip install -r backend\requirements-dev.txt
if errorlevel 1 goto :error
move /y ".venv\requirements.new" ".venv\requirements.installed" >nul

:secret
rem Stable for this window (survives --reload); sessions end when it is closed.
if defined PHANTOM_JWT_SECRET goto :run
for /f "delims=" %%s in ('.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"') do set "PHANTOM_JWT_SECRET=%%s"

:run
echo ========================================================
echo  PHANTOM SOAR - BACKEND SERVICE
echo  FastAPI Server running on: http://localhost:8000
echo  Interactive Swagger Docs:  http://localhost:8000/docs
echo  Webhook ingest token:      %PHANTOM_INGEST_TOKEN%
echo  Simulation mode:           %PHANTOM_SIMULATION_MODE%
echo ========================================================
if not defined PHANTOM_BOOTSTRAP_ADMIN_PASSWORD (
  echo  PHANTOM_BOOTSTRAP_ADMIN_PASSWORD is not set: on a fresh database the
  echo  generated admin password is printed once in the log below [WARNING].
)
".venv\Scripts\python.exe" -m uvicorn backend.main:app --host %BACKEND_HOST% --port 8000 --reload --reload-dir backend
pause
exit /b 0

:error
echo [error] Backend setup failed. Install Python 3.12+ and make sure "python" is on PATH.
pause
exit /b 1
