@echo off
setlocal EnableExtensions
title Phantom SOAR - Backend (FastAPI :8000)
cd /d "%~dp0"
call "%~dp0scripts\dev_env.bat"

rem The API listens on loopback only. A Wazuh VM that must post alerts to this machine needs
rem BACKEND_HOST=0.0.0.0 (set it in .env on purpose, on a trusted network, and prefer the TLS proxy
rem of docker-compose.yml for anything beyond a lab).
if /i "%BACKEND_HOST%"=="127.0.0.1" goto :hostok
if /i "%BACKEND_HOST%"=="localhost" goto :hostok
echo [warn] BACKEND_HOST=%BACKEND_HOST%: the API is reachable from other machines over plain HTTP.
echo [warn] Use this only on a trusted lab network. Press Ctrl+C within 5 seconds to cancel.
timeout /t 5 >nul
:hostok

rem --- Virtualenv (created on first run, refreshed when requirements change) ---
where python >nul 2>&1
if errorlevel 1 goto :nopython
if exist ".venv\Scripts\python.exe" goto :deps
echo [setup] Creating virtualenv in .venv ...
python -m venv .venv
if errorlevel 1 goto :error

:deps
copy /b /y "backend\requirements.txt"+"backend\requirements-dev.txt" ".venv\requirements.new" >nul
fc /b ".venv\requirements.new" ".venv\requirements.installed" >nul 2>&1
if not errorlevel 1 goto :run
echo [setup] Installing backend dependencies ...
".venv\Scripts\python.exe" -m pip install -r backend\requirements-dev.txt
if errorlevel 1 goto :error
move /y ".venv\requirements.new" ".venv\requirements.installed" >nul

:run
echo ========================================================
echo  PHANTOM SOAR - BACKEND SERVICE (development)
echo  API:                http://%BACKEND_HOST%:8000/api/health
echo  Interactive docs:   http://%BACKEND_HOST%:8000/docs
echo  Simulation mode:    %PHANTOM_SIMULATION_MODE%
echo  Development secrets are kept in .phantom_dev_secrets (git-ignored, not shown).
echo  Create a per-sender webhook token in the console (Accounts) or use the
echo  PHANTOM_INGEST_TOKEN line of .phantom_dev_secrets for local tests.
echo ========================================================
if not defined PHANTOM_BOOTSTRAP_ADMIN_PASSWORD (
  echo  PHANTOM_BOOTSTRAP_ADMIN_PASSWORD is not set: on a fresh database a one-time
  echo  admin password is written to phantom_bootstrap_admin_password.txt next to
  echo  the database file ^(its path is shown in the log below^). Change it, then delete the file.
)
".venv\Scripts\python.exe" -m uvicorn backend.main:app --host %BACKEND_HOST% --port 8000 --reload --reload-dir backend
pause
exit /b 0

:nopython
echo [error] Python was not found on PATH. Install Python 3.12 or newer from python.org and tick "Add to PATH".
pause
exit /b 1

:error
echo [error] Backend setup failed. Install Python 3.12+ and make sure "python" is on PATH.
pause
exit /b 1
