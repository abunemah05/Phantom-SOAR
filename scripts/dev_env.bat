@echo off
rem Shared development environment for run_backend.bat / run_frontend.bat. Must be CALLed.
rem
rem The work is done by scripts\dev_env.py (standard library only) so that .env values with quotes,
rem "&", "^", "%", "!" or trailing comments are parsed correctly; batch "for /f" parsing of such files is
rem unreliable. The script prints NAME=VALUE lines; variables already set in the shell win. It also
rem creates random development secrets once (.phantom_dev_secrets, git-ignored). No secret is echoed.
rem If Python is not found, .env is skipped and only the non-secret defaults below are applied.

set "PHANTOM_PY="
python -c "import sys" >nul 2>&1
if not errorlevel 1 set "PHANTOM_PY=python"
if not defined PHANTOM_PY (
  py -3 -c "import sys" >nul 2>&1
  if not errorlevel 1 set "PHANTOM_PY=py -3"
)

if not defined PHANTOM_PY (
  echo [dev] WARNING: Python was not found, so .env and the development secrets were not loaded.
  goto :defaults
)

for /f "usebackq tokens=1,* delims==" %%a in (`%PHANTOM_PY% "%~dp0dev_env.py"`) do set "%%a=%%b"

:defaults
if not defined PHANTOM_ENV set "PHANTOM_ENV=development"
if not defined PHANTOM_SIMULATION_MODE set "PHANTOM_SIMULATION_MODE=true"
if not defined BACKEND_HOST set "BACKEND_HOST=127.0.0.1"
if not defined PHANTOM_CORS_ORIGINS set "PHANTOM_CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000"
if not defined NEXT_PUBLIC_API_URL set "NEXT_PUBLIC_API_URL=http://localhost:8000"
exit /b 0
