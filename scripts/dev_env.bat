@echo off
rem Shared development environment for run_backend.bat / run_frontend.bat
rem (Windows counterpart of the defaults in scripts/dev.sh).
rem Loads KEY=VALUE lines from the repo-root .env (variables already set in the
rem shell win), then fills in development defaults for anything still unset.
rem Must be CALLed.

if not exist "%~dp0..\.env" goto :defaults
echo [dev] loading .env
for /f "usebackq eol=# tokens=1,* delims==" %%a in ("%~dp0..\.env") do if not defined %%a set "%%a=%%b"

:defaults
if not defined PHANTOM_ENV set "PHANTOM_ENV=development"
if not defined PHANTOM_SIMULATION_MODE set "PHANTOM_SIMULATION_MODE=true"
if not defined PHANTOM_INGEST_TOKEN set "PHANTOM_INGEST_TOKEN=dev-ingest-token"
if not defined PHANTOM_CORS_ORIGINS set "PHANTOM_CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000"
if not defined NEXT_PUBLIC_API_URL set "NEXT_PUBLIC_API_URL=http://localhost:8000"
exit /b 0
