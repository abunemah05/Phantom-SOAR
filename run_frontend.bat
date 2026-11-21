@echo off
setlocal EnableExtensions
title Phantom SOAR - Frontend (Next.js :3000)
set "PATH=C:\Program Files\nodejs;%PATH%"
cd /d "%~dp0"
call "%~dp0scripts\dev_env.bat"

where node >nul 2>&1
if errorlevel 1 goto :nonode
where npm >nul 2>&1
if errorlevel 1 goto :nonode

cd /d "%~dp0frontend"

rem Install on first run, and again when a newly added package (the self-hosted
rem Inter / JetBrains Mono fonts) is missing from an older node_modules.
if not exist "node_modules" goto :install
if not exist "node_modules\@fontsource-variable\inter" goto :install
if not exist "node_modules\@fontsource-variable\jetbrains-mono" goto :install
goto :run

:install
echo [setup] Installing frontend dependencies ...
call npm ci --no-audit --no-fund
if errorlevel 1 goto :error

:run
echo ========================================================
echo  PHANTOM SOAR - FRONTEND (development)
echo  Next.js app on: http://localhost:3000
echo  Backend API:    %NEXT_PUBLIC_API_URL%
echo ========================================================
echo  If "next dev" fails with EINVAL / readlink errors on .next, the project
echo  is probably inside OneDrive: move the folder to a local path such as
echo  C:\dev\phantom-soar (see README, Troubleshooting).
echo ========================================================
call npm run dev
pause
exit /b 0

:nonode
echo [error] Node.js / npm were not found. Install Node.js 20 or newer (LTS) from nodejs.org.
pause
exit /b 1

:error
echo [error] npm ci failed. Install Node.js 20+ and try again.
pause
exit /b 1
