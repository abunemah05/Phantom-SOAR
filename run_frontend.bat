@echo off
setlocal EnableExtensions
title Phantom SOAR - Frontend (Next.js :3000)
set "PATH=C:\Program Files\nodejs;%PATH%"
cd /d "%~dp0"
call "%~dp0scripts\dev_env.bat"
cd /d "%~dp0frontend"

if exist "node_modules" goto :run
echo [setup] Installing frontend dependencies ...
call npm ci --no-audit --no-fund
if errorlevel 1 goto :error

:run
echo ========================================================
echo  PHANTOM SOAR - FRONTEND DASHBOARD
echo  Next.js App running on: http://localhost:3000
echo  Backend API:            %NEXT_PUBLIC_API_URL%
echo ========================================================
call npm run dev
pause
exit /b 0

:error
echo [error] npm ci failed. Install Node.js 20+ and try again.
pause
exit /b 1
