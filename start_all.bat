@echo off
setlocal EnableExtensions
title Phantom SOAR - Launcher
cd /d "%~dp0"
echo ========================================================
echo   Phantom SOAR - local development launcher
echo   Settings: .env (optional, see .env.example)
echo ========================================================

rem --- Prerequisites ---------------------------------------------------------
where python >nul 2>&1
if errorlevel 1 (
  echo [error] Python was not found on PATH. Install Python 3.12+ from python.org.
  goto :fail
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1
if errorlevel 1 (
  echo [error] Python 3.12 or newer is required.
  goto :fail
)
where node >nul 2>&1
if errorlevel 1 (
  echo [error] Node.js was not found. Install Node.js 20+ ^(LTS^) from nodejs.org.
  goto :fail
)
where npm >nul 2>&1
if errorlevel 1 (
  echo [error] npm was not found. Reinstall Node.js.
  goto :fail
)
set "NODEMAJOR="
for /f "tokens=1 delims=." %%v in ('node --version') do set "NODEMAJOR=%%v"
set "NODEMAJOR=%NODEMAJOR:v=%"
if %NODEMAJOR% LSS 20 (
  echo [error] Node.js 20 or newer is required ^(found %NODEMAJOR%^).
  goto :fail
)

rem --- Stale processes from an earlier launch --------------------------------
set "BUSY="
netstat -ano | findstr /R /C:":8000 .*LISTENING" >nul 2>&1 && set "BUSY=8000 %BUSY%"
netstat -ano | findstr /R /C:":3000 .*LISTENING" >nul 2>&1 && set "BUSY=3000 %BUSY%"
if defined BUSY (
  echo [error] Port^(s^) in use: %BUSY%
  echo         An earlier Phantom SOAR launch may still be running: run stop_all.bat, or close
  echo         the program that uses the port, then start again.
  goto :fail
)

echo [1/2] Launching backend on http://127.0.0.1:8000 ...
start "Phantom SOAR - Backend" cmd /c "run_backend.bat"

echo [2/2] Launching frontend on http://localhost:3000 ...
start "Phantom SOAR - Frontend" cmd /c "run_frontend.bat"

echo.
echo ========================================================
echo   Both servers are starting in their own windows.
echo   Console:   http://localhost:3000
echo   API docs:  http://127.0.0.1:8000/docs   ^(development mode only^)
echo   The first start installs dependencies and can take a few minutes.
echo   On a fresh database the generated admin password is written to
echo   phantom_bootstrap_admin_password.txt ^(path shown in the backend window^).
echo.
echo   Press any key HERE to stop both servers and close their windows.
echo ========================================================
pause >nul
call "%~dp0stop_all.bat"
exit /b 0

:fail
echo.
pause
exit /b 1
