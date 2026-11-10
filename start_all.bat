@echo off
title Phantom SOAR - Platform Launcher
cd /d "%~dp0"
echo ========================================================
echo   Launching Phantom SOAR Enterprise Platform
echo ========================================================
echo [1/2] Launching Backend on http://localhost:8000 ...
start "Phantom SOAR - Backend" cmd /k "run_backend.bat"

echo [2/2] Launching Frontend on http://localhost:3000 ...
start "Phantom SOAR - Frontend" cmd /k "run_frontend.bat"

echo.
echo ========================================================
echo   All systems launching in separate terminal windows!
echo   Frontend Dashboard: http://localhost:3000
echo   API Swagger Docs:   http://localhost:8000/docs
echo ========================================================
timeout /t 5
