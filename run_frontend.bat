@echo off
title Phantom SOAR - Frontend (Next.js :3000)
echo ========================================================
echo  PHANTOM SOAR - FRONTEND DASHBOARD
echo  Next.js App running on: http://localhost:3000
echo ========================================================
set "PATH=C:\Program Files\nodejs;%PATH%"
cd /d "%~dp0\frontend"
call npm run dev
pause
