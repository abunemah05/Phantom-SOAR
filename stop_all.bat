@echo off
setlocal EnableExtensions
rem Stops the windows opened by start_all.bat / run_backend.bat / run_frontend.bat together with
rem everything they started (uvicorn reloader, node). Only windows with the Phantom SOAR titles are
rem touched; other programs that happen to use ports 8000 / 3000 are never killed.
echo Stopping Phantom SOAR development servers ...
taskkill /FI "WINDOWTITLE eq Phantom SOAR - Backend*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq Phantom SOAR - Frontend*" /T /F >nul 2>&1
timeout /t 2 >nul
set "BUSY="
netstat -ano | findstr /R /C:":8000 .*LISTENING" >nul 2>&1 && set "BUSY=8000 %BUSY%"
netstat -ano | findstr /R /C:":3000 .*LISTENING" >nul 2>&1 && set "BUSY=3000 %BUSY%"
if defined BUSY (
  echo Port^(s^) still in use: %BUSY%. Another program is using them; find it with:
  echo   netstat -ano ^| findstr :8000
  echo and stop it from Task Manager.
) else (
  echo Done.
)
exit /b 0
