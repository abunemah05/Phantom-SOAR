@echo off
rem Launcher for the Phantom SOAR active-response script on Windows agents.
rem Wazuh runs active-response\bin\<name>.cmd and pipes the JSON message to stdin; this file is copied under
rem one name per action (see install-windows.ps1) and takes the action from its own file name:
rem   phantom-isolate-host.cmd -> isolate-host, phantom-block-ip.cmd -> block-ip, ...
rem Arguments are never passed on the command line: everything is read from stdin by phantom-ar.ps1.
setlocal
set "PHANTOM_NAME=%~n0"
set "PHANTOM_ACTION=%PHANTOM_NAME:phantom-=%"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0phantom-ar.ps1" -Action "%PHANTOM_ACTION%"
exit /b %ERRORLEVEL%
