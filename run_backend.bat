@echo off
title Phantom SOAR - Backend (FastAPI :8000)
echo ========================================================
echo  PHANTOM SOAR - BACKEND SERVICE
echo  FastAPI Server running on: http://localhost:8000
echo  Interactive Swagger Docs:  http://localhost:8000/docs
echo ========================================================
cd /d "%~dp0"
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
pause
