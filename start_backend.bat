@echo off
echo ========================================================
echo Starting Aegis Phishing Analyzer Backend Server...
echo ========================================================
cd /d "%~dp0aegis-backend"
if exist ".venv\Scripts\uvicorn.exe" (
    ".venv\Scripts\uvicorn.exe" main:app --reload --port 8000
) else (
    echo Error: .venv virtual environment not found in aegis-backend!
    pause
)
