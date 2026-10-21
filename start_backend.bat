@echo off
echo ========================================================
echo  Aegis Phishing Analyzer — Backend Server
echo ========================================================
echo.
echo  Environment: DEVELOPMENT (CORS wildcard)
echo  Local URL:   http://localhost:8000
echo  Render URL:  https://aegis-backend.onrender.com
echo.
echo  [PR-07] PRODUCTION DEPLOYMENT CHECKLIST (Render.com):
echo    1. Set ENVIRONMENT=production in Render.com env vars
echo    2. Set CORS_ORIGIN=chrome-extension://{your-extension-id}
echo    3. Set VT_API_KEY={your-virustotal-api-key}
echo    See: aegis-backend/.env.example for full documentation
echo.
echo ========================================================
cd /d "%~dp0aegis-backend"
if exist ".venv\Scripts\uvicorn.exe" (
    ".venv\Scripts\uvicorn.exe" main:app --reload --port 8000
) else (
    echo Error: .venv virtual environment not found in aegis-backend!
    echo Run: python -m venv .venv ^&^& .venv\Scripts\pip install -r requirements.txt
    pause
)
