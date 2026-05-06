@echo off
REM NEXUS — single-command start (Windows)
setlocal EnableDelayedExpansion

set SCRIPT_DIR=%~dp0
set BACKEND=%SCRIPT_DIR%backend
set VENV=%SCRIPT_DIR%.venv
set ENV_FILE=%SCRIPT_DIR%.env

echo [NEXUS] Starting NEXUS Phase 1 ...

REM .env bootstrap
if not exist "%ENV_FILE%" (
    if exist "%SCRIPT_DIR%.env.example" (
        copy "%SCRIPT_DIR%.env.example" "%ENV_FILE%" >nul
        echo [NEXUS] .env not found - copied from .env.example
    )
)

REM Python check
where python >nul 2>&1
if errorlevel 1 (
    echo [NEXUS] ERROR: python not found. Install Python 3.10+ and add to PATH.
    pause
    exit /b 1
)

REM Virtual env
if not exist "%VENV%\" (
    echo [NEXUS] Creating virtualenv ...
    python -m venv "%VENV%"
)

call "%VENV%\Scripts\activate.bat"

REM Dependencies
pip install --quiet fastapi "uvicorn[standard]" httpx pydantic python-dotenv beautifulsoup4

echo [NEXUS] Starting backend on http://0.0.0.0:8000
echo [NEXUS] API docs: http://localhost:8000/docs
echo.

cd /d "%BACKEND%"
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

pause
