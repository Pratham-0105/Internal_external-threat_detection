@echo off
title Unified Security Operations Center (SOC) Launcher
echo ======================================================================
echo   STARTING UNIFIED SECURITY OPERATIONS CENTER (SOC)
echo   Single Host Link: http://localhost:8000
echo ======================================================================
echo.

set "ROOT_DIR=%~dp0"

set "INSIDER_PY=%ROOT_DIR%src\insider-threat\.venv\Scripts\python.exe"
if not exist "%INSIDER_PY%" set "INSIDER_PY=python"

set "FLASK_PY=%ROOT_DIR%src\flask-api\.venv\Scripts\python.exe"
if not exist "%FLASK_PY%" set "FLASK_PY=python"

set "PORTAL_PY=%FLASK_PY%"
if not exist "%PORTAL_PY%" set "PORTAL_PY=%INSIDER_PY%"

:: 1. Start Insider Threat Detection System (Port 5001)
echo [+] Launching Insider Threat Detection System (Port 5001)...
start "Insider Threat System (Port 5001)" cmd /k "cd /d "%ROOT_DIR%src\insider-threat" && "%INSIDER_PY%" run.py"

:: 2. Start NIDS Flask ML API (Port 5000)
echo [+] Launching NIDS ML API (Port 5000)...
start "NIDS ML API (Port 5000)" cmd /k "cd /d "%ROOT_DIR%src\flask-api" && "%FLASK_PY%" run.py"

:: 3. Start NIDS React Frontend (Port 3000)
echo [+] Launching NIDS React Dashboard (Port 3000)...
start "NIDS React UI (Port 3000)" cmd /k "cd /d "%ROOT_DIR%src\frontend\my-app" && npm start"

:: 4. Start Unified Portal Gateway (Port 8000)
echo [+] Launching Unified SOC Portal Gateway (Port 8000)...
start "Unified SOC Gateway (Port 8000)" cmd /k "cd /d "%ROOT_DIR%" && "%PORTAL_PY%" unified_soc_portal.py"

:: Give the gateway 2 seconds to initialize then launch the browser
ping 127.0.0.1 -n 3 >nul
echo.
echo [OK] Opening Unified Host Link in default browser...
start http://localhost:8000

echo.
echo ======================================================================
echo   All systems launched! Access everything at: http://localhost:8000
echo ======================================================================
