@echo off
title CASOC Red-Team Threat Simulator
echo ====================================================================
echo  CASOC Red-Team Penetration Testing & Faculty Demonstration Suite
echo ====================================================================
echo.

set "PYTHON_CMD=%~dp0src\flask-api\.venv\Scripts\python.exe"
if not exist "%PYTHON_CMD%" (
    set "PYTHON_CMD=python"
)

"%PYTHON_CMD%" "%~dp0simulate_attacks.py" %*
pause
