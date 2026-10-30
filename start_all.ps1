# Unified SOC Launcher for PowerShell
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  STARTING UNIFIED SECURITY OPERATIONS CENTER (SOC)" -ForegroundColor Green
Write-Host "  Single Host Link: http://localhost:8000" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan

$rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$insiderPy = Join-Path $rootDir "src\insider-threat\.venv\Scripts\python.exe"
if (-not (Test-Path $insiderPy)) { $insiderPy = "python" }

$flaskPy = Join-Path $rootDir "src\flask-api\.venv\Scripts\python.exe"
if (-not (Test-Path $flaskPy)) { $flaskPy = "python" }

$portalPy = if (Test-Path $flaskPy) { $flaskPy } elseif (Test-Path $insiderPy) { $insiderPy } else { "python" }

# 1. Start Insider Threat Detection System (Port 5001)
Write-Host "[+] Launching Insider Threat Detection System (Port 5001)..." -ForegroundColor White
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$rootDir\src\insider-threat'; & '$insiderPy' run.py"

# 2. Start NIDS Flask ML API (Port 5000)
Write-Host "[+] Launching NIDS ML API (Port 5000)..." -ForegroundColor White
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$rootDir\src\flask-api'; & '$flaskPy' run.py"

# 3. Start NIDS React Frontend (Port 3000)
Write-Host "[+] Launching NIDS React Dashboard (Port 3000)..." -ForegroundColor White
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$rootDir\src\frontend\my-app'; npm start"

# 4. Start Unified Portal Gateway (Port 8000)
Write-Host "[+] Launching Unified SOC Portal Gateway (Port 8000)..." -ForegroundColor White
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$rootDir'; & '$portalPy' unified_soc_portal.py"

Start-Sleep -Seconds 2
Write-Host "[OK] Opening Unified Host Link in default browser..." -ForegroundColor Green
Start-Process "http://localhost:8000"

Write-Host ""
Write-Host "All systems initiated. Single host link ready: http://localhost:8000" -ForegroundColor Green
