# ==============================================================================
# SOC Copilot - Live Demo PowerShell Script
# Resets the database and injects the full_attack_chain threat scenario
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "           SOC COPILOT — LIVE DEMO AUTOMATION SCRIPT                  " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# Locate Python
$PythonCmd = "python"
if (Test-Path "backend\venv\Scripts\python.exe") {
    $PythonCmd = "backend\venv\Scripts\python.exe"
}

# 1. Health check
Write-Host "`n[1/3] Checking Backend Health on http://127.0.0.1:8000/api/health..." -ForegroundColor Yellow
try {
    $resp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -Method Get -TimeoutSec 3 -ErrorAction Stop
    Write-Host "[✓] Backend is online! Status: $($resp.status)" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Backend is not responding on http://127.0.0.1:8000!" -ForegroundColor Red
    Write-Host "Please start the backend server in another terminal:"
    Write-Host "  cd backend; .\venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000"
    exit 1
}

# 2. Reset database
Write-Host "`n[2/3] Resetting database tables for a clean demo state..." -ForegroundColor Yellow
& $PythonCmd backend/reset_db.py

# 3. Trigger simulation
Write-Host "`n[3/3] Launching 'full_attack_chain' threat simulation (Speed: 3.0x)..." -ForegroundColor Yellow
Write-Host ">>> Watch the live dashboard on http://localhost:5173/ <<<`n" -ForegroundColor Cyan

& $PythonCmd simulator/simulate.py --scenario full_attack_chain --speed 3.0 --target http://127.0.0.1:8000/api/ingest

Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host " [✓] Threat scenario injected successfully!" -ForegroundColor Green
Write-Host " Next Steps for Evaluator / Analyst:" -ForegroundColor Green
Write-Host " 1. Open Dashboard: http://localhost:5173/" -ForegroundColor White
Write-Host " 2. Inspect the Correlated Critical Incident in 'Active Threat Incidents'" -ForegroundColor White
Write-Host " 3. View Attack Timeline, MITRE Techniques & AI Executive Summary" -ForegroundColor White
Write-Host " 4. Click 'Block IP' to contain adversary 185.220.101.5" -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Green

