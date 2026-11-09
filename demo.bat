@echo off
REM ==============================================================================
REM SOC Copilot - Live Demo Batch File
REM Resets the database and injects the full_attack_chain threat scenario
REM ==============================================================================

echo ======================================================================
echo            SOC COPILOT -- LIVE DEMO AUTOMATION SCRIPT                  
echo ======================================================================

set PYTHON_CMD=python
if exist backend\venv\Scripts\python.exe set PYTHON_CMD=backend\venv\Scripts\python.exe

echo.
echo [1/3] Resetting database tables for a clean demo state...
%PYTHON_CMD% backend/reset_db.py

echo.
echo [2/3] Launching 'full_attack_chain' threat simulation (Speed: 3.0x)...
echo ^>^>^> Watch the live dashboard on http://localhost:5173/ ^<^<^<
echo.

%PYTHON_CMD% simulator/simulate.py --scenario full_attack_chain --speed 3.0 --target http://127.0.0.1:8000/api/ingest

echo.
echo ======================================================================
echo  [DONE] Threat scenario injected successfully!
echo  Next Steps for Evaluator / Analyst:
echo  1. Open Dashboard: http://localhost:5173/
echo  2. Inspect the Correlated Critical Incident in 'Active Threat Incidents'
echo  3. View Attack Timeline, MITRE Techniques ^& AI Executive Summary
echo  4. Click 'Block IP' to contain adversary 185.220.101.5
echo ======================================================================

