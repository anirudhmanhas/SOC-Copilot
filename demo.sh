#!/usr/bin/env bash
# ==============================================================================
# SOC Copilot - Live Demo Script
# Resets the database and injects the full_attack_chain threat scenario
# ==============================================================================

set -e

BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
NC="\033[0m"

echo -e "${BLUE}${BOLD}======================================================================"
echo -e "           SOC COPILOT — LIVE DEMO AUTOMATION SCRIPT                  "
echo -e "======================================================================${NC}"

# Detect Python interpreter (virtualenv preferred)
if [ -f "backend/venv/bin/python" ]; then
    PYTHON_CMD="backend/venv/bin/python"
elif [ -f "backend/venv/Scripts/python.exe" ]; then
    PYTHON_CMD="backend/venv/Scripts/python.exe"
else
    PYTHON_CMD="python"
fi

# 1. Health check: Ensure backend is running
echo -e "\n${YELLOW}[1/3] Checking Backend Health on http://127.0.0.1:8000/api/health...${NC}"
if ! $PYTHON_CMD -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" 2>/dev/null; then
    echo -e "${RED}[ERROR] Backend is not responding on http://127.0.0.1:8000!${NC}"
    echo -e "Please start the backend first in a separate terminal:"
    echo -e "  cd backend && uvicorn app.main:app --reload --port 8000"
    exit 1
fi
echo -e "${GREEN}[✓] Backend is online and healthy!${NC}"

# 2. Reset database schema
echo -e "\n${YELLOW}[2/3] Resetting database tables for a clean demo state...${NC}"
$PYTHON_CMD backend/reset_db.py

# 3. Trigger full attack chain simulation at demo speed (3.0x)
echo -e "\n${YELLOW}[3/3] Launching 'full_attack_chain' threat simulation (Speed: 3.0x)...${NC}"
echo -e "${BLUE}>>> Watch the live dashboard on http://localhost:5173/ <<<${NC}\n"

$PYTHON_CMD simulator/simulate.py \
    --scenario full_attack_chain \
    --speed 3.0 \
    --target http://127.0.0.1:8000/api/ingest

echo -e "\n${GREEN}${BOLD}======================================================================"
echo -e " [✓] Threat scenario injected successfully!"
echo -e " Next Steps for Evaluator / Analyst:"
echo -e " 1. Open Dashboard: http://localhost:5173/"
echo -e " 2. Inspect the Correlated Critical Incident in 'Active Threat Incidents'"
echo -e " 3. View Attack Timeline, MITRE Techniques & AI Executive Summary"
echo -e " 4. Click 'Block IP' to contain adversary 185.220.101.5"
echo -e "======================================================================${NC}"

