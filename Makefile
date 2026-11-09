.PHONY: help install backend frontend test reset-db demo docker-build docker-up docker-demo docker-down

PYTHON ?= $(shell which python3 || which python || echo backend/venv/bin/python)

help:
	@echo "======================================================================"
	@echo "                   SOC COPILOT — MAKE COMMANDS                        "
	@echo "======================================================================"
	@echo "  make install      - Install backend and frontend dependencies"
	@echo "  make backend      - Run FastAPI backend server (port 8000)"
	@echo "  make frontend     - Run React/Vite development server (port 5173)"
	@echo "  make test         - Run 107 pytest unit & integration tests"
	@echo "  make reset-db     - Wipe SQLite database tables and re-init schema"
	@echo "  make demo         - Reset DB and run full_attack_chain simulation"
	@echo "  make docker-up    - Build and launch all services with Docker Compose"
	@echo "  make docker-demo  - Launch Docker Compose with automated simulator"
	@echo "  make docker-down  - Stop and remove Docker containers"
	@echo "======================================================================"

install:
	@echo "[*] Installing backend dependencies..."
	cd backend && pip install -r requirements.txt
	@echo "[*] Installing frontend dependencies..."
	cd frontend && npm install

backend:
	@echo "[*] Starting FastAPI Backend on http://127.0.0.1:8000..."
	cd backend && uvicorn app.main:app --reload --port 8000

frontend:
	@echo "[*] Starting Vite Frontend on http://localhost:5173..."
	cd frontend && npm run dev

test:
	@echo "[*] Running backend test suite..."
	pytest backend/tests -v

reset-db:
	@echo "[*] Resetting database..."
	$(PYTHON) backend/reset_db.py

demo: reset-db
	@echo "[*] Running full_attack_chain scenario at demo speed (3.0x)..."
	$(PYTHON) simulator/simulate.py --scenario full_attack_chain --speed 3.0 --target http://127.0.0.1:8000/api/ingest

docker-build:
	docker compose build

docker-up:
	docker compose up --build

docker-demo:
	docker compose --profile demo up --build

docker-down:
	docker compose down -v

