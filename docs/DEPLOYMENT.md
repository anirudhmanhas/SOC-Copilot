# SOC Copilot — Deployment & Operations Guide

> Complete installation, configuration, containerization, and production operations guide for SOC Copilot.

---

## Table of Contents
1. [Prerequisites & System Requirements](#prerequisites--system-requirements)
2. [Environment Configuration (`.env`)](#environment-configuration-env)
3. [Docker Compose Deployment (Recommended)](#docker-compose-deployment-recommended)
   - [Service Architecture](#service-architecture)
   - [Multi-Stage Dockerfile Internals](#multi-stage-dockerfile-internals)
   - [Common Docker CLI Commands](#common-docker-cli-commands)
   - [Persistent Storage & Volumes](#persistent-storage--volumes)
4. [Native Bare-Metal / Local Setup](#native-bare-metal--local-setup)
   - [Backend Setup (FastAPI & Python 3.12)](#backend-setup-fastapi--python-312)
   - [Frontend Setup (React 18 & Vite)](#frontend-setup-react-18--vite)
5. [Production Reverse Proxy & WebSockets](#production-reverse-proxy--websockets)
6. [Healthchecks & Monitoring](#healthchecks--monitoring)
7. [Troubleshooting & FAQ](#troubleshooting--faq)

---

## Prerequisites & System Requirements

### Minimum Hardware Specifications
- **CPU:** 2 vCPU cores (4 cores recommended for simultaneous high-throughput ingestion and UI rendering)
- **RAM:** 4 GB RAM (8 GB recommended for Docker Compose with local DB)
- **Disk Space:** 5 GB free disk space for container images and telemetry storage
- **Operating System:** Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+), macOS 13+, or Windows 10/11 with WSL2 / Docker Desktop

### Software Prerequisites
| Tool | Minimum Version | Purpose |
|---|---|---|
| **Docker** | 24.0+ | Container runtime engine |
| **Docker Compose** | v2.20+ | Multi-container composition and volume orchestrator |
| **Python** *(Optional if using Docker)* | 3.12+ | Native FastAPI backend runtime |
| **Node.js** *(Optional if using Docker)* | 18.0+ | Native Vite development server |

---

## Environment Configuration (`.env`)

Create a `.env` file in the repository root (or in `backend/.env`). A pre-configured template is provided below:

```bash
# ============================================================
# Google Gemini API Key for LLM Triage
# Get your free key at: https://aistudio.google.com/
# ============================================================
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.5-flash-lite

# When set to true, disables external Gemini API calls and uses
# the built-in deterministic multi-perspective analytical engine.
USE_MOCK_AI=false

# ============================================================
# Backend Server Configuration
# ============================================================
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
DATABASE_URL=sqlite:///./soc_copilot.db
CORS_ORIGINS=http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173

# ============================================================
# Rules and MITRE ATT&CK Catalog Paths
# ============================================================
RULES_DIR=../rules
MITRE_DATA_PATH=../data/mitre_attack_subset.json
```

### Environment Variables Reference Table

| Variable | Default Value | Description |
|---|---|---|
| `GEMINI_API_KEY` | *(Empty)* | Google Gemini API key required for live AI incident analysis. |
| `GEMINI_MODEL` | `gemini-3.5-flash-lite` | Model identifier (`gemini-3.5-flash-lite` or `gemini-pro-latest`). |
| `USE_MOCK_AI` | `false` | Fallback flag: when `true`, rotates heuristic analysis without network calls. |
| `BACKEND_HOST` | `0.0.0.0` | Network interface to bind FastAPI. |
| `BACKEND_PORT` | `8000` | Port for the backend REST and WebSocket server. |
| `DATABASE_URL` | `sqlite:///./soc_copilot.db` | SQLAlchemy connection string (SQLite file or PostgreSQL URI). |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Comma-separated list of allowed frontend origins. |
| `RULES_DIR` | `../rules` | Path to directory containing detection rule YAML definitions. |
| `MITRE_DATA_PATH` | `../data/mitre_attack.json` | Path to the MITRE ATT&CK knowledgebase catalog. |

---

## Docker Compose Deployment (Recommended)

SOC Copilot provides production-ready containerization with zero external dependencies.

### Service Architecture

```
                    ┌────────────────────────────────────────────────────────┐
                    │                   Host Machine                         │
                    │                                                        │
                    │    Port 5173 ──► [soc-copilot-frontend] (Nginx)        │
                    │                       │                                │
                    │                       │ /api and /ws reverse proxy     │
                    │                       ▼                                │
                    │    Port 8000 ──► [soc-copilot-backend] (FastAPI)       │
                    │                       ▲                                │
                    │                       │ Telemetry ingestion            │
                    │    (Optional) ─────── [soc-copilot-simulator]          │
                    │    --profile demo                                      │
                    │                       │                                │
                    │                       ▼                                │
                    │             [Volume: soc-db-data]                      │
                    │                    SQLite                              │
                    └────────────────────────────────────────────────────────┘
```

### Container Specifications

| Container Name | Base Image | Role & Responsibilities | Port Mappings |
|---|---|---|---|
| `soc-copilot-backend` | `python:3.12-slim` | FastAPI REST API, correlation engine, Gemini AI triage, SQLite database | `8000:8000` |
| `soc-copilot-frontend` | `node:20-alpine` $\to$ `nginx:alpine` | Multi-stage build serving React dashboard with Nginx reverse proxy | `5173:80` |
| `soc-copilot-simulator` | `python:3.12-slim` | *(Profile: demo)* Plays back the 4-phase `full_attack_chain` attack scenario | *Internal network* |

---

### Multi-Stage Dockerfile Internals

#### 1. Frontend ([`frontend/Dockerfile`](../frontend/Dockerfile))
- **Stage 1 (Builder):** Uses `node:20-alpine` to install dependencies and execute `npm run build` to generate the minified production bundle.
- **Stage 2 (Runtime):** Copies the compiled dist assets into `nginx:alpine`. Uses a custom [`nginx.conf`](../frontend/nginx.conf) with reverse proxying for `/api/` and WebSocket protocol upgrades for `/ws`.

#### 2. Backend ([`backend/Dockerfile`](../backend/Dockerfile))
- Uses lightweight `python:3.12-slim`.
- Installs `curl` to enable container health checks.
- Pre-compiles Python wheels from `requirements.txt`.
- Mounts volume `soc-db-data` to `/app/backend` to guarantee database records and audit trails survive container restarts.

---

### Common Docker CLI Commands

#### 1. Start the Complete Platform
```bash
docker compose up --build
```
- Dashboard UI: **`http://localhost:5173`**
- API Swagger Docs: **`http://localhost:8000/docs`**
- Health Endpoint: **`http://localhost:8000/api/health`**

#### 2. Start in Background (Daemon Mode)
```bash
docker compose up -d
```

#### 3. Run with Automated Attack Simulation (Live Demo Profile)
```bash
docker compose --profile demo up --build
```

#### 4. Stream Container Logs
```bash
# All logs
docker compose logs -f

# Backend logs only
docker compose logs -f backend

# Frontend logs only
docker compose logs -f frontend
```

#### 5. Stop and Clean Containers & Volumes
```bash
# Stop containers (preserves DB volume)
docker compose down

# Stop containers AND wipe database volume (clean reset)
docker compose down -v
```

---

## Native Bare-Metal / Local Setup

If developing locally or running outside Docker, follow these instructions:

### Backend Setup (FastAPI & Python 3.12)

```bash
cd backend

# 1. Create a virtual environment
python -m venv venv

# 2. Activate virtual environment
# Windows (PowerShell):
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1

# Windows (CMD):
.\venv\Scripts\activate.bat

# Linux / macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start backend server with auto-reload
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Backend will be live at: **`http://127.0.0.1:8000`**.

### Frontend Setup (React 18 & Vite)

In a separate terminal window:
```bash
cd frontend

# 1. Install dependencies
npm install

# 2. Start Vite development server
npm run dev
```
Frontend will be live at: **`http://localhost:5173`**.

---

## Production Reverse Proxy & WebSockets

When serving SOC Copilot behind an enterprise reverse proxy (e.g. Nginx, Traefik, or Caddy), ensure HTTP/1.1 and WebSocket upgrade headers are passed:

### Sample Production Nginx Configuration
```nginx
server {
    listen 80;
    server_name soc.yourdomain.com;

    # Frontend Single-Page App static build
    location / {
        root /var/www/soc-copilot/frontend/dist;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # REST API Endpoints
    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Real-Time WebSocket Bus
    location /ws {
        proxy_pass http://127.0.0.1:8000/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

---

## Healthchecks & Monitoring

The backend exposes a health status endpoint:
```bash
curl http://localhost:8000/api/health
```
**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database": "connected",
  "detection_engine": "active",
  "active_rules_loaded": 11,
  "blocked_ips_active": 1
}
```

---

## Troubleshooting & FAQ

### Q: Why do I see "WS: Polling" instead of "WS: Live" in the dashboard?
**A:** This indicates the browser cannot establish a native WebSocket connection to `/ws`.
- If running natively: Ensure the backend is running on port 8000 and the Vite proxy in `vite.config.js` is forwarding `/ws`.
- If running under Docker: Ensure container `soc-copilot-frontend` is proxying `/ws` with HTTP 1.1 upgrade headers as defined in `frontend/nginx.conf`.

### Q: How do I reset the test database for a fresh demo run?
**A:** Run:
```bash
# Using Makefile
make reset-db

# Or native script
python backend/reset_db.py
```
This drops and recreates the SQLite schema with clean indexes.

