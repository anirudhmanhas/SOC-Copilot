# SOC Copilot — Attack Simulation & Demo Guide

> Comprehensive guide to generating synthetic adversary attacks, running automated demonstration flows, and testing the SOC Copilot detection and correlation pipeline.

---

## Table of Contents
1. [Overview & Simulation Engine](#overview--simulation-engine)
2. [Automated Demo Scripts (1-Command Run)](#automated-demo-scripts-1-command-run)
3. [Pre-Packaged Threat Scenarios](#pre-packaged-threat-scenarios)
   - [Scenario 1: Full Multi-Stage Attack Chain (Flagship)](#scenario-1-full-multi-stage-attack-chain-flagship)
   - [Scenario 2: SSH Brute Force Attack](#scenario-2-ssh-brute-force-attack)
   - [Scenario 3: SQL Injection Web Application Attack](#scenario-3-sql-injection-web-application-attack)
   - [Scenario 4: Perimeter Firewall Port Scan Reconnaissance](#scenario-4-perimeter-firewall-port-scan-reconnaissance)
4. [Simulator CLI Reference (`simulate.py`)](#simulator-cli-reference-simulatepy)
5. [In-App UI Attack Trigger](#in-app-ui-attack-trigger)
6. [Pipeline Telemetry Breakdown](#pipeline-telemetry-breakdown)

---

## Overview & Simulation Engine

SOC Copilot includes an integrated attack simulation engine (`simulator/simulate.py`) that generates authentic, RFC-compliant security logs across three heterogeneous formats:
- **Perimeter Firewall Logs:** Key-Value format (Fortinet / Palo Alto style)
- **Web Application Server Logs:** Nginx Combined Log Format
- **Host Authentication Logs:** Linux `/var/log/auth.log` (sshd service)

The simulator dispatches logs over HTTP to `POST /api/ingest`, exercising the live normalization parsers, sliding-window detection rules, temporal correlation engine, Google Gemini AI analyst, and WebSocket event broadcaster.

---

## Automated Demo Scripts (1-Command Run)

To run a clean live demonstration that resets the test database, verifies backend health, and streams the 4-phase attack scenario at optimal evaluation speed:

```bash
# Linux / macOS / WSL:
make demo
# or:
./demo.sh

# Windows (PowerShell):
.\demo.ps1

# Windows (Command Prompt):
demo.bat
```

### What the Automated Script Does:
1. Pings `http://127.0.0.1:8000/api/health` to confirm the backend is running.
2. Executes `backend/reset_db.py` to truncate previous events, alerts, incidents, and firewall blocks.
3. Launches `simulate.py --scenario full_attack_chain --delay 0.05`.
4. Dispatches 71 security logs over ~10 seconds.
5. Verifies that exactly **1 unified Critical incident** is created.

---

## Pre-Packaged Threat Scenarios

### Scenario 1: Full Multi-Stage Attack Chain (Flagship)
- **Attacker IP:** `185.220.101.5`
- **Target Host:** `10.0.0.5`
- **Victim User:** `admin` / `root`
- **Total Log Count:** 71 logs
- **MITRE Tactics Traversed:** 4 (`Discovery` $\to$ `Credential Access` $\to$ `Defense Evasion` $\to$ `Exfiltration`)

#### The 4 Kill-Chain Phases:
1. **Phase 1: Discovery (Port Scan Reconnaissance)**
   - 25 perimeter firewall drop logs across destination ports 21, 22, 23, 25, 80, 443, 8080, etc.
   - *Rule Triggered:* `Network Port Scan Reconnaissance` (MITRE `T1046`).
2. **Phase 2: Credential Access (SSH Brute-Force)**
   - 15 failed authentication attempts against `root` and `admin` within 2 minutes.
   - *Rule Triggered:* `SSH Brute Force Attack` (MITRE `T1110.001`).
3. **Phase 3: Defense Evasion (Initial Access & Compromise)**
   - A successful login from `185.220.101.5` following multiple failed attempts.
   - *Rule Triggered:* `Successful Login After Multiple Failures` (MITRE `T1078`).
4. **Phase 4: Exfiltration (Data Outflow)**
   - Large outbound data transfer of **125 MB** over port 443 to external IP `185.220.101.5`.
   - *Rule Triggered:* `Large Outbound Data Transfer` (MITRE `T1041`).

*Outcome:* The correlation engine collapses all 71 events into **Incident #1**, escalates severity to **CRITICAL**, triggers Gemini AI triage, and displays the attack trajectory on the threat map.

---

### Scenario 2: SSH Brute Force Attack
- **Attacker IP:** `194.26.29.112`
- **Scenario Name:** `ssh_brute_force`
- **Description:** 12 rapid failed authentication attempts against accounts `root`, `admin`, `ubuntu`, and `service`.
- **Target Rule:** `SSH Brute Force Attack` (MITRE `T1110.001`).
- **Resulting Severity:** `HIGH`.

```bash
python simulator/simulate.py --scenario ssh_brute_force --delay 0.1
```

---

### Scenario 3: SQL Injection Web Application Attack
- **Attacker IP:** `45.154.255.89`
- **Scenario Name:** `sql_injection`
- **Description:** Exploitation attempts against Nginx web server targeting endpoints like `/api/users?id=1' UNION SELECT username, password FROM users--` and `sqlmap` automated scanners.
- **Target Rule:** `Web Application SQL Injection` (MITRE `T1190`).
- **Resulting Severity:** `HIGH`.

```bash
python simulator/simulate.py --scenario sql_injection --delay 0.1
```

---

### Scenario 4: Perimeter Firewall Port Scan Reconnaissance
- **Attacker IP:** `103.203.57.18`
- **Scenario Name:** `port_scan`
- **Description:** Rapid connection drops across 20 distinct destination ports in 60 seconds.
- **Target Rule:** `Network Port Scan Reconnaissance` (MITRE `T1046`).
- **Resulting Severity:** `MEDIUM` (1 tactic).

```bash
python simulator/simulate.py --scenario port_scan --delay 0.05
```

---

## Simulator CLI Reference (`simulate.py`)

Run the simulator directly via Python:

```bash
python simulator/simulate.py [OPTIONS]
```

### Supported Flags:

| Flag | Default | Description |
|---|---|---|
| `--scenario` | `full_attack_chain` | Scenario to replay (`full_attack_chain`, `ssh_brute_force`, `sql_injection`, `port_scan`). |
| `--delay` | `0.1` | Inter-log dispatch delay in seconds. Use `0.05` for demo speed. |
| `--target-url` | `http://localhost:8000/api/ingest` | Backend ingestion endpoint URL. |
| `--repeat` | `1` | Number of times to replay the selected scenario. |
| `--noise` | `true` | When true, injects benign background web and SSH traffic. |

---

## In-App UI Attack Trigger

If you prefer not to use the terminal, you can trigger simulations directly from the dashboard:
1. Open the dashboard at **[http://localhost:5173](http://localhost:5173)**.
2. In the top navigation bar, click the green **"Simulate Attack"** button.
3. Select any scenario from the dropdown:
   - *Full Attack Chain*
   - *SSH Brute Force*
   - *SQL Injection*
   - *Port Scan*
4. Detections and KPI cards will immediately stream onto the screen in real time.

---

## Pipeline Telemetry Breakdown

During simulation playback, watch the following components react:
1. **Toast Notifications:** Alert popups appear in the bottom-right corner.
2. **Velocity Chart:** Area chart spikes as event volume climbs.
3. **Tactical Threat Map:** Red dashed attack trajectory arrows animate from adversary country nodes to your enterprise headquarters.
4. **Incidents Hub:** Detections are correlated into a single high-priority card.
5. **AI Analyst Card:** Gemini generates root-cause analysis, attacker intent, and containment playbooks in under 3 seconds.

