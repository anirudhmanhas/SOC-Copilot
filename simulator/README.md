# SOC Copilot — Threat Simulator Specification

> **Telemetry Generator**: Synthetic multi-phase attack dispatcher generating realistic enterprise telemetry across firewalls, web servers, and authentication endpoints.

---

## 1. What is the Threat Simulator?
The **Threat Simulator** ([`simulate.py`](simulate.py)) is a standalone telemetry generation engine built to test, benchmark, and demonstrate the SOC Copilot ingestion and correlation pipeline. It produces authentic, high-fidelity log streams with accurate RFC-compliant timestamps, realistic HTTP access logs, Linux PAM auth events, and firewall key-value pairs without requiring external attack infrastructure.

---

## 2. Why Use Synthetic Telemetry?

1. **Safe Testing Environment**: Real-world attacks cannot be safely executed against production systems during live demonstrations or automated continuous integration (CI) tests.
2. **Reproducible Multi-Stage Attack Chains**: Replicating complex multi-phase breaches (reconnaissance $\to$ credential brute-force $\to$ valid account session $\to$ massive outbound data transfer) on demand ensures consistent benchmarking of correlation algorithms.
3. **Zero Risk**: 100% of IP addresses, user accounts, and payloads are synthetic, eliminating security, legal, and privacy risks.

---

## 3. How It Works — Multi-Phase Kill-Chain Playback

The flagship scenario, `full_attack_chain`, executes the complete adversary lifecycle:

```
Step 1: Network Reconnaissance (T1046)
└── Firewall Deny Logs: Attacker probes 26 distinct destination ports within 60s
       │
       ▼
Step 2: Credential Access (T1110.001)
└── SSH Auth Logs: 15 rapid-fire failed logins targeting accounts admin, root, ubuntu
       │
       ▼
Step 3: Initial Access & Defense Evasion (T1078)
└── SSH Auth Logs: Successful authentication for user 'admin' + PAM session opened
       │
       ▼
Step 4: Exfiltration (T1041)
└── Firewall Allow Logs: Massive 75 MB outbound transfer over port 443 to attacker IP
```

---

## 4. CLI Options & Execution Guide

```bash
python simulator/simulate.py [OPTIONS]
```

### Options Reference:
- `--scenario`: Attack scenario to execute. Options:
  - `full_attack_chain` (Default: Complete 4-phase kill-chain)
  - `ssh_bruteforce` (15+ failed SSH authentications)
  - `sql_injection` (Web exploits with `UNION SELECT` and `sqlmap` user-agents)
  - `port_scan` (Firewall drops across 25+ ports)
  - `credential_stuffing_then_login` (Failed attempts followed by valid login)
  - `data_exfil` (High-volume outbound data transfer)
  - `normal` (Background enterprise noise: valid HTTPS/DNS/SSH sessions)
- `--target`: Ingestion endpoint URL. Default: `http://localhost:8000/api/ingest`.
- `--speed`: Playback speed multiplier (e.g. `1.0` = real-time, `3.0` = 3x demo speed, `10.0` = rapid CI test).
- `--batch-size`: Number of log events bundled per HTTP POST. Default: `5`.
- `--attacker-ip`: Explicit adversary IP address (e.g. `185.220.101.5`).
- `--loop`: Runs continuously for persistent dashboard monitoring sessions.
- `--dry-run`: Prints generated logs to terminal stdout without sending HTTP requests.

---

## 5. Usage Examples

### 1. 3-Minute Live Hackathon Demo (Recommended)
```bash
python simulator/simulate.py --scenario full_attack_chain --speed 3.0
```

### 2. Standalone Docker Simulator Service
```bash
docker compose --profile demo up
```

### 3. Rapid Pipeline Verification (10x Speed)
```bash
python simulator/simulate.py --scenario full_attack_chain --speed 10.0
```

### 4. Background Enterprise Noise Generator
```bash
python simulator/simulate.py --scenario normal --loop --speed 2.0
```
