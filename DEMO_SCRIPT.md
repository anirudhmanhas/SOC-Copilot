# SOC Copilot — 3-Minute Evaluator & Judge Demo Script

**Target Duration:** 3 minutes (180 seconds)  
**Audience:** Hackathon Judges, Security Architects, SOC Managers, Technical Evaluators  
**Core Narrative:** 
- **WHAT**: An autonomous, AI-powered Security Operations Center platform.
- **WHY**: Traditional SIEMs cost \$100k+, generate 80% false positives, fragment multi-stage breaches, and autonomous black-box AI is unsafe.
- **HOW**: Multi-source log ingestion $\to$ 11 YAML rules $\to$ MITRE ATT&CK correlation $\to$ Google Gemini 3.5 Flash RAG triage $\to$ 1-click human-in-the-loop active containment.

---

## Pre-Demo Checklist (T-Minus 1 Minute)

### Option A: Docker Compose Deployment (Zero Configuration)
```bash
# Launch full platform in 1 command
docker compose up --build
```
- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8000`

### Option B: Native Deployment
- [ ] **Backend Process:** Running on `http://127.0.0.1:8000`
- [ ] **Frontend Process:** Running on `http://localhost:5173`
- [ ] **Clean State:** Run `make demo` (or `./demo.sh` / `.\demo.ps1` / `demo.bat`) to reset data.

---

## Live Demo Flow & Narrative Cue Sheet

### Scene 1: The Problem & Solution — The WHAT & WHY (0:00 – 0:30)
**On Screen:** Overview Dashboard (`http://localhost:5173/`). Point cursor to the KPI cards and Threat Map.

> **What to Say:**
> *"Modern security teams face an impossible crisis: traditional tools like Splunk and Sentinel cost over \$100,000 annually, generate 10,000 alerts a day where 80% are false alarms, and treat complex attacks as dozens of disconnected tickets.*
>
> *This is **SOC Copilot** — an open-source, AI-powered Security Operations Center. It ingests raw logs across firewalls, web servers, and authentication systems, correlates them into single multi-stage incidents using the MITRE ATT&CK framework, uses **Google Gemini 3.5 Flash** for instant threat triage, and enables safe, 1-click active containment with zero vendor lock-in."*

---

### Scene 2: Live Ingestion & The Global Threat Map — The HOW (0:30 – 1:15)
**Action:** Click **"Simulate Attack"** in the top navigation bar, select **"Full Attack Chain (Multi-Stage Critical)"**, and trigger it (or run `make demo` in terminal).  
**On Screen:** Point to the **Real-Time Live Alerts Stream** and the **Global Threat Vector Map**.

> **What to Say:**
> *"Let's inject realistic adversary telemetry. We simulate an advanced actor originating from IP `185.220.101.5`.*
>
> *Watch the dashboard update live over WebSockets:*
> 1. *Perimeter firewall drops light up as the attacker probes 25 ports.*
> 2. *Next, rapid password spraying hits our SSH servers against users `ubuntu`, `postgres`, and `admin`.*
> 3. *Third, they find a valid password and authenticate.*
> 4. *Finally, a massive 75-megabyte outbound transfer triggers our exfiltration detection.*
>
> *Notice our tactical map: trajectory lines stream live from Europe to our Washington D.C. protected gateway without needing a page refresh."*

---

### Scene 3: Multi-Stage MITRE Incident Correlation (1:15 – 1:45)
**Action:** Click **"Incidents"** in the navbar. Click on the Critical incident: `"Multi-stage attack from 185.220.101.5: scan, brute force, successful login, exfiltration"`.  
**On Screen:** Incident Detail page (`/incidents/{id}`). Scroll through the **Attack Timeline**.

> **What to Say:**
> *"Instead of generating 71 noisy atomic tickets, our correlation engine used sliding temporal windows and IP clustering to collapse the entire campaign into **one single Critical Incident**.*
>
> *On the Attack Timeline, alerts are automatically organized in MITRE kill-chain progression order:*
> *Discovery → Credential Access → Initial Access → Exfiltration.*
> *An analyst immediately understands the full anatomy of the breach in seconds."*

---

### Scene 4: Google Gemini AI Triage & RAG (1:45 – 2:25)
**On Screen:** Point to the **Gemini AI Triage Analyst** card on the left. Highlight the **Executive Summary**, **Confidence Score (95%+)**, **Likely Attacker Goal**, and **Recommended Playbook**.

> **What to Say:**
> *"Here is where Google Gemini steps in as our AI Tier-2 Analyst.*
>
> *Using Retrieval-Augmented Generation (RAG), the engine feeds the incident timeline alongside curated MITRE ATT&CK techniques into **Google Gemini 3.5 Flash**.*
>
> *Gemini delivers an executive threat summary in plain English, pinpoints the attacker's goal as high-privilege credential access and data exfiltration, and provides actionable containment steps.*
>
> *Notice our core design principle: **Human-in-the-Loop Safety**. The AI only recommends; actions are never executed autonomously without explicit human verification."*

---

### Scene 5: 1-Click Active Containment & Verification (2:25 – 3:00)
**Action:** 
1. In the AI Analyst card, click the red **"Block IP"** button.
2. In the confirmation modal, point to the pre-filled target IP `185.220.101.5`, enter analyst ID, and click **"Confirm Action"**.
3. Point out the incident status changing to **`contained`**.
4. Click **"Response Center"** in the top navbar to show the **Blocked IPs** table and **Audit Log**.
5. *(Optional)* Click **"Showcase / Tour"** in the navbar to show the built-in product website.

> **What to Say:**
> *"To neutralize the threat, I click **Block IP**. A modal asks for operator confirmation, analyst identity, and justification for compliance.*
>
> *I confirm the containment. Instantly:*
> 1. *The incident status transitions to **Contained**.*
> 2. *Our perimeter firewall drops any subsequent traffic from this IP at ingestion.*
> 3. *On the Threat Map, the attacker marker turns gray.*
> 4. *And in our **Response Center**, an immutable audit log entry is recorded with full timestamps and analyst attribution.*
>
> *In under three minutes, we ingested multi-source telemetry, correlated a 4-phase kill chain, generated AI triage with Gemini, and fully contained an active breach with Docker 1-command deployment. That is SOC Copilot."*

---

## Speaker Quick Reference Table

| Time | Screen | What to Show | Why It Matters |
|---|---|---|---|
| **0:00 - 0:30** | Overview | KPI cards & Threat Map | Explains the \$100k SIEM cost problem and alert fatigue crisis |
| **0:30 - 1:15** | Threat Map & Live Feed | Ingest 71 logs in real time | Demonstrates multi-source ingestion & live WebSockets |
| **1:15 - 1:45** | Incident Detail | Kill-Chain Attack Timeline | Shows 71 alerts collapsed into **1 correlated incident** |
| **1:45 - 2:25** | AI Analyst Card | Gemini Summary & Confidence | Demonstrates RAG over MITRE ATT&CK with human-in-the-loop safety |
| **2:25 - 3:00** | Modal & Response Center | Block IP action & Audit Log | Proves active containment, firewall drop, and compliance audit trail |
