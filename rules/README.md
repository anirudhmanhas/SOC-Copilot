# SOC Copilot — Detection Rules Engine Specification

> **Framework**: Human-Readable YAML Detection Rules mapped directly to the **MITRE ATT&CK Enterprise Matrix** with sliding temporal window evaluation and alert deduplication.

---

## 1. What is the Rules Engine?
The **Rules Engine** is the deterministic threat detection core of SOC Copilot. It inspects normalized `LogEvent` records emitted by the ingestion pipeline and evaluates them against 11 detection rules covering the most frequent attack vectors: credential spraying, SSH brute force, SQL injection, network port scanning, privilege escalation, and high-volume data exfiltration.

---

## 2. Why YAML & MITRE ATT&CK?

1. **Vendor Independence**: Traditional SIEMs force operators into proprietary query languages (Splunk SPL, Microsoft KQL). SOC Copilot uses declarative YAML rules that any security engineer can read, audit, and modify in seconds without proprietary certifications.
2. **Standardized Adversary Taxonomy**: Every detection rule maps to an official MITRE ATT&CK tactic (`Initial Access`, `Credential Access`, `Discovery`, `Exfiltration`) and technique ID (`T1110`, `T1046`, `T1190`). This powers downstream automated correlation and RAG AI triage.
3. **Sliding-Window Deduplication**: Prevents alert floods by maintaining in-memory temporal sliding windows ($W$) that suppress redundant alerts from the same source within active investigation intervals.

---

## 3. How It Works — Rule Architecture

### Complete YAML Rule Schema
```yaml
id: RULE-AUTH-001
name: SSH Password Spraying & Brute Force
description: Detects rapid-fire failed authentication attempts against multiple or targeted accounts from a single external IP.
severity: high # low | medium | high | critical
source: ssh # ssh | firewall | web | system
mitre_technique: T1110.001 # Primary MITRE ATT&CK Technique ID

detection:
  type: threshold # threshold | distinct | pattern
  field: src_ip # Pivot field to group events by
  conditions: # Filter criteria to isolate candidate events
    status: failed
    event_type: authentication
  count: 5 # Minimum event threshold to trigger an alert
  window_seconds: 60 # Sliding temporal window in seconds

action_recommendations:
  - action_type: block_ip
    target_field: src_ip
    reason: "Block malicious source IP at perimeter firewall to halt brute-force attempts."
    priority: high
  - action_type: disable_user
    target_field: user
    reason: "Force password reset and terminate active sessions for targeted accounts."
    priority: high
  - action_type: create_ticket
    target_field: null
    reason: "Escalate to SecOps incident response team for forensic scoping."
    priority: medium
```

---

## 4. Detection Types Explained

| Detection Type | Mechanism | Example Rule |
|---|---|---|
| **`threshold`** | Triggers when $\ge N$ matching events occur within $W$ seconds grouped by a pivot field (`src_ip`, `user`). | `ssh_brute_force.yaml`: $\ge 5$ failed logins in 60s from one IP. |
| **`distinct`** | Triggers when an event sequence targets $\ge N$ distinct values within $W$ seconds. | `port_scan.yaml`: Drops across $\ge 20$ distinct destination ports in 60s. |
| **`pattern`** | Evaluates regular expression signatures against raw content or URI paths. | `sql_injection.yaml`: Matches `UNION SELECT`, `OR 1=1`, or `sqlmap` user-agents. |

---

## 5. Active Rule Catalog

| Rule ID | File | Severity | MITRE Technique | Description |
|---|---|:---:|:---:|---|
| `RULE-SSH-001` | `ssh_brute_force.yaml` | **High** | `T1110.001` | $\ge 5$ failed password attempts within 60s from a single source IP |
| `RULE-AUTH-002` | `password_spraying.yaml` | **High** | `T1110.003` | Authentication failures across multiple user accounts from one origin |
| `RULE-AUTH-003` | `successful_login_after_failures.yaml` | **Critical** | `T1078` | Accepted authentication following a sequence of failed login attempts |
| `RULE-NET-001` | `port_scan.yaml` | **High** | `T1046` | Connection drops across $\ge 20$ distinct ports within 60s |
| `RULE-WEB-001` | `sql_injection.yaml` | **High** | `T1190` | SQL injection exploit signatures in HTTP query strings or bodies |
| `RULE-WEB-002` | `xss_probe.yaml` | **Medium** | `T1190` | Cross-site scripting probe tags (`<script>`, `onerror=`) in web requests |
| `RULE-WEB-003` | `directory_traversal.yaml` | **High** | `T1083` | Path traversal exploit sequences (`../`, `%2e%2e%2f`) targeting web roots |
| `RULE-WEB-004` | `automated_scanner_probe.yaml` | **Medium** | `T1595` | Security scanner user-agents (`Nikto`, `sqlmap`, `Nmap Scripting Engine`) |
| `RULE-NET-002` | `large_outbound_transfer.yaml` | **Critical** | `T1041` | High-volume outbound data transfer ($\ge 50\text{ MB}$) to an external IP |
| `RULE-PRIV-001` | `sudo_privilege_escalation.yaml` | **Critical** | `T1548.003` | Unauthorized sudo commands or failed root privilege elevations |
| `RULE-AUTH-004` | `anomalous_login_location.yaml` | **Medium** | `T1078.003` | Valid logins originating from geographically anomalous IP subnets |

---

## 6. How to Author a Custom Rule

1. Create a new `.yaml` file inside the `rules/` directory (e.g. `rules/my_new_rule.yaml`).
2. Specify the unique `id`, `name`, `severity`, and valid `mitre_technique` ID.
3. Define the `detection` block with `type`, `field`, `conditions`, and `window_seconds`.
4. Add `action_recommendations` for the AI Analyst and operators.
5. The rules engine auto-loads all `.yaml` files from `rules/` on application startup without code modifications.
