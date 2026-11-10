# SOC Copilot — API & Telemetry Reference

> Complete technical specification of REST endpoints, WebSocket events, log schemas, and ingestion protocols for SOC Copilot.

---

## Table of Contents
1. [Overview & Base URLs](#overview--base-urls)
2. [Telemetry Ingestion (`POST /api/ingest`)](#telemetry-ingestion-post-apiingest)
   - [Supported Log Formats](#supported-log-formats)
   - [Perimeter Firewall Filtering Behavior](#perimeter-firewall-filtering-behavior)
3. [Incidents API](#incidents-api)
   - [`GET /api/incidents`](#get-apiincidents)
   - [`GET /api/incidents/{id}`](#get-apiincidentsid)
   - [`POST /api/incidents/{id}/reanalyze`](#post-apiincidentsidreanalyze)
4. [Response & Containment API](#response--containment-api)
   - [`POST /api/incidents/{id}/actions`](#post-apiincidentsidactions)
   - [`POST /api/response/unblock`](#post-apiresponseunblock)
   - [`GET /api/response/blocked-ips`](#get-apiresponseblocked-ips)
   - [`GET /api/response/audit-log`](#get-apiresponseaudit-log)
5. [Alerts & Rules API](#alerts--rules-api)
   - [`GET /api/alerts`](#get-apialerts)
   - [`GET /api/rules`](#get-apirules)
6. [System Health & Status](#system-health--status)
   - [`GET /api/health`](#get-apihealth)
7. [Real-Time WebSocket Protocol (`/ws`)](#real-time-websocket-protocol-ws)

---

## Overview & Base URLs

- **Default Local Base URL:** `http://localhost:8000`
- **Interactive Swagger Documentation:** `http://localhost:8000/docs`
- **OpenAPI JSON Schema:** `http://localhost:8000/openapi.json`
- **WebSocket Endpoint:** `ws://localhost:8000/ws`

All REST endpoints accept and return JSON encoded as UTF-8.

---

## Telemetry Ingestion (`POST /api/ingest`)

Accepts raw security event logs, normalizes them via regex parsers, applies the perimeter firewall drop filter, checks detection rules, and returns processing metrics.

- **Method:** `POST`
- **Path:** `/api/ingest`
- **Headers:** `Content-Type: application/json`

### Request Body Schema:
```json
{
  "logs": [
    "Jan 01 12:01:10 webserver sshd[1234]: Failed password for invalid user admin from 185.220.101.5 port 44820 ssh2",
    "date=2024-01-01 time=12:00:01 devname=\"FW-EDGE-01\" srcip=103.203.57.18 dstip=10.0.0.5 dstport=22 action=\"drop\"",
    "185.220.101.5 - - [01/Jan/2024:12:02:00 +0000] \"POST /api/export HTTP/1.1\" 200 131072000 \"-\" \"curl/7.68.0\""
  ]
}
```

### Supported Log Formats:
1. **Host Authentication (`/var/log/auth.log` / `secure`):**
   - Syntax: `Jan 01 12:01:10 <host> sshd[<pid>]: <message>`
   - Extracted: `timestamp`, `service`, `user`, `src_ip`, `status` (`failed` / `accepted`).
2. **Perimeter Firewall (Key-Value Format):**
   - Syntax: `date=... time=... devname="..." srcip=... dstip=... dstport=... action="..."`
   - Extracted: `timestamp`, `src_ip`, `dst_ip`, `dst_port`, `action` (`drop`, `allow`, `deny`), `bytes_sent`.
3. **Nginx / Apache Web Server (Combined Log Format):**
   - Syntax: `<ip> - <user> [<timestamp>] "<method> <path> <proto>" <status> <bytes> "<ref>" "<ua>"`
   - Extracted: `src_ip`, `user`, `url`, `http_status`, `bytes_sent`, `user_agent`.

### Response (200 OK):
```json
{
  "status": "success",
  "ingested_count": 3,
  "dropped_firewall_count": 0,
  "alerts_generated": 1,
  "incidents_affected": 1
}
```

---

## Incidents API

### `GET /api/incidents`
Lists correlated multi-stage threat incidents with filtering options.

**Query Parameters:**
- `status` *(optional)*: Filter by `open`, `contained`, or `closed`.
- `severity` *(optional)*: Filter by `critical`, `high`, `medium`, or `low`.
- `limit` *(optional, default 50)*: Maximum number of incidents to return.

**Response (200 OK):**
```json
[
  {
    "id": 1,
    "title": "Multi-stage attack from 185.220.101.5: scan, brute force, successful login, exfiltration",
    "severity": "critical",
    "status": "contained",
    "attacker_ip": "185.220.101.5",
    "affected_users": ["root", "admin"],
    "created_at": "2024-01-01T12:00:00Z",
    "updated_at": "2024-01-01T12:02:15Z",
    "alert_count": 4,
    "ai_triage_confidence": 0.92
  }
]
```

---

### `GET /api/incidents/{id}`
Returns full incident telemetry, including all linked atomic alerts ordered chronologically by MITRE ATT&CK tactic progression, and the Gemini AI triage brief.

**Response (200 OK):**
```json
{
  "id": 1,
  "title": "Multi-stage attack from 185.220.101.5",
  "severity": "critical",
  "status": "open",
  "attacker_ip": "185.220.101.5",
  "affected_users": ["admin"],
  "ai_summary": "A multi-stage attack campaign was detected originating from 185.220.101.5...",
  "likely_attacker_goal": "Initial foothold leading to bulk unauthorized database exfiltration.",
  "ai_confidence": 0.92,
  "recommended_actions": [
    {
      "action_type": "block_ip",
      "target": "185.220.101.5",
      "priority": "critical",
      "description": "Block the adversary source IP at the edge firewall."
    }
  ],
  "alerts": [
    {
      "id": 101,
      "rule_id": "network_port_scan",
      "severity": "medium",
      "mitre_tactic": "discovery",
      "mitre_technique_id": "T1046",
      "timestamp": "2024-01-01T12:00:00Z"
    }
  ]
}
```

---

### `POST /api/incidents/{id}/reanalyze`
Forces an immediate re-evaluation of the incident using the Google Gemini 3.5 Flash RAG engine.

**Response (200 OK):**
Returns the refreshed incident object with updated `ai_summary`, `ai_confidence`, and playbooks.

---

## Response & Containment API

### `POST /api/incidents/{id}/actions`
Executes an active defensive containment action with human-in-the-loop audit validation.

**Request Body:**
```json
{
  "action_type": "block_ip",
  "target": "185.220.101.5",
  "analyst_id": "analyst-john-tier2",
  "justification": "Adversary confirmed exfiltrating customer database over port 443."
}
```

**Supported Action Types:**
- `block_ip`: Adds the IP to the active perimeter firewall blocklist and transitions parent incident status to `contained`.
- `disable_user`: Marks user account disabled, invalidates active tokens, and transitions incident to `contained`.
- `create_ticket`: Emits a formal SecOps remediation ticket with audit confirmation.

**Response (200 OK):**
```json
{
  "status": "success",
  "action_id": 42,
  "action_type": "block_ip",
  "target": "185.220.101.5",
  "incident_status": "contained",
  "audit_logged": true
}
```

---

### `POST /api/response/unblock`
Reverses a previously applied firewall block or re-enables a user account.

**Request Body:**
```json
{
  "target": "185.220.101.5",
  "analyst_id": "analyst-john-tier2",
  "justification": "IP determined to be an authorized vulnerability scanner partner."
}
```

---

### `GET /api/response/blocked-ips`
Returns list of all currently active perimeter firewall blocks.

---

### `GET /api/response/audit-log`
Returns the immutable compliance audit trail capturing timestamps, operator IDs, action types, targets, and operational justifications.

---

## System Health & Status

### `GET /api/health`
Checks system components, active database connection, rule count, and active blocklist length.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database": "connected",
  "active_rules_loaded": 11,
  "blocked_ips_active": 1,
  "timestamp": "2024-01-01T12:05:00Z"
}
```

---

## Real-Time WebSocket Protocol (`/ws`)

Connect via standard WebSocket protocol: `ws://localhost:8000/ws`.

The backend broadcasts real-time events as JSON envelopes:

```json
{
  "type": "ALERT_TRIGGERED",
  "data": {
    "id": 105,
    "rule_id": "ssh_brute_force",
    "severity": "high",
    "src_ip": "185.220.101.5",
    "timestamp": "2024-01-01T12:01:15Z"
  }
}
```

### Broadcast Event Types:
| Event Type | Trigger | Payload Data |
|---|---|---|
| `ALERT_TRIGGERED` | A detection rule threshold was breached | Enriched alert record |
| `INCIDENT_UPDATED` | An incident was created, escalated, or contained | Full incident metadata |
| `ACTION_EXECUTED` | Analyst confirmed a containment action | Action type, target, analyst ID |
| `ACTION_UNDONE` | Analyst reversed a block or account restriction | Target, operator ID, justification |
| `LOGS_INGESTED` | A batch of logs was ingested | Count of ingested vs dropped events |

