"""
SOC Copilot - Incident Correlation Engine
Aggregates atomic detection Alerts into multi-stage Incidents using temporal sliding windows
(10-minute threshold), pivot clustering (src_ip / compromised user), MITRE kill-chain
severity escalation, dynamic human-readable attack titles, and kill-chain timeline sequencing.
"""

import datetime
import logging
from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session, selectinload

from ..models import Alert, Incident

logger = logging.getLogger("soc_copilot.correlation")

# Standard MITRE ATT&CK Enterprise Matrix Kill-Chain Order
KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Attack phase labels mapped to kill-chain progression for title generation
PHASE_PRIORITY = [
    "scan",
    "scanner probe",
    "directory scan",
    "SQL injection",
    "XSS probe",
    "brute force",
    "password spraying",
    "successful login",
    "anomalous login",
    "privilege escalation",
    "exfiltration",
]


def get_alert_phase_label(alert: Alert) -> str:
    """Extract a concise readable attack stage descriptor from an Alert."""
    rule_id = (alert.rule_id or "").upper()
    rule_name = (alert.rule_name or "").lower()
    tactic = (alert.mitre_tactic or "").lower()
    tech_id = (alert.mitre_technique_id or "").upper()

    if "RULE-NET-001" in rule_id or tech_id == "T1046" or "port scan" in rule_name:
        return "scan"
    if "RULE-SSH-001" in rule_id or "brute force" in rule_name or tech_id == "T1110.001":
        return "brute force"
    if "RULE-AUTH-002" in rule_id or "spraying" in rule_name or tech_id == "T1110.003":
        return "password spraying"
    if "RULE-AUTH-003" in rule_id or "successful login" in rule_name:
        return "successful login"
    if "RULE-AUTH-004" in rule_id or "new ip" in rule_name:
        return "anomalous login"
    if "RULE-WEB-001" in rule_id or "sql" in rule_name:
        return "SQL injection"
    if "RULE-WEB-002" in rule_id or "xss" in rule_name:
        return "XSS probe"
    if "RULE-WEB-003" in rule_id or "directory" in rule_name:
        return "directory scan"
    if "RULE-WEB-004" in rule_id or "scanner" in rule_name:
        return "scanner probe"
    if "RULE-NET-002" in rule_id or "exfil" in rule_name or tech_id == "T1041" or "exfiltration" in tactic:
        return "exfiltration"
    if "RULE-PRIV-001" in rule_id or "sudo" in rule_name or "privilege" in tactic:
        return "privilege escalation"

    return alert.rule_name.lower()


def generate_incident_title(src_ip: Optional[str], affected_users: List[str], alerts: List[Alert]) -> str:
    """
    Generate readable incident title like:
    'Multi-stage attack from 185.x.x.x: scan, brute force, successful login'
    """
    labels: List[str] = []
    for a in alerts:
        lbl = get_alert_phase_label(a)
        if lbl not in labels:
            labels.append(lbl)

    # Sort labels in kill-chain progression order
    sorted_labels = sorted(
        labels,
        key=lambda x: PHASE_PRIORITY.index(x) if x in PHASE_PRIORITY else 99
    )

    entity = src_ip or (affected_users[0] if affected_users else "unknown host")

    if len(sorted_labels) >= 2:
        return f"Multi-stage attack from {entity}: {', '.join(sorted_labels)}"
    elif len(sorted_labels) == 1:
        return f"{sorted_labels[0].capitalize()} activity from {entity}"
    else:
        return f"Security incident on {entity}"


def calculate_incident_severity(alerts: List[Alert]) -> str:
    """
    Escalate severity based on the number and kinds of alerts:
    e.g. recon + brute force + successful login + exfil = critical
    """
    if not alerts:
        return "low"

    severities = {a.severity.lower() for a in alerts if a.severity}
    tactics = {a.mitre_tactic for a in alerts if a.mitre_tactic}

    # Condition 1: Explicit Critical alert
    if "critical" in severities:
        return "critical"

    # Condition 2: Multi-stage attack traversing >= 3 distinct tactics
    if len(tactics) >= 3:
        return "critical"

    # Condition 3: Exfiltration combined with Initial Access, Credential Access, or Privilege Escalation
    has_exfil = any(
        a.mitre_tactic == "Exfiltration"
        or "T1041" in (a.mitre_technique_id or "")
        or "RULE-NET-002" in (a.rule_id or "")
        for a in alerts
    )
    has_compromise_or_access = any(
        a.mitre_tactic in ("Credential Access", "Initial Access", "Privilege Escalation", "Defense Evasion")
        for a in alerts
    )
    if has_exfil and has_compromise_or_access:
        return "critical"

    # Condition 4: Multi-stage chain (e.g. Recon + Brute Force + Successful Login)
    has_recon = any(a.mitre_tactic in ("Reconnaissance", "Discovery") for a in alerts)
    has_cred = any(a.mitre_tactic == "Credential Access" for a in alerts)
    has_login = any("RULE-AUTH-003" in (a.rule_id or "") or "successful login" in (a.rule_name or "").lower() for a in alerts)
    if has_recon and has_cred and has_login:
        return "critical"

    # High severity conditions:
    if "high" in severities or len(tactics) >= 2 or len(alerts) >= 3:
        return "high"

    # Medium severity conditions:
    if "medium" in severities or len(alerts) >= 2:
        return "medium"

    return "low"


def _to_utc_naive(dt: Optional[datetime.datetime]) -> datetime.datetime:
    """Safely convert datetime to UTC naive to allow universal comparisons across SQLite/Python."""
    if dt is None:
        dt = datetime.datetime.now(datetime.timezone.utc)
    if dt.tzinfo is not None:
        return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt


def find_matching_open_incident(
    db: Session,
    alert: Alert,
    window_seconds: int = 600,
) -> Optional[Incident]:
    """
    Find an existing open incident sharing the same src_ip (or user) within a 10-minute window.
    """
    ref_time = _to_utc_naive(alert.timestamp)
    window_start = ref_time - datetime.timedelta(seconds=window_seconds)

    # 1. Match by primary pivot: src_ip
    if alert.src_ip:
        candidate = (
            db.query(Incident)
            .options(selectinload(Incident.alerts))
            .filter(
                Incident.status != "closed",
                Incident.src_ip == alert.src_ip,
                Incident.updated_at >= window_start,
            )
            .order_by(Incident.updated_at.desc())
            .first()
        )
        if candidate:
            return candidate

    # 2. Match by secondary pivot: user
    if alert.user:
        open_incidents = (
            db.query(Incident)
            .options(selectinload(Incident.alerts))
            .filter(
                Incident.status != "closed",
                Incident.updated_at >= window_start,
            )
            .order_by(Incident.updated_at.desc())
            .all()
        )
        for inc in open_incidents:
            if inc.affected_users and alert.user in inc.affected_users:
                return inc

    return None


def correlate_alerts(alerts: List[Alert], db: Session, window_seconds: int = 600) -> List[Incident]:
    """
    Correlates a batch of Alert records into Incidents:
    - Finds or creates open incidents sharing the same src_ip or user within window_seconds (10 min).
    - Merges MITRE techniques and affected users.
    - Escalates severity and updates dynamic title.
    """
    if not alerts:
        return []

    # Process alerts in chronological order
    sorted_alerts = sorted(alerts, key=lambda a: _to_utc_naive(a.timestamp))
    affected_incidents: Dict[int, Incident] = {}

    for alert in sorted_alerts:
        incident = find_matching_open_incident(db, alert, window_seconds=window_seconds)

        if incident:
            # Associate alert to existing open incident
            alert.incident_id = incident.id
            if _to_utc_naive(alert.timestamp) > _to_utc_naive(incident.updated_at):
                incident.updated_at = alert.timestamp

            # Merge user
            if alert.user and alert.user not in (incident.affected_users or []):
                users = list(incident.affected_users or [])
                users.append(alert.user)
                incident.affected_users = users

            # Merge MITRE technique
            if alert.mitre_technique_id and alert.mitre_technique_id not in (incident.mitre_techniques or []):
                techniques = list(incident.mitre_techniques or [])
                techniques.append(alert.mitre_technique_id)
                incident.mitre_techniques = techniques

            # Gather all alerts linked to this incident (including current alert)
            all_alerts = list(incident.alerts) if incident.alerts else []
            if alert not in all_alerts:
                all_alerts.append(alert)

            # Recalculate severity and title
            incident.severity = calculate_incident_severity(all_alerts)
            incident.title = generate_incident_title(incident.src_ip, incident.affected_users or [], all_alerts)

            affected_incidents[incident.id] = incident

        else:
            # Create a brand new incident
            initial_alerts = [alert]
            src_ip = alert.src_ip
            users = [alert.user] if alert.user else []
            techniques = [alert.mitre_technique_id] if alert.mitre_technique_id else []

            severity = calculate_incident_severity(initial_alerts)
            title = generate_incident_title(src_ip, users, initial_alerts)

            new_incident = Incident(
                title=title,
                severity=severity,
                status="open",
                src_ip=src_ip,
                affected_users=users,
                mitre_techniques=techniques,
                created_at=alert.timestamp,
                updated_at=alert.timestamp,
            )
            db.add(new_incident)
            db.flush()  # assign new_incident.id

            alert.incident_id = new_incident.id
            new_incident.alerts.append(alert)

            affected_incidents[new_incident.id] = new_incident

    db.commit()
    for inc in affected_incidents.values():
        db.refresh(inc)

    if affected_incidents:
        from .broadcaster import broadcast_event
        for inc in affected_incidents.values():
            broadcast_event("INCIDENT_UPDATED", {
                "id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "src_ip": inc.src_ip,
                "mitre_techniques": inc.mitre_techniques or [],
                "affected_users": inc.affected_users or [],
            })

    return list(affected_incidents.values())


def get_incident_timeline(incident: Incident) -> Dict[str, Any]:
    """
    Orders the incident's alerts into an attack timeline using the MITRE tactic kill-chain order.
    """
    def tactic_sort_key(alert: Alert):
        tactic = alert.mitre_tactic or "Unknown"
        order = KILL_CHAIN_ORDER.index(tactic) if tactic in KILL_CHAIN_ORDER else 999
        return (order, _to_utc_naive(alert.timestamp))

    sorted_alerts = sorted(incident.alerts, key=tactic_sort_key)

    timeline_steps = []
    tactics_seen = []

    for idx, a in enumerate(sorted_alerts, start=1):
        tactic = a.mitre_tactic or "Unknown"
        if tactic not in tactics_seen:
            tactics_seen.append(tactic)
        order = KILL_CHAIN_ORDER.index(tactic) if tactic in KILL_CHAIN_ORDER else 999

        timeline_steps.append({
            "step": idx,
            "alert_id": a.id,
            "tactic": tactic,
            "tactic_order": order,
            "technique_id": a.mitre_technique_id,
            "technique_name": a.mitre_technique_name,
            "rule_id": a.rule_id,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "timestamp": a.timestamp,
            "description": a.description,
            "src_ip": a.src_ip,
            "user": a.user,
            "log_event_ids": a.log_event_ids or [],
        })

    return {
        "incident_id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "src_ip": incident.src_ip,
        "affected_users": incident.affected_users or [],
        "mitre_techniques": incident.mitre_techniques or [],
        "tactics_traversed": tactics_seen,
        "timeline": timeline_steps,
    }
