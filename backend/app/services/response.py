"""
SOC Copilot - Active Response Engine
====================================
Executes containment, eradication, and tracking actions for correlated Incidents:
  - block_ip: adds target IP to BlockedIP (simulated firewall perimeter) and updates incident status to 'contained'
  - disable_user: adds username to DisabledUser (simulated IdP/IAM) and updates incident status to 'contained'
  - create_ticket: creates an auto-filled Ticket in ticketing system with incident metadata and AI summary
  - undo endpoints: unblock_ip and enable_user
  - audit logging: records every action and undo event into the AuditLog table
"""

import datetime
import logging
import uuid
from typing import Any, Dict, List, Optional, Union

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from ..models import AuditLog, BlockedIP, DisabledUser, Incident, ResponseAction, Ticket, utc_now

logger = logging.getLogger("soc_copilot.response")
audit_logger = logging.getLogger("soc_copilot.audit")

SUPPORTED_ACTIONS = {"block_ip", "disable_user", "create_ticket"}


def write_audit_log(
    action: str,
    target: str,
    analyst: str = "analyst",
    incident_id: Optional[int] = None,
    status_str: str = "success",
    details: Optional[str] = None,
    db: Optional[Session] = None,
) -> AuditLog:
    """
    Persist an audit log entry to the database and write to the audit logger.
    """
    entry = AuditLog(
        timestamp=utc_now(),
        action=action,
        target=target,
        analyst=analyst or "analyst",
        incident_id=incident_id,
        status=status_str,
        details=details,
    )
    if db:
        db.add(entry)
    
    audit_logger.info(
        "AUDIT [%s] action='%s' target='%s' analyst='%s' incident_id=%s status='%s': %s",
        entry.timestamp.isoformat(),
        action,
        target,
        analyst,
        incident_id,
        status_str,
        details,
    )
    return entry


def _block_ip_action(
    target: str,
    incident: Incident,
    analyst: str,
    reason: Optional[str],
    db: Session,
) -> BlockedIP:
    """Add or re-activate firewall block for target IP."""
    target_ip = target.strip()
    if not target_ip:
        target_ip = incident.src_ip or ""
    if not target_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot block IP: target IP address is required and incident has no src_ip",
        )

    block_reason = reason or f"Blocked via response action on incident {incident.id}: {incident.title}"

    blocked = db.query(BlockedIP).filter(BlockedIP.ip_address == target_ip).first()
    if blocked:
        blocked.status = "active"
        blocked.blocked_at = utc_now()
        blocked.reason = block_reason
        blocked.incident_id = incident.id
    else:
        blocked = BlockedIP(
            ip_address=target_ip,
            reason=block_reason,
            incident_id=incident.id,
            status="active",
            blocked_at=utc_now(),
        )
        db.add(blocked)

    # Move incident status to contained
    incident.status = "contained"
    incident.updated_at = utc_now()
    return blocked


def _disable_user_action(
    target: str,
    incident: Incident,
    analyst: str,
    reason: Optional[str],
    db: Session,
) -> DisabledUser:
    """Add or re-activate disabled account status for target username."""
    username = target.strip()
    if not username and incident.affected_users:
        username = incident.affected_users[0]
    if not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot disable user: target username is required and incident has no affected_users",
        )

    disable_reason = reason or f"Disabled via response action on incident {incident.id}: {incident.title}"

    disabled = db.query(DisabledUser).filter(DisabledUser.username == username).first()
    if disabled:
        disabled.status = "disabled"
        disabled.disabled_at = utc_now()
        disabled.reason = disable_reason
        disabled.incident_id = incident.id
    else:
        disabled = DisabledUser(
            username=username,
            reason=disable_reason,
            incident_id=incident.id,
            status="disabled",
            disabled_at=utc_now(),
        )
        db.add(disabled)

    # Move incident status to contained
    incident.status = "contained"
    incident.updated_at = utc_now()
    return disabled


def _create_ticket_action(
    target: str,
    incident: Incident,
    analyst: str,
    reason: Optional[str],
    db: Session,
) -> Ticket:
    """Auto-fill and create a Ticket from incident metadata and AI summary."""
    ticket_num = f"SOC-{incident.id}-{uuid.uuid4().hex[:6].upper()}"

    # Auto-filled title
    if target and target.strip() and target.strip() != incident.src_ip and target.strip() not in (incident.affected_users or []):
        ticket_title = target.strip()
    else:
        ticket_title = f"[INCIDENT-{incident.id}] {incident.title}"

    # Auto-filled description with AI summary and timeline context
    desc_lines = [
        f"Incident ID   : {incident.id}",
        f"Title         : {incident.title}",
        f"Severity      : {incident.severity.upper()}",
        f"Status        : {incident.status}",
        f"Attacker IP   : {incident.src_ip or 'N/A'}",
        f"Affected Users: {', '.join(incident.affected_users or []) or 'N/A'}",
        f"MITRE Techs   : {', '.join(incident.mitre_techniques or []) or 'N/A'}",
        f"Analyst       : {analyst}",
        "",
        "=== AI TRIAGE SUMMARY ===",
        incident.ai_summary or "No AI summary available yet.",
    ]

    if incident.ai_recommendations:
        desc_lines.append("")
        desc_lines.append("=== AI RECOMMENDED ACTIONS ===")
        for rec in incident.ai_recommendations:
            if isinstance(rec, dict):
                desc_lines.append(f"- [{rec.get('action_type', 'action')}] {rec.get('target', '')}: {rec.get('reason', '')}")

    if reason:
        desc_lines.append("")
        desc_lines.append(f"Analyst Notes : {reason}")

    ticket_description = "\n".join(desc_lines)

    ticket = Ticket(
        ticket_number=ticket_num,
        title=ticket_title,
        description=ticket_description,
        severity=incident.severity or "medium",
        status="open",
        incident_id=incident.id,
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    db.add(ticket)
    return ticket


def execute_action(
    incident_id: int,
    action_type: str,
    target: str,
    analyst: str = "analyst",
    reason: Optional[str] = None,
    db: Optional[Session] = None,
) -> ResponseAction:
    """
    Main entry point for executing response actions on an incident.
    """
    if db is None:
        raise ValueError("Database session is required")

    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found",
        )

    norm_action = (action_type or "").strip().lower()
    if norm_action not in SUPPORTED_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported action_type: '{action_type}'. Must be one of: {', '.join(sorted(SUPPORTED_ACTIONS))}",
        )

    analyst_name = (analyst or "analyst").strip()
    target_clean = (target or "").strip()

    action_details = ""

    # Execute specific action logic
    if norm_action == "block_ip":
        blocked_obj = _block_ip_action(target_clean, incident, analyst_name, reason, db)
        target_clean = blocked_obj.ip_address
        action_details = f"Firewall block active for {target_clean}. Incident moved to contained."

    elif norm_action == "disable_user":
        disabled_obj = _disable_user_action(target_clean, incident, analyst_name, reason, db)
        target_clean = disabled_obj.username
        action_details = f"Account disabled for {target_clean}. Incident moved to contained."

    elif norm_action == "create_ticket":
        ticket_obj = _create_ticket_action(target_clean, incident, analyst_name, reason, db)
        target_clean = ticket_obj.title
        action_details = f"Ticket {ticket_obj.ticket_number} created with AI summary and incident context."

    # Record ResponseAction
    action_record = ResponseAction(
        incident_id=incident.id,
        action_type=norm_action,
        target=target_clean,
        status="executed",
        performed_at=utc_now(),
        details=action_details,
        analyst=analyst_name,
    )
    db.add(action_record)

    # Write Audit Log
    write_audit_log(
        action=norm_action,
        target=target_clean,
        analyst=analyst_name,
        incident_id=incident.id,
        status_str="success",
        details=action_details,
        db=db,
    )

    db.commit()
    db.refresh(action_record)
    db.refresh(incident)

    # Attach current incident status dynamically for response schemas
    setattr(action_record, "incident_status", incident.status)

    from .broadcaster import broadcast_event
    broadcast_event("ACTION_EXECUTED", {
        "incident_id": incident.id,
        "action_type": norm_action,
        "target": target_clean,
        "status": "executed",
        "analyst": analyst_name,
        "incident_status": incident.status,
    })

    logger.info(
        "Action executed: incident=%d action=%s target=%s analyst=%s status=%s",
        incident.id,
        norm_action,
        target_clean,
        analyst_name,
        incident.status,
    )
    return action_record


def undo_block_ip(
    ip_or_id: Union[int, str],
    analyst: str = "analyst",
    reason: Optional[str] = None,
    db: Optional[Session] = None,
) -> BlockedIP:
    """
    Undo a block_ip action: marks BlockedIP status as 'unblocked' and audits the event.
    """
    if db is None:
        raise ValueError("Database session is required")

    analyst_name = (analyst or "analyst").strip()

    # Find blocked IP record
    query = db.query(BlockedIP)
    if isinstance(ip_or_id, int) or (isinstance(ip_or_id, str) and ip_or_id.isdigit()):
        blocked = query.filter(BlockedIP.id == int(ip_or_id)).first()
    else:
        blocked = query.filter(BlockedIP.ip_address == str(ip_or_id).strip()).first()

    if not blocked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Blocked IP record not found for '{ip_or_id}'",
        )

    blocked.status = "unblocked"
    details = reason or f"IP {blocked.ip_address} unblocked by analyst {analyst_name}"

    # Log undo in ResponseAction if associated with an incident
    if blocked.incident_id:
        undo_action = ResponseAction(
            incident_id=blocked.incident_id,
            action_type="unblock_ip",
            target=blocked.ip_address,
            status="executed",
            performed_at=utc_now(),
            details=details,
            analyst=analyst_name,
        )
        db.add(undo_action)

    # Write Audit Log
    write_audit_log(
        action="unblock_ip",
        target=blocked.ip_address,
        analyst=analyst_name,
        incident_id=blocked.incident_id,
        status_str="success",
        details=details,
        db=db,
    )

    db.commit()
    db.refresh(blocked)
    from .broadcaster import broadcast_event
    broadcast_event("ACTION_UNDONE", {
        "action_type": "unblock_ip",
        "target": blocked.ip_address,
        "status": "unblocked",
        "analyst": analyst_name,
    })
    logger.info("Unblocked IP %s (analyst=%s)", blocked.ip_address, analyst_name)
    return blocked


def undo_disable_user(
    user_or_id: Union[int, str],
    analyst: str = "analyst",
    reason: Optional[str] = None,
    db: Optional[Session] = None,
) -> DisabledUser:
    """
    Undo a disable_user action: marks DisabledUser status as 'enabled' and audits the event.
    """
    if db is None:
        raise ValueError("Database session is required")

    analyst_name = (analyst or "analyst").strip()

    query = db.query(DisabledUser)
    if isinstance(user_or_id, int) or (isinstance(user_or_id, str) and user_or_id.isdigit()):
        disabled = query.filter(DisabledUser.id == int(user_or_id)).first()
    else:
        disabled = query.filter(DisabledUser.username == str(user_or_id).strip()).first()

    if not disabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Disabled user record not found for '{user_or_id}'",
        )

    disabled.status = "enabled"
    details = reason or f"User account '{disabled.username}' re-enabled by analyst {analyst_name}"

    if disabled.incident_id:
        undo_action = ResponseAction(
            incident_id=disabled.incident_id,
            action_type="enable_user",
            target=disabled.username,
            status="executed",
            performed_at=utc_now(),
            details=details,
            analyst=analyst_name,
        )
        db.add(undo_action)

    # Write Audit Log
    write_audit_log(
        action="enable_user",
        target=disabled.username,
        analyst=analyst_name,
        incident_id=disabled.incident_id,
        status_str="success",
        details=details,
        db=db,
    )

    db.commit()
    db.refresh(disabled)
    from .broadcaster import broadcast_event
    broadcast_event("ACTION_UNDONE", {
        "action_type": "enable_user",
        "target": disabled.username,
        "status": "enabled",
        "analyst": analyst_name,
    })
    logger.info("Re-enabled user %s (analyst=%s)", disabled.username, analyst_name)
    return disabled


def undo_incident_action(
    incident_id: int,
    action_type: str,
    target: str,
    analyst: str = "analyst",
    reason: Optional[str] = None,
    db: Optional[Session] = None,
) -> Dict[str, Any]:
    """
    Undo an action by action_type and target for a specific incident.
    """
    if db is None:
        raise ValueError("Database session is required")

    norm = (action_type or "").strip().lower()
    if norm in ("block_ip", "unblock_ip"):
        rec = undo_block_ip(target, analyst=analyst, reason=reason, db=db)
        return {"status": "success", "action": "unblock_ip", "target": rec.ip_address, "entity_status": rec.status}
    elif norm in ("disable_user", "enable_user"):
        rec = undo_disable_user(target, analyst=analyst, reason=reason, db=db)
        return {"status": "success", "action": "enable_user", "target": rec.username, "entity_status": rec.status}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Undo not supported for action_type '{action_type}'. Can undo: block_ip, disable_user",
        )

