from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AuditLog, BlockedIP, DisabledUser, Ticket
from ..schemas import (
    AuditLogRead,
    BlockedIPCreate,
    BlockedIPRead,
    DisabledUserCreate,
    DisabledUserRead,
    EnableUserRequest,
    TicketCreate,
    TicketRead,
    UnblockIPRequest,
)
from ..services.response import undo_block_ip, undo_disable_user

router = APIRouter(tags=["Response & Simulated Systems"])


# ---------------------------------------------------------
# Blocked IPs (Firewall)
# ---------------------------------------------------------
@router.get(
    "/api/blocked-ips",
    response_model=List[BlockedIPRead],
    summary="List blocked IPs",
)
@router.get(
    "/api/simulations/blocked-ips",
    response_model=List[BlockedIPRead],
    summary="List blocked IPs (alias)",
)
def list_blocked_ips(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
) -> List[BlockedIP]:
    query = db.query(BlockedIP)
    if status_filter:
        query = query.filter(BlockedIP.status == status_filter)
    return query.order_by(BlockedIP.blocked_at.desc()).offset(offset).limit(limit).all()


@router.post(
    "/api/blocked-ips",
    response_model=BlockedIPRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add blocked IP",
)
@router.post(
    "/api/simulations/blocked-ips",
    response_model=BlockedIPRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add blocked IP (alias)",
)
def create_blocked_ip(
    ip_in: BlockedIPCreate,
    db: Session = Depends(get_db),
) -> BlockedIP:
    db_obj = BlockedIP(**ip_in.model_dump(exclude_unset=True))
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


# Undo endpoints for block_ip
@router.post(
    "/api/blocked-ips/{id}/unblock",
    response_model=BlockedIPRead,
    summary="Unblock IP by ID",
)
@router.delete(
    "/api/blocked-ips/{id}",
    response_model=BlockedIPRead,
    summary="Unblock IP by ID (DELETE)",
)
def unblock_ip_by_id(
    id: int,
    analyst: str = Query("analyst", description="Analyst approving unblock"),
    db: Session = Depends(get_db),
) -> BlockedIP:
    return undo_block_ip(id, analyst=analyst, db=db)


@router.post(
    "/api/blocked-ips/unblock",
    response_model=BlockedIPRead,
    summary="Unblock IP by IP address or ID via body",
)
def unblock_ip_by_body(
    payload: UnblockIPRequest,
    db: Session = Depends(get_db),
) -> BlockedIP:
    if not payload.ip_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Field 'ip_address' is required to unblock",
        )
    return undo_block_ip(payload.ip_address, analyst=payload.analyst or "analyst", reason=payload.reason, db=db)


# ---------------------------------------------------------
# Disabled Users (Identity System)
# ---------------------------------------------------------
@router.get(
    "/api/disabled-users",
    response_model=List[DisabledUserRead],
    summary="List disabled users",
)
@router.get(
    "/api/simulations/disabled-users",
    response_model=List[DisabledUserRead],
    summary="List disabled users (alias)",
)
def list_disabled_users(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
) -> List[DisabledUser]:
    query = db.query(DisabledUser)
    if status_filter:
        query = query.filter(DisabledUser.status == status_filter)
    return query.order_by(DisabledUser.disabled_at.desc()).offset(offset).limit(limit).all()


@router.post(
    "/api/disabled-users",
    response_model=DisabledUserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Disable user",
)
@router.post(
    "/api/simulations/disabled-users",
    response_model=DisabledUserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Disable user (alias)",
)
def create_disabled_user(
    user_in: DisabledUserCreate,
    db: Session = Depends(get_db),
) -> DisabledUser:
    db_obj = DisabledUser(**user_in.model_dump(exclude_unset=True))
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


# Undo endpoints for disable_user
@router.post(
    "/api/disabled-users/{id}/enable",
    response_model=DisabledUserRead,
    summary="Re-enable user by ID",
)
@router.delete(
    "/api/disabled-users/{id}",
    response_model=DisabledUserRead,
    summary="Re-enable user by ID (DELETE)",
)
def enable_user_by_id(
    id: int,
    analyst: str = Query("analyst", description="Analyst approving user enable"),
    db: Session = Depends(get_db),
) -> DisabledUser:
    return undo_disable_user(id, analyst=analyst, db=db)


@router.post(
    "/api/disabled-users/enable",
    response_model=DisabledUserRead,
    summary="Re-enable user by username via body",
)
def enable_user_by_body(
    payload: EnableUserRequest,
    db: Session = Depends(get_db),
) -> DisabledUser:
    if not payload.username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Field 'username' is required to re-enable user",
        )
    return undo_disable_user(payload.username, analyst=payload.analyst or "analyst", reason=payload.reason, db=db)


# ---------------------------------------------------------
# Tickets (Ticketing System)
# ---------------------------------------------------------
@router.get(
    "/api/tickets",
    response_model=List[TicketRead],
    summary="List response tickets",
)
@router.get(
    "/api/simulations/tickets",
    response_model=List[TicketRead],
    summary="List response tickets (alias)",
)
def list_tickets(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    db: Session = Depends(get_db),
) -> List[Ticket]:
    query = db.query(Ticket)
    if status_filter:
        query = query.filter(Ticket.status == status_filter)
    if severity:
        query = query.filter(Ticket.severity == severity.lower())
    return query.order_by(Ticket.created_at.desc()).offset(offset).limit(limit).all()


@router.post(
    "/api/tickets",
    response_model=TicketRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create ticket",
)
@router.post(
    "/api/simulations/tickets",
    response_model=TicketRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create ticket (alias)",
)
def create_ticket(
    ticket_in: TicketCreate,
    db: Session = Depends(get_db),
) -> Ticket:
    db_obj = Ticket(**ticket_in.model_dump(exclude_unset=True))
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


# ---------------------------------------------------------
# Audit Logs
# ---------------------------------------------------------
@router.get(
    "/api/audit-logs",
    response_model=List[AuditLogRead],
    summary="List audit logs of all response actions",
)
def list_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None, description="Filter by action"),
    analyst: Optional[str] = Query(None, description="Filter by analyst"),
    incident_id: Optional[int] = Query(None, description="Filter by incident ID"),
    db: Session = Depends(get_db),
) -> List[AuditLog]:
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action.lower())
    if analyst:
        query = query.filter(AuditLog.analyst == analyst)
    if incident_id is not None:
        query = query.filter(AuditLog.incident_id == incident_id)
    return query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
