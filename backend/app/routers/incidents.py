from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, selectinload

from ..db import get_db
from ..models import Incident
from ..schemas import (
    ActionExecutionRequest,
    ActionUndoRequest,
    IncidentCreate,
    IncidentDetailRead,
    IncidentRead,
    IncidentTimelineRead,
    IncidentUpdate,
    RecommendedAction,
    ResponseActionRead,
    TriageResponse,
)
from ..services.correlation import get_incident_timeline
from ..services.ai_triage import generate_incident_triage
from ..services.response import execute_action, undo_incident_action

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


@router.get("", response_model=List[IncidentRead], summary="Get correlated incidents")
def list_incidents(
    limit: int = Query(100, ge=1, le=1000, description="Max incidents to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (open, investigating, contained, closed)"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    src_ip: Optional[str] = Query(None, description="Filter by primary attacker IP"),
    db: Session = Depends(get_db),
) -> List[Incident]:
    query = db.query(Incident)

    if status_filter:
        query = query.filter(Incident.status == status_filter.lower())
    if severity:
        query = query.filter(Incident.severity == severity.lower())
    if src_ip:
        query = query.filter(Incident.src_ip == src_ip)

    return query.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/{id}", response_model=IncidentDetailRead, summary="Get incident details by ID")
def get_incident(
    id: int,
    db: Session = Depends(get_db),
) -> Incident:
    incident = (
        db.query(Incident)
        .options(selectinload(Incident.alerts), selectinload(Incident.response_actions))
        .filter(Incident.id == id)
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {id} not found"
        )
    return incident


@router.get("/{id}/timeline", response_model=IncidentTimelineRead, summary="Get incident attack timeline ordered by MITRE kill-chain")
def get_incident_timeline_endpoint(
    id: int,
    db: Session = Depends(get_db),
):
    incident = (
        db.query(Incident)
        .options(selectinload(Incident.alerts))
        .filter(Incident.id == id)
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {id} not found"
        )
    return get_incident_timeline(incident)


@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED, summary="Create an incident")
def create_incident(
    incident_in: IncidentCreate,
    db: Session = Depends(get_db),
) -> Incident:
    incident_data = incident_in.model_dump(exclude_unset=True)
    db_incident = Incident(**incident_data)
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident


@router.post(
    "/{id}/analyze",
    response_model=TriageResponse,
    summary="Trigger AI triage for an incident (also auto-triggers on high/critical severity)",
)
def analyze_incident(
    id: int,
    force: bool = Query(False, description="Re-generate even if triage already exists"),
    db: Session = Depends(get_db),
) -> TriageResponse:
    """
    Triggers Gemini LLM triage for the specified incident.

    **Safety**: The AI only RECOMMENDS actions. Nothing is executed without an explicit
    human action via POST /api/incidents/{id}/respond.

    Set `USE_MOCK_AI=true` in your environment for offline/demo usage without an API key.
    """
    incident = (
        db.query(Incident)
        .options(selectinload(Incident.alerts))
        .filter(Incident.id == id)
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {id} not found",
        )

    result = generate_incident_triage(incident, db, force=force)

    # Normalise recommended_actions into Pydantic models
    raw_actions = result.get("recommended_actions", [])
    actions = [
        RecommendedAction(
            action_type=a.get("action_type", "monitor"),
            target=a.get("target", ""),
            reason=a.get("reason", ""),
            priority=a.get("priority", "medium"),
        )
        for a in raw_actions
        if isinstance(a, dict)
    ]

    return TriageResponse(
        incident_id=incident.id,
        summary=result.get("summary", ""),
        attack_stage_analysis=result.get("attack_stage_analysis", ""),
        likely_attacker_goal=result.get("likely_attacker_goal", ""),
        confidence=float(result.get("confidence", 0.5)),
        severity_justification=result.get("severity_justification", ""),
        recommended_actions=actions,
        ai_generated_at=incident.ai_generated_at,
        cached=bool(result.get("_cached")),
        mock=bool(result.get("_mock")),
        fallback=bool(result.get("_fallback")),
    )


@router.post(
    "/{id}/actions",
    response_model=ResponseActionRead,
    summary="Execute containment or remediation action on an incident",
)
@router.post(
    "/{id}/respond",
    response_model=ResponseActionRead,
    summary="Execute containment or remediation action on an incident (alias)",
)
def execute_incident_action_endpoint(
    id: int,
    payload: ActionExecutionRequest,
    db: Session = Depends(get_db),
) -> ResponseActionRead:
    """
    Executes a response action (block_ip, disable_user, create_ticket) approved by an analyst.
    - block_ip: adds target IP to firewall blocklist; moves incident status to 'contained'
    - disable_user: disables target user account in identity system; moves incident status to 'contained'
    - create_ticket: generates ticket with AI summary, severity, and context
    - Records ResponseAction with timestamp and approving analyst
    - Writes an audit log of the action
    """
    return execute_action(
        incident_id=id,
        action_type=payload.action_type,
        target=payload.target,
        analyst=payload.analyst or "analyst",
        reason=payload.reason,
        db=db,
    )


@router.post(
    "/{id}/actions/undo",
    summary="Undo a containment action for an incident",
)
def undo_incident_action_endpoint(
    id: int,
    payload: ActionUndoRequest,
    db: Session = Depends(get_db),
):
    """
    Undoes a previously executed containment action (block_ip or disable_user).
    """
    if not payload.action_type or not payload.target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Both 'action_type' and 'target' are required to undo an action",
        )
    return undo_incident_action(
        incident_id=id,
        action_type=payload.action_type,
        target=payload.target,
        analyst=payload.analyst or "analyst",
        reason=payload.reason,
        db=db,
    )


@router.patch("/{id}", response_model=IncidentDetailRead, summary="Update an incident")
def update_incident(
    id: int,
    incident_in: IncidentUpdate,
    db: Session = Depends(get_db),
) -> Incident:
    incident = (
        db.query(Incident)
        .options(selectinload(Incident.alerts), selectinload(Incident.response_actions))
        .filter(Incident.id == id)
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {id} not found"
        )

    update_data = incident_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(incident, field, value)

    db.commit()
    db.refresh(incident)
    return incident

