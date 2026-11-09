from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------
# LogEvent Schemas
# ---------------------------------------------------------
class LogEventBase(BaseModel):
    source: str = Field(..., description="Source system: ssh, web, firewall")
    raw: str = Field(..., description="Raw log entry text")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    user: Optional[str] = Field(None, description="Target or authenticating user")
    event_type: str = Field(..., description="Normalized event type (e.g. login_failed, sql_injection)")
    status: str = Field("unknown", description="Status (success, failed, blocked, allowed)")
    extra: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Arbitrary additional metadata")


class LogEventCreate(LogEventBase):
    timestamp: Optional[datetime] = None


class LogEventRead(LogEventBase):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class IngestRequest(BaseModel):
    source: Optional[str] = Field(None, description="Source system: ssh, web, firewall")
    lines: Optional[List[str]] = Field(default_factory=list, description="Raw log lines to ingest")
    logs: Optional[List[Dict[str, Any]]] = Field(default=None, description="Optional batch logs format")
    raw: Optional[str] = Field(default=None, description="Single raw log line")
    raw_message: Optional[str] = Field(default=None, description="Alternative raw message field")
    source_ip: Optional[str] = Field(default=None, description="Optional explicit source IP")
    username: Optional[str] = Field(default=None, description="Optional explicit username")
    event_type: Optional[str] = Field(default=None, description="Optional explicit event type")


class IngestResponse(BaseModel):
    status: str = "success"
    ingested: int
    count: int
    event_ids: List[int] = Field(default_factory=list)
    events: List[LogEventRead] = Field(default_factory=list)


# ---------------------------------------------------------
# Alert Schemas
# ---------------------------------------------------------
class AlertBase(BaseModel):
    rule_id: str
    rule_name: str
    severity: str = Field(..., description="low, medium, high, critical")
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    src_ip: Optional[str] = None
    user: Optional[str] = None
    description: str
    log_event_ids: List[int] = Field(default_factory=list)
    incident_id: Optional[int] = None


class AlertCreate(AlertBase):
    timestamp: Optional[datetime] = None


class AlertRead(AlertBase):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------
# ResponseAction Schemas
# ---------------------------------------------------------
class ResponseActionBase(BaseModel):
    incident_id: int
    action_type: str = Field(..., description="block_ip, disable_user, create_ticket")
    target: str = Field(..., description="Target entity (IP address, username, ticket title)")
    status: str = Field("pending", description="pending, executed, failed")
    details: Optional[str] = None
    analyst: Optional[str] = Field("analyst", description="Analyst approving or executing the action")


class ResponseActionCreate(ResponseActionBase):
    performed_at: Optional[datetime] = None


class ResponseActionRead(ResponseActionBase):
    id: int
    performed_at: datetime
    incident_status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ActionExecutionRequest(BaseModel):
    action_type: str = Field(..., description="block_ip, disable_user, create_ticket")
    target: str = Field(..., description="Target entity (IP address, username, ticket title)")
    analyst: Optional[str] = Field("analyst", description="Analyst approving or executing the action")
    reason: Optional[str] = Field(None, description="Optional justification for the response action")


class ActionUndoRequest(BaseModel):
    action_type: Optional[str] = Field(None, description="block_ip or disable_user")
    target: Optional[str] = Field(None, description="IP address or username")
    analyst: Optional[str] = Field("analyst", description="Analyst approving the undo action")
    reason: Optional[str] = Field(None, description="Reason for undoing the action")


class UnblockIPRequest(BaseModel):
    ip_address: Optional[str] = Field(None, description="IP address to unblock")
    analyst: Optional[str] = Field("analyst", description="Analyst authorizing the unblock")
    reason: Optional[str] = Field(None, description="Reason for unblocking")


class EnableUserRequest(BaseModel):
    username: Optional[str] = Field(None, description="Username to re-enable")
    analyst: Optional[str] = Field("analyst", description="Analyst authorizing re-enabling user")
    reason: Optional[str] = Field(None, description="Reason for re-enabling")


class AuditLogRead(BaseModel):
    id: int
    timestamp: datetime
    action: str
    target: str
    analyst: str
    incident_id: Optional[int] = None
    status: str
    details: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)



# ---------------------------------------------------------
# Incident Schemas
# ---------------------------------------------------------
class IncidentBase(BaseModel):
    title: str
    severity: str = Field(..., description="low, medium, high, critical")
    status: str = Field("open", description="open, investigating, contained, closed")
    src_ip: Optional[str] = None
    affected_users: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    ai_summary: Optional[str] = None
    ai_recommendations: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    ai_generated_at: Optional[datetime] = None


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    src_ip: Optional[str] = None
    affected_users: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    ai_summary: Optional[str] = None
    ai_recommendations: Optional[List[Dict[str, Any]]] = None
    ai_generated_at: Optional[datetime] = None


class IncidentRead(IncidentBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailRead(IncidentRead):
    alerts: List[AlertRead] = Field(default_factory=list)
    response_actions: List[ResponseActionRead] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class TimelineStepRead(BaseModel):
    step: int
    alert_id: int
    tactic: str
    tactic_order: int
    technique_id: str
    technique_name: str
    rule_id: str
    rule_name: str
    severity: str
    timestamp: datetime
    description: str
    src_ip: Optional[str] = None
    user: Optional[str] = None
    log_event_ids: List[int] = Field(default_factory=list)


class IncidentTimelineRead(BaseModel):
    incident_id: int
    title: str
    severity: str
    status: str
    src_ip: Optional[str] = None
    affected_users: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    tactics_traversed: List[str] = Field(default_factory=list)
    timeline: List[TimelineStepRead] = Field(default_factory=list)


# ---------------------------------------------------------
# AI Triage Schemas
# ---------------------------------------------------------
class RecommendedAction(BaseModel):
    action_type: str = Field(..., description="block_ip, disable_user, create_ticket, or monitor")
    target: str = Field(..., description="The specific IP, username, or ticket title to act on")
    reason: str = Field(..., description="Why this action is recommended")
    priority: str = Field("medium", description="high, medium, or low")


class TriageResponse(BaseModel):
    incident_id: int
    summary: str
    attack_stage_analysis: str
    likely_attacker_goal: str
    confidence: float = Field(..., ge=0.0, le=1.0, description="AI confidence score (0-1)")
    severity_justification: str
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    ai_generated_at: Optional[datetime] = None
    # Metadata flags (present only when True)
    cached: bool = False
    mock: bool = False
    fallback: bool = False

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------
# Simulation Tables Schemas (Firewall, Identity, Ticketing)
# ---------------------------------------------------------
class BlockedIPBase(BaseModel):
    ip_address: str
    reason: Optional[str] = None
    incident_id: Optional[int] = None
    status: str = "active"


class BlockedIPCreate(BlockedIPBase):
    pass


class BlockedIPRead(BlockedIPBase):
    id: int
    blocked_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DisabledUserBase(BaseModel):
    username: str
    reason: Optional[str] = None
    incident_id: Optional[int] = None
    status: str = "disabled"


class DisabledUserCreate(DisabledUserBase):
    pass


class DisabledUserRead(DisabledUserBase):
    id: int
    disabled_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TicketBase(BaseModel):
    ticket_number: str
    title: str
    description: str
    severity: str = "medium"
    status: str = "open"
    incident_id: Optional[int] = None


class TicketCreate(TicketBase):
    pass


class TicketRead(TicketBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

