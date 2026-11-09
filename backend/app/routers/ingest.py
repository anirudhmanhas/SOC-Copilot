"""
SOC Copilot - Ingestion Router
Provides endpoints for ingesting raw security telemetry:
- POST /api/ingest
- POST /api/logs/ingest (alias)
"""

from typing import Any, Dict, List
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import BlockedIP, LogEvent
from ..schemas import IngestRequest, IngestResponse
from ..services.parsers import _extract_timestamp, parse_line
from ..services.detection import process_events_for_detections
from ..services.broadcaster import broadcast_event

router = APIRouter(tags=["Ingestion"])


@router.post(
    "/api/ingest",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest batch of raw log lines",
)
@router.post(
    "/api/logs/ingest",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest batch of raw log lines (alias)",
)
def ingest_logs(
    payload: IngestRequest,
    db: Session = Depends(get_db),
) -> IngestResponse:
    parsed_items: List[Dict[str, Any]] = []

    # Case 1: Standard payload {source: "ssh", lines: ["..."]}
    if payload.lines:
        source = payload.source or "unknown"
        for line in payload.lines:
            parsed = parse_line(source, line)
            parsed_items.append(parsed)

    # Case 2: Batch format payload {logs: [{"source": "...", "raw": "..."}]}
    elif payload.logs:
        for item in payload.logs:
            item_source = item.get("source") or payload.source or "unknown"
            raw_content = item.get("raw") or item.get("raw_message") or str(item)
            parsed = parse_line(item_source, raw_content)

            # Allow explicit fields from simulator payload to supplement parsed fields
            if item.get("timestamp"):
                parsed["timestamp"] = _extract_timestamp(item["timestamp"])
            if item.get("source_ip"):
                parsed["src_ip"] = item["source_ip"]
            if item.get("username"):
                parsed["user"] = item["username"]
            if item.get("event_type") and item["event_type"] != "unknown":
                parsed["event_type"] = item["event_type"]
            parsed_items.append(parsed)

    # Case 3: Single log item payload (e.g. from generator.py)
    elif payload.raw or payload.raw_message:
        raw_content = payload.raw or payload.raw_message or ""
        source = payload.source or "unknown"
        parsed = parse_line(source, raw_content)

        if payload.source_ip:
            parsed["src_ip"] = payload.source_ip
        if payload.username:
            parsed["user"] = payload.username
        if payload.event_type and payload.event_type != "unknown":
            parsed["event_type"] = payload.event_type

        parsed_items.append(parsed)

    # Query active firewall blocked IPs (Active Containment)
    active_blocked_ips = {
        row[0]
        for row in db.query(BlockedIP.ip_address).filter(BlockedIP.status == "active").all()
    }

    # Persist parsed log events to database
    new_db_events: List[LogEvent] = []
    for item in parsed_items:
        src_ip = item.get("src_ip")
        if src_ip and src_ip in active_blocked_ips:
            item["status"] = "blocked"
            if not item.get("extra") or not isinstance(item.get("extra"), dict):
                item["extra"] = {}
            item["extra"]["firewall_blocked"] = True
            item["extra"]["firewall_action"] = "dropped"
            item["extra"]["blocked_reason"] = f"Traffic dropped: source IP {src_ip} is in active firewall blocklist"

        db_log = LogEvent(
            timestamp=item["timestamp"],
            source=item["source"],
            raw=item["raw"],
            src_ip=item.get("src_ip"),
            user=item.get("user"),
            event_type=item.get("event_type", "unknown"),
            status=item.get("status", "unknown"),
            extra=item.get("extra", {}),
        )
        db.add(db_log)
        new_db_events.append(db_log)

    if new_db_events:
        db.commit()
        for ev in new_db_events:
            db.refresh(ev)

        # Pass non-blocked events to detection engine (dropped traffic does not trigger detections)
        detection_events = [
            ev for ev in new_db_events
            if not (ev.extra and ev.extra.get("firewall_blocked"))
        ]
        if detection_events:
            process_events_for_detections(detection_events, db=db)

    return IngestResponse(
        status="success",
        ingested=len(new_db_events),
        count=len(new_db_events),
        event_ids=[ev.id for ev in new_db_events],
        events=new_db_events,
    )

