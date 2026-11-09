"""
SOC Copilot Backend Services Package:
- Log Ingestion and Normalization (parsers)
- Detection Engine (YAML Rule Evaluator)
- Incident Correlation Engine
- LLM Triage (Google Gemini)
- Active Response Actions
"""

from .parsers import (
    parse_ssh_line,
    parse_web_line,
    parse_firewall_line,
    parse_line,
    parse_log_events,
)
from .detection import process_events_for_detections, get_detection_engine
from .correlation import (
    correlate_alerts,
    get_incident_timeline,
    calculate_incident_severity,
    generate_incident_title,
)

__all__ = [
    "parse_ssh_line",
    "parse_web_line",
    "parse_firewall_line",
    "parse_line",
    "parse_log_events",
    "process_events_for_detections",
    "get_detection_engine",
    "correlate_alerts",
    "get_incident_timeline",
    "calculate_incident_severity",
    "generate_incident_title",
]
