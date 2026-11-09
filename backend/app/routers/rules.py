"""
SOC Copilot - Detection Rules Router
Provides endpoint:
- GET /api/rules
"""

from typing import Any, Dict, List
from fastapi import APIRouter

from ..services.detection import get_detection_engine

router = APIRouter(prefix="/api/rules", tags=["Rules"])


@router.get("", summary="Get all detection rules with MITRE mapping")
def list_rules() -> List[Dict[str, Any]]:
    """Returns all loaded YAML detection rules enriched with MITRE ATT&CK details."""
    engine = get_detection_engine()
    results: List[Dict[str, Any]] = []

    for rule in engine.rules:
        mitre_info = engine.get_mitre_info(rule.mitre_technique)
        results.append({
            "id": rule.id,
            "name": rule.name,
            "severity": rule.severity,
            "source": rule.source,
            "mitre_technique": rule.mitre_technique,
            "mitre_technique_name": mitre_info["name"],
            "mitre_tactic": mitre_info["tactic"],
            "description": rule.description,
            "detection": rule.detection,
            "action_recommendations": rule.action_recommendations,
        })

    return results

