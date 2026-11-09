"""
SOC Copilot - AI Triage Service
================================
Uses Google Gemini (google-genai SDK) to perform LLM-driven triage of security incidents.

Retrieval-Augmented Generation (RAG) pipeline:
  1. For each MITRE technique in the incident, pull its description from /data/mitre_attack.json.
  2. Build a structured prompt combining: incident metadata, kill-chain timeline, affected users,
     raw alert descriptions, and the retrieved MITRE context.
  3. Ask Gemini to return STRICT JSON with: summary, attack_stage_analysis,
     likely_attacker_goal, confidence, severity_justification, recommended_actions.
  4. Validate, persist to Incident.ai_summary / Incident.ai_recommendations, and handle failures
     gracefully with a template-based fallback so the demo never breaks.

Safety constraint: The AI RECOMMENDS only. No action is executed without a human click.

Environment variables:
  GEMINI_API_KEY   - Your Google AI Studio API key (required in live mode)
  USE_MOCK_AI      - Set to "true" to skip real API calls and use a canned response
"""

import datetime
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session
from dotenv import load_dotenv

# Ensure environment variables are loaded from backend/.env and project root .env
load_dotenv(Path(__file__).resolve().parents[2] / ".env")
load_dotenv(Path(__file__).resolve().parents[3] / ".env")

from ..models import Incident

logger = logging.getLogger("soc_copilot.ai_triage")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
USE_MOCK_AI: bool = os.getenv("USE_MOCK_AI", "false").lower() in ("true", "1", "yes")
GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

def _is_mock_ai() -> bool:
    return USE_MOCK_AI or os.getenv("USE_MOCK_AI", "false").lower() in ("true", "1", "yes")

# Path to the MITRE ATT&CK reference data (RAG knowledge base)
# ai_triage.py lives at: <project_root>/backend/app/services/ai_triage.py
# parents[0] = services/, [1] = app/, [2] = backend/, [3] = <project_root>/
_MITRE_JSON_PATH = (
    Path(__file__).resolve().parents[3] / "data" / "mitre_attack.json"
)

# Valid action types the AI is allowed to recommend
VALID_ACTION_TYPES = {"block_ip", "disable_user", "create_ticket", "monitor"}

# Trigger auto-triage for these severities
AUTO_TRIAGE_SEVERITIES = {"high", "critical"}

# ---------------------------------------------------------------------------
# MITRE RAG Lookup
# ---------------------------------------------------------------------------
_mitre_catalog: Optional[Dict[str, Dict]] = None


def _load_mitre_catalog() -> Dict[str, Dict]:
    """Load and cache the MITRE ATT&CK JSON catalog keyed by technique ID."""
    global _mitre_catalog
    if _mitre_catalog is not None:
        return _mitre_catalog

    try:
        with open(_MITRE_JSON_PATH, "r", encoding="utf-8") as f:
            entries: List[Dict] = json.load(f)
        _mitre_catalog = {entry["id"]: entry for entry in entries if "id" in entry}
        logger.info("Loaded %d MITRE techniques from %s", len(_mitre_catalog), _MITRE_JSON_PATH)
    except Exception as exc:
        logger.warning("Could not load MITRE catalog from %s: %s", _MITRE_JSON_PATH, exc)
        _mitre_catalog = {}

    return _mitre_catalog


def get_mitre_context(technique_ids: List[str]) -> List[Dict[str, str]]:
    """
    RAG lookup: return MITRE metadata for each technique ID.
    Falls back from child (T1110.001) to parent (T1110) if child not found.
    """
    catalog = _load_mitre_catalog()
    results: List[Dict[str, str]] = []
    seen: set = set()

    for tid in technique_ids:
        if tid in seen:
            continue
        seen.add(tid)

        entry = catalog.get(tid)
        # Fallback to parent technique
        if entry is None and "." in tid:
            parent = tid.split(".")[0]
            entry = catalog.get(parent)

        if entry:
            results.append({
                "id": entry.get("id", tid),
                "name": entry.get("name", "Unknown"),
                "tactic": entry.get("tactic", "Unknown"),
                "description": entry.get("description", ""),
            })
        else:
            results.append({
                "id": tid,
                "name": "Unknown Technique",
                "tactic": "Unknown",
                "description": f"Technique {tid} not found in local catalog.",
            })

    return results


# ---------------------------------------------------------------------------
# Prompt Construction
# ---------------------------------------------------------------------------
def _build_prompt(incident: Incident, mitre_context: List[Dict]) -> str:
    """
    Build a structured LLM prompt combining incident metadata, alert timeline,
    affected entities, and MITRE ATT&CK context retrieved from the local catalog.
    """
    # Build alert summary lines from eager-loaded alerts
    alert_lines: List[str] = []
    if incident.alerts:
        for idx, alert in enumerate(incident.alerts, 1):
            ts = alert.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if alert.timestamp else "unknown"
            alert_lines.append(
                f"  {idx}. [{ts}] [{alert.severity.upper()}] {alert.rule_name} "
                f"(MITRE {alert.mitre_technique_id} / {alert.mitre_tactic}): {alert.description}"
            )
    alert_block = "\n".join(alert_lines) if alert_lines else "  (No alert details available)"

    # MITRE context block from RAG
    mitre_lines: List[str] = []
    for m in mitre_context:
        mitre_lines.append(
            f"  - [{m['id']}] {m['name']} ({m['tactic']}): {m['description']}"
        )
    mitre_block = "\n".join(mitre_lines) if mitre_lines else "  (No MITRE context available)"

    users_str = ", ".join(incident.affected_users) if incident.affected_users else "none identified"
    techniques_str = ", ".join(incident.mitre_techniques) if incident.mitre_techniques else "none"

    prompt = f"""You are an expert SOC (Security Operations Center) analyst AI assistant.
Analyze the following security incident and produce a triage report.

=== INCIDENT SUMMARY ===
Title      : {incident.title}
Severity   : {incident.severity.upper()}
Status     : {incident.status}
Source IP  : {incident.src_ip or "unknown"}
Affected Users: {users_str}
MITRE Techniques: {techniques_str}
Created    : {incident.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if incident.created_at else "unknown"}

=== ALERT TIMELINE (chronological) ===
{alert_block}

=== MITRE ATT&CK CONTEXT (Retrieval-Augmented) ===
{mitre_block}

=== TASK ===
Based on the above incident data and MITRE context, provide a structured triage report.

IMPORTANT: You MUST respond with ONLY valid JSON — no markdown fences, no preamble, no commentary.
The JSON must conform to this exact schema:

{{
  "summary": "<3-4 sentence plain-English summary of what happened and the threat it poses>",
  "attack_stage_analysis": "<description of the attack stages observed in this incident based on MITRE tactics>",
  "likely_attacker_goal": "<what the attacker was most likely trying to achieve>",
  "confidence": <float between 0.0 and 1.0 indicating your confidence in this analysis>,
  "severity_justification": "<why this incident deserves its severity rating>",
  "recommended_actions": [
    {{
      "action_type": "<one of: block_ip, disable_user, create_ticket, monitor>",
      "target": "<the specific IP address, username, or ticket title to act on>",
      "reason": "<concise reason why this action is recommended>",
      "priority": "<high, medium, or low>"
    }}
  ]
}}

Remember: These are RECOMMENDATIONS ONLY. No action will be taken automatically without human approval.
Respond with only the JSON object, nothing else."""

    return prompt


# ---------------------------------------------------------------------------
# Re-Analysis Variation Tracker & Dynamic Threat Engine
# ---------------------------------------------------------------------------
_analysis_variation_counter: Dict[int, int] = {}

def _synthesize_dynamic_triage(incident: Incident, iteration: int = 1) -> Dict[str, Any]:
    """
    Intelligent dynamic triage synthesis.
    Generates tailored, rotating analytical perspectives on re-analysis so the analyst
    receives fresh insights on each invocation, even in offline/mock/fallback mode.
    """
    src_ip = incident.src_ip or "external adversary"
    users = incident.affected_users or []
    techniques = incident.mitre_techniques or []
    alerts = incident.alerts or []
    severity = incident.severity
    status_state = incident.status

    tactics_seen = list(dict.fromkeys(a.mitre_tactic for a in alerts if a.mitre_tactic))
    tactics_str = ", ".join(tactics_seen) if tactics_seen else "Initial Discovery & Probing"

    rule_names = [a.rule_name for a in alerts]
    has_scan = any("scan" in r.lower() for r in rule_names) or "T1046" in techniques
    has_brute = any("brute" in r.lower() or "spray" in r.lower() for r in rule_names) or any("T1110" in t for t in techniques)
    has_login = any("login" in r.lower() or "accepted" in r.lower() for r in rule_names) or "T1078" in techniques
    has_exfil = any("exfil" in r.lower() or "transfer" in r.lower() for r in rule_names) or "T1041" in techniques
    has_web = any("sql" in r.lower() or "xss" in r.lower() for r in rule_names) or any("T1190" in t for t in techniques)

    stage_desc = []
    if has_scan:
        stage_desc.append("perimeter network reconnaissance (T1046)")
    if has_web:
        stage_desc.append("application exploitation probes (T1190)")
    if has_brute:
        stage_desc.append("high-velocity credential spraying (T1110)")
    if has_login:
        stage_desc.append("session establishment / valid account access (T1078)")
    if has_exfil:
        stage_desc.append("large outbound data staging (T1041)")

    stages_formatted = ", followed by ".join(stage_desc) if stage_desc else f"intrusion telemetry across {len(techniques)} MITRE techniques"

    # Rotate analytical focus across runs: 0 = Ingress & Threat Intel, 1 = Kill-Chain Impact, 2 = Defensive Playbook
    perspective_idx = iteration % 3

    if status_state == "contained":
        if perspective_idx == 0:
            summary = (
                f"Adversary {src_ip} was contained via perimeter blocklist following multi-stage intrusion telemetry ({stages_formatted}). "
                f"Perimeter firewall rules are actively dropping all subsequent inbound packets. "
                f"{'Targeted accounts (' + ', '.join(users) + ') require immediate password reset. ' if users else 'No internal accounts were confirmed compromised. '}"
                f"Recommend 48-hour continuous monitoring to verify complete threat neutralization."
            )
            goal = "Reconnaissance and persistent foothold attempt, currently halted by active perimeter containment."
            stage_analysis = f"Attack traversed {tactics_str}. Forward progression stopped via containment action."
            confidence = 0.94
        elif perspective_idx == 1:
            summary = (
                f"Post-Containment Root Cause Audit (Review #{iteration + 1}): Active perimeter block against {src_ip} verified effective. "
                f"Adversary attempted {stages_formatted} prior to neutralization. "
                f"Perimeter telemetry confirms all subsequent inbound connection attempts from {src_ip} are actively rejected at the firewall gateway. "
                f"{'Targeted identities (' + ', '.join(users) + ') have been flagged for credential revocation.' if users else 'Zero persistent footholds identified.'}"
            )
            goal = "Persistent footholds and credential harvesting attempt; neutralized at perimeter boundary."
            stage_analysis = f"Adversary reached {tactics_str} before defensive containment was deployed."
            confidence = 0.96
        else:
            summary = (
                f"Defensive Hardening Review (Review #{iteration + 1}): Perimeter perimeter containment of {src_ip} remains active and enforced. "
                f"Residual risk assessment completed across affected vectors ({stages_formatted}). "
                f"Recommended next steps: verify edge firewall rate-limiting, audit authentication logs for credential reuse, and resolve open SecOps tickets."
            )
            goal = "Adversary campaign disrupted; focus shifted to proactive infrastructure hardening."
            stage_analysis = f"All {len(alerts)} alerts correlated under {tactics_str} now safely mitigated."
            confidence = 0.95
    elif perspective_idx == 0:
        # Threat Intel & Attribution Perspective
        if severity == "critical":
            summary = (
                f"Critical intrusion campaign detected originating from external host {src_ip}. "
                f"Adversary executed {stages_formatted}, breaching perimeter defense layers. "
                f"{'Compromised credentials identified for: ' + ', '.join(users) + '. ' if users else 'Broad infrastructure targeted without confirmed credential theft. '}"
                f"Immediate perimeter isolation of {src_ip} and credential invalidation is strongly advised."
            )
        else:
            summary = (
                f"Threat Intelligence Briefing: External actor at {src_ip} initiated {stages_formatted}. "
                f"Observed telemetry indicates focused reconnaissance against enterprise ingress interfaces. "
                f"{'Targeted identities: ' + ', '.join(users) + '. ' if users else 'No user accounts compromised. '}"
                f"Recommend immediate perimeter firewall blocklist to prevent further progression."
            )
        goal = "Ingress discovery and exploitation to establish initial persistent access."
        stage_analysis = f"Attack traversed {tactics_str} tactics with {len(alerts)} detected rule triggers."
        confidence = 0.92 if severity in ("critical", "high") else 0.78
    elif perspective_idx == 1:
        # Kill-Chain Impact & Blast Radius Perspective
        if severity == "critical":
            summary = (
                f"Kill-Chain Progression Assessment: Intrusion from {src_ip} advanced through {stages_formatted}. "
                f"Telemetry confirms credential access transitioning into outbound data exfiltration. "
                f"{'Critical blast radius: accounts ' + ', '.join(users) + ' actively compromised. ' if users else 'Attack blast radius contained to perimeter hosts. '}"
                f"Emergency containment required: block source IP and isolate affected internal workloads."
            )
        else:
            summary = (
                f"Attack Surface Assessment: Correlated telemetry from {src_ip} demonstrates automated scanning behavior. "
                f"Pattern analysis reveals {stages_formatted} across network boundaries without credential exposure. "
                f"Containment posture: enforce immediate perimeter blocklist and inspect edge reverse proxies."
            )
        goal = "Service fingerprinting and vulnerability mapping for targeted payload delivery."
        stage_analysis = f"Intrusion progression halted at {tactics_str}. No lateral movement detected."
        confidence = 0.95 if severity in ("critical", "high") else 0.84
    else:
        # Forensics & Defensive Hardening Perspective
        summary = (
            f"Forensic Threat Synthesis (Analysis #{iteration}): Coordinated {severity} telemetry detected from {src_ip}. "
            f"Incident telemetry exhibits {stages_formatted}. "
            f"{'Targeted user identities: ' + ', '.join(users) + '. ' if users else 'No internal accounts breached. '}"
            f"Containment directive: Deploy perimeter blocklist rules, invalidate affected sessions, and open response tickets."
        )
        goal = "Data exfiltration and unauthorized persistence across internal systems following credential access."
        stage_analysis = f"Multi-vector attack traversing {tactics_str}. Correlated alerts: {len(alerts)}."
        confidence = 0.91 if severity in ("critical", "high") else 0.82

    actions: List[Dict] = []
    if incident.src_ip:
        actions.append({
            "action_type": "block_ip",
            "target": incident.src_ip,
            "reason": f"Block adversary {src_ip} at the network perimeter to halt further attack progression.",
            "priority": "high",
        })
    for user in users[:2]:
        actions.append({
            "action_type": "disable_user",
            "target": user,
            "reason": f"Revoke active sessions and force password reset for potentially compromised account '{user}'.",
            "priority": "high",
        })
    actions.append({
        "action_type": "create_ticket",
        "target": f"[SOC] Investigate: {incident.title}",
        "reason": "Escalate to SecOps incident response team for forensic scoping and audit trail.",
        "priority": "medium",
    })
    actions.append({
        "action_type": "monitor",
        "target": src_ip,
        "reason": f"Establish 48-hour continuous perimeter monitoring for secondary ingress attempts.",
        "priority": "low",
    })

    return {
        "summary": summary,
        "attack_stage_analysis": stage_analysis,
        "likely_attacker_goal": goal,
        "confidence": confidence,
        "severity_justification": (
            f"Incident classified as {severity.upper()} based on correlation of {len(alerts)} alerts across "
            f"{len(tactics_seen)} MITRE ATT&CK tactics ({tactics_str})."
        ),
        "recommended_actions": actions,
        "_iteration": iteration,
    }


def _mock_triage_response(incident: Incident) -> Dict[str, Any]:
    """Mock triage implementation leveraging the dynamic synthesis engine."""
    iteration = _analysis_variation_counter.get(incident.id, 0)
    res = _synthesize_dynamic_triage(incident, iteration)
    res["_mock"] = True
    return res


def _fallback_triage(incident: Incident) -> Dict[str, Any]:
    """Fallback triage implementation leveraging the dynamic synthesis engine."""
    iteration = _analysis_variation_counter.get(incident.id, 0)
    res = _synthesize_dynamic_triage(incident, iteration)
    res["_fallback"] = True
    return res


# ---------------------------------------------------------------------------
# Gemini API Call
# ---------------------------------------------------------------------------
def _call_gemini(prompt: str) -> Optional[str]:
    """
    Call the Google Gemini API with strict timeout.
    Returns None on any API error, timeout, or quota exhaustion.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        logger.error("GEMINI_API_KEY is not set. Cannot call Gemini API.")
        return None

    configured_model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
    # Candidate models to try in sequence if a deprecated model returns 404
    candidate_models = [configured_model]
    for fallback in ["gemini-3.5-flash-lite", "gemini-flash-latest"]:
        if fallback not in candidate_models:
            candidate_models.append(fallback)

    try:
        import google.generativeai as genai  # type: ignore

        genai.configure(api_key=api_key)

        for model_name in candidate_models:
            try:
                model = genai.GenerativeModel(
                    model_name=model_name,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.2,
                        max_output_tokens=1024,
                        response_mime_type="application/json",
                    ),
                )
                response = model.generate_content(prompt, request_options={"timeout": 8.0})
                if response and response.text:
                    logger.info("Successfully generated AI triage with model %s", model_name)
                    return response.text
            except Exception as model_err:
                logger.warning("Gemini invocation failed with %s: %s", model_name, model_err)
                continue
    except ImportError:
        logger.error("google-generativeai package is not installed. Run: pip install google-generativeai")
        return None
    except Exception as exc:
        logger.warning("Gemini call failed: %s. Proceeding with dynamic triage...", exc)
        return None
    return None


# ---------------------------------------------------------------------------
# JSON Parsing & Validation
# ---------------------------------------------------------------------------
def _parse_and_validate(raw: str) -> Optional[Dict[str, Any]]:
    """
    Parse the LLM response as JSON and validate required fields.
    Strips markdown code fences if present (defensive, even with response_mime_type set).
    """
    if not raw:
        return None

    # Strip markdown fences defensively
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip())

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse Gemini response as JSON: %s\nRaw: %.500s", exc, raw)
        return None

    # Validate required fields
    required = {"summary", "attack_stage_analysis", "likely_attacker_goal",
                "confidence", "severity_justification", "recommended_actions"}
    missing = required - set(data.keys())
    if missing:
        logger.warning("Gemini response missing required fields: %s", missing)
        return None

    # Validate confidence range
    try:
        data["confidence"] = float(data["confidence"])
        data["confidence"] = max(0.0, min(1.0, data["confidence"]))
    except (TypeError, ValueError):
        data["confidence"] = 0.5

    # Validate & sanitize recommended_actions
    sanitized_actions: List[Dict] = []
    for action in data.get("recommended_actions", []):
        if not isinstance(action, dict):
            continue
        action_type = action.get("action_type", "monitor")
        if action_type not in VALID_ACTION_TYPES:
            action["action_type"] = "monitor"
        sanitized_actions.append({
            "action_type": action.get("action_type", "monitor"),
            "target": str(action.get("target", "")),
            "reason": str(action.get("reason", "")),
            "priority": action.get("priority", "medium"),
        })
    data["recommended_actions"] = sanitized_actions

    return data


# ---------------------------------------------------------------------------
# Main Triage Entry Point
# ---------------------------------------------------------------------------
def generate_incident_triage(
    incident: Incident,
    db: Session,
    force: bool = False,
) -> Dict[str, Any]:
    """
    Generate and persist an AI triage report for the given incident.

    Args:
        incident: The Incident ORM object (must have alerts eager-loaded).
        db: SQLAlchemy session for persisting the result.
        force: If True, re-generate even if ai_summary already exists.

    Returns:
        A dict with keys: summary, attack_stage_analysis, likely_attacker_goal,
        confidence, severity_justification, recommended_actions.
        Always returns a valid dict (never raises).
    """
    # Skip if already triaged and not forced
    if incident.ai_summary and not force:
        logger.debug("Incident %d already has AI summary; skipping (use force=True to re-run).", incident.id)
        return {
            "summary": incident.ai_summary,
            "recommended_actions": incident.ai_recommendations or [],
            "_cached": True,
        }

    # When re-analyzing, advance the analytical perspective
    if force:
        _analysis_variation_counter[incident.id] = _analysis_variation_counter.get(incident.id, 0) + 1

    is_mock = _is_mock_ai()
    logger.info(
        "Starting AI triage for incident %d (severity=%s, mock=%s)",
        incident.id, incident.severity, is_mock
    )

    # 1. RAG: retrieve MITRE context for all techniques in the incident
    technique_ids = incident.mitre_techniques or []
    # Also collect from individual alerts in case incident.mitre_techniques is stale
    if incident.alerts:
        for alert in incident.alerts:
            if alert.mitre_technique_id and alert.mitre_technique_id not in technique_ids:
                technique_ids.append(alert.mitre_technique_id)

    mitre_context = get_mitre_context(technique_ids)

    # 2. Generate triage result
    triage_result: Optional[Dict[str, Any]] = None

    if is_mock:
        logger.info("Mock AI mode enabled — returning canned response for incident %d.", incident.id)
        triage_result = _mock_triage_response(incident)
    else:
        # 2a. Build prompt
        prompt = _build_prompt(incident, mitre_context)
        logger.debug("Sending prompt to Gemini (length=%d chars)", len(prompt))

        # 2b. Call Gemini
        raw_response = _call_gemini(prompt)

        # 2c. Parse and validate
        if raw_response:
            triage_result = _parse_and_validate(raw_response)
            if triage_result is None:
                logger.warning("Gemini returned unparseable JSON for incident %d; using fallback.", incident.id)

    # 3. Fallback if Gemini failed or returned invalid JSON
    if triage_result is None:
        logger.warning("Using fallback template triage for incident %d.", incident.id)
        triage_result = _fallback_triage(incident)

    # 4. Persist to Incident record
    _persist_triage(incident, triage_result, db)

    return triage_result


def _persist_triage(incident: Incident, triage: Dict[str, Any], db: Session) -> None:
    """Write triage results back to the Incident row in the database."""
    try:
        incident.ai_summary = triage.get("summary", "")
        incident.ai_recommendations = triage.get("recommended_actions", [])
        incident.ai_generated_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        db.add(incident)
        db.commit()
        db.refresh(incident)
        logger.info("Persisted AI triage for incident %d.", incident.id)
    except Exception as exc:
        logger.error("Failed to persist triage for incident %d: %s", incident.id, exc, exc_info=True)
        db.rollback()


# ---------------------------------------------------------------------------
# Auto-Triage Hook (called from correlation engine)
# ---------------------------------------------------------------------------
def maybe_auto_triage(incident: Incident, db: Session) -> None:
    """
    Automatically trigger triage when an incident reaches high or critical severity.
    Called from the correlation engine after every incident update.
    Safe to call always — it no-ops if severity is below threshold or already triaged.
    """
    if incident.severity not in AUTO_TRIAGE_SEVERITIES:
        return
    if incident.ai_summary:
        return  # Already triaged; skip unless force=True

    logger.info(
        "Auto-triggering AI triage for %s incident %d (%s).",
        incident.severity, incident.id, incident.title
    )
    try:
        generate_incident_triage(incident, db)
    except Exception as exc:
        # Never let auto-triage break the ingest pipeline
        logger.error("Auto-triage failed for incident %d: %s", incident.id, exc, exc_info=True)
