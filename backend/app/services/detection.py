"""
SOC Copilot - Rule-Based Detection Engine
Loads YAML detection rules, evaluates incoming LogEvents using sliding time windows,
enforces alert deduplication within time windows, and enriches generated Alerts with
MITRE ATT&CK technique and tactic intelligence.
"""

import datetime
from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml
from sqlalchemy.orm import Session

from ..models import Alert, LogEvent

logger = logging.getLogger("soc_copilot.detection")


@dataclass
class DetectionRule:
    id: str
    name: str
    severity: str
    source: str
    mitre_technique: str
    description: str
    detection: Dict[str, Any]
    action_recommendations: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def detection_type(self) -> str:
        return self.detection.get("type", "threshold").lower()

    @property
    def field(self) -> str:
        return self.detection.get("field", "src_ip")

    @property
    def conditions(self) -> Dict[str, Any]:
        return self.detection.get("conditions", {})

    @property
    def count(self) -> int:
        return int(self.detection.get("count", 1))

    @property
    def window_seconds(self) -> int:
        return int(self.detection.get("window_seconds", 60))

    @property
    def distinct_field(self) -> Optional[str]:
        return self.detection.get("distinct_field")


class DetectionEngine:
    def __init__(self, rules_dir: Optional[Path] = None, mitre_file: Optional[Path] = None):
        self.rules_dir = rules_dir or self._discover_rules_dir()
        self.mitre_file = mitre_file or self._discover_mitre_file()
        self.rules: List[DetectionRule] = []
        self.mitre_catalog: Dict[str, Dict[str, Any]] = {}
        self.reload()

    def _discover_rules_dir(self) -> Path:
        # Check relative to this file: backend/app/services/detection.py -> root/rules
        candidate = Path(__file__).resolve().parents[3] / "rules"
        if candidate.is_dir():
            return candidate
        # Fallback to CWD
        cwd_candidate = Path.cwd() / "rules"
        if cwd_candidate.is_dir():
            return cwd_candidate
        return candidate

    def _discover_mitre_file(self) -> Path:
        candidate = Path(__file__).resolve().parents[3] / "data" / "mitre_attack.json"
        if candidate.is_file():
            return candidate
        cwd_candidate = Path.cwd() / "data" / "mitre_attack.json"
        if cwd_candidate.is_file():
            return cwd_candidate
        return candidate

    def load_mitre_catalog(self) -> None:
        """Loads MITRE ATT&CK techniques from JSON file."""
        self.mitre_catalog.clear()
        if not self.mitre_file.is_file():
            logger.warning(f"MITRE ATT&CK file not found at {self.mitre_file}")
            return

        try:
            with open(self.mitre_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        tech_id = item.get("id")
                        if tech_id:
                            self.mitre_catalog[tech_id] = item
                elif isinstance(data, dict):
                    # Handle tactics/techniques structure if present
                    if "techniques" in data:
                        for item in data["techniques"]:
                            self.mitre_catalog[item.get("id")] = item
                    elif "tactics" in data:
                        for t in data["tactics"]:
                            tactic_name = t.get("name", "Unknown")
                            for tech in t.get("techniques", []):
                                tech["tactic"] = tactic_name
                                self.mitre_catalog[tech.get("id")] = tech
                    else:
                        for k, v in data.items():
                            if isinstance(v, dict):
                                self.mitre_catalog[v.get("id", k)] = v
            logger.info(f"Loaded {len(self.mitre_catalog)} MITRE techniques from {self.mitre_file}")
        except Exception as e:
            logger.error(f"Error reading MITRE ATT&CK catalog from {self.mitre_file}: {e}")

    def load_rules(self) -> None:
        """Loads all YAML detection rules from the rules directory."""
        self.rules.clear()
        if not self.rules_dir.is_dir():
            logger.warning(f"Rules directory not found at {self.rules_dir}")
            return

        for filepath in self.rules_dir.glob("*.y*ml"):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    doc = yaml.safe_load(f)
                    if not doc or not isinstance(doc, dict):
                        continue

                    rule_id = doc.get("id")
                    if not rule_id:
                        continue

                    rule = DetectionRule(
                        id=str(rule_id),
                        name=doc.get("name", "Unnamed Rule"),
                        severity=doc.get("severity", "MEDIUM"),
                        source=doc.get("source", "unknown"),
                        mitre_technique=doc.get("mitre_technique") or doc.get("mitre", {}).get("technique_id", "T1000"),
                        description=doc.get("description", ""),
                        detection=doc.get("detection") or doc.get("criteria", {}),
                        action_recommendations=doc.get("action_recommendations", []),
                    )
                    self.rules.append(rule)
            except Exception as e:
                logger.error(f"Failed to load detection rule {filepath}: {e}")

        logger.info(f"Loaded {len(self.rules)} detection rules from {self.rules_dir}")

    def reload(self) -> None:
        self.load_mitre_catalog()
        self.load_rules()

    def get_mitre_info(self, technique_id: str) -> Dict[str, str]:
        """Look up MITRE technique and tactic details."""
        clean_id = technique_id.strip() if technique_id else ""
        info = self.mitre_catalog.get(clean_id)
        if not info and "." in clean_id:
            # Try parent technique ID (e.g. T1110 for T1110.001)
            parent_id = clean_id.split(".")[0]
            info = self.mitre_catalog.get(parent_id)

        if info:
            return {
                "id": clean_id,
                "name": info.get("name", "Unknown Technique"),
                "tactic": info.get("tactic", "Unknown Tactic"),
                "description": info.get("description", ""),
            }

        return {
            "id": clean_id,
            "name": f"Technique {clean_id}",
            "tactic": "General",
            "description": "",
        }

    @staticmethod
    def _sources_match(rule_source: str, event_source: str) -> bool:
        """Check if rule source matches event source with common aliases."""
        r_src = rule_source.lower().strip()
        e_src = event_source.lower().strip()
        if r_src == e_src:
            return True
        ssh_aliases = {"ssh", "auth", "sshd"}
        web_aliases = {"web", "nginx", "apache", "http"}
        fw_aliases = {"firewall", "fw", "iptables"}
        if r_src in ssh_aliases and e_src in ssh_aliases:
            return True
        if r_src in web_aliases and e_src in web_aliases:
            return True
        if r_src in fw_aliases and e_src in fw_aliases:
            return True
        return False

    def is_duplicate_alert(
        self,
        db: Session,
        rule_id: str,
        src_ip: Optional[str],
        user: Optional[str],
        window_seconds: int,
        ref_time: datetime.datetime,
    ) -> bool:
        """
        Check if an Alert with the same rule_id and pivot (IP or user)
        was already recorded within the sliding window up to ref_time.
        """
        window_start = ref_time - datetime.timedelta(seconds=window_seconds)

        q = db.query(Alert).filter(
            Alert.rule_id == rule_id,
            Alert.timestamp >= window_start,
            Alert.timestamp <= ref_time,
        )
        if src_ip:
            q = q.filter(Alert.src_ip == src_ip)
        elif user:
            q = q.filter(Alert.user == user)

        return q.first() is not None

    def evaluate_events(self, events: List[LogEvent], db: Session) -> List[Alert]:
        """
        Evaluates a batch of newly ingested LogEvent records against all loaded rules.
        Creates and persists enriched Alert records with window-based deduplication.
        """
        if not events:
            return []

        created_alerts: List[Alert] = []
        # In-memory batch deduplication tracker: (rule_id, pivot_key)
        batch_dedup: Set[Tuple[str, str]] = set()

        for rule in self.rules:
            dtype = rule.detection_type

            for event in events:
                if not self._sources_match(rule.source, event.source):
                    continue

                if dtype == "pattern":
                    alert = self._evaluate_pattern_rule(rule, event, db, batch_dedup)
                    if alert:
                        created_alerts.append(alert)

                elif dtype == "threshold":
                    alert = self._evaluate_threshold_rule(rule, event, db, batch_dedup)
                    if alert:
                        created_alerts.append(alert)

                elif dtype == "sequence":
                    alert = self._evaluate_sequence_rule(rule, event, db, batch_dedup)
                    if alert:
                        created_alerts.append(alert)

        if created_alerts:
            for al in created_alerts:
                db.add(al)
            db.commit()
            for al in created_alerts:
                db.refresh(al)

        return created_alerts

    def _evaluate_pattern_rule(
        self,
        rule: DetectionRule,
        event: LogEvent,
        db: Session,
        batch_dedup: Set[Tuple[str, str]],
    ) -> Optional[Alert]:
        conds = rule.conditions

        # 1. Check event_type
        if "event_type" in conds and event.event_type != conds["event_type"]:
            return None

        # 2. Check status
        if "status" in conds and event.status != conds["status"]:
            return None

        # 3. Check regex_match
        if "regex_match" in conds:
            pattern = re.compile(conds["regex_match"], re.IGNORECASE)
            search_targets = [event.raw or ""]
            if event.extra and isinstance(event.extra, dict):
                if event.extra.get("endpoint"):
                    search_targets.append(str(event.extra["endpoint"]))
                if event.extra.get("user_agent"):
                    search_targets.append(str(event.extra["user_agent"]))
                if event.extra.get("msg"):
                    search_targets.append(str(event.extra["msg"]))

            if not any(pattern.search(target) for target in search_targets):
                return None

        # 4. Check new_ip_for_user condition
        if conds.get("new_ip_for_user"):
            if not event.user or not event.src_ip:
                return None

            # Look for prior successful logins for this user from different IPs
            prior_rows = (
                db.query(LogEvent.src_ip)
                .filter(
                    LogEvent.user == event.user,
                    LogEvent.status == "success",
                    LogEvent.id != event.id,
                )
                .distinct()
                .all()
            )
            prior_ips = {r[0] for r in prior_rows if r[0]}
            # Only trigger if user has established history and this IP is unseen
            if not prior_ips or event.src_ip in prior_ips:
                return None

        # Determine pivot
        pivot_val = event.src_ip if rule.field == "src_ip" else (event.user or event.src_ip or "global")
        dedup_key = (rule.id, pivot_val)

        if dedup_key in batch_dedup:
            return None

        if self.is_duplicate_alert(db, rule.id, event.src_ip, event.user, rule.window_seconds, event.timestamp):
            return None

        batch_dedup.add(dedup_key)
        return self._create_alert_instance(rule, [event.id], event.src_ip, event.user, event.timestamp)

    def _evaluate_threshold_rule(
        self,
        rule: DetectionRule,
        event: LogEvent,
        db: Session,
        batch_dedup: Set[Tuple[str, str]],
    ) -> Optional[Alert]:
        conds = rule.conditions

        # Quick check: does the current event match the threshold filter?
        if "event_type" in conds and event.event_type != conds["event_type"]:
            return None
        if "status" in conds and event.status != conds["status"]:
            return None
        if "status_code" in conds:
            ev_code = event.extra.get("status_code") if isinstance(event.extra, dict) else None
            if ev_code != conds["status_code"]:
                return None
        if "bytes_min" in conds:
            ev_bytes = (event.extra.get("bytes") or 0) if isinstance(event.extra, dict) else 0
            if ev_bytes < conds["bytes_min"]:
                return None

        if rule.field == "dst_ip":
            pivot_val = event.extra.get("dst_ip") if isinstance(event.extra, dict) else None
        elif rule.field == "src_ip":
            pivot_val = event.src_ip
        else:
            pivot_val = event.user or event.src_ip

        if not pivot_val:
            return None

        dedup_key = (rule.id, pivot_val)
        if dedup_key in batch_dedup:
            return None

        dedup_ip = pivot_val if rule.field in ("src_ip", "dst_ip") else event.src_ip
        if self.is_duplicate_alert(db, rule.id, dedup_ip, event.user, rule.window_seconds, event.timestamp):
            return None

        # Query events in sliding window [timestamp - window_seconds, timestamp]
        window_start = event.timestamp - datetime.timedelta(seconds=rule.window_seconds)

        q = db.query(LogEvent).filter(
            LogEvent.timestamp >= window_start,
            LogEvent.timestamp <= event.timestamp,
        )
        if rule.field == "src_ip":
            q = q.filter(LogEvent.src_ip == pivot_val)
        elif rule.field == "user":
            q = q.filter(LogEvent.user == pivot_val)

        matching_logs = q.all()

        # In-memory condition filtering across window logs
        filtered_logs: List[LogEvent] = []
        for log in matching_logs:
            if not self._sources_match(rule.source, log.source):
                continue
            if rule.field == "dst_ip":
                dst = log.extra.get("dst_ip") if isinstance(log.extra, dict) else None
                if dst != pivot_val:
                    continue
            if "event_type" in conds and log.event_type != conds["event_type"]:
                continue
            if "status" in conds and log.status != conds["status"]:
                continue
            if "status_code" in conds:
                code = log.extra.get("status_code") if isinstance(log.extra, dict) else None
                if code != conds["status_code"]:
                    continue
            if "bytes_min" in conds:
                b = (log.extra.get("bytes") or 0) if isinstance(log.extra, dict) else 0
                if b < conds["bytes_min"]:
                    continue
            filtered_logs.append(log)

        # Evaluate count / distinct count
        distinct_field = rule.distinct_field
        if distinct_field == "user":
            distinct_values = {l.user for l in filtered_logs if l.user}
            count_achieved = len(distinct_values)
        elif distinct_field == "dst_port":
            distinct_values = {
                l.extra.get("dst_port")
                for l in filtered_logs
                if isinstance(l.extra, dict) and l.extra.get("dst_port") is not None
            }
            count_achieved = len(distinct_values)
        else:
            count_achieved = len(filtered_logs)

        if count_achieved >= rule.count:
            batch_dedup.add(dedup_key)
            matched_ids = [l.id for l in filtered_logs]
            alert_ip = pivot_val if rule.field in ("src_ip", "dst_ip") else event.src_ip
            return self._create_alert_instance(rule, matched_ids, alert_ip, event.user, event.timestamp)

        return None

    def _evaluate_sequence_rule(
        self,
        rule: DetectionRule,
        event: LogEvent,
        db: Session,
        batch_dedup: Set[Tuple[str, str]],
    ) -> Optional[Alert]:
        conds = rule.conditions
        trigger_event_type = conds.get("trigger_event_type", "login_success")

        # Sequence triggers when the terminal event (e.g. login_success) is observed
        if event.event_type != trigger_event_type:
            return None

        pivot_val = event.src_ip if rule.field == "src_ip" else (event.user or event.src_ip)
        if not pivot_val:
            return None

        dedup_key = (rule.id, pivot_val)
        if dedup_key in batch_dedup:
            return None

        if self.is_duplicate_alert(db, rule.id, event.src_ip, event.user, rule.window_seconds, event.timestamp):
            return None

        prior_event_type = conds.get("prior_event_type", "login_failed")
        prior_count = int(conds.get("prior_count", 5))

        window_start = event.timestamp - datetime.timedelta(seconds=rule.window_seconds)

        # Query prior failed events for this pivot in window
        q = db.query(LogEvent).filter(
            LogEvent.timestamp >= window_start,
            LogEvent.timestamp <= event.timestamp,
            LogEvent.event_type == prior_event_type,
            LogEvent.id != event.id,
        )
        if rule.field == "src_ip":
            q = q.filter(LogEvent.src_ip == pivot_val)
        else:
            q = q.filter(LogEvent.user == pivot_val)

        prior_logs = q.all()

        if len(prior_logs) >= prior_count:
            batch_dedup.add(dedup_key)
            matched_ids = [l.id for l in prior_logs] + [event.id]
            return self._create_alert_instance(rule, matched_ids, event.src_ip, event.user, event.timestamp)

        return None

    def _create_alert_instance(
        self,
        rule: DetectionRule,
        log_event_ids: List[int],
        src_ip: Optional[str],
        user: Optional[str],
        alert_timestamp: datetime.datetime,
    ) -> Alert:
        mitre_info = self.get_mitre_info(rule.mitre_technique)

        alert = Alert(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity.lower(),
            mitre_technique_id=rule.mitre_technique,
            mitre_technique_name=mitre_info["name"],
            mitre_tactic=mitre_info["tactic"],
            src_ip=src_ip,
            user=user,
            description=rule.description,
            log_event_ids=log_event_ids,
            timestamp=alert_timestamp,
        )
        return alert


# Singleton instance
engine_instance = DetectionEngine()


def get_detection_engine() -> DetectionEngine:
    return engine_instance


def process_events_for_detections(events: List[LogEvent], db: Optional[Session] = None) -> List[Alert]:
    """
    Main entry point for detection engine rule evaluation.
    Takes newly stored LogEvent records and evaluates active rules against them.
    Correlates generated alerts into Incidents, then auto-triggers AI triage
    for high/critical incidents when GEMINI_API_KEY or USE_MOCK_AI is set.
    """
    if not db or not events:
        return []
    alerts = engine_instance.evaluate_events(events, db)
    if alerts:
        from .broadcaster import broadcast_event
        for a in alerts:
            broadcast_event("ALERT_TRIGGERED", {
                "id": a.id,
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "src_ip": a.src_ip,
                "user": a.user,
                "description": a.description,
                "mitre_technique_id": a.mitre_technique_id,
                "mitre_technique_name": a.mitre_technique_name,
                "mitre_tactic": a.mitre_tactic,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            })

        from .correlation import correlate_alerts
        from .ai_triage import maybe_auto_triage
        incidents = correlate_alerts(alerts, db=db)
        for incident in incidents:
            maybe_auto_triage(incident, db=db)
    return alerts
