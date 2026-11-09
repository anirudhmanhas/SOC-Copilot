"""
SOC Copilot - Security Log Parsers
Provides normalization parsers for heterogeneous log sources:
- SSH (/var/log/auth.log format)
- Web Server Access Logs (Nginx/Apache combined format)
- Firewall Event Logs (Perimeter CEF/KV format)

All parsers gracefully handle malformed, partial, or unexpected lines,
returning normalized dictionaries ready for LogEvent creation.
"""

import datetime
import ipaddress
import re
import urllib.parse
from typing import Any, Dict, List, Optional


IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")

SYSLOG_TS_PATTERN = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
WEB_TS_PATTERN = re.compile(r"\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)\]")
ISO_TS_PATTERN = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b")

SQLI_PATTERN = re.compile(
    r"(union\s+select|'\s*or\s*['\d]|--|/\*|information_schema|xp_cmdshell|sleep\(\s*\d+\s*\))",
    re.IGNORECASE,
)


def _get_utc_now() -> datetime.datetime:
    """Return current UTC timestamp."""
    return datetime.datetime.now(datetime.timezone.utc)


def _extract_ip(text: str) -> Optional[str]:
    """Extract first valid IPv4 address found in string."""
    match = IPV4_PATTERN.search(text)
    if match:
        candidate = match.group(0)
        try:
            ipaddress.IPv4Address(candidate)
            return candidate
        except ValueError:
            return None
    return None


def _parse_iso_timestamp(ts_str: str) -> Optional[datetime.datetime]:
    """Parse ISO formatted timestamp."""
    try:
        clean_ts = ts_str.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return None


def _parse_syslog_timestamp(ts_str: str) -> Optional[datetime.datetime]:
    """Parse Syslog formatted timestamp ('Oct 24 12:00:00') adding current year."""
    try:
        # Normalize double space between month and day
        normalized = " ".join(ts_str.split())
        parsed = datetime.datetime.strptime(normalized, "%b %d %H:%M:%S")
        now = _get_utc_now()
        dt = parsed.replace(year=now.year, tzinfo=datetime.timezone.utc)
        # If timestamp is accidentally in the future by > 30 days (e.g. year transition), use previous year
        if dt > now + datetime.timedelta(days=30):
            dt = dt.replace(year=now.year - 1)
        return dt
    except Exception:
        return None


def _parse_web_timestamp(ts_str: str) -> Optional[datetime.datetime]:
    """Parse Common/Nginx log timestamp ('09/Nov/2026:14:28:53 +0000')."""
    try:
        if " " in ts_str:
            dt = datetime.datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        else:
            dt = datetime.datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return None


def _extract_timestamp(text: str) -> datetime.datetime:
    """Attempt extraction of timestamp from various formats, fallback to utc_now."""
    # Check Web format [09/Nov/2026:14:28:53 +0000]
    web_match = WEB_TS_PATTERN.search(text)
    if web_match:
        dt = _parse_web_timestamp(web_match.group(1))
        if dt:
            return dt

    # Check ISO format
    iso_match = ISO_TS_PATTERN.search(text)
    if iso_match:
        dt = _parse_iso_timestamp(iso_match.group(1))
        if dt:
            return dt

    # Check Syslog format at start of line
    syslog_match = SYSLOG_TS_PATTERN.match(text)
    if syslog_match:
        dt = _parse_syslog_timestamp(syslog_match.group(1))
        if dt:
            return dt

    return _get_utc_now()


# ---------------------------------------------------------------------------
# 1. SSH Parser
# ---------------------------------------------------------------------------
def parse_ssh_line(raw: str) -> Dict[str, Any]:
    """
    Parse an SSH / auth log entry.
    Handles standard OpenSSH syslog events and raw auth messages.
    """
    if not isinstance(raw, str) or not raw.strip():
        return {
            "source": "ssh",
            "raw": str(raw) if raw is not None else "",
            "src_ip": None,
            "user": None,
            "event_type": "unknown",
            "status": "unknown",
            "timestamp": _get_utc_now(),
            "extra": {"parse_error": "Empty or non-string raw log"},
        }

    line = raw.strip()
    timestamp = _extract_timestamp(line)
    src_ip: Optional[str] = None
    user: Optional[str] = None
    event_type = "ssh_event"
    status = "unknown"
    extra: Dict[str, Any] = {}

    # Extract PID if present (e.g. sshd[12345]:)
    pid_match = re.search(r"sshd\[(\d+)\]:", line)
    if pid_match:
        extra["pid"] = int(pid_match.group(1))

    # Extract source IP - commonly preceded by 'from'
    ip_from_match = re.search(r"\bfrom\s+([0-9a-fA-F:.]+)", line)
    if ip_from_match:
        candidate_ip = ip_from_match.group(1)
        if _extract_ip(candidate_ip):
            src_ip = candidate_ip
    if not src_ip:
        src_ip = _extract_ip(line)

    # Extract port
    port_match = re.search(r"\bport\s+(\d+)", line)
    if port_match:
        extra["port"] = int(port_match.group(1))

    # Pattern: Failed password for invalid user <user>
    invalid_match = re.search(r"Failed password for invalid user\s+([^\s]+)", line)
    if invalid_match:
        user = invalid_match.group(1)
        event_type = "login_failed"
        status = "failed"
        extra["invalid_user"] = True
        extra["auth_method"] = "password"

    # Pattern: Failed password for <user>
    elif re.search(r"Failed password for\s+([^\s]+)", line):
        m = re.search(r"Failed password for\s+([^\s]+)", line)
        user = m.group(1)
        event_type = "login_failed"
        status = "failed"
        extra["invalid_user"] = False
        extra["auth_method"] = "password"

    # Pattern: Accepted password for <user>
    elif re.search(r"Accepted password for\s+([^\s]+)", line):
        m = re.search(r"Accepted password for\s+([^\s]+)", line)
        user = m.group(1)
        event_type = "login_success"
        status = "success"
        extra["auth_method"] = "password"

    # Pattern: Accepted publickey for <user>
    elif re.search(r"Accepted publickey for\s+([^\s]+)", line):
        m = re.search(r"Accepted publickey for\s+([^\s]+)", line)
        user = m.group(1)
        event_type = "login_success"
        status = "success"
        extra["auth_method"] = "publickey"

    # Pattern: pam_unix(sshd:session): session opened for user <user>
    elif re.search(r"session opened for user\s+([^\s]+)", line):
        m = re.search(r"session opened for user\s+([^\s]+)", line)
        user = m.group(1)
        event_type = "session_opened"
        status = "success"

    # Pattern: pam_unix(sshd:session): session closed for user <user>
    elif re.search(r"session closed for user\s+([^\s]+)", line):
        m = re.search(r"session closed for user\s+([^\s]+)", line)
        user = m.group(1)
        event_type = "session_closed"
        status = "closed"

    # Pattern: Connection closed by authenticating user <user>
    elif re.search(r"Connection closed by authenticating user\s+([^\s]+)", line):
        m = re.search(r"Connection closed by authenticating user\s+([^\s]+)", line)
        user = m.group(1)
        event_type = "disconnect"
        status = "closed"

    # Pattern: Connection closed by <ip>
    elif "Connection closed" in line:
        event_type = "disconnect"
        status = "closed"

    # Pattern: Sudo failure / privilege escalation attempt
    elif "sudo" in line.lower() and ("authentication failure" in line.lower() or "incorrect password" in line.lower()):
        event_type = "sudo_failure"
        status = "failed"
        user_m = re.search(r"(?:user=|logname=)([^\s;]+)", line) or re.search(r"^([^\s:]+)\s*:", line)
        if user_m:
            user = user_m.group(1)
        extra["service"] = "sudo"

    # Generic user fallback if not identified yet
    if not user:
        user_m = re.search(r"\buser[=:\s]+([^\s;]+)", line, re.IGNORECASE)
        if user_m and user_m.group(1).lower() not in ("from", "by", "unknown"):
            user = user_m.group(1)

    return {
        "source": "ssh",
        "raw": line,
        "src_ip": src_ip,
        "user": user,
        "event_type": event_type,
        "status": status,
        "timestamp": timestamp,
        "extra": extra,
    }


# ---------------------------------------------------------------------------
# 2. Web Parser
# ---------------------------------------------------------------------------
def parse_web_line(raw: str) -> Dict[str, Any]:
    """
    Parse a web server access log entry (Nginx/Apache combined or simple request).
    Extracts HTTP method, path, status, user agent, IP, and detects injection signatures.
    """
    if not isinstance(raw, str) or not raw.strip():
        return {
            "source": "web",
            "raw": str(raw) if raw is not None else "",
            "src_ip": None,
            "user": None,
            "event_type": "unknown",
            "status": "unknown",
            "timestamp": _get_utc_now(),
            "extra": {"parse_error": "Empty or non-string raw log"},
        }

    line = raw.strip()
    timestamp = _extract_timestamp(line)
    src_ip: Optional[str] = None
    user: Optional[str] = None
    event_type = "http_request"
    status = "unknown"
    extra: Dict[str, Any] = {}

    # Standard Nginx / Apache Combined Log Format:
    # 203.0.113.15 - frank [09/Nov/2026:14:28:53 +0000] "GET /api/v1/users HTTP/1.1" 200 4521 "referer" "UA"
    combined_regex = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<protocol>[^"]+))?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    combined_match = combined_regex.search(line)
    if combined_match:
        m = combined_match.groupdict()
        src_ip = _extract_ip(m["ip"])
        auth_user = m.get("user")
        if auth_user and auth_user != "-":
            user = auth_user

        method = m.get("method")
        path = m.get("path")
        status_code_str = m.get("status")
        status_code = int(status_code_str) if status_code_str and status_code_str.isdigit() else None

        extra["method"] = method
        extra["endpoint"] = path
        if status_code is not None:
            extra["status_code"] = status_code

        bytes_sent = m.get("bytes")
        if bytes_sent and bytes_sent.isdigit():
            extra["bytes_sent"] = int(bytes_sent)

        if m.get("referer") and m["referer"] != "-":
            extra["referer"] = m["referer"]
        if m.get("user_agent") and m["user_agent"] != "-":
            extra["user_agent"] = m["user_agent"]
        if m.get("protocol"):
            extra["protocol"] = m["protocol"]

    else:
        # Fallback / Simpler formats: e.g. 'GET /api/users?id=1 HTTP/1.1 500'
        simple_req = re.search(r'\b(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<path>[^\s"]+)(?:\s+(?P<protocol>HTTP/[0-9.]+))?(?:\s+(?P<status>\d{3}))?', line)
        if simple_req:
            m = simple_req.groupdict()
            method = m.get("method")
            path = m.get("path")
            extra["method"] = method
            extra["endpoint"] = path
            if m.get("protocol"):
                extra["protocol"] = m["protocol"]
            if m.get("status") and m["status"].isdigit():
                extra["status_code"] = int(m["status"])
        else:
            path = None

        src_ip = _extract_ip(line)

    # Determine status based on HTTP status code
    sc = extra.get("status_code")
    if sc is not None:
        if 200 <= sc < 400:
            status = "allowed"
        elif sc in (401, 403):
            status = "blocked"
        elif sc >= 400:
            status = "failed"
        else:
            status = "unknown"
    else:
        status = "unknown"

    # Check for SQL injection signature in path/raw message (after decoding)
    path_to_check = extra.get("endpoint") or line
    try:
        decoded_path = urllib.parse.unquote_plus(path_to_check)
    except Exception:
        decoded_path = path_to_check

    if SQLI_PATTERN.search(decoded_path) or SQLI_PATTERN.search(line):
        extra["sqli_detected"] = True

    return {
        "source": "web",
        "raw": line,
        "src_ip": src_ip,
        "user": user,
        "event_type": event_type,
        "status": status,
        "timestamp": timestamp,
        "extra": extra,
    }


# ---------------------------------------------------------------------------
# 3. Firewall Parser
# ---------------------------------------------------------------------------
def parse_firewall_line(raw: str) -> Dict[str, Any]:
    """
    Parse a perimeter firewall log entry (KV format, CEF, or syslog).
    Extracts action, src_ip, dst_ip, ports, protocol, bytes, and device metadata.
    """
    if not isinstance(raw, str) or not raw.strip():
        return {
            "source": "firewall",
            "raw": str(raw) if raw is not None else "",
            "src_ip": None,
            "user": None,
            "event_type": "unknown",
            "status": "unknown",
            "timestamp": _get_utc_now(),
            "extra": {"parse_error": "Empty or non-string raw log"},
        }

    line = raw.strip()
    timestamp = _extract_timestamp(line)
    src_ip: Optional[str] = None
    user: Optional[str] = None
    event_type = "firewall_traffic"
    status = "unknown"
    extra: Dict[str, Any] = {}

    # Parse key=value pairs: e.g. action="allow" srcip=10.0.1.15 proto=tcp bytes=1452
    kv_matches = re.findall(r'(\w+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s]+))', line)
    kv_dict: Dict[str, str] = {}
    for key, v1, v2, v3 in kv_matches:
        val = v1 or v2 or v3
        kv_dict[key.lower()] = val

    # Extract source IP
    for ip_key in ("srcip", "src", "source_ip", "src_ip", "saddr"):
        if ip_key in kv_dict and _extract_ip(kv_dict[ip_key]):
            src_ip = kv_dict[ip_key]
            break
    if not src_ip:
        src_ip = _extract_ip(line)

    # Extract destination IP
    for dst_key in ("dstip", "dst", "destination_ip", "dst_ip", "daddr"):
        if dst_key in kv_dict and _extract_ip(kv_dict[dst_key]):
            extra["dst_ip"] = kv_dict[dst_key]
            break

    # Extract ports
    for sport_key in ("srcport", "spt", "src_port"):
        if sport_key in kv_dict and kv_dict[sport_key].isdigit():
            extra["src_port"] = int(kv_dict[sport_key])
            break

    for dport_key in ("dstport", "dpt", "dst_port"):
        if dport_key in kv_dict and kv_dict[dport_key].isdigit():
            extra["dst_port"] = int(kv_dict[dport_key])
            break

    # Extract protocol
    for proto_key in ("proto", "protocol"):
        if proto_key in kv_dict:
            extra["proto"] = kv_dict[proto_key].lower()
            break

    # Extract bytes
    for bytes_key in ("bytes", "byte_count", "sentbyte", "rcvdbyte"):
        if bytes_key in kv_dict and kv_dict[bytes_key].isdigit():
            extra["bytes"] = int(kv_dict[bytes_key])
            break

    # Extract device / hostname
    for dev_key in ("devname", "device", "dev", "hostname"):
        if dev_key in kv_dict:
            extra["devname"] = kv_dict[dev_key]
            break

    # Extract message
    for msg_key in ("msg", "message"):
        if msg_key in kv_dict:
            extra["msg"] = kv_dict[msg_key]
            break

    # Extract user if available
    for user_key in ("user", "usr", "username"):
        if user_key in kv_dict:
            user = kv_dict[user_key]
            break

    # Extract action
    action = kv_dict.get("action") or kv_dict.get("act")
    if not action:
        # Check syslog/kernel keywords
        if "drop" in line.lower() or "dropped" in line.lower():
            action = "deny"
        elif "allow" in line.lower() or "allowed" in line.lower() or "accept" in line.lower():
            action = "allow"
        elif "reject" in line.lower():
            action = "reject"

    if action:
        clean_action = action.lower()
        extra["action"] = clean_action
        if clean_action in ("allow", "accept", "pass", "permit"):
            status = "allowed"
            event_type = "firewall_traffic"
        elif clean_action in ("deny", "drop", "reject", "block", "blocked"):
            status = "blocked"
            event_type = "firewall_drop"
        else:
            status = clean_action

    return {
        "source": "firewall",
        "raw": line,
        "src_ip": src_ip,
        "user": user,
        "event_type": event_type,
        "status": status,
        "timestamp": timestamp,
        "extra": extra,
    }


# ---------------------------------------------------------------------------
# General Dispatcher
# ---------------------------------------------------------------------------
SOURCE_PARSER_MAP = {
    "ssh": parse_ssh_line,
    "auth": parse_ssh_line,
    "sshd": parse_ssh_line,
    "web": parse_web_line,
    "nginx": parse_web_line,
    "apache": parse_web_line,
    "http": parse_web_line,
    "firewall": parse_firewall_line,
    "fw": parse_firewall_line,
    "iptables": parse_firewall_line,
}


def parse_line(source: str, raw: str) -> Dict[str, Any]:
    """
    Parse a single raw log line given its source identifier.
    Gracefully handles unknown sources and malformed lines.
    """
    clean_source = (source or "unknown").lower().strip()
    parser_func = SOURCE_PARSER_MAP.get(clean_source)

    if parser_func:
        return parser_func(raw)

    # Fallback for unrecognized sources
    if not isinstance(raw, str) or not raw.strip():
        return {
            "source": clean_source,
            "raw": str(raw) if raw is not None else "",
            "src_ip": None,
            "user": None,
            "event_type": "unknown",
            "status": "unknown",
            "timestamp": _get_utc_now(),
            "extra": {"parse_error": f"Unknown source '{clean_source}' and empty line"},
        }

    line = raw.strip()
    return {
        "source": clean_source,
        "raw": line,
        "src_ip": _extract_ip(line),
        "user": None,
        "event_type": "unknown",
        "status": "unknown",
        "timestamp": _extract_timestamp(line),
        "extra": {"warning": f"No specialized parser for source '{clean_source}'"},
    }


def parse_log_events(source: str, lines: List[str]) -> List[Dict[str, Any]]:
    """
    Parse a batch of raw log lines into normalized dictionaries.
    Any single failed or malformed line is handled gracefully without failing the batch.
    """
    results: List[Dict[str, Any]] = []
    for line in lines:
        try:
            results.append(parse_line(source, line))
        except Exception as err:
            # Absolute fallback guarantee
            results.append({
                "source": (source or "unknown").lower().strip(),
                "raw": str(line),
                "src_ip": None,
                "user": None,
                "event_type": "unknown",
                "status": "unknown",
                "timestamp": _get_utc_now(),
                "extra": {"parse_error": str(err)},
            })
    return results

