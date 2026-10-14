"""Log normalization into the common event schema.

Supported inputs:
* PhishShield application/auth events (native JSON)
* RFC3164/RFC5424-ish syslog lines (best-effort)
* Suricata ``eve.json`` records (when Suricata is installed)
* Zeek ``conn``/``http``/``notice`` TSV or JSON records (when Zeek is installed)

Anything we cannot confidently parse is reported as a malformed record rather
than being silently dropped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

SEVERITY_MAP = {
    "emerg": "critical", "alert": "critical", "crit": "critical",
    "err": "high", "error": "high", "warning": "medium", "warn": "medium",
    "notice": "low", "info": "info", "debug": "info",
}

SURICATA_SEVERITY = {
    1: "critical", 2: "high", 3: "medium", 4: "low",
}

_SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-\./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)


@dataclass
class NormalizedEvent:
    source: str
    event_time: datetime
    severity: str = "info"
    category: str = "generic"
    asset: str | None = None
    actor: str | None = None
    message: str = ""
    evidence: dict = field(default_factory=dict)
    dedup_key: str | None = None
    simulated: bool = False
    raw: str | None = None


class NormalizationError(ValueError):
    pass


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    value = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        pass
    for fmt in ("%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt).replace(year=datetime.now(UTC).year)
            return dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    return datetime.now(UTC)


def normalize_suricata(record: dict) -> NormalizedEvent:
    etype = record.get("event_type", "unknown")
    severity = SURICATA_SEVERITY.get(int(record.get("alert", {}).get("severity", 3)), "medium")
    alert = record.get("alert", {}) or {}
    src = record.get("src_ip")
    dest = record.get("dest_ip")
    signature = alert.get("signature", etype)
    return NormalizedEvent(
        source="suricata",
        event_time=_parse_ts(record.get("timestamp")),
        severity=severity if etype == "alert" else "info",
        category=f"ids.{etype}",
        asset=dest,
        actor=src,
        message=f"{signature} ({src} -> {dest})",
        evidence={
            "signature_id": alert.get("signature_id"),
            "category": alert.get("category"),
            "proto": record.get("proto"),
            "src_port": record.get("src_port"),
            "dest_port": record.get("dest_port"),
        },
        dedup_key=f"suricata:{record.get('flow_id')}:{alert.get('signature_id')}:{record.get('timestamp')}",
        raw=json.dumps(record)[:4000],
    )


def normalize_zeek(record: dict, *, sensor: str = "zeek") -> NormalizedEvent:
    # Zeek JSON logs include a "path" or we infer from fields.
    path = record.get("path", record.get("_path", "conn"))
    notice = record.get("msg") or record.get("note") or path
    severity = "medium" if path in {"notice", "weird"} else "info"
    return NormalizedEvent(
        source="zeek",
        event_time=_parse_ts(
            record.get("ts") if isinstance(record.get("ts"), str) else None
        ),
        severity=severity,
        category=f"network.{path}",
        asset=record.get("id.resp_h") or record.get("id_orig_h"),
        actor=record.get("id.orig_h"),
        message=str(notice),
        evidence={k: record.get(k) for k in ("id.orig_h", "id.resp_h", "id.resp_p", "proto") if k in record},
        dedup_key=f"zeek:{sensor}:{path}:{record.get('uid', '')}",
        raw=json.dumps(record, default=str)[:4000],
    )


def normalize_syslog(line: str) -> NormalizedEvent:
    m = _SYSLOG_RE.match(line.strip())
    if not m:
        raise NormalizationError("unrecognised syslog line")
    pri = int(m.group("pri")) if m.group("pri") else None
    severity = "info"
    if pri is not None:
        facility_severity = pri % 8
        severity = {
            0: "critical", 1: "critical", 2: "critical", 3: "high",
            4: "medium", 5: "medium", 6: "info", 7: "info",
        }.get(facility_severity, "info")
    msg = m.group("msg")
    return NormalizedEvent(
        source="syslog",
        event_time=_parse_ts(m.group("ts")),
        severity=severity,
        category="system",
        asset=m.group("host"),
        actor=None,
        message=msg[:1000],
        evidence={"process": m.group("proc"), "pid": m.group("pid")},
        dedup_key=None,
        raw=line[:4000],
    )


def normalize_auth_log(line: str, *, host: str | None = None) -> NormalizedEvent:
    """Parse sshd/sudo style auth log lines into identity events."""
    failed = "Failed password" in line or "authentication failure" in line
    accepted = "Accepted" in line
    user_m = re.search(r"(?:for|user)\s+(?:invalid user\s+)?([\w\.\-@]+)", line)
    ip_m = re.search(r"from\s+([0-9a-fA-F:\.]+)", line)
    actor = user_m.group(1) if user_m else None
    ip = ip_m.group(1) if ip_m else None
    severity = "medium" if failed else "info"
    category = "identity.auth.failure" if failed else ("identity.auth.success" if accepted else "identity.auth.other")
    return NormalizedEvent(
        source="authlog",
        event_time=datetime.now(UTC),
        severity=severity,
        category=category,
        asset=host,
        actor=actor,
        message=line[:1000],
        evidence={"ip": ip, "success": accepted and not failed},
        dedup_key=f"authlog:{actor}:{ip}:{line[:60]}",
        raw=line[:4000],
    )


def normalize_native(payload: dict) -> NormalizedEvent:
    """Normalize a PhishShield-originated event."""
    return NormalizedEvent(
        source=payload.get("source", "phishshield"),
        event_time=_parse_ts(payload.get("event_time") or payload.get("timestamp")),
        severity=str(payload.get("severity", "info")),
        category=payload.get("category", "application"),
        asset=payload.get("asset"),
        actor=payload.get("actor"),
        message=str(payload.get("message", ""))[:2000],
        evidence=payload.get("evidence", {}) or {},
        dedup_key=payload.get("dedup_key"),
        simulated=bool(payload.get("simulated", False)),
        raw=json.dumps(payload)[:4000],
    )
