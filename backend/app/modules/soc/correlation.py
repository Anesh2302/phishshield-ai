"""Correlation rules over the common event schema.

Rules are deliberately simple, explainable, and configurable. Out-of-order
events are handled by comparing against a time window relative to each event's
own timestamp, not ingestion order.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import SOCEvent
from app.services.alerts import create_alert


@dataclass
class CorrelationConfig:
    window_minutes: int = 15
    brute_force_threshold: int = 5
    password_spray_distinct_users: int = 4
    scan_surge_threshold: int = 10
    ids_alert_min_severity: str = "high"


@dataclass
class Proposal:
    rule_id: str
    title: str
    severity: str
    dedup_key: str
    evidence: dict = field(default_factory=dict)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def evaluate(db: Session, tenant_id: str, *, config: CorrelationConfig | None = None,
             now: datetime | None = None) -> list[Proposal]:
    config = config or CorrelationConfig()
    now = now or datetime.now(UTC)
    since = now - timedelta(minutes=config.window_minutes)

    events = db.execute(
        select(SOCEvent).where(
            SOCEvent.tenant_id == tenant_id,
            SOCEvent.event_time >= since,
            SOCEvent.event_time <= now,
        )
    ).scalars().all()

    proposals: list[Proposal] = []

    # Rule 1 & 2: failed authentication analysis
    failures_by_actor: dict[str, list[SOCEvent]] = defaultdict(list)
    failures_by_ip: dict[str, set[str]] = defaultdict(set)
    for ev in events:
        if ev.category in {"identity.auth.failure", "auth.failure", "login_failed"} or (
            ev.source in {"authlog", "identity"} and ev.severity in {"medium", "high", "critical"}
            and "fail" in ev.category
        ):
            actor = ev.actor or "unknown"
            failures_by_actor[actor].append(ev)
            ip = (ev.evidence or {}).get("ip") or ev.actor or "unknown"
            failures_by_ip[ip].add(actor)

    for actor, evs in failures_by_actor.items():
        if len(evs) >= config.brute_force_threshold:
            proposals.append(
                Proposal(
                    rule_id="soc.auth.repeated_failures",
                    title=f"Repeated failed logins for '{actor}' ({len(evs)} in {config.window_minutes}m)",
                    severity="high",
                    dedup_key=f"corr:bruteforce:{tenant_id}:{actor}",
                    evidence={"actor": actor, "count": len(evs),
                              "event_ids": [e.id for e in evs][:20]},
                )
            )

    for ip, actors in failures_by_ip.items():
        if len(actors) >= config.password_spray_distinct_users:
            proposals.append(
                Proposal(
                    rule_id="soc.auth.password_spray",
                    title=f"Password spray from {ip} across {len(actors)} accounts",
                    severity="high",
                    dedup_key=f"corr:spray:{tenant_id}:{ip}",
                    evidence={"ip": ip, "distinct_accounts": len(actors),
                              "accounts": sorted(actors)[:20]},
                )
            )

    # Rule 3: unusual scan activity (many high-severity scan events by one actor)
    scans_by_actor: dict[str, list[SOCEvent]] = defaultdict(list)
    for ev in events:
        if ev.category.startswith("scan.") and ev.severity in {"high", "critical"}:
            scans_by_actor[ev.actor or "unknown"].append(ev)
    for actor, evs in scans_by_actor.items():
        if len(evs) >= config.scan_surge_threshold:
            proposals.append(
                Proposal(
                    rule_id="soc.scan.surge",
                    title=f"Unusual high-risk scan activity by '{actor}' ({len(evs)})",
                    severity="medium",
                    dedup_key=f"corr:scansurge:{tenant_id}:{actor}",
                    evidence={"actor": actor, "count": len(evs)},
                )
            )

    # Rule 4: IDS alerts at or above the configured severity
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_rank = order.get(config.ids_alert_min_severity, 3)
    for ev in events:
        if ev.category.startswith("ids.") and order.get(ev.severity, 0) >= min_rank:
            proposals.append(
                Proposal(
                    rule_id="soc.ids.alert",
                    title=f"IDS alert: {ev.message[:120]}",
                    severity=ev.severity,
                    dedup_key=f"corr:ids:{tenant_id}:{ev.dedup_key or ev.id}",
                    evidence={"event_id": ev.id, "asset": ev.asset, "actor": ev.actor},
                )
            )
    return proposals


def run_correlations(db: Session, tenant_id: str, *, config: CorrelationConfig | None = None,
                     now: datetime | None = None) -> dict:
    proposals = evaluate(db, tenant_id, config=config, now=now)
    created = 0
    for p in proposals:
        _, was_created = create_alert(
            db,
            tenant_id=tenant_id,
            source_module="soc",
            rule_id=p.rule_id,
            title=p.title[:300],
            severity=p.severity,
            category="correlation",
            evidence=p.evidence,
            dedup_key=p.dedup_key,
        )
        created += int(was_created)
    return {"proposals": len(proposals), "alerts_created": created}
