"""SOC/SIEM console endpoints: ingestion, search, sensors, correlation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.database import get_db
from app.core.deps import AuthContext, get_auth_context, require_csrf, require_role
from app.models import SensorStatus, SOCEvent
from app.modules.soc.correlation import CorrelationConfig, run_correlations
from app.modules.soc.normalize import (
    NormalizationError,
    normalize_auth_log,
    normalize_native,
    normalize_suricata,
    normalize_syslog,
    normalize_zeek,
)
from app.schemas import Page, Severity

router = APIRouter(prefix="/soc", tags=["soc"])

IngestFormat = Literal["native", "suricata", "zeek", "syslog", "authlog", "auto"]


class IngestIn(BaseModel):
    format: IngestFormat = "auto"
    payload: dict[str, Any] | str


class BatchIn(BaseModel):
    format: IngestFormat = "auto"
    records: list[dict[str, Any] | str]


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    source: str
    event_time: datetime
    ingested_at: datetime
    severity: str
    category: str
    asset: str | None
    actor: str | None
    message: str
    evidence: dict[str, Any]
    simulated: bool


def _normalize(fmt: str, payload):
    if fmt == "suricata" or (fmt == "auto" and isinstance(payload, dict) and "event_type" in payload):
        return normalize_suricata(payload)
    if fmt == "zeek" or (fmt == "auto" and isinstance(payload, dict) and ("uid" in payload or "_path" in payload)):
        return normalize_zeek(payload)
    if fmt == "authlog" or (fmt == "auto" and isinstance(payload, str) and ("sshd" in payload or "Failed password" in payload)):
        return normalize_auth_log(payload)
    if fmt == "syslog" or (fmt == "auto" and isinstance(payload, str)):
        return normalize_syslog(payload)
    if isinstance(payload, dict):
        return normalize_native(payload)
    raise NormalizationError("unrecognized payload")


def _store(db: Session, ctx: AuthContext, norm, *, simulated: bool = False) -> SOCEvent:
    event = SOCEvent(
        tenant_id=ctx.tenant_id, source=norm.source, event_time=norm.event_time,
        severity=norm.severity, category=norm.category, asset=norm.asset, actor=norm.actor,
        message=norm.message, evidence=norm.evidence, dedup_key=norm.dedup_key,
        simulated=simulated or norm.simulated, raw=norm.raw,
    )
    db.add(event)
    _touch_sensor(db, ctx.tenant_id, norm.source)
    db.commit()
    db.refresh(event)
    return event


def _touch_sensor(db: Session, tenant_id: str, sensor: str) -> None:
    row = db.execute(
        select(SensorStatus).where(SensorStatus.tenant_id == tenant_id, SensorStatus.sensor == sensor)
    ).scalar_one_or_none()
    if row is None:
        row = SensorStatus(tenant_id=tenant_id, sensor=sensor)
        db.add(row)
    row.status = "active"
    row.last_event_at = datetime.now(UTC)
    row.events_total = (row.events_total or 0) + 1


@router.post("/events/ingest", status_code=201)
def ingest_event(payload: IngestIn, ctx: AuthContext = Depends(require_csrf),
                 db: Session = Depends(get_db)) -> dict:
    try:
        norm = _normalize(payload.format, payload.payload)
    except NormalizationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Malformed record: {exc}") from exc
    event = _store(db, ctx, norm)
    return {"id": event.id, "source": event.source, "severity": event.severity}


@router.post("/events/batch", status_code=201)
def ingest_batch(payload: BatchIn, ctx: AuthContext = Depends(require_csrf),
                 db: Session = Depends(get_db)) -> dict:
    stored = 0
    malformed = 0
    errors: list[str] = []
    for rec in payload.records:
        try:
            norm = _normalize(payload.format, rec)
        except NormalizationError as exc:
            malformed += 1
            errors.append(str(exc))
            continue
        _store(db, ctx, norm)
        stored += 1
    return {"stored": stored, "malformed": malformed, "errors": errors[:20]}


@router.get("/events", response_model=Page[EventOut])
def list_events(source: str | None = None, severity: Severity | None = None,
                category: str | None = None, q: str | None = None,
                simulated: bool | None = None,
                since_minutes: int | None = None,
                page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
                ctx: AuthContext = Depends(get_auth_context),
                db: Session = Depends(get_db)) -> Page[EventOut]:
    stmt = select(SOCEvent).where(SOCEvent.tenant_id == ctx.tenant_id)
    if source:
        stmt = stmt.where(SOCEvent.source == source)
    if severity:
        stmt = stmt.where(SOCEvent.severity == str(severity))
    if category:
        stmt = stmt.where(SOCEvent.category == category)
    if simulated is not None:
        stmt = stmt.where(SOCEvent.simulated.is_(simulated))
    if since_minutes:
        stmt = stmt.where(SOCEvent.event_time >= datetime.now(UTC) - timedelta(minutes=since_minutes))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(SOCEvent.message.ilike(like), SOCEvent.actor.ilike(like),
                              SOCEvent.asset.ilike(like)))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(SOCEvent.event_time.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    pages = max(1, (total + page_size - 1) // page_size)
    return Page(items=[EventOut.model_validate(r) for r in rows], total=total,
                page=page, page_size=page_size, pages=pages)


@router.get("/sensors")
def list_sensors(ctx: AuthContext = Depends(get_auth_context),
                 db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(SensorStatus).where(SensorStatus.tenant_id == ctx.tenant_id)).scalars().all()
    return {
        "sensors": [
            {"sensor": r.sensor, "status": r.status, "last_event_at": r.last_event_at,
             "events_total": r.events_total, "detail": r.detail}
            for r in rows
        ],
        "note": "A sensor only appears as active after it has delivered at least one event.",
    }


class CorrelateIn(BaseModel):
    window_minutes: int = 15
    brute_force_threshold: int = 5
    password_spray_distinct_users: int = 4
    scan_surge_threshold: int = 10


@router.post("/correlate")
def correlate(payload: CorrelateIn, ctx: AuthContext = Depends(require_csrf),
              db: Session = Depends(get_db)) -> dict:
    cfg = CorrelationConfig(
        window_minutes=payload.window_minutes,
        brute_force_threshold=payload.brute_force_threshold,
        password_spray_distinct_users=payload.password_spray_distinct_users,
        scan_surge_threshold=payload.scan_surge_threshold,
    )
    result = run_correlations(db, ctx.tenant_id, config=cfg)
    record_audit(db, action="soc.correlate", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 detail=result)
    return result


class DemoIn(BaseModel):
    scenario: Literal["brute_force", "ids", "password_spray"] = "brute_force"
    count: int = Field(default=6, ge=1, le=100)


@router.post("/demo", status_code=201, dependencies=[Depends(require_role("admin"))])
def generate_demo(payload: DemoIn, ctx: AuthContext = Depends(require_role("admin")),
                  db: Session = Depends(get_db)) -> dict:
    """Generate clearly-labelled SIMULATED events for local testing.

    These are synthetic and must never be presented as live attacks.
    """
    now = datetime.now(UTC)
    stored = 0
    for i in range(payload.count):
        if payload.scenario == "brute_force":
            rec = {
                "source": "identity", "event_time": (now - timedelta(minutes=i)).isoformat(),
                "severity": "medium", "category": "identity.auth.failure",
                "actor": "admin@example.test", "message": "simulated failed login",
                "evidence": {"ip": "203.0.113.9"}, "simulated": True,
                "dedup_key": f"demo-bf-{uuid.uuid4().hex}",
            }
        elif payload.scenario == "password_spray":
            rec = {
                "source": "identity", "event_time": (now - timedelta(seconds=i)).isoformat(),
                "severity": "medium", "category": "identity.auth.failure",
                "actor": f"user{i}@example.test", "message": "simulated failed login",
                "evidence": {"ip": "198.51.100.7"}, "simulated": True,
                "dedup_key": f"demo-spray-{uuid.uuid4().hex}",
            }
        else:
            rec = {
                "source": "suricata", "event_time": (now - timedelta(seconds=i)).isoformat(),
                "severity": "high", "category": "ids.alert", "asset": "10.0.0.5",
                "actor": "203.0.113.50", "message": "SIMULATED IDS signature match",
                "evidence": {"simulated": True}, "simulated": True,
                "dedup_key": f"demo-ids-{uuid.uuid4().hex}",
            }
        norm = normalize_native(rec)
        _store(db, ctx, norm, simulated=True)
        stored += 1
    record_audit(db, action="soc.demo.generate", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 detail={"scenario": payload.scenario, "count": stored})
    return {"stored": stored, "simulated": True, "note": "Events are labelled simulated=True."}


@router.get("/parsers")
def parser_health(ctx: AuthContext = Depends(get_auth_context),
                  db: Session = Depends(get_db)) -> dict:
    sources = db.execute(
        select(SOCEvent.source, func.count()).where(SOCEvent.tenant_id == ctx.tenant_id)
        .group_by(SOCEvent.source)
    ).all()
    return {
        "supported_formats": ["native", "suricata", "zeek", "syslog", "authlog"],
        "ingested_by_source": dict(sources),
        "optional_scanners": {
            "suricata": _tool_available("suricata"),
            "zeek": _tool_available("zeek"),
        },
    }


def _tool_available(name: str) -> bool:
    import shutil

    return shutil.which(name) is not None
