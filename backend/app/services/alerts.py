"""Alert creation with deduplication and lifecycle management."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.models import Alert


def create_alert(
    db: Session,
    *,
    tenant_id: str,
    source_module: str,
    rule_id: str,
    title: str,
    severity: str,
    category: str = "",
    asset: str | None = None,
    evidence: dict | None = None,
    dedup_key: str | None = None,
    scan_id: str | None = None,
    commit: bool = True,
) -> tuple[Alert, bool]:
    """Create an alert, deduplicating against existing *open* alerts.

    Returns (alert, created). When an open alert with the same dedup_key exists
    it is returned unchanged and ``created`` is False.
    """
    if dedup_key:
        existing = db.execute(
            select(Alert).where(
                Alert.tenant_id == tenant_id,
                Alert.dedup_key == dedup_key,
                Alert.status.in_(["open", "acknowledged"]),
            )
        ).scalars().first()
        if existing is not None:
            return existing, False

    alert = Alert(
        tenant_id=tenant_id,
        source_module=source_module,
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        asset=asset,
        evidence=evidence or {},
        dedup_key=dedup_key,
        scan_id=scan_id,
    )
    db.add(alert)
    if commit:
        db.commit()
        db.refresh(alert)
    return alert, True


def acknowledge_alert(db: Session, *, alert: Alert, user_id: str, note: str = "") -> Alert:
    alert.status = "acknowledged"
    alert.acknowledged_by = user_id
    alert.acknowledged_at = datetime.now(UTC)
    record_audit(
        db,
        action="alert.acknowledge",
        tenant_id=alert.tenant_id,
        user_id=user_id,
        resource_type="alert",
        resource_id=alert.id,
        detail={"note": note},
        commit=False,
    )
    db.commit()
    db.refresh(alert)
    return alert


def close_alert(db: Session, *, alert: Alert, user_id: str, note: str = "") -> Alert:
    alert.status = "closed"
    alert.closed_at = datetime.now(UTC)
    record_audit(
        db,
        action="alert.close",
        tenant_id=alert.tenant_id,
        user_id=user_id,
        resource_type="alert",
        resource_id=alert.id,
        detail={"note": note},
        commit=False,
    )
    db.commit()
    db.refresh(alert)
    return alert


def list_alerts(
    db: Session,
    *,
    tenant_id: str,
    severity: str | None = None,
    status: str | None = None,
    q: str | None = None,
    page: int = 1,
    page_size: int = 25,
):
    stmt = select(Alert).where(Alert.tenant_id == tenant_id)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if status:
        stmt = stmt.where(Alert.status == status)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Alert.title.ilike(like) | Alert.rule_id.ilike(like))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    stmt = stmt.order_by(Alert.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    return db.execute(stmt).scalars().all(), total
