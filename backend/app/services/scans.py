"""Persistence for unified scan results (shared by all detection modules)."""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import Scan
from app.schemas import DetectionResult


def persist_detection(
    db: Session,
    *,
    tenant_id: str,
    user_id: str | None,
    result: DetectionResult,
    source: str = "api",
    status: str = "completed",
    commit: bool = True,
) -> Scan:
    scan = Scan(
        tenant_id=tenant_id,
        user_id=user_id,
        module=result.module,
        target=result.target,
        status=status,
        score=result.score,
        severity=str(result.severity),
        verdict=result.verdict,
        source=source,
        evidence={
            "evidence": [e.model_dump(mode="json") for e in result.evidence],
            "recommended_action": result.recommended_action,
            "metadata": result.metadata,
        },
    )
    db.add(scan)
    if commit:
        db.commit()
        db.refresh(scan)
    return scan


def list_scans(
    db: Session,
    *,
    tenant_id: str,
    module: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    page: int = 1,
    page_size: int = 25,
):
    stmt = select(Scan).where(Scan.tenant_id == tenant_id)
    if module:
        stmt = stmt.where(Scan.module == module)
    if severity:
        stmt = stmt.where(Scan.severity == severity)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Scan.target.ilike(like), Scan.verdict.ilike(like)))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    stmt = stmt.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    items = db.execute(stmt).scalars().all()
    return items, total
