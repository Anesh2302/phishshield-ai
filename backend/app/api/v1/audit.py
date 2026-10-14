"""Audit-log and identity-event read endpoints (tenant scoped)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import AuthContext, require_role
from app.models import AuditLog, IdentityEvent
from app.schemas import Page

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: datetime
    tenant_id: str | None
    user_id: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    ip: str | None
    detail: dict[str, Any]


class IdentityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: datetime
    event_type: str
    success: bool
    email: str | None
    ip: str | None
    user_agent: str | None
    detail: dict[str, Any]


@router.get("/logs", response_model=Page[AuditOut])
def list_audit_logs(
    action: str | None = None,
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ctx: AuthContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> Page[AuditOut]:
    stmt = select(AuditLog).where(AuditLog.tenant_id == ctx.tenant_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if q:
        stmt = stmt.where(AuditLog.action.ilike(f"%{q}%"))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(
        stmt.order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).scalars().all()
    pages = max(1, (total + page_size - 1) // page_size)
    return Page(items=[AuditOut.model_validate(r) for r in rows], total=total,
                page=page, page_size=page_size, pages=pages)


@router.get("/identity-events", response_model=Page[IdentityOut])
def list_identity_events(
    event_type: str | None = None,
    success: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ctx: AuthContext = Depends(require_role("analyst")),
    db: Session = Depends(get_db),
) -> Page[IdentityOut]:
    stmt = select(IdentityEvent).where(IdentityEvent.tenant_id == ctx.tenant_id)
    if event_type:
        stmt = stmt.where(IdentityEvent.event_type == event_type)
    if success is not None:
        stmt = stmt.where(IdentityEvent.success.is_(success))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(
        stmt.order_by(IdentityEvent.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).scalars().all()
    pages = max(1, (total + page_size - 1) // page_size)
    return Page(items=[IdentityOut.model_validate(r) for r in rows], total=total,
                page=page, page_size=page_size, pages=pages)
