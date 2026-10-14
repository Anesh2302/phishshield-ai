"""Alert listing and lifecycle endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import AuthContext, get_auth_context, require_csrf
from app.models import Alert
from app.schemas import Page, Severity
from app.services.alerts import acknowledge_alert, close_alert, list_alerts

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    source_module: str
    rule_id: str
    title: str
    severity: str
    category: str
    asset: str | None
    status: str
    evidence: dict[str, Any]
    created_at: datetime
    acknowledged_by: str | None
    acknowledged_at: datetime | None
    closed_at: datetime | None


class NoteIn(BaseModel):
    note: str = ""


@router.get("", response_model=Page[AlertOut])
def list_my_alerts(
    severity: Severity | None = None,
    status_filter: str | None = Query(None, alias="status"),
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> Page[AlertOut]:
    items, total = list_alerts(
        db, tenant_id=ctx.tenant_id, severity=str(severity) if severity else None,
        status=status_filter, q=q, page=page, page_size=page_size,
    )
    pages = max(1, (total + page_size - 1) // page_size)
    return Page(items=[AlertOut.model_validate(i) for i in items], total=total,
                page=page, page_size=page_size, pages=pages)


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: str, ctx: AuthContext = Depends(get_auth_context),
              db: Session = Depends(get_db)) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.tenant_id != ctx.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return AlertOut.model_validate(alert)


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
def ack_alert(alert_id: str, payload: NoteIn,
              ctx: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.tenant_id != ctx.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return AlertOut.model_validate(acknowledge_alert(db, alert=alert, user_id=ctx.user_id, note=payload.note))


@router.post("/{alert_id}/close", response_model=AlertOut)
def close(alert_id: str, payload: NoteIn,
          ctx: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.tenant_id != ctx.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return AlertOut.model_validate(close_alert(db, alert=alert, user_id=ctx.user_id, note=payload.note))
