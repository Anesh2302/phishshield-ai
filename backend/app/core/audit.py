"""Audit-trail helpers. Every sensitive action is recorded append-only."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models import AuditLog, IdentityEvent


def record_audit(
    db: Session,
    *,
    action: str,
    tenant_id: str | None = None,
    user_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    detail: dict | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        action=action,
        tenant_id=tenant_id,
        user_id=user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        ip=ip,
        user_agent=(user_agent or "")[:400] or None,
        detail=detail or {},
    )
    db.add(entry)
    if commit:
        db.commit()
    return entry


def record_identity_event(
    db: Session,
    *,
    event_type: str,
    tenant_id: str,
    user_id: str | None = None,
    email: str | None = None,
    success: bool = True,
    ip: str | None = None,
    user_agent: str | None = None,
    token_expires_at: datetime | None = None,
    detail: dict | None = None,
    commit: bool = True,
) -> IdentityEvent:
    event = IdentityEvent(
        event_type=event_type,
        tenant_id=tenant_id,
        user_id=user_id,
        email=email,
        success=success,
        ip=ip,
        user_agent=(user_agent or "")[:400] or None,
        token_expires_at=token_expires_at,
        detail=detail or {},
    )
    db.add(event)
    if commit:
        db.commit()
    return event


def utcnow() -> datetime:
    return datetime.now(UTC)
