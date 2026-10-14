"""Identity & access security: authentication auditing and anomaly detection."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import IdentityEvent, User, UserSession
from app.services.alerts import create_alert

ROLE_ORDER = {"viewer": 1, "analyst": 2, "admin": 3, "owner": 4}


def run_identity_correlations(db: Session, tenant_id: str, *, window_minutes: int = 15,
                              threshold: int = 5, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    since = now - timedelta(minutes=window_minutes)
    events = db.execute(
        select(IdentityEvent).where(
            IdentityEvent.tenant_id == tenant_id,
            IdentityEvent.event_type == "login",
            IdentityEvent.success.is_(False),
            IdentityEvent.created_at >= since,
        )
    ).scalars().all()

    by_email: dict[str, list[IdentityEvent]] = defaultdict(list)
    for ev in events:
        by_email[ev.email or ev.user_id or "unknown"].append(ev)

    created = 0
    for email, evs in by_email.items():
        if len(evs) >= threshold:
            _, was_created = create_alert(
                db,
                tenant_id=tenant_id,
                source_module="identity",
                rule_id="identity.repeated_failed_logins",
                title=f"Repeated failed logins for {email} ({len(evs)})",
                severity="high",
                category="identity",
                evidence={"email": email, "count": len(evs),
                          "ips": sorted({e.ip for e in evs if e.ip})},
                dedup_key=f"identity:fail:{tenant_id}:{email}",
            )
            created += int(was_created)
    return {"analyzed": len(events), "alerts_created": created}


def session_inventory(db: Session, *, user_id: str) -> dict:
    active = db.execute(
        select(UserSession).where(
            UserSession.user_id == user_id, UserSession.revoked.is_(False)
        ).order_by(UserSession.created_at.desc())
    ).scalars().all()
    now = datetime.now(UTC)
    return {
        "active_sessions": len(active),
        "sessions": [
            {
                "id": s.id,
                "ip": s.ip,
                "user_agent": s.user_agent,
                "expires_at": s.expires_at,
                "expired": (s.expires_at.replace(tzinfo=UTC) < now)
                if s.expires_at.tzinfo is None else (s.expires_at < now),
            }
            for s in active
        ],
    }


def token_posture(db: Session, *, tenant_id: str) -> dict:
    from app.models import IntegrationAccount

    accounts = db.execute(
        select(IntegrationAccount).where(IntegrationAccount.tenant_id == tenant_id)
    ).scalars().all()
    now = datetime.now(UTC)
    out = []
    for a in accounts:
        exp = a.token_expires_at
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        out.append(
            {
                "account_id": a.id,
                "provider": a.provider,
                "email": a.email_address,
                "status": a.status,
                "token_expires_at": a.token_expires_at,
                "token_expired": bool(exp and exp < now),
                "has_refresh_token": bool(a.refresh_token_enc),
                "revoked": a.status == "disconnected",
            }
        )
    return {"accounts": out, "count": len(out)}


def role_posture(db: Session, *, tenant_id: str) -> dict:
    users = db.execute(select(User).where(User.tenant_id == tenant_id)).scalars().all()
    counts = defaultdict(int)
    mfa_missing = []
    for u in users:
        counts[u.role] += 1
        if not u.mfa_enabled:
            mfa_missing.append(u.email)
    return {
        "users": len(users),
        "roles": dict(counts),
        "privileged_without_mfa": mfa_missing if mfa_missing else [],
        "recommendation": (
            "Enable MFA for all admin/owner accounts and minimise the number of "
            "owners (least privilege)."
        ),
    }


def mfa_guidance() -> dict:
    return {
        "supported": True,
        "method": "TOTP (RFC 6238)",
        "enroll_endpoint": "/api/v1/auth/mfa/setup",
        "enable_endpoint": "/api/v1/auth/mfa/enable",
        "enforced_by_default": False,
        "note": "MFA is optional per user; enforcement is a deployment policy decision.",
        "session_ttl_minutes": settings.session_ttl_minutes,
    }
