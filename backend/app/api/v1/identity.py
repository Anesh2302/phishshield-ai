"""Identity & access security endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit, record_identity_event
from app.core.database import get_db
from app.core.deps import AuthContext, require_csrf, require_role
from app.models import IdentityEvent
from app.modules.identity.service import (
    mfa_guidance,
    role_posture,
    run_identity_correlations,
    session_inventory,
    token_posture,
)

router = APIRouter(prefix="/identity", tags=["identity-security"])


@router.get("/overview")
def overview(ctx: AuthContext = Depends(require_role("analyst")),
             db: Session = Depends(get_db)) -> dict:
    failed = db.execute(
        select(func.count()).select_from(IdentityEvent).where(
            IdentityEvent.tenant_id == ctx.tenant_id, IdentityEvent.success.is_(False)
        )
    ).scalar_one()
    recent = db.execute(
        select(IdentityEvent).where(IdentityEvent.tenant_id == ctx.tenant_id)
        .order_by(IdentityEvent.created_at.desc()).limit(20)
    ).scalars().all()
    return {
        "failed_events_total": failed,
        "recent_events": [
            {"id": e.id, "event_type": e.event_type, "success": e.success, "email": e.email,
             "ip": e.ip, "created_at": e.created_at}
            for e in recent
        ],
        "session_inventory": session_inventory(db, user_id=ctx.user_id),
        "token_posture": token_posture(db, tenant_id=ctx.tenant_id),
        "role_posture": role_posture(db, tenant_id=ctx.tenant_id),
        "mfa": mfa_guidance(),
    }


@router.post("/correlate")
def correlate(window_minutes: int = Query(15, ge=1, le=1440),
              threshold: int = Query(5, ge=2, le=1000),
              ctx: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> dict:
    result = run_identity_correlations(db, ctx.tenant_id, window_minutes=window_minutes,
                                       threshold=threshold)
    record_audit(db, action="identity.correlate", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 detail=result)
    return result


class SimulateIn(BaseModel):
    scenario: str = Field(default="bruteforce", pattern="^(bruteforce|replay)$")
    attempts: int = Field(default=6, ge=1, le=50)
    target_email: str = "simulated.user@example.test"


@router.post("/simulate", dependencies=[Depends(require_role("admin"))])
def simulate(payload: SimulateIn, ctx: AuthContext = Depends(require_role("admin")),
             db: Session = Depends(get_db)) -> dict:
    """Write clearly-labelled simulated identity events into the local test log.

    This does NOT attempt to authenticate against any real account and performs
    no credential guessing. It exists so detection rules can be exercised safely.
    """
    created = 0
    ip = "198.51.100.23" if payload.scenario == "bruteforce" else "203.0.113.77"
    for _ in range(payload.attempts):
        record_identity_event(
            db, event_type="login", tenant_id=ctx.tenant_id, email=payload.target_email,
            success=False, ip=ip, user_agent="phishshield-simulator",
            detail={"simulated": True, "scenario": payload.scenario}, commit=False,
        )
        created += 1
    db.commit()
    result = run_identity_correlations(db, ctx.tenant_id, window_minutes=15, threshold=5)
    record_audit(db, action="identity.simulate", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 detail={"scenario": payload.scenario, "count": created})
    return {"simulated_events": created, "simulated": True, "correlation": result}
