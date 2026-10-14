"""Health, readiness and integration-status endpoints.

These endpoints report *actual* capability and integration state. A feature is
only marked active when its dependencies are configured and reachable.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app import __version__
from app.core.config import settings
from app.core.database import get_db
from app.models import IntegrationAccount, Job, SensorStatus
from app.schemas import HealthResponse

router = APIRouter(tags=["health"])


def _check_database(db: Session) -> dict:
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "dialect": "postgresql" if not settings.is_sqlite else "sqlite"}
    except Exception as exc:  # pragma: no cover
        return {"status": "error", "error": str(exc)[:200]}


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    db_status = _check_database(db)
    overall = "ok" if db_status["status"] == "ok" else "degraded"
    return HealthResponse(
        status=overall,
        version=__version__,
        environment=settings.environment,
        time=datetime.now(UTC),
        components={"database": db_status},
        capabilities=settings.capability_report(),
    )


@router.get("/readiness")
def readiness(db: Session = Depends(get_db)) -> dict:
    db_status = _check_database(db)
    ready = db_status["status"] == "ok"
    return {"ready": ready, "checks": {"database": db_status}}


@router.get("/status/integrations")
def integration_status(db: Session = Depends(get_db)) -> dict:
    """Report provider integration health without overstating it.

    Gmail/Outlook monitoring is reported as active only when an account is in
    the ``monitoring`` state. Webhook configuration gaps are surfaced explicitly.
    """
    caps = settings.capability_report()

    accounts = db.execute(select(IntegrationAccount)).scalars().all()
    gmail_accounts = [a for a in accounts if a.provider in {"gmail", "mock_gmail"}]
    outlook_accounts = [a for a in accounts if a.provider in {"outlook", "mock_outlook"}]

    def summarize(items: list[IntegrationAccount]) -> dict:
        states: dict[str, int] = {}
        for a in items:
            states[a.status] = states.get(a.status, 0) + 1
        return {
            "accounts": len(items),
            "states": states,
            "monitoring_active": states.get("monitoring", 0) > 0,
        }

    pending_jobs = db.execute(
        select(func.count()).select_from(Job).where(Job.status.in_(["pending", "running"]))
    ).scalar_one()
    failed_jobs = db.execute(
        select(func.count()).select_from(Job).where(Job.status == "failed")
    ).scalar_one()

    sensors = {
        s.sensor: {"status": s.status, "last_event_at": s.last_event_at, "events_total": s.events_total}
        for s in db.execute(select(SensorStatus)).scalars().all()
    }

    webhook = {
        "public_base_url_configured": bool(settings.public_webhook_base_url),
        "https_required": True,
        "gmail_pubsub_configured": bool(settings.google_pubsub_topic),
    }

    return {
        "time": datetime.now(UTC),
        "capabilities": caps,
        "gmail": {
            "configured": caps["gmail"],
            "scopes": [
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/gmail.metadata",
            ],
            **summarize(gmail_accounts),
        },
        "outlook": {
            "configured": caps["outlook"],
            "scopes": ["Mail.ReadBasic", "offline_access", "openid", "email"],
            **summarize(outlook_accounts),
        },
        "webhook": webhook,
        "jobs": {"pending_or_running": pending_jobs, "failed": failed_jobs},
        "sensors": sensors,
        "notes": [
            "Gmail watch requires a Google Cloud Pub/Sub topic and a public HTTPS push endpoint.",
            "Outlook change notifications require a public HTTPS webhook base URL.",
            "Monitoring is never reported active when webhook configuration is missing.",
        ],
    }


@router.get("/status/modules")
def module_status() -> dict:
    """Static capability map for every module, with honest implementation state."""
    return {
        "modules": [
            {"name": "url_scan", "state": "implemented"},
            {"name": "email_security", "state": "implemented"},
            {"name": "email_integrations", "state": "implemented"},
            {"name": "android_qr", "state": "implemented"},
            {"name": "file_analysis", "state": "implemented"},
            {"name": "soc_siem", "state": "implemented"},
            {"name": "network_ids", "state": "implemented"},
            {"name": "forensics", "state": "implemented"},
            {"name": "vulnerability_assets", "state": "implemented"},
            {"name": "identity_access", "state": "implemented"},
            {"name": "incident_response", "state": "implemented"},
            {"name": "threat_intel", "state": "implemented"},
            {"name": "ml", "state": "implemented"},
        ]
    }
