"""Registered job handlers. Handlers must be idempotent."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models import (
    IntegrationAccount,
    IntegrationEvent,
    Scan,
    SOCEvent,
)
from app.modules.integrations.service import renew_account, sync_account
from app.modules.soc.correlation import run_correlations

logger = logging.getLogger(__name__)

REGISTRY: dict[str, callable] = {}


def task(name: str):
    def _decorator(fn):
        REGISTRY[name] = fn
        return fn

    return _decorator


@task("integration.sync_account")
def sync_account_task(db: Session, payload: dict) -> dict:
    account = db.get(IntegrationAccount, payload.get("account_id"))
    if account is None:
        return {"skipped": "account not found"}
    return sync_account(db, account)


@task("integration.renew")
def renew_account_task(db: Session, payload: dict) -> dict:
    account = db.get(IntegrationAccount, payload.get("account_id"))
    if account is None:
        return {"skipped": "account not found"}
    return renew_account(db, account)


@task("soc.correlate")
def correlate_task(db: Session, payload: dict) -> dict:
    tenant_id = payload.get("tenant_id")
    if not tenant_id:
        return {"skipped": "no tenant"}
    window = int(payload.get("window_minutes", 15))
    from app.modules.soc.correlation import CorrelationConfig

    cfg = CorrelationConfig(window_minutes=window)
    return run_correlations(db, tenant_id, config=cfg)


@task("retention.purge")
def purge_task(db: Session, payload: dict) -> dict:
    """Delete records older than the configured retention window."""
    tenant_id = payload.get("tenant_id")
    days = int(payload.get("days", 90))
    cutoff = datetime.now(UTC) - timedelta(days=days)
    deleted = {"scans": 0, "soc_events": 0, "integration_events": 0}
    if tenant_id:
        deleted["scans"] = db.execute(
            delete(Scan).where(Scan.tenant_id == tenant_id, Scan.created_at < cutoff)
        ).rowcount
        deleted["soc_events"] = db.execute(
            delete(SOCEvent).where(SOCEvent.tenant_id == tenant_id, SOCEvent.event_time < cutoff)
        ).rowcount
        deleted["integration_events"] = db.execute(
            delete(IntegrationEvent).where(
                IntegrationEvent.tenant_id == tenant_id, IntegrationEvent.created_at < cutoff
            )
        ).rowcount
        db.commit()
    return deleted
