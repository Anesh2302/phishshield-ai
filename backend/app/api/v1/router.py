"""Aggregate API v1 router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    alerts,
    audit,
    auth,
    emails,
    files,
    forensics,
    health,
    identity,
    incidents,
    integrations,
    ml,
    scans,
    soc,
    threatintel,
    vuln,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(scans.router)
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(audit.router)
api_router.include_router(emails.router)
api_router.include_router(files.router)
api_router.include_router(soc.router)
api_router.include_router(forensics.router)
api_router.include_router(vuln.router)
api_router.include_router(identity.router)
api_router.include_router(integrations.router)
api_router.include_router(threatintel.router)
api_router.include_router(ml.router)
