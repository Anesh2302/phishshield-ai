"""Threat-intelligence status and lookup endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.deps import AuthContext, get_auth_context, require_csrf
from app.modules.threatintel.service import get_threatintel

router = APIRouter(prefix="/threat-intel", tags=["threat-intelligence"])


@router.get("/providers")
def providers(ctx: AuthContext = Depends(get_auth_context)) -> dict:
    return {
        "providers": [
            {"name": "urlhaus", "configured": settings.urlhaus_enabled, "auth": "none",
             "note": "abuse.ch URLhaus; free, rate-limited."},
            {"name": "virustotal", "configured": bool(settings.threatintel_enabled and settings.virustotal_api_key),
             "auth": "api_key", "note": "Requires an API key; stored server-side only."},
        ],
        "disclaimer": "Absence from a feed does not mean a URL is safe. Results are cached within provider terms.",
    }


class LookupIn(BaseModel):
    url: str = Field(min_length=1, max_length=4000)


@router.post("/lookup")
def lookup(payload: LookupIn, ctx: AuthContext = Depends(require_csrf)) -> dict:
    service = get_threatintel()
    result = service.lookup(payload.url)
    return {
        "url": result.url,
        "any_hit": result.any_hit,
        "indicators": result.indicators,
        "providers": [
            {"provider": p.provider, "status": p.status, "detail": p.detail}
            for p in result.providers
        ],
        "available": result.available,
        "disclaimer": "Absence from a feed does not mean the URL is safe.",
    }
