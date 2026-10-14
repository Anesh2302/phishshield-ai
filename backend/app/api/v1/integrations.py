"""Gmail and Outlook integration endpoints (OAuth, webhooks, monitoring)."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.config import settings
from app.core.database import get_db
from app.core.deps import AuthContext, get_auth_context, require_csrf
from app.models import IntegrationAccount
from app.modules.integrations.base import ProviderError
from app.modules.integrations.gmail import GmailProvider
from app.modules.integrations.outlook import OutlookProvider
from app.modules.integrations.service import (
    begin_connect,
    complete_connect,
    derive_status,
    disconnect,
    is_mock,
    record_integration_event,
    renew_account,
    sync_account,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/integrations", tags=["integrations"])

VALID_PROVIDERS = {"gmail", "outlook", "mock_gmail", "mock_outlook"}


def _validate_provider(provider: str) -> str:
    if provider not in VALID_PROVIDERS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown provider")
    if is_mock(provider):
        if settings.is_production:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Mock providers disabled in production")
        if not settings.mock_providers:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Mock providers disabled. Set MOCK_PROVIDERS=1 in a non-production environment.",
            )
    return provider


class AccountOut(BaseModel):
    id: str
    provider: str
    email_address: str
    status: str
    state: str
    monitoring_active: bool
    scopes: list[str]
    last_sync_at: datetime | None
    watch_expires_at: datetime | None
    subscription_expires_at: datetime | None
    subscription_id: str | None
    last_error: str | None
    mock: bool


def _account_out(account: IntegrationAccount) -> AccountOut:
    status_info = derive_status(account)
    return AccountOut(
        id=account.id, provider=account.provider, email_address=account.email_address,
        status=account.status, state=status_info["state"],
        monitoring_active=status_info["monitoring_active"], scopes=account.scopes or [],
        last_sync_at=status_info["last_sync_at"], watch_expires_at=status_info["watch_expires_at"],
        subscription_expires_at=status_info["subscription_expires_at"],
        subscription_id=status_info["subscription_id"], last_error=status_info["last_error"],
        mock=status_info["mock"],
    )


@router.get("/config")
def integration_config(ctx: AuthContext = Depends(get_auth_context)) -> dict:
    caps = settings.capability_report()
    return {
        "gmail": {
            "configured": caps["gmail"],
            "enabled_flag": settings.gmail_enabled,
            "scopes": ["openid", "email", "https://www.googleapis.com/auth/gmail.readonly"],
            "pubsub_topic_configured": bool(settings.google_pubsub_topic),
            "redirect_uri": settings.google_oauth_redirect_uri,
        },
        "outlook": {
            "configured": caps["outlook"],
            "enabled_flag": settings.outlook_enabled,
            "scopes": ["offline_access", "openid", "email", "Mail.Read"],
            "webhook_base_configured": bool(settings.public_webhook_base_url),
            "redirect_uri": settings.ms_oauth_redirect_uri,
        },
        "mock_providers_enabled": settings.mock_providers and not settings.is_production,
        "https_note": "Provider change notifications require a public HTTPS endpoint.",
    }


@router.get("/accounts", response_model=list[AccountOut])
def list_accounts(ctx: AuthContext = Depends(get_auth_context),
                  db: Session = Depends(get_db)) -> list[AccountOut]:
    rows = db.execute(
        select(IntegrationAccount).where(
            IntegrationAccount.tenant_id == ctx.tenant_id,
            IntegrationAccount.user_id == ctx.user_id,
        )
    ).scalars().all()
    return [_account_out(a) for a in rows]


class ConnectOut(BaseModel):
    authorize_url: str
    state: str
    provider: str
    mock: bool


@router.post("/{provider}/connect", response_model=ConnectOut)
def connect(provider: str, ctx: AuthContext = Depends(require_csrf),
            db: Session = Depends(get_db)) -> ConnectOut:
    _validate_provider(provider)
    url = begin_connect(db, user=ctx.user, tenant_id=ctx.tenant_id, provider=provider)
    state = url.split("state=")[-1].split("&")[0]
    return ConnectOut(authorize_url=url, state=state, provider=provider, mock=is_mock(provider))


@router.get("/{provider}/callback")
def oauth_callback(provider: str, request: Request, code: str | None = None,
                   state: str | None = None, error: str | None = None,
                   db: Session = Depends(get_db)) -> dict:
    _validate_provider(provider)
    if error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Provider returned error: {error}")
    if not code or not state:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing code or state")
    try:
        account = complete_connect(db, state=state, code=code)
    except ProviderError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return {"connected": True, "account": _account_out(account).model_dump()}


class CallbackIn(BaseModel):
    code: str
    state: str


@router.post("/{provider}/callback-json", response_model=AccountOut)
def oauth_callback_json(provider: str, payload: CallbackIn,
                        ctx: AuthContext = Depends(require_csrf),
                        db: Session = Depends(get_db)) -> AccountOut:
    _validate_provider(provider)
    try:
        account = complete_connect(db, state=payload.state, code=payload.code)
    except ProviderError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _account_out(account)


def _get_owned(db: Session, account_id: str, ctx: AuthContext) -> IntegrationAccount:
    account = db.get(IntegrationAccount, account_id)
    if account is None or account.tenant_id != ctx.tenant_id or account.user_id != ctx.user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Integration account not found")
    return account


@router.get("/accounts/{account_id}", response_model=AccountOut)
def get_account(account_id: str, ctx: AuthContext = Depends(get_auth_context),
                db: Session = Depends(get_db)) -> AccountOut:
    return _account_out(_get_owned(db, account_id, ctx))


@router.post("/accounts/{account_id}/sync")
def sync_now(account_id: str, ctx: AuthContext = Depends(require_csrf),
             db: Session = Depends(get_db)) -> dict:
    account = _get_owned(db, account_id, ctx)
    result = sync_account(db, account)
    record_audit(db, action="integration.sync", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="integration_account", resource_id=account.id, detail=result)
    return {"account": _account_out(account).model_dump(), "result": result}


@router.post("/accounts/{account_id}/renew")
def renew_now(account_id: str, ctx: AuthContext = Depends(require_csrf),
              db: Session = Depends(get_db)) -> dict:
    account = _get_owned(db, account_id, ctx)
    result = renew_account(db, account)
    record_audit(db, action="integration.renew", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="integration_account", resource_id=account.id, detail=result)
    return {"account": _account_out(account).model_dump(), "result": result}


@router.post("/accounts/{account_id}/disconnect")
def disconnect_account(account_id: str, ctx: AuthContext = Depends(require_csrf),
                       db: Session = Depends(get_db)) -> dict:
    account = _get_owned(db, account_id, ctx)
    disconnect(db, account, user_id=ctx.user_id)
    return {"disconnected": True, "account": _account_out(account).model_dump()}


# --- Gmail Pub/Sub push ----------------------------------------------------

@router.post("/gmail/webhook")
async def gmail_webhook(request: Request, token: str | None = Query(default=None),
                        db: Session = Depends(get_db)) -> dict:
    """Receive a Google Pub/Sub push notification.

    Verification: when GOOGLE_PUBSUB_VERIFICATION_TOKEN is set, the push
    subscription must include it as a ``token`` query parameter. For stronger
    verification configure the push subscription with an OIDC service account
    and validate the bearer token (documented in docs/integrations.md).
    """
    if settings.google_pubsub_verification_token:
        if token != settings.google_pubsub_verification_token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid Pub/Sub verification token")
    body = await request.json()
    parsed = GmailProvider.parse_push(body)
    if not parsed:
        return {"accepted": False, "reason": "unparseable payload"}
    account = db.execute(
        select(IntegrationAccount).where(
            IntegrationAccount.provider == "gmail",
            IntegrationAccount.email_address == parsed["email"],
        )
    ).scalars().first()
    if account is None:
        # Unknown mailbox; acknowledge without action (do not leak existence).
        return {"accepted": False, "reason": "unknown mailbox"}
    dedup = f"gmail:{parsed.get('message_id') or parsed.get('history_id')}"
    event, created = record_integration_event(
        db, account=account, event_type="messageAdded", dedup_key=dedup,
        resource_id=parsed.get("history_id"), signature_verified=bool(settings.google_pubsub_verification_token),
        payload=parsed,
    )
    if not created:
        return {"accepted": True, "duplicate": True}
    result = sync_account(db, account)
    event.processed = True
    db.commit()
    return {"accepted": True, "sync": result}


# --- Outlook Graph change notifications -----------------------------------

@router.get("/outlook/webhook")
def outlook_validation(validationToken: str | None = Query(default=None)) -> PlainTextResponse:
    """Microsoft Graph subscription validation handshake."""
    if validationToken is not None:
        return PlainTextResponse(content=validationToken, status_code=200)
    return PlainTextResponse(content="ok", status_code=200)


@router.post("/outlook/webhook")
async def outlook_webhook(request: Request,
                          validationToken: str | None = Query(default=None),
                          db: Session = Depends(get_db)) -> Any:
    if validationToken is not None:
        return PlainTextResponse(content=validationToken, status_code=200)
    body = await request.json()
    expected_state = settings.ms_webhook_client_state
    if not expected_state:
        # Cannot verify -> reject rather than accept unverified notifications.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "MS_WEBHOOK_CLIENT_STATE not configured; cannot verify notifications")
    accepted = OutlookProvider.validate_notification(body, expected_state)
    results = []
    for note in accepted:
        account = db.execute(
            select(IntegrationAccount).where(
                IntegrationAccount.subscription_id == note["subscription_id"]
            )
        ).scalars().first()
        if account is None:
            results.append({"subscription_id": note["subscription_id"], "accepted": False,
                            "reason": "unknown subscription"})
            continue
        # Verify resource is the mailbox we subscribed for.
        expected_resource = "/me/mailFolders('inbox')/messages"
        resource_ok = expected_resource in (note.get("resource") or "")
        dedup = f"outlook:{note['subscription_id']}:{note.get('resource_data', {}).get('id', '')}"
        event, created = record_integration_event(
            db, account=account, event_type=note.get("change_type") or "notification",
            dedup_key=dedup, resource_id=note.get("resource"),
            signature_verified=True, payload=note,
        )
        if note.get("lifecycle_event"):
            account.last_error = f"lifecycle: {note['lifecycle_event']}"
            if note["lifecycle_event"] in {"reauthorizationRequired", "subscriptionRemoved"}:
                account.status = "needs_reauth"
            db.commit()
        if created and resource_ok:
            result = sync_account(db, account)
            event.processed = True
            db.commit()
            results.append({"subscription_id": note["subscription_id"], "accepted": True,
                            "sync": result})
        else:
            results.append({"subscription_id": note["subscription_id"], "accepted": True,
                            "duplicate": not created, "resource_verified": resource_ok})
    return {"processed": len(results), "results": results}
