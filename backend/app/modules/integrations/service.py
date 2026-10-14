"""Orchestration for email provider integrations.

Handles OAuth state, encrypted token storage, watch/subscription lifecycle,
idempotent synchronization, and analysis persistence. Detection only: messages
are never modified, moved, deleted, or answered.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.config import settings
from app.core.security import (
    decrypt_secret,
    encrypt_secret,
    sign_state,
    verify_state,
)
from app.models import EmailScan, IntegrationAccount, IntegrationEvent, OAuthState
from app.modules.email_security.analyzer import analyze_email
from app.modules.integrations.base import EmailProvider, ProviderError
from app.modules.integrations.mock import make_provider
from app.schemas import Severity
from app.services.alerts import create_alert
from app.services.scans import persist_detection

logger = logging.getLogger(__name__)

PROVIDER_STATES = {"connected", "monitoring", "degraded", "needs_reauth", "disconnected"}


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def is_mock(provider: str) -> bool:
    return provider.startswith("mock")


def begin_connect(db: Session, *, user, tenant_id: str, provider: str) -> str:
    # The nonce guarantees a unique state even for two connects in the same second.
    payload = f"{provider}:{user.id}:{tenant_id}:{uuid.uuid4().hex}"
    state = sign_state(payload, ttl_seconds=600)
    row = OAuthState(
        state=state,
        provider=provider,
        user_id=user.id,
        tenant_id=tenant_id,
        expires_at=_utcnow() + timedelta(minutes=10),
    )
    db.add(row)
    db.commit()
    prov = make_provider(provider)
    return prov.authorize_url(state)


def _consume_state(db: Session, state: str) -> OAuthState:
    valid, payload = verify_state(state)
    if not valid:
        raise ProviderError("invalid or expired OAuth state")
    row = db.execute(select(OAuthState).where(OAuthState.state == state)).scalar_one_or_none()
    if row is None or row.used:
        raise ProviderError("OAuth state already used or unknown (possible replay)")
    if _aware(row.expires_at) < _utcnow():
        raise ProviderError("OAuth state expired")
    row.used = True
    db.commit()
    return row


def complete_connect(db: Session, *, state: str, code: str) -> IntegrationAccount:
    row = _consume_state(db, state)
    provider = row.provider
    prov = make_provider(provider)
    bundle = prov.exchange_code(code)
    profile = prov.get_profile(bundle.access_token)

    account = db.execute(
        select(IntegrationAccount).where(
            IntegrationAccount.tenant_id == row.tenant_id,
            IntegrationAccount.user_id == row.user_id,
            IntegrationAccount.provider == provider,
            IntegrationAccount.email_address == profile.get("email", ""),
        )
    ).scalar_one_or_none()
    if account is None:
        account = IntegrationAccount(
            tenant_id=row.tenant_id,
            user_id=row.user_id,
            provider=provider,
            email_address=profile.get("email", ""),
        )
        db.add(account)

    account.external_account_id = profile.get("id", "")
    account.scopes = bundle.scope.split() if bundle.scope else []
    account.access_token_enc = encrypt_secret(bundle.access_token)
    account.refresh_token_enc = encrypt_secret(bundle.refresh_token)
    account.token_expires_at = bundle.expires_at()
    account.status = "connected"
    account.last_error = None
    db.commit()
    db.refresh(account)

    _activate_monitoring(db, account)
    record_audit(
        db,
        action="integration.connect",
        tenant_id=account.tenant_id,
        user_id=row.user_id,
        resource_type="integration_account",
        resource_id=account.id,
        detail={"provider": provider, "status": account.status, "mock": is_mock(provider)},
        commit=False,
    )
    db.commit()
    return account


def _activate_monitoring(db: Session, account: IntegrationAccount) -> None:
    """Start watch/subscription when the provider supports it and config exists."""
    prov = make_provider(account.provider)
    token = _access_token(account)
    if token is None:
        account.status = "connected"
        db.commit()
        return
    try:
        info = prov.start_watch(token)
        if account.provider in {"outlook", "mock_outlook"}:
            account.subscription_id = info.subscription_id
            account.subscription_expires_at = info.expiration
        else:
            account.watch_expiration = info.expiration
            account.history_id = info.history_id or account.history_id
        account.status = "monitoring"
        account.last_error = None
    except ProviderError as exc:
        # Cannot monitor (e.g. missing Pub/Sub topic / webhook URL). Stay honest.
        account.status = "connected"
        account.last_error = f"monitoring not active: {exc}"
        logger.info("Monitoring not activated for %s: %s", account.id, exc)
    db.commit()


def _access_token(account: IntegrationAccount) -> str | None:
    return decrypt_secret(account.access_token_enc)


def ensure_fresh_token(db: Session, account: IntegrationAccount) -> str:
    prov = make_provider(account.provider)
    exp = _aware(account.token_expires_at)
    token = _access_token(account)
    if token and exp and (exp - _utcnow()).total_seconds() > 120:
        return token
    refresh = decrypt_secret(account.refresh_token_enc)
    if not refresh:
        account.status = "needs_reauth"
        db.commit()
        raise ProviderError("no refresh token; reauthorization required", status=401)
    try:
        bundle = prov.refresh(refresh)
    except ProviderError:
        account.status = "needs_reauth"
        db.commit()
        raise
    account.access_token_enc = encrypt_secret(bundle.access_token)
    if bundle.refresh_token:
        account.refresh_token_enc = encrypt_secret(bundle.refresh_token)
    account.token_expires_at = bundle.expires_at()
    if account.status == "needs_reauth":
        account.status = "connected"
    db.commit()
    return bundle.access_token


def sync_account(db: Session, account: IntegrationAccount, max_messages: int = 25) -> dict:
    """Synchronize one account. Idempotent: duplicate messages are skipped."""
    if account.status in {"disconnected", "needs_reauth"}:
        return {"skipped": True, "reason": account.status}
    prov = make_provider(account.provider)
    try:
        token = ensure_fresh_token(db, account)
    except ProviderError as exc:
        account.last_error = str(exc)
        account.status = "needs_reauth"
        db.commit()
        return {"error": "needs_reauth"}

    cursor = account.delta_link if account.provider in {"outlook", "mock_outlook"} else account.history_id
    try:
        result = prov.sync(token, cursor)
    except ProviderError as exc:
        account.last_error = str(exc)
        account.status = "degraded"
        db.commit()
        return {"error": str(exc), "transient": exc.transient}

    if result.expired_cursor:
        # Reconcile from scratch after an expired history id / delta link.
        if account.provider in {"outlook", "mock_outlook"}:
            account.delta_link = None
        else:
            account.history_id = None
        account.last_error = "cursor expired; re-baselining"
        result = prov.sync(token, None)

    processed = 0
    duplicates = 0
    for msg in result.messages[:max_messages]:
        outcome = _process_message(db, account, prov, token, msg.id)
        if outcome == "processed":
            processed += 1
        elif outcome == "duplicate":
            duplicates += 1

    if account.provider in {"outlook", "mock_outlook"}:
        account.delta_link = result.new_cursor
    else:
        account.history_id = result.new_cursor
    account.last_sync_at = _utcnow()
    if account.status == "degraded":
        account.status = "monitoring" if (account.watch_expiration or account.subscription_id or is_mock(account.provider)) else "connected"
    elif account.status == "connected" and is_mock(account.provider):
        account.status = "monitoring"
    db.commit()
    return {"processed": processed, "duplicates": duplicates}


def _process_message(db: Session, account: IntegrationAccount, prov: EmailProvider,
                     token: str, message_id: str) -> str:
    if not message_id:
        return "skipped"
    existing = db.execute(
        select(EmailScan).where(
            EmailScan.tenant_id == account.tenant_id,
            EmailScan.provider == account.provider,
            EmailScan.message_id == message_id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return "duplicate"
    try:
        raw = prov.fetch_raw(token, message_id)
    except ProviderError as exc:
        logger.info("fetch_raw failed for %s: %s", message_id, exc)
        return "skipped"
    if not raw:
        return "skipped"

    result = analyze_email(raw)
    meta = result.metadata
    scan = persist_detection(
        db, tenant_id=account.tenant_id, user_id=account.user_id, result=result,
        source="integration", commit=False,
    )
    email_scan = EmailScan(
        tenant_id=account.tenant_id,
        account_id=account.id,
        provider=account.provider,
        message_id=message_id,
        from_addr=meta.get("from", ""),
        reply_to=meta.get("reply_to", ""),
        subject=meta.get("subject", ""),
        score=result.score,
        severity=str(result.severity),
        verdict=result.verdict,
        indicators={"evidence": [e.model_dump(mode="json") for e in result.evidence]},
    )
    db.add(email_scan)
    db.commit()

    if result.severity in (Severity.high, Severity.critical) or result.score >= 65:
        create_alert(
            db,
            tenant_id=account.tenant_id,
            source_module="email_security",
            rule_id="email.high_risk_message",
            title=f"High-risk email from {meta.get('from','unknown')}",
            severity=str(result.severity),
            category="phishing",
            asset=account.email_address,
            evidence={"email_scan_id": email_scan.id, "scan_id": scan.id, "score": result.score},
            dedup_key=f"email:{account.provider}:{message_id}",
            scan_id=scan.id,
        )
    return "processed"


def renew_account(db: Session, account: IntegrationAccount) -> dict:
    if account.status in {"disconnected", "needs_reauth"}:
        return {"renewed": False, "reason": account.status}
    prov = make_provider(account.provider)
    try:
        token = ensure_fresh_token(db, account)
    except ProviderError:
        return {"renewed": False, "reason": "needs_reauth"}
    try:
        if account.provider in {"outlook", "mock_outlook"}:
            if not account.subscription_id:
                info = prov.start_watch(token)
                account.subscription_id = info.subscription_id
            else:
                info = prov.renew_subscription(
                    token, account.subscription_id,
                    f"{settings.public_webhook_base_url.rstrip('/')}/api/v1/integrations/outlook/webhook"
                    if settings.public_webhook_base_url else "",
                )
            account.subscription_expires_at = info.expiration
        else:
            info = prov.start_watch(token)
            account.watch_expiration = info.expiration
            if info.history_id:
                account.history_id = info.history_id
        account.status = "monitoring"
        account.last_error = None
        db.commit()
        return {"renewed": True, "expiration": info.expiration}
    except ProviderError as exc:
        account.status = "degraded"
        account.last_error = str(exc)
        db.commit()
        return {"renewed": False, "reason": str(exc)}


def disconnect(db: Session, account: IntegrationAccount, *, user_id: str | None = None) -> None:
    prov = make_provider(account.provider)
    token = _access_token(account)
    if token:
        try:
            prov.stop_watch(token)
        except Exception:  # pragma: no cover - best effort
            pass
        try:
            prov.revoke(decrypt_secret(account.refresh_token_enc) or token)
        except Exception:  # pragma: no cover - best effort
            pass
    account.access_token_enc = None
    account.refresh_token_enc = None
    account.client_state = None
    account.status = "disconnected"
    account.watch_expiration = None
    account.subscription_id = None
    account.subscription_expires_at = None
    record_audit(
        db, action="integration.disconnect", tenant_id=account.tenant_id,
        user_id=user_id, resource_type="integration_account", resource_id=account.id,
        detail={"provider": account.provider}, commit=False,
    )
    db.commit()


def record_integration_event(
    db: Session, *, account: IntegrationAccount, event_type: str, dedup_key: str,
    resource_id: str | None = None, signature_verified: bool = False, payload: dict | None = None,
) -> tuple[IntegrationEvent, bool]:
    existing = db.execute(
        select(IntegrationEvent).where(IntegrationEvent.dedup_key == dedup_key)
    ).scalar_one_or_none()
    if existing is not None:
        return existing, False
    event = IntegrationEvent(
        account_id=account.id,
        tenant_id=account.tenant_id,
        provider=account.provider,
        event_type=event_type,
        resource_id=resource_id,
        dedup_key=dedup_key,
        signature_verified=signature_verified,
        payload=payload or {},
    )
    db.add(event)
    db.commit()
    return event, True


def derive_status(account: IntegrationAccount) -> dict:
    """Compute the user-visible integration state without overstating it."""
    now = _utcnow()
    has_tokens = bool(account.access_token_enc or account.refresh_token_enc)
    watch_exp = _aware(account.watch_expiration or account.subscription_expires_at)
    monitoring = account.status == "monitoring"
    if not has_tokens or account.status == "disconnected":
        state = "disconnected"
    elif account.status == "needs_reauth":
        state = "needs_reauth"
    elif account.status == "degraded":
        state = "degraded"
    elif monitoring and (watch_exp is None or watch_exp > now):
        state = "monitoring"
    else:
        state = "connected"
    return {
        "state": state,
        "last_sync_at": account.last_sync_at,
        "watch_expires_at": account.watch_expiration,
        "subscription_expires_at": account.subscription_expires_at,
        "subscription_id": account.subscription_id,
        "last_error": account.last_error,
        "mock": is_mock(account.provider),
        "monitoring_active": state == "monitoring",
    }
