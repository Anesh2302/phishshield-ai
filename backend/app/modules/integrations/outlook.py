"""Microsoft Outlook integration via the Microsoft identity platform and
Microsoft Graph (delegated permissions).

Scopes: offline_access, openid, email, Mail.Read. Mail.Read is the minimum
delegated scope that allows reading message bodies; Mail.ReadBasic (headers
only) is documented as the alternative when body analysis is not required.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import httpx

from app.core.config import settings
from app.modules.integrations.base import (
    EmailProvider,
    ProviderError,
    RemoteMessage,
    SyncResult,
    TokenBundle,
    WatchInfo,
)

logger = logging.getLogger(__name__)

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPES = ["offline_access", "openid", "email", "Mail.Read"]
# Microsoft caps message subscriptions at 4230 minutes (~70.5 hours).
SUBSCRIPTION_MINUTES = 4230
RENEW_MARGIN_MINUTES = 60


def _authority() -> str:
    tenant = settings.ms_tenant_id or "common"
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"


class OutlookProvider(EmailProvider):
    name = "outlook"

    def __init__(self, client: httpx.Client | None = None):
        self._client = client

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=15.0)
        return self._client

    def authorize_url(self, state: str) -> str:
        params = {
            "client_id": settings.ms_client_id,
            "response_type": "code",
            "redirect_uri": settings.ms_oauth_redirect_uri,
            "response_mode": "query",
            "scope": " ".join(SCOPES),
            "state": state,
        }
        return f"{_authority()}/authorize?{urlencode(params)}"

    def exchange_code(self, code: str) -> TokenBundle:
        resp = self._http().post(
            f"{_authority()}/token",
            data={
                "client_id": settings.ms_client_id,
                "client_secret": settings.ms_client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": settings.ms_oauth_redirect_uri,
                "scope": " ".join(SCOPES),
            },
        )
        if resp.status_code != 200:
            raise ProviderError(f"token exchange failed: {resp.status_code}", status=resp.status_code)
        return self._to_bundle(resp.json())

    def refresh(self, refresh_token: str) -> TokenBundle:
        resp = self._http().post(
            f"{_authority()}/token",
            data={
                "client_id": settings.ms_client_id,
                "client_secret": settings.ms_client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
                "scope": " ".join(SCOPES),
            },
        )
        if resp.status_code in (400, 401):
            raise ProviderError("refresh token rejected; reauthorization required",
                                status=resp.status_code)
        if resp.status_code != 200:
            raise ProviderError(f"refresh failed: {resp.status_code}", status=resp.status_code)
        bundle = self._to_bundle(resp.json())
        bundle.refresh_token = resp.json().get("refresh_token", refresh_token)
        return bundle

    def revoke(self, token: str) -> bool:
        # Microsoft does not offer a token revocation endpoint for public clients;
        # deleting stored tokens client-side is the supported disconnect path.
        return True

    def _to_bundle(self, data: dict) -> TokenBundle:
        return TokenBundle(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            expires_in=int(data.get("expires_in", 3600)),
            scope=data.get("scope", " ".join(SCOPES)),
        )

    def get_profile(self, access_token: str) -> dict:
        resp = self._http().get(
            f"{GRAPH}/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status_code != 200:
            raise ProviderError(f"profile fetch failed: {resp.status_code}", status=resp.status_code)
        body = resp.json()
        email = body.get("mail") or body.get("userPrincipalName") or ""
        return {"email": email, "id": body.get("id", "")}

    def subscribe(self, access_token: str, webhook_url: str) -> WatchInfo:
        expiration = datetime.now(UTC) + timedelta(
            minutes=SUBSCRIPTION_MINUTES - RENEW_MARGIN_MINUTES
        )
        body = {
            "changeType": "created",
            "notificationUrl": webhook_url,
            "resource": "/me/mailFolders('inbox')/messages",
            "expirationDateTime": expiration.isoformat().replace("+00:00", "Z"),
            "clientState": settings.ms_webhook_client_state,
        }
        resp = self._http().post(
            f"{GRAPH}/subscriptions",
            headers={"Authorization": f"Bearer {access_token}"},
            json=body,
        )
        if resp.status_code not in (200, 201):
            raise ProviderError(f"subscribe failed: {resp.status_code}: {resp.text[:200]}",
                                status=resp.status_code, transient=resp.status_code == 429)
        data = resp.json()
        exp = _parse_dt(data.get("expirationDateTime"))
        return WatchInfo(expiration=exp, subscription_id=data.get("id"))

    def renew_subscription(self, access_token: str, subscription_id: str, webhook_url: str) -> WatchInfo:
        expiration = datetime.now(UTC) + timedelta(
            minutes=SUBSCRIPTION_MINUTES - RENEW_MARGIN_MINUTES
        )
        resp = self._http().patch(
            f"{GRAPH}/subscriptions/{subscription_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            json={"expirationDateTime": expiration.isoformat().replace("+00:00", "Z")},
        )
        if resp.status_code != 200:
            raise ProviderError(f"renew failed: {resp.status_code}", status=resp.status_code,
                                transient=resp.status_code == 429)
        return WatchInfo(expiration=expiration, subscription_id=subscription_id)

    def start_watch(self, access_token: str) -> WatchInfo:
        if not settings.public_webhook_base_url:
            raise ProviderError("PUBLIC_WEBHOOK_BASE_URL is not configured")
        webhook = f"{settings.public_webhook_base_url.rstrip('/')}/api/v1/integrations/outlook/webhook"
        return self.subscribe(access_token, webhook)

    def sync(self, access_token: str, cursor: str | None) -> SyncResult:
        headers = {"Authorization": f"Bearer {access_token}"}
        url = cursor or f"{GRAPH}/me/mailFolders/inbox/messages/delta"
        params = None
        if cursor:
            params = None  # deltaLink already carries query parameters
        resp = self._http().get(url, headers=headers, params=params)
        if resp.status_code == 410:
            return SyncResult(expired_cursor=True)
        if resp.status_code == 429:
            raise ProviderError("graph throttled", status=429, transient=True)
        if resp.status_code != 200:
            raise ProviderError(f"delta failed: {resp.status_code}", status=resp.status_code,
                                transient=resp.status_code >= 500)
        body = resp.json()
        messages: list[RemoteMessage] = []
        for item in body.get("value", []) or []:
            if item.get("@removed"):
                continue
            messages.append(
                RemoteMessage(
                    id=item.get("id", ""),
                    thread_id=item.get("conversationId"),
                    from_addr=(item.get("from", {}) or {}).get("emailAddress", {}).get("address", ""),
                    subject=item.get("subject", "") or "",
                )
            )
        new_cursor = body.get("@odata.deltaLink") or body.get("@odata.nextLink") or cursor
        return SyncResult(
            messages=messages,
            new_cursor=new_cursor,
            more=bool(body.get("@odata.nextLink")),
        )

    def fetch_raw(self, access_token: str, message_id: str) -> str | None:
        resp = self._http().get(
            f"{GRAPH}/me/messages/{message_id}/$value",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status_code != 200:
            raise ProviderError(f"message fetch failed: {resp.status_code}", status=resp.status_code)
        return resp.text

    @staticmethod
    def validate_notification(payload: dict, expected_client_state: str) -> list[dict]:
        """Return accepted notification notifications with verified clientState.

        Notifications whose clientState does not match are dropped. Unknown
        subscription/resource associations are reported by the caller.
        """
        accepted: list[dict] = []
        for note in payload.get("value", []) or []:
            if note.get("clientState") != expected_client_state:
                continue
            accepted.append(
                {
                    "subscription_id": note.get("subscriptionId"),
                    "change_type": note.get("changeType"),
                    "resource": note.get("resource"),
                    "resource_data": note.get("resourceData", {}) or {},
                    "tenant_id": note.get("tenantId"),
                    "lifecycle_event": note.get("lifecycleEvent"),
                }
            )
        return accepted


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def renewal_due(expiration: datetime | None, now: datetime | None = None) -> bool:
    if expiration is None:
        return True
    now = now or datetime.now(UTC)
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=UTC)
    return expiration - now < timedelta(minutes=RENEW_MARGIN_MINUTES)
