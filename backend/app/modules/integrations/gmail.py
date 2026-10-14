"""Gmail integration using the official Google OAuth 2.0 and Gmail APIs.

Least-privilege scopes: gmail.readonly (read messages + history) plus openid and
email to identify the account. No send, modify, or delete scopes are requested.
Nothing is ever sent, deleted, moved, or replied to.
"""

from __future__ import annotations

import base64
import json
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

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GMAIL_API = "https://gmail.googleapis.com/gmail/v1"

SCOPES = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/gmail.readonly",
]


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


class GmailProvider(EmailProvider):
    name = "gmail"

    def __init__(self, client: httpx.Client | None = None):
        self._client = client

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=15.0)
        return self._client

    def authorize_url(self, state: str) -> str:
        params = {
            "client_id": settings.google_client_id,
            "redirect_uri": settings.google_oauth_redirect_uri,
            "response_type": "code",
            "scope": " ".join(SCOPES),
            "access_type": "offline",
            "include_granted_scopes": "true",
            "prompt": "consent",
            "state": state,
        }
        return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"

    def exchange_code(self, code: str) -> TokenBundle:
        resp = self._http().post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": settings.google_oauth_redirect_uri,
            },
        )
        if resp.status_code != 200:
            raise ProviderError(f"token exchange failed: {resp.status_code}", status=resp.status_code)
        return self._to_bundle(resp.json())

    def refresh(self, refresh_token: str) -> TokenBundle:
        resp = self._http().post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
        )
        if resp.status_code in (400, 401):
            raise ProviderError("refresh token rejected; reauthorization required",
                                status=resp.status_code)
        if resp.status_code != 200:
            raise ProviderError(f"refresh failed: {resp.status_code}", status=resp.status_code)
        bundle = self._to_bundle(resp.json())
        bundle.refresh_token = refresh_token
        return bundle

    def revoke(self, token: str) -> bool:
        resp = self._http().post(GOOGLE_REVOKE_URL, data={"token": token})
        return resp.status_code == 200

    def _to_bundle(self, data: dict) -> TokenBundle:
        return TokenBundle(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            expires_in=int(data.get("expires_in", 3600)),
            scope=data.get("scope", " ".join(SCOPES)),
        )

    def get_profile(self, access_token: str) -> dict:
        resp = self._http().get(
            f"{GMAIL_API}/users/me/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status_code != 200:
            raise ProviderError(f"profile fetch failed: {resp.status_code}", status=resp.status_code)
        body = resp.json()
        return {"email": body.get("emailAddress", ""), "id": body.get("emailAddress", "")}

    def start_watch(self, access_token: str) -> WatchInfo:
        if not settings.google_pubsub_topic:
            raise ProviderError("GOOGLE_PUBSUB_TOPIC is not configured", transient=False)
        resp = self._http().post(
            f"{GMAIL_API}/users/me/watch",
            headers={"Authorization": f"Bearer {access_token}"},
            json={"topicName": settings.google_pubsub_topic, "labelIds": ["INBOX"]},
        )
        if resp.status_code != 200:
            raise ProviderError(f"watch failed: {resp.status_code}", status=resp.status_code,
                                transient=resp.status_code >= 500)
        body = resp.json()
        exp_ms = int(body.get("expiration", 0))
        expiration = datetime.fromtimestamp(exp_ms / 1000, tz=UTC) if exp_ms else None
        return WatchInfo(expiration=expiration, history_id=str(body.get("historyId", "")) or None)

    def stop_watch(self, access_token: str) -> None:
        try:
            self._http().post(
                f"{GMAIL_API}/users/me/stop",
                headers={"Authorization": f"Bearer {access_token}"},
                json={},
            )
        except Exception as exc:  # pragma: no cover - best effort
            logger.info("gmail stop watch failed: %s", exc)

    def sync(self, access_token: str, cursor: str | None) -> SyncResult:
        headers = {"Authorization": f"Bearer {access_token}"}
        if not cursor:
            # Establish a baseline cursor from the current history id.
            prof = self._http().get(f"{GMAIL_API}/users/me/profile", headers=headers)
            if prof.status_code != 200:
                raise ProviderError("profile fetch failed during sync", status=prof.status_code)
            return SyncResult(messages=[], new_cursor=str(prof.json().get("historyId", "")))
        resp = self._http().get(
            f"{GMAIL_API}/users/me/history",
            headers=headers,
            params={"startHistoryId": cursor, "historyTypes": "messageAdded"},
        )
        if resp.status_code == 404:
            # Expired/invalid history id: caller must reconcile from scratch.
            return SyncResult(expired_cursor=True)
        if resp.status_code == 429:
            raise ProviderError("gmail rate limited", status=429, transient=True)
        if resp.status_code != 200:
            raise ProviderError(f"history fetch failed: {resp.status_code}", status=resp.status_code,
                                transient=resp.status_code >= 500)
        body = resp.json()
        messages: list[RemoteMessage] = []
        seen: set[str] = set()
        for record in body.get("history", []) or []:
            for added in record.get("messagesAdded", []) or []:
                mid = added.get("message", {}).get("id")
                if mid and mid not in seen:
                    seen.add(mid)
                    messages.append(RemoteMessage(id=mid, thread_id=added.get("message", {}).get("threadId")))
        return SyncResult(
            messages=messages,
            new_cursor=str(body.get("historyId", cursor)),
            more=bool(body.get("nextPageToken")),
        )

    def fetch_raw(self, access_token: str, message_id: str) -> str | None:
        resp = self._http().get(
            f"{GMAIL_API}/users/me/messages/{message_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"format": "raw"},
        )
        if resp.status_code != 200:
            raise ProviderError(f"message fetch failed: {resp.status_code}", status=resp.status_code)
        raw = resp.json().get("raw")
        if not raw:
            return None
        return _b64url_decode(raw).decode("utf-8", errors="replace")

    def subscribe(self, access_token: str, webhook_url: str) -> WatchInfo:
        return self.start_watch(access_token)

    @staticmethod
    def parse_push(payload: dict) -> dict | None:
        """Decode a Google Pub/Sub push envelope into {email, historyId}."""
        try:
            data = payload.get("message", {}).get("data")
            if not data:
                return None
            decoded = json.loads(_b64url_decode(data).decode("utf-8"))
            return {
                "email": decoded.get("emailAddress", ""),
                "history_id": str(decoded.get("historyId", "")) or None,
                "publish_time": payload.get("message", {}).get("publishTime"),
                "message_id": payload.get("message", {}).get("messageId"),
            }
        except Exception:
            return None


def watch_renewal_due(expiration: datetime | None, now: datetime | None = None) -> bool:
    """Gmail watches last up to 7 days; renew with a safety margin."""
    if expiration is None:
        return True
    now = now or datetime.now(UTC)
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=UTC)
    return expiration - now < timedelta(hours=12)
