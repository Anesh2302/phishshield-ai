"""Mock email providers for local development and tests.

These are ONLY used when MOCK_PROVIDERS=1. They are clearly labelled in the API
as mock accounts and must never be enabled in production. They exist so the full
integration lifecycle (OAuth state, token storage, watch/subscription, sync,
webhook handling, retries, disconnect) can be exercised without external
credentials.
"""

from __future__ import annotations

import itertools
import threading
from datetime import UTC, datetime, timedelta

from app.modules.integrations.base import (
    EmailProvider,
    ProviderError,
    RemoteMessage,
    SyncResult,
    TokenBundle,
    WatchInfo,
)

_counter = itertools.count(1)


class MockEmailProvider(EmailProvider):
    def __init__(self, name: str = "mock"):
        self.name = name
        self._lock = threading.Lock()
        # Per-access-token state.
        self.revoked_tokens: set[str] = set()
        self.fail_refresh = False
        self.watch_calls = 0
        self.subscription_calls = 0
        self._queued: dict[str, list[str]] = {}
        self._raw: dict[str, str] = {}
        self.expire_cursor_once = False
        self.rate_limit_once = False
        self._cursor_seq = 1000

    # --- helpers used by tests -------------------------------------------
    def queue_message(self, access_token: str, message_id: str, raw: str) -> None:
        with self._lock:
            self._queued.setdefault(access_token, []).append(message_id)
            self._raw[message_id] = raw

    def _email_for(self, code: str) -> str:
        return code if "@" in code else f"mock-{code}@example.test"

    # --- interface --------------------------------------------------------
    def authorize_url(self, state: str) -> str:
        return f"https://mock.{self.name}.test/oauth?state={state}"

    def exchange_code(self, code: str) -> TokenBundle:
        if code == "invalid":
            raise ProviderError("invalid grant", status=400)
        return TokenBundle(
            access_token=f"{self.name}-access-{next(_counter)}",
            refresh_token=f"{self.name}-refresh-{code}",
            expires_in=3600,
            scope="mock.readonly",
        )

    def refresh(self, refresh_token: str) -> TokenBundle:
        if self.fail_refresh:
            raise ProviderError("refresh token rejected; reauthorization required", status=400)
        if "refresh-invalid" in refresh_token:
            raise ProviderError("refresh token rejected", status=400)
        return TokenBundle(
            access_token=f"{self.name}-access-{next(_counter)}",
            refresh_token=refresh_token,
            expires_in=3600,
            scope="mock.readonly",
        )

    def revoke(self, token: str) -> bool:
        with self._lock:
            self.revoked_tokens.add(token)
        return True

    def get_profile(self, access_token: str) -> dict:
        if access_token in self.revoked_tokens:
            raise ProviderError("token revoked", status=401)
        return {"email": f"user@{self.name}.example.test", "id": access_token}

    def start_watch(self, access_token: str) -> WatchInfo:
        self.watch_calls += 1
        return WatchInfo(
            expiration=datetime.now(UTC) + timedelta(days=7),
            history_id=str(self._cursor_seq),
        )

    def stop_watch(self, access_token: str) -> None:
        return None

    def subscribe(self, access_token: str, webhook_url: str) -> WatchInfo:
        self.subscription_calls += 1
        sub_id = f"mock-sub-{next(_counter)}"
        return WatchInfo(
            expiration=datetime.now(UTC) + timedelta(hours=48),
            subscription_id=sub_id,
        )

    def renew_subscription(self, access_token: str, subscription_id: str, webhook_url: str) -> WatchInfo:
        self.subscription_calls += 1
        return WatchInfo(
            expiration=datetime.now(UTC) + timedelta(hours=48),
            subscription_id=subscription_id,
        )

    def sync(self, access_token: str, cursor: str | None) -> SyncResult:
        if self.rate_limit_once:
            self.rate_limit_once = False
            raise ProviderError("throttled", status=429, transient=True)
        if self.expire_cursor_once and cursor:
            self.expire_cursor_once = False
            return SyncResult(expired_cursor=True)
        self._cursor_seq += 1
        if cursor is None:
            return SyncResult(messages=[], new_cursor=str(self._cursor_seq))
        ids = self._queued.pop(access_token, [])
        msgs = [RemoteMessage(id=mid) for mid in ids]
        return SyncResult(messages=msgs, new_cursor=str(self._cursor_seq))

    def fetch_raw(self, access_token: str, message_id: str) -> str | None:
        return self._raw.get(message_id)


def make_provider(provider: str, *, client=None) -> EmailProvider:
    """Factory used by the service layer."""
    from app.modules.integrations.gmail import GmailProvider
    from app.modules.integrations.outlook import OutlookProvider

    if provider in {"mock_gmail", "mock_outlook", "mock"}:
        return _mock_registry.setdefault(provider, MockEmailProvider(provider))
    if provider == "gmail":
        return GmailProvider(client)
    if provider == "outlook":
        return OutlookProvider(client)
    raise ValueError(f"Unknown provider '{provider}'")


_mock_registry: dict[str, MockEmailProvider] = {}


def get_mock(provider: str) -> MockEmailProvider:
    return _mock_registry.setdefault(provider, MockEmailProvider(provider))


def reset_mocks() -> None:
    _mock_registry.clear()
