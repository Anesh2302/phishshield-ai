"""Provider-agnostic interface and shared data types for email integrations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class TokenBundle:
    access_token: str
    refresh_token: str | None = None
    expires_in: int = 3600
    scope: str = ""

    def expires_at(self, now: datetime | None = None) -> datetime:

        base = now or datetime.now(UTC)
        from datetime import timedelta

        return base + timedelta(seconds=self.expires_in)


@dataclass
class RemoteMessage:
    id: str
    thread_id: str | None = None
    raw: str | None = None  # RFC822 text, when fetched
    from_addr: str = ""
    subject: str = ""


@dataclass
class WatchInfo:
    expiration: datetime | None = None
    history_id: str | None = None
    subscription_id: str | None = None


@dataclass
class SyncResult:
    messages: list[RemoteMessage] = field(default_factory=list)
    new_cursor: str | None = None
    expired_cursor: bool = False
    more: bool = False


class EmailProvider:
    """Interface implemented by real and mock providers."""

    name: str = "generic"

    def authorize_url(self, state: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def exchange_code(self, code: str) -> TokenBundle:  # pragma: no cover
        raise NotImplementedError

    def refresh(self, refresh_token: str) -> TokenBundle:  # pragma: no cover
        raise NotImplementedError

    def revoke(self, token: str) -> bool:  # pragma: no cover
        raise NotImplementedError

    def get_profile(self, access_token: str) -> dict:  # pragma: no cover
        raise NotImplementedError

    def start_watch(self, access_token: str) -> WatchInfo:  # pragma: no cover
        raise NotImplementedError

    def stop_watch(self, access_token: str) -> None:  # pragma: no cover
        return None

    def sync(self, access_token: str, cursor: str | None) -> SyncResult:  # pragma: no cover
        raise NotImplementedError

    def fetch_raw(self, access_token: str, message_id: str) -> str | None:  # pragma: no cover
        raise NotImplementedError

    def subscribe(self, access_token: str, webhook_url: str) -> WatchInfo:  # pragma: no cover
        raise NotImplementedError

    def renew_subscription(self, access_token: str, subscription_id: str, webhook_url: str) -> WatchInfo:
        return self.subscribe(access_token, webhook_url)


class ProviderError(Exception):
    def __init__(self, message: str, *, status: int | None = None, transient: bool = False):
        super().__init__(message)
        self.status = status
        self.transient = transient
