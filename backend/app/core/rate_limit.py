"""Fixed-window rate limiting.

This implementation is process-local (in-memory). It is correct for a single
API process and for the test suite. For horizontally scaled production
deployments replace ``_STORE`` with a shared backend (e.g. Redis) behind the
same ``check`` interface; this limitation is documented in docs/security-model.md.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

from fastapi import HTTPException, Request, status


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self._store: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> list[float]:
        cutoff = now - self.window
        hits = [t for t in self._store[key] if t >= cutoff]
        self._store[key] = hits
        return hits

    def check(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._prune(key, now)
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._store.clear()


def client_ip(request: Request) -> str:
    # Trust X-Forwarded-For only when a trusted proxy is configured; here we use
    # the direct peer to avoid spoofable rate-limit bypass.
    return request.client.host if request.client else "unknown"


def rate_limit_dependency(limiter: RateLimiter):
    def _dep(request: Request) -> None:
        key = f"{client_ip(request)}:{request.url.path}"
        if not limiter.check(key):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")

    return _dep
