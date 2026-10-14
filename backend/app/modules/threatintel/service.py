"""Optional threat-intelligence lookups.

Design principles:
* Lookups are optional and configurable. When a provider is not configured the
  service reports ``not_configured`` rather than guessing.
* Absence from a feed is NOT evidence that a URL is safe.
* Results are cached in-process for a bounded TTL to respect provider terms.
* Credentials live only on the backend and are never sent to the client.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 900
MAX_CACHE_ENTRIES = 5000


@dataclass
class ProviderResult:
    provider: str
    status: str  # hit|clean|not_configured|unavailable|error
    detail: dict = field(default_factory=dict)


@dataclass
class ThreatIntelResult:
    url: str
    providers: list[ProviderResult] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    any_hit: bool = False

    @property
    def available(self) -> bool:
        return any(p.status in {"hit", "clean"} for p in self.providers)


class _TTLCache:
    def __init__(self, ttl: int, max_entries: int):
        self.ttl = ttl
        self.max_entries = max_entries
        self._data: dict[str, tuple[float, object]] = {}

    def get(self, key: str):
        item = self._data.get(key)
        if not item:
            return None
        ts, value = item
        if time.time() - ts > self.ttl:
            self._data.pop(key, None)
            return None
        return value

    def set(self, key: str, value) -> None:
        if len(self._data) >= self.max_entries:
            oldest = min(self._data.items(), key=lambda kv: kv[1][0])[0]
            self._data.pop(oldest, None)
        self._data[key] = (time.time(), value)

    def clear(self) -> None:
        self._data.clear()


class ThreatIntelService:
    def __init__(self, client: httpx.Client | None = None):
        self._client = client
        self._cache = _TTLCache(CACHE_TTL_SECONDS, MAX_CACHE_ENTRIES)
        self._own_client = client is None

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=6.0, follow_redirects=False)
        return self._client

    def close(self) -> None:
        if self._client is not None and self._own_client:
            self._client.close()
            self._client = None

    def urlhaus_lookup(self, url: str) -> ProviderResult:
        if not settings.urlhaus_enabled:
            return ProviderResult("urlhaus", "not_configured")
        cached = self._cache.get(f"urlhaus:{url}")
        if cached is not None:
            return cached
        try:
            resp = self._http().post(
                "https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}
            )
            if resp.status_code != 200:
                result = ProviderResult("urlhaus", "unavailable", {"http_status": resp.status_code})
            else:
                body = resp.json()
                status = body.get("query_status")
                if status == "ok":
                    result = ProviderResult(
                        "urlhaus",
                        "hit",
                        {
                            "threat": body.get("threat"),
                            "tags": body.get("tags"),
                            "date_added": body.get("date_added"),
                            "url_status": body.get("url_status"),
                        },
                    )
                elif status == "no_results":
                    result = ProviderResult("urlhaus", "clean")
                else:
                    result = ProviderResult("urlhaus", "unavailable", {"query_status": status})
        except Exception as exc:
            logger.info("urlhaus lookup failed: %s", exc)
            result = ProviderResult("urlhaus", "error", {"error": str(exc)[:200]})
        self._cache.set(f"urlhaus:{url}", result)
        return result

    def virustotal_lookup(self, url: str) -> ProviderResult:
        if not (settings.threatintel_enabled and settings.virustotal_api_key):
            return ProviderResult("virustotal", "not_configured")
        cached = self._cache.get(f"vt:{url}")
        if cached is not None:
            return cached
        try:
            import base64

            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            resp = self._http().get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
            if resp.status_code == 200:
                stats = (
                    resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                result = ProviderResult(
                    "virustotal",
                    "hit" if malicious else "clean",
                    {"malicious": malicious, "stats": stats},
                )
            elif resp.status_code == 404:
                result = ProviderResult("virustotal", "clean", {"note": "no report"})
            else:
                result = ProviderResult("virustotal", "unavailable", {"http_status": resp.status_code})
        except Exception as exc:
            result = ProviderResult("virustotal", "error", {"error": str(exc)[:200]})
        self._cache.set(f"vt:{url}", result)
        return result

    def lookup(self, url: str) -> ThreatIntelResult:
        result = ThreatIntelResult(url=url)
        for fn in (self.urlhaus_lookup, self.virustotal_lookup):
            pr = fn(url)
            result.providers.append(pr)
            if pr.status == "hit":
                result.any_hit = True
                result.indicators.append(f"{pr.provider}:{pr.detail.get('threat', 'malicious')}")
        return result


_service: ThreatIntelService | None = None


def get_threatintel() -> ThreatIntelService:
    global _service
    if _service is None:
        _service = ThreatIntelService()
    return _service
