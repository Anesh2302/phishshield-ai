"""Structured logging with secret and sensitive-content redaction.

The redaction filter is applied to every log record. It removes common
credential material (bearer tokens, cookies, passwords, API keys, OAuth
codes/state) and truncates obvious long secret-looking blobs. This is a
defence-in-depth measure: application code must still avoid logging secrets.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

REDACTED = "***REDACTED***"

# Keys whose values are always redacted (case-insensitive, matched as substrings).
_SENSITIVE_KEY_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "set-cookie",
    "client_secret",
    "refresh_token",
    "access_token",
    "code",
    "state",
    "client_state",
    "mfa",
    "otp",
    "private_key",
    "session",
)

_PATTERNS = [
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer " + REDACTED),
    (re.compile(r"(?i)(authorization|cookie|set-cookie)\s*[:=]\s*[^\s,;]+"), r"\1: " + REDACTED),
    (re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[^\s,;&\"']+"), r"\1=" + REDACTED),
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), REDACTED),  # JWT
    (re.compile(r"\b[A-Za-z0-9_\-]{40,}\b"), lambda m: m.group(0)[:6] + "..." + REDACTED),
]


def redact_text(value: str) -> str:
    if not value:
        return value
    out = value
    for pattern, repl in _PATTERNS:
        out = pattern.sub(repl, out)
    return out


def _redact_obj(obj: Any, depth: int = 0) -> Any:
    if depth > 6:
        return REDACTED
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if isinstance(k, str) and any(h in k.lower() for h in _SENSITIVE_KEY_HINTS):
                result[k] = REDACTED
            else:
                result[k] = _redact_obj(v, depth + 1)
        return result
    if isinstance(obj, (list, tuple)):
        return [_redact_obj(v, depth + 1) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = redact_text(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = _redact_obj(record.args)
                else:
                    record.args = tuple(
                        _redact_obj(a) if isinstance(a, (str, dict, list)) else a
                        for a in record.args
                    )
            if getattr(record, "extra_data", None):
                record.extra_data = _redact_obj(record.extra_data)
        except Exception:  # never let logging break the request
            pass
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("request_id", "user_id", "tenant_id", "path", "method", "status"):
            val = getattr(record, key, None)
            if val is not None:
                payload[key] = val
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(_redact_obj(payload), default=str)


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(RedactionFilter())
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
    root.addHandler(handler)
    # Reduce noise from third-party libraries.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
