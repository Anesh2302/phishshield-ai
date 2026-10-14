# Security Model

PhishShield AI is built defensively and is intended to *observe and report*. This document
describes the controls that are implemented, where they live in the code, and the honest
limitations.

## 1. Authentication

- **Passwords** are hashed with bcrypt (cost 12). Inputs are truncated to bcrypt's 72-byte limit
  before hashing (`app/core/security.py`).
- **Sessions** are opaque random tokens (`secrets.token_urlsafe(48)`). Only the **SHA-256 hash**
  of the token is stored (`UserSession.token_hash`); the raw token lives only in the client cookie
  (or is handed to Bearer clients). Sessions carry an expiry (`SESSION_TTL_MINUTES`) and can be
  listed and revoked.
- **Bootstrap** creates the initial `owner` and is only permitted while the instance has **no
  users** (`GET /auth/bootstrap-status` reports the state).
- **MFA**: TOTP (RFC 6238, SHA-1/6-digit/30s with ±1 step window) can be enrolled per user.
  Secrets are generated server-side; the provisioning URI is returned for authenticator apps.
- **Roles**: `viewer < analyst < admin < owner`, enforced by `require_role(minimum)`.

## 2. Session transport & CSRF

- The session cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` when `COOKIE_SECURE=1`.
- **CSRF**: state-changing requests that authenticate via the **cookie** must send
  `X-CSRF-Token`, an HMAC over the server-side session id keyed by `SECRET_KEY`, compared in
  constant time (`verify_csrf_token`). Because the value is derived from server-side state and the
  request must already carry the cookie, an attacker on another origin cannot forge it.
  Bearer-token clients are exempt (they don't ride ambient browser credentials).

## 3. Authorization & tenant isolation

- Every tenant-scoped model carries `tenant_id`; queries are constrained via `tenant_scope()`
  (`app/core/deps.py`). Cross-tenant identifiers resolve to **404**, not 403, to avoid existence
  disclosure.
- Privileged actions (user creation, integration changes, destructive deletes) require
  `admin`/`owner`.

## 4. Secrets & token protection

- OAuth refresh/access tokens are encrypted at rest with **Fernet** (`encrypt_secret` /
  `decrypt_secret`). The key comes from `TOKEN_ENCRYPTION_KEY`; if unset, a key is derived from
  `SECRET_KEY` so development works out of the box (production must set an explicit key).
- **OAuth `state`** is `payload.expiry.HMAC-SHA256`, time-limited, and additionally persisted in
  the `OAuthState` table with a random nonce to prevent replay.
- Configuration never hard-codes secrets; missing values leave the feature **disabled** rather
  than falling back to something insecure.

## 5. Webhooks & integrations

- Microsoft Graph notifications are validated against `MS_WEBHOOK_CLIENT_STATE`; Google Pub/Sub
  push is validated against `GOOGLE_PUBSUB_VERIFICATION_TOKEN`.
- Webhook and OAuth endpoints require HTTPS in production (`PUBLIC_WEBHOOK_BASE_URL`).
- Provider availability is **truthful**: `/status/integrations` and `/integrations/config` report
  `disabled`/`error` rather than pretending a feed is live.

## 6. Input handling

- **Uploads**: size-limited (`MAX_UPLOAD_MB`), type-sniffed with `puremagic`, hashed, and stored
  outside the web root; suspicious files can be quarantined. Archive handling enforces
  `max_archive_files`, a compression-ratio bound (`max_archive_expansion_ratio`), and a total
  extraction cap (`max_extract_bytes`) to mitigate decompression bombs.
- **URL analysis** handles dangerous/malformed schemes and inputs lacking a host without
  crashing.
- **Email parsing** uses `email.utils.getaddresses` and header analysis rather than brittle
  regexes.
- **Validation** is Pydantic v2 on every request body; failures return a normalized error shape.

## 7. HTTP hardening

The `security_headers` middleware (`app/main.py`) sets on every response:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY` and `frame-ancestors 'none'` in CSP
- `Referrer-Policy: no-referrer`
- `Permissions-Policy` disabling geolocation/microphone/camera
- A restrictive `Content-Security-Policy`
- `Strict-Transport-Security` when `COOKIE_SECURE` is enabled
- `X-Request-ID` for correlation

CORS is locked to `CORS_ORIGINS`, with credentials enabled and a minimal method/header allowlist.

## 8. Rate limiting

Fixed-window limiter (`app/core/rate_limit.py`): a general per-IP-per-path limit and a stricter
**login** limit (`LOGIN_RATE_LIMIT_PER_MINUTE`). Client IP is taken from the **direct peer** to
avoid spoofable `X-Forwarded-For` bypass.

> **Limitation:** the store is **in-memory and per-process**. For multiple API replicas, enforce
> limits at the proxy or replace the store with a shared backend (e.g. Redis) behind the same
> `check()` interface.

## 9. Logging & audit

- Structured logging with redaction; secrets and tokens are not logged.
- An append-only `AuditLog` records sensitive actions, and `IdentityEvent` records identity- and
  auth-related events (`/audit/logs`, `/audit/identity-events`).

## 10. Threat model notes & known limitations

- **In-memory cache / rate limiter** are single-process; documented above.
- **ML model** is trained on synthetic data and must be re-validated on real traffic; treat its
  output as one signal among many, never the sole basis for a decision.
- **Feed-dependent features** (threat intel, provider sync, optional scanners like YARA/Trivy)
  only function when those systems/keys are supplied; otherwise they are reported unavailable.
- **No offensive capability**: the platform does not block, quarantine at the network layer, or
  take disruptive action on external systems. Response actions are advisory for a human operator.
- **Dependency hygiene**: run `pip-audit`/`npm audit` in CI and keep images pinned and rebuilt
  regularly.
