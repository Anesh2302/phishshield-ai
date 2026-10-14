# Architecture

PhishShield AI is a layered, single-repo platform. This document explains how the pieces
fit together, the request lifecycle, the data model, and the background processing design.

```
┌──────────────────────────── Clients ────────────────────────────┐
│  Next.js console   Chrome MV3 extension   Android (Kotlin)      │
└───────────────┬───────────────┬───────────────────┬─────────────┘
                │  HTTPS / JSON  (cookie session + CSRF, or Bearer)
                ▼
        ┌───────────────────────────────────────────────┐
        │            FastAPI  (app.main:app)            │
        │  middleware: request-id, security headers,    │
        │              CORS, rate limiting              │
        │  /api/v1/*  routers                           │
        └───────┬───────────────────────────┬───────────┘
                │                           │
        ┌───────▼────────┐          ┌───────▼──────────┐
        │  services/*    │          │  modules/*       │
        │  scans, alerts │          │  domain logic    │
        └───────┬────────┘          └───────┬──────────┘
                │                           │
        ┌───────▼───────────────────────────▼──────────┐
        │   SQLAlchemy 2.0 ORM  +  Alembic migrations   │
        └───────┬───────────────────────────────────────┘
                │
        ┌───────▼────────┐     ┌────────────────────────┐
        │  Postgres/SQLite│    │  jobs: queue + worker  │  (separate process)
        └─────────────────┘     └────────────────────────┘
```

## 1. Application object & middleware

`app/main.py` builds the app:

- **CORS** restricted to `CORS_ORIGINS`; credentials allowed; only the methods/headers the SPA
  needs.
- **Security-header middleware** stamps every response with `X-Request-ID`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  a restrictive `Content-Security-Policy`, `Permissions-Policy`, and (when `COOKIE_SECURE`) HSTS.
  It also emits one structured log line per request with method, path, status and duration.
- **Validation errors** are normalized to `{detail, errors:[{loc,msg}]}` so clients get a stable
  shape.
- Docs (`/docs`, `/openapi.json`) are **disabled** when `ENVIRONMENT=production`.

## 2. Request lifecycle (authenticated state change)

1. `get_auth_context` (`app/core/deps.py`) resolves the session from the cookie **or** a Bearer
   token, loads `UserSession` by SHA-256 token hash, rejects revoked/expired sessions, loads the
   `User` and `Tenant`, updates `last_seen_at`, and returns an `AuthContext{user, session, tenant}`.
2. `require_role(min)` enforces the `viewer < analyst < admin < owner` hierarchy.
3. `require_csrf` — **only when the request used the session cookie** — verifies an
   `X-CSRF-Token` header against an HMAC derived from the server-side session id. Bearer clients
   are exempt (no ambient browser credentials).
4. The handler queries only tenant-scoped rows (`tenant_scope(...)`).

## 3. Configuration

`app/core/config.py` (`pydantic-settings`) reads `.env` then `../.env`. It exposes helpers:
`cors_origin_list`, `is_production`, `is_sqlite`, resolved storage paths, and `capability_report()`
which drives `/health` and `/status/*`. Missing secrets are never hard-coded; the affected
feature is simply reported as unavailable.

## 4. Data model (`app/models.py`)

Portable types keep the same schema on Postgres (production) and SQLite (tests/quickstart):

- IDs are `String(36)` UUIDs; free-form structures are `JSON`.

Core entities: `Tenant`, `User`, `UserSession`, `Device`, `AuditLog`, `IdentityEvent`,
`Scan` (URL/email), `EmailScan`, `Alert`, `Incident` (+ links, notes), `FileRecord`,
`SOCEvent` (+ sensor, parser metadata), `Evidence` (+ custody entries), `Asset`, `Finding`,
`IntegrationAccount`, `OAuthState`, `Job`, ML-related records. Every tenant-scoped table carries
`tenant_id`.

### Migrations

Alembic lives in `backend/migrations`. The initial schema is revision `87071b699202`
("initial schema"). Commands:

```powershell
Set-Location backend
..\backend\.venv\Scripts\python.exe -m alembic upgrade head
..\backend\.venv\Scripts\python.exe -m alembic revision -m "add xyz" --autogenerate
```

## 5. Domain modules (`app/modules/*`)

Each module owns its logic and is intentionally decoupled from transport:

| Module | Responsibility |
| --- | --- |
| `phishing/` | URL parsing/features, deterministic scoring engine, optional ML `classifier` |
| `email_security/` | RFC822 `parser` (SPF/DKIM/DMARC header inspection, attachments) + `analyzer` |
| `files/` | magic sniffing, hashing, archive/macro heuristics (`analyzer`) + quarantine `storage` |
| `soc/` | event `normalize` (multiple input formats) + `correlation` rules |
| `forensics/` | evidence intake, integrity verification, custody chain (`service`) |
| `vuln/` | asset inventory + scanner-output `parsers` (e.g. Trivy/OSV JSON) |
| `identity/` | identity-event correlation (`service`) |
| `integrations/` | provider abstraction (`base`) + `gmail`, `outlook`, `mock`, orchestration `service` |
| `threatintel/` | provider lookups (`service`); feed-dependent |

## 6. Services & jobs

- `services/scans.py` and `services/alerts.py` hold cross-module orchestration (persist a scan,
  raise alerts, link incidents).
- **Queue** (`app/jobs/queue.py`): a durable, DB-backed job table. `enqueue` supports
  `idempotency_key` (re-enqueue is a no-op) and `run_at` scheduling. `claim_next` uses
  `SELECT … FOR UPDATE SKIP LOCKED` on Postgres for safe multi-worker claims, and a conditional
  `UPDATE` on SQLite. Failures retry with randomized exponential backoff (30s → 3600s cap) up to
  `max_attempts`; `reclaim_stale` returns jobs orphaned by crashed workers to `pending`.
- **Worker** (`app/jobs/worker.py`): polls the queue, dispatches to
  `app/jobs/tasks.py:REGISTRY`, reclaims stale jobs periodically, and shuts down cleanly on
  SIGINT/SIGTERM. Registered handlers: `integration.sync_account`, `integration.renew`,
  `soc.correlate`, `retention.purge`.

## 7. Integrations

`integrations/base.py` defines the provider contract. `gmail.py` and `outlook.py` implement OAuth
connect + callback, token storage (Fernet-encrypted), and sync; `mock.py` provides fully local
fake providers gated behind `MOCK_PROVIDERS` for tests/dev. OAuth `state` is HMAC-signed with an
expiry and a random nonce, and persisted in `OAuthState` to prevent replay. Webhooks are
validated (Microsoft `clientState`, Google verification token) and require HTTPS.

The mock, Gmail and Outlook implementations are selected by `integrations/service.py`, which is
also where the truthful `state` (`disabled`/`connecting`/`monitoring`/`error`) is computed.

## 8. Frontend

Next.js 16 App Router, TypeScript, no CSS framework. `lib/api.ts` is a tiny fetch wrapper that
sends `credentials: "include"` and the CSRF header; `lib/auth.ts` manages session/UX state.
Each module has a page under `app/<module>/page.tsx`, all sharing components from
`components/ui.tsx`. The client calls the API directly, so `NEXT_PUBLIC_API_BASE_URL` must
include the `/api/v1` suffix (inlined at build time).

## 9. Clients beyond the web console

- **Chrome MV3 extension** (`extension/`): service worker + popup + options, calls `/scans/url`.
- **Android** (`android/`): Kotlin, `HttpURLConnection`, cookie session + CSRF in
  `SharedPreferences`, login + URL scan screens.

## 10. Non-goals

PhishShield AI is defensive and observational. It does not perform offensive actions,
automatic blocking, or host isolation; it detects, correlates, and reports.
