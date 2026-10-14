# PhishShield AI

A multi-domain, **defensive** cybersecurity platform: phishing / URL detection, email
security, file & malware triage, SOC event correlation, digital forensics (custody +
hashing), vulnerability management, identity threat detection, third-party integrations,
alerts/incidents, and a small ML URL classifier — exposed through a FastAPI backend, a
Next.js console, a Chrome extension, and an Android client.

> **Honest scope notice.** This is a self-contained, runnable platform, not a certified
> product. Where a capability needs an external feed, sensor, or tool that is not present
> in the environment, the feature **detects availability and degrades gracefully**, and
> the platform **reports the true status** rather than pretending a control is active. See
> [`docs/final-audit-report.md`](docs/final-audit-report.md) for a frank capability assessment.

---

## Contents

- [Feature overview](#feature-overview)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Running with Docker](#running-with-docker)
- [Testing & quality gates](#testing--quality-gates)
- [The ML model (and its limits)](#the-ml-model-and-its-limits)
- [Browser extension](#browser-extension)
- [Android app](#android-app)
- [Security model](#security-model)
- [Known limitations](#known-limitations)

---

## Feature overview

Module statuses below use a strict definition:

- **Real** — fully implemented logic running end-to-end in this repo.
- **Real (feed-dependent)** — real logic, but enrichment requires keys/sensors you supply;
  without them it reports `disabled`/`unavailable`, never a fake "clean".
- **Simulated** — an explicit lab/demo path (clearly labelled in the UI/API), not a live
  control.

| Module | Endpoints | Status |
| --- | --- | --- |
| Auth & sessions | `/auth/*` | Real — bcrypt, TOTP MFA, session + device tracking, CSRF, bootstrap |
| URL / phishing scanner | `/scans/*` | Real — deterministic feature engine + optional ML |
| Email security | `/emails/*` | Real — RFC822 parsing, auth-header analysis, attachment extraction |
| File analysis | `/files/*` | Real — magic sniffing, hashing, archive + macro heuristics, quarantine |
| SOC correlation | `/soc/*` | Real — normalization, batch ingest, correlation; sensors are simulated unless you feed them |
| Digital forensics | `/forensics/*` | Real — evidence store, SHA-256 integrity, chain-of-custody |
| Vulnerability management | `/vuln/*` | Real (feed-dependent) — asset inventory + import of scanner output (e.g. Trivy/OSV JSON) |
| Identity security | `/identity/*` | Real logic on ingested events; `simulate` path is Simulated |
| Integrations | `/integrations/*` | Real OAuth plumbing; providers need credentials. `mock_gmail`/`mock_outlook` are Simulated (dev only) |
| Threat intel | `/threat-intel/*` | Real (feed-dependent) — VirusTotal / URLhaus / PhishTank when keys present |
| ML URL model | `/ml/*` | Real pipeline, **synthetic** training data (see caveats) |
| Alerts & incidents | `/alerts/*`, `/incidents/*` | Real — lifecycle, acknowledgement, linking, notes |
| Audit | `/audit/*` | Real — append-only request + identity event logs |
| Status | `/status/*`, `/health`, `/readiness` | Real — truthful module/integration availability |

---

## Architecture

```
Browser (Next.js console) ─┐
Chrome extension ──────────┼──► FastAPI (app.main:app) ──► SQLAlchemy 2.0 ──► Postgres / SQLite
Android client ────────────┘              │
                                          ├── modules/*        (domain logic)
                                          ├── services/*       (scans, alerts)
                                          ├── jobs/*           (DB-backed queue + worker)
                                          └── integrations/*   (gmail, outlook, mock, threat intel)
```

- **API:** FastAPI, versioned at `/api/v1`. OpenAPI at `/openapi.json`, Swagger at `/docs`
  (disabled automatically when `ENVIRONMENT=production`).
- **DB:** SQLAlchemy 2.0 (sync) + Alembic. Portable column types (String UUIDs, JSON) so the
  same models run on Postgres (target) and SQLite (tests). Initial migration `87071b699202`.
- **Queue:** durable, DB-backed queue with a separate `python -m app.jobs.worker` process.
  Registered handlers: `integration.sync_account`, `integration.renew`, `soc.correlate`,
  `retention.purge`.
- **Frontend:** Next.js 16 (App Router, TypeScript, no CSS framework), cookie-based auth with
  `credentials: "include"` and a CSRF header.

Details: [`docs/architecture.md`](docs/architecture.md).

---

## Repository layout

```
phishshield-ai/
├─ backend/                 FastAPI service, tests, Alembic migrations, worker
│  ├─ app/
│  │  ├─ api/v1/            routers: auth, scans, emails, files, soc, forensics, vuln,
│  │  │                     identity, integrations, threatintel, ml, alerts, incidents, audit, health
│  │  ├─ core/             config, database, security, deps, logging, rate limiting, audit
│  │  ├─ modules/          phishing, email_security, files, soc, forensics, identity,
│  │  │                     vuln, integrations, threatintel
│  │  ├─ services/         scans, alerts
│  │  ├─ jobs/             queue, tasks (REGISTRY), worker
│  │  ├─ models.py         ORM models
│  │  └─ schemas.py        Pydantic v2 schemas
│  ├─ migrations/          Alembic env + versions
│  ├─ scripts/smoke_test.py
│  └─ tests/               78 tests
├─ frontend/                Next.js console (12 module pages + login + dashboard)
├─ extension/               Chrome MV3 extension (URL + email detection)
├─ android/                 Kotlin Android client (login + URL scan)
├─ ml/                      train_url_model.py + artifacts/
├─ docs/                    architecture, api-reference, deployment, security, final-audit-report
├─ docker-compose.yml       db + backend + worker + frontend
├─ .env.example
└─ README.md
```

---

## Quickstart

### 1. Backend

```powershell
# from the repo root
Copy-Item .env.example backend\.env            # then edit secrets (see Configuration)
python -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt

# create the schema and run the API
Set-Location backend
..\backend\.venv\Scripts\python.exe -m alembic upgrade head
..\backend\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

Health check: `GET http://localhost:8000/api/v1/health`.

> **Port note (this machine).** `com.docker.backend`/`wslrelay` may already hold port 8000.
> If so, run on another port (e.g. `--port 8099`) and set `NEXT_PUBLIC_API_BASE_URL`
> accordingly. The bundled smoke test uses `SMOKE_PORT` (default `8099`) for that reason.

First-run bootstrap: create the initial owner with
`POST /api/v1/auth/bootstrap` (only allowed while the instance has no users). Check
`GET /api/v1/auth/bootstrap-status` first.

### 2. Worker (optional, for background jobs)

```powershell
Set-Location backend
$env:MOCK_PROVIDERS="1"; ..\backend\.venv\Scripts\python.exe -m app.jobs.worker
```

### 3. Frontend

```powershell
Set-Location frontend
npm install
"`nNEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api/v1" | Add-Content .env.local
npm run dev            # http://localhost:3000
```

### 4. End-to-end smoke test

Boots the API on a spare port, bootstraps/logs in, runs a URL scan, checks the ML model, and
connects the mock Gmail provider:

```powershell
Set-Location backend
..\backend\.venv\Scripts\python.exe scripts\smoke_test.py
```

---

## Configuration

All configuration is environment-driven (`backend/app/core/config.py`); see
[`.env.example`](.env.example) for the full annotated list. Highlights:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | App signing secret (session JWT). Generate with `secrets.token_urlsafe(48)`. |
| `TOKEN_ENCRYPTION_KEY` | Fernet key for encrypting stored OAuth tokens. |
| `DATABASE_URL` | Full SQLAlchemy URL. Overrides the individual `POSTGRES_*` values. |
| `CORS_ORIGINS` | Comma-separated allowed browser origins. |
| `COOKIE_SECURE` | Set to `1` under HTTPS so cookies get the `Secure` flag (+ HSTS). |
| `MOCK_PROVIDERS` | Development-only: enables `mock_gmail`/`mock_outlook`. **Never in prod.** |
| `ML_ENABLED` / `ML_MODEL_PATH` | Toggle and locate the URL classifier artifact. |
| `VIRUSTOTAL_API_KEY`, `URLHAUS_ENABLED`, `PHISHTANK_ENABLED` | Optional threat-intel feeds. |

**Never commit `.env`.** It is gitignored; only `.env.example` (placeholders) is tracked.

---

## Running with Docker

```powershell
Copy-Item .env.example .env      # fill in secrets
docker compose build
docker compose up
```

Compose brings up `db` (Postgres 16), `backend` (runs `alembic upgrade head` then uvicorn),
`worker`, and `frontend` (Next.js). The backend image is non-root and health-checked. The
frontend image receives `NEXT_PUBLIC_API_BASE_URL` as a build arg because `NEXT_PUBLIC_*`
values are inlined into the client bundle at build time.

See [`docs/deployment.md`](docs/deployment.md) for production hardening (HTTPS, secrets,
Postgres backups, scaling the worker).

---

## Testing & quality gates

```powershell
Set-Location backend
..\backend\.venv\Scripts\python.exe -m pytest -q                       # 78 passed
..\backend\.venv\Scripts\python.exe -m pytest --cov=app --cov-report=term   # ~78% coverage
..\backend\.venv\Scripts\python.exe -m ruff check app tests            # clean
```

Tests run with `MOCK_PROVIDERS=1` and `ML_ENABLED=0` (the ML artifact is optional). Markers
`integration` and `realprovider` gate tests that need external services or real credentials.

Frontend:

```powershell
Set-Location frontend
npm run build      # 16 routes
npm run lint
```

---

## The ML model (and its limits)

`ml/train_url_model.py` trains a `RandomForestClassifier` over a **synthetic, in-repo
dataset** (train 9,600 / validation 2,400 / holdout 4,000) using 22 lexical/structural URL
features. The recorded metrics are near-perfect **because the dataset is synthetic** — that
is a benchmark of the pipeline, **not** a real-world detection rate.

`ml/artifacts/url_model_metrics.json` states this explicitly. **Validate against real,
labelled traffic (and re-tune) before trusting the model in production.** The deterministic
feature engine in `app/modules/phishing/` works with or without the model.

---

## Browser extension

`extension/` is a Manifest V3 extension. It scans the active tab's URL (or a right-clicked
link) via `POST /scans/url` and shows the verdict in the popup; options let you set the API
base URL and enable/disable scanning. It sends only the URL you scan — see
`extension/README.md` for the privacy note. Load it unpacked from `chrome://extensions`
(enable Developer mode → *Load unpacked* → select `extension/`).

---

## Android app

`android/` is a Kotlin app (compileSdk 35 / minSdk 24) with a login screen and URL scanner
backed by the same API. Build:

```powershell
Set-Location android
.\gradlew.bat assembleDebug
# -> android\app\build\outputs\apk\debug\app-debug.apk
```

`android/local.properties` is machine-specific and gitignored. On low-memory hosts, build
with a constrained Gradle JVM (`org.gradle.jvmargs=-Xmx512m`, serial GC, `workers.max=1`).

---

## Security model

Defense-in-depth defaults (details in [`docs/security-model.md`](docs/security-model.md)):

- Per-tenant data isolation on every query.
- CSRF protection (`X-CSRF-Token`, session-bound) on state-changing requests.
- bcrypt password hashing; TOTP-based MFA; session + device listing and revocation.
- HTTPS-only webhooks and OAuth redirect validation; HMAC-signed, nonce'd OAuth state.
- Redacting structured logging; security headers (CSP, HSTS when secure, `nosniff`, etc.).
- Rate limiting (in-memory; swap for a shared store when scaling out).
- OAuth tokens encrypted at rest with Fernet.
- Detect-and-alert posture: the platform observes and reports; it does not take offensive
  or disruptive action.

---

## Known limitations

- Some feeds/sensors/tools (YARA, Suricata, Zeek, Trivy/OSV CLI, email providers, VirusTotal)
  are **not present** by default; those features report `disabled`/`unavailable` honestly.
- The ML model is trained on synthetic data and must be re-validated on real traffic.
- Rate limiting is per-process (in-memory), not distributed.
- The in-memory cache and the DB-backed queue are suitable for a single-region deployment;
  see `docs/deployment.md` for scaling notes.
- The mobile and browser clients cover the core scan/login flows, not every module.

See [`docs/final-audit-report.md`](docs/final-audit-report.md) for the full, verified list of
what is real, what is feed-dependent, and what is simulated.
