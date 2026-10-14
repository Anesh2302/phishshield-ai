# Final Audit Report

This is a frank, evidence-based assessment of PhishShield AI as built. Status labels:

- **Real** — complete logic, exercised end-to-end in this repository.
- **Real (feed-dependent)** — real code path, but enrichment requires keys/sensors/tools you
  provide. Without them the feature reports `disabled`/`unavailable` — **never a false "clean"**.
- **Simulated** — an explicitly labelled demo/lab path, not a live control.

Nothing below is claimed as verified unless the verification method is stated.

---

## 1. Verified quality gates

| Check | Command | Result |
| --- | --- | --- |
| Backend tests | `python -m pytest` | **78 passed** (≈26s) |
| Coverage | `pytest --cov=app --cov-report=term` | **78%** (4136 stmts, 928 missed) |
| Lint | `ruff check app tests` | **clean** (0 findings) |
| Fresh migration | `alembic upgrade head` on empty DB | **ok** → revision `87071b699202` ("initial schema") |
| Worker import | `python -c "import app.jobs.tasks"` | **ok** — 4 handlers registered |
| Frontend build | `npm run build` | **ok** — 16 routes |
| Extension JS | `node --check` on all `.js` | **ok** |
| Android build | `gradlew assembleDebug` | **BUILD SUCCESSFUL** → `app-debug.apk` (5.91 MB) |
| Live smoke test | `python scripts/smoke_test.py` | **SMOKE OK** (health, role, scan, ML, integration) |

Smoke-test observed values: `health=ok`, `me_role=owner`, `scan_verdict=suspicious`,
`ml_available=true`, `ml_algorithm=RandomForestClassifier`, `integration_state=monitoring`
(mock provider).

Job handlers registered: `integration.sync_account`, `integration.renew`, `soc.correlate`,
`retention.purge`.

---

## 2. Module-by-module assessment

| Module | Status | Evidence / notes |
| --- | --- | --- |
| Auth & sessions (bcrypt, opaque sessions, CSRF, roles, TOTP) | **Real** | Covered by `test_auth*`; CSRF bound to session id; bootstrap gated on empty user table |
| URL/phishing scanner | **Real** | Deterministic feature engine + rules; `test_url_scanner` (10 tests); handles bad schemes/no-host |
| ML URL classifier | **Real pipeline; synthetic data** | `ml/train_url_model.py`; RandomForest, 22 features; **metrics are synthetic** (see §3) |
| Email security | **Real** | RFC822 parsing, SPF/DKIM/DMARC header checks, attachment extraction; tests present |
| File analysis | **Real** | magic sniffing, hashing, archive + macro heuristics, quarantine; decompression-bomb bounds; tests present |
| SOC correlation | **Real** (sensors simulated unless fed) | normalize + batch ingest + correlation; `/soc/demo` is clearly Simulated |
| Digital forensics | **Real** | Evidence store, SHA-256 integrity re-verification, chain-of-custody; tests present |
| Vulnerability management | **Real (feed-dependent)** | Asset inventory real; findings come from imported scanner JSON (e.g. Trivy/OSV) |
| Identity security | **Real logic; `simulate` is Simulated** | Correlation over ingested `IdentityEvent`s; demo path labelled |
| Integrations (Gmail/Outlook) | **Real plumbing (credential-dependent)** | OAuth connect/callback, encrypted tokens, signed+nonced state, webhook validation |
| Mock providers (`mock_gmail`/`mock_outlook`) | **Simulated (dev/test only)** | Gated behind `MOCK_PROVIDERS`; refused semantics in production |
| Threat intelligence | **Real (feed-dependent)** | VirusTotal/URLhaus/PhishTank when keys present; otherwise explicit "no providers" |
| Alerts & incidents | **Real** | Lifecycle, ack/close, linking, notes; tests present |
| Audit | **Real** | Append-only request/identity logs |
| Status/health endpoints | **Real** | Truthful capability reporting drives the "availability" claims |
| Next.js console | **Real (UI)** | 12 module pages + login + dashboard; build passes |
| Chrome MV3 extension | **Real (scoped)** | Active-tab/context-menu URL scan; options + privacy note |
| Android app | **Real (scoped)** | Login + URL scan; APK builds |

---

## 3. The ML claim, stated precisely

`ml/artifacts/url_model_metrics.json` reports validation and holdout accuracy/ROC-AUC of **1.0**.
**This is a synthetic-dataset benchmark, not a real-world detection rate.** The generator
produces separable classes, so near-perfect scores are expected and are *not* evidence of
production efficacy. The metrics file carries this disclaimer verbatim. **Action required before
production:** retrain and validate on real, labelled, and adversarially-diverse URL traffic, and
treat the model as one signal among many.

---

## 4. Environment constraints discovered (and how the platform responds)

The build/verification host is memory/commit-constrained (16 GB RAM, ~3–4 GB typically free, a
4 GB pagefile, ~15.8/20.5 GB committed). This affected tooling, not the correctness of the code:

- **Gradle** only succeeded with a constrained JVM (`-Xmx512m`, serial GC, `workers.max=1`).
- **Port 8000** is held by Docker Desktop's WSL relay on this machine; the smoke test therefore
  binds `SMOKE_PORT` (default 8099).
- Optional security tooling (YARA, Suricata, Zeek, Trivy/OSV CLI) is **not installed**; the
  corresponding code paths degrade and report unavailability honestly.
- **Docker Desktop** was paused to free memory for the Android build and subsequently failed to
  restart (its `com.docker.build` process crash-loops with a stack overflow while the host is
  memory-starved; a Docker context `meta.json` was momentarily locked). This is a **host resource
  condition**, unrelated to PhishShield AI containers. Restore by freeing memory and starting
  Docker Desktop (it will prompt for elevation), or reboot. See §7.

---

## 5. Known gaps / not done

- **Rate limiting is in-memory/per-process** (documented; swap for a shared store to scale).
- **No CI is committed yet** (planned: GitHub Actions running pytest + ruff + frontend build).
- **`npm audit` reported 5 high-severity advisories** in the frontend dependency tree —
  unaddressed; review and pin/patch in CI.
- **Mobile/browser clients cover core flows only** (login + URL scan), not every module.
- **No load/soak testing** or chaos testing was performed.
- **No end-to-end test against real Postgres** was run here (schema is portable and migrations
  were verified on SQLite; validate on Postgres in staging).
- **No real provider OAuth flow** was exercised (requires real credentials); only the mock
  provider path was smoke-tested.

---

## 6. Recommendation summary

| Area | Verdict |
| --- | --- |
| Core detection engines (URL/email/file/SOC/forensics/vuln/identity) | Ship-ready as a **defensive triage** platform, with the feed/sensor caveats above |
| Auth & tenancy | Solid; enforce `COOKIE_SECURE=1` + `MOCK_PROVIDERS=0` in production |
| ML | **Do not** rely on the shipped model's metrics; retrain on real data |
| Integrations | Code-complete; requires real credentials and HTTPS webhooks to go live |
| Scalability | Fine for single-region; address rate-limit store and run migrations as a release step |
| Clients | Functional for core flows; expand coverage as needed |

## 7. Reproduce the evidence

```powershell
Set-Location backend
..\backend\.venv\Scripts\python.exe -m pytest -q
..\backend\.venv\Scripts\python.exe -m ruff check app tests
Remove-Item phishshield.db -ErrorAction SilentlyContinue
..\backend\.venv\Scripts\python.exe -m alembic upgrade head
..\backend\.venv\Scripts\python.exe scripts\smoke_test.py

Set-Location ..\frontend; npm run build
Set-Location ..\android;  .\gradlew.bat assembleDebug
```

To restore Docker (host condition, not an app issue): free memory (close heavy apps), launch
**Docker Desktop** and approve its elevation prompt, or reboot, then `docker compose up -d`.
