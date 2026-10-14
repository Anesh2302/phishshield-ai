# Deployment

This guide covers running PhishShield AI beyond a laptop: hardened configuration, containers,
database, workers, TLS, scaling, backups and operations.

## 1. Build & run with Docker Compose

```bash
cp .env.example .env      # then edit secrets (see §2)
docker compose build
docker compose up -d
docker compose ps
```

Compose provisions:

| Service | Role |
| --- | --- |
| `db` | Postgres 16 (named volume `pgdata`), health-checked with `pg_isready` |
| `backend` | Runs `alembic upgrade head` then `uvicorn app.main:app` on `:8000` |
| `worker` | Runs `python -m app.jobs.worker` |
| `frontend` | Next.js `npm start` on `:3000` |

The backend container runs as a non-root user and stores files under the `storage` volume
(`/data/uploads`, `/data/quarantine`, `/data/evidence`).

## 2. Required secrets (production)

Generate strong values and set them in `.env`:

```bash
python -c "import secrets;print('SECRET_KEY='+secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet;print('TOKEN_ENCRYPTION_KEY='+Fernet.generate_key().decode())"
```

Set at minimum:

- `ENVIRONMENT=production` (disables `/docs` and `/openapi.json`; enables JSON logs)
- `SECRET_KEY`, `TOKEN_ENCRYPTION_KEY`
- `DATABASE_URL` (Postgres) and Postgres credentials
- `CORS_ORIGINS` = your exact console origin(s)
- `COOKIE_SECURE=1` (required behind HTTPS; enables Secure cookies + HSTS)

**Rotating `TOKEN_ENCRYPTION_KEY` invalidates stored OAuth tokens** — re-connect providers after
a rotation. Keep it out of source control and inject it via your secret manager.

## 3. TLS / reverse proxy

Terminate TLS at a proxy (nginx, Caddy, Traefik, or your cloud LB) and forward to `backend:8000`
and `frontend:3000`. Requirements:

- Serve the console over HTTPS and set `COOKIE_SECURE=1`.
- Preserve `X-Forwarded-Proto`/`Host`. The app intentionally derives the client IP from the
  **direct peer** to avoid spoofable rate-limit bypass; place the proxy on a trusted network and,
  if you need real client IPs for limiting, configure that at the proxy.
- Webhooks (Gmail/Outlook) and OAuth callbacks must be reachable over **HTTPS** with the exact
  redirect URIs you registered. Set `PUBLIC_WEBHOOK_BASE_URL` accordingly.

## 4. Database

- Use Postgres in production. Alembic runs on backend start; for zero-downtime rollouts, run
  migrations as a separate step before rolling the new app version:

  ```bash
  docker compose run --rm backend alembic upgrade head
  ```

- Back up regularly:

  ```bash
  docker compose exec db pg_dump -U phishshield phishshield > backup_$(date +%F).sql
  ```

- The schema uses portable types, so SQLite works for local dev/quickstart only — do not run
  SQLite in production.

## 5. Workers & scaling

- The queue is **durable in the database**. Scale `worker` horizontally: multiple replicas are
  safe on Postgres because jobs are claimed with `SELECT … FOR UPDATE SKIP LOCKED`.
- Scale `backend` behind the proxy. **Rate limiting is process-local (in-memory)**; for multiple
  API replicas either enforce limits at the proxy or swap `app/core/rate_limit.py`'s store for a
  shared backend (e.g. Redis) behind the same `check()` interface.
- The worker requeues jobs orphaned by crashed replicas (`reclaim_stale`, default 600s).

## 6. Configuration reference

See [`.env.example`](../.env.example). Notable production toggles:

| Variable | Production guidance |
| --- | --- |
| `MOCK_PROVIDERS` | **Must be `0`.** Mock providers are for dev/tests only. |
| `GMAIL_ENABLED` / `OUTLOOK_ENABLED` | `1` only with real OAuth credentials configured |
| `THREATINTEL_ENABLED` + feed keys | Enable feeds you actually have keys for |
| `ML_ENABLED` / `ML_MODEL_PATH` | Point at a **re-validated** model artifact (see below) |
| `MAX_UPLOAD_MB` | Align with proxy body-size limits |

## 7. ML artifact in production

`ml/artifacts/*.joblib` is gitignored (built locally by `ml/train_url_model.py`). The shipped
model is trained on **synthetic** data and must be re-tuned/validated on real labelled traffic
before you rely on it. If no artifact is present, `/ml/model` reports unavailable and the
deterministic feature engine still works.

## 8. Health, readiness & monitoring

- `GET /api/v1/health` — liveness and capability snapshot.
- `GET /api/v1/readiness` — DB connectivity + capabilities (use for readiness probes).
- `GET /api/v1/status/modules` and `/status/integrations` — truthful per-feature state; wire these
  into dashboards so operators can see when a feed/provider is `disabled`/`error`.

All logs are structured; set `LOG_LEVEL=INFO` (or `WARNING`) and ship them to your aggregator.
Never log secrets — logging is redacting by design.

## 9. Operations checklist

- [ ] `ENVIRONMENT=production`, `COOKIE_SECURE=1`, real `SECRET_KEY`/`TOKEN_ENCRYPTION_KEY`
- [ ] `MOCK_PROVIDERS=0`
- [ ] Postgres with backups + tested restore
- [ ] TLS terminated; webhook/callback URLs registered with providers
- [ ] Migrations run as a release step
- [ ] Multiple workers (if async workloads) behind the shared DB
- [ ] Rate limiting enforced (proxy or shared store) for multi-replica API
- [ ] ML model re-validated on real data before enabling
