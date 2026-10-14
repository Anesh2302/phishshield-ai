# API Reference

Base path: **`/api/v1`**. Interactive docs are served at `/docs` (Swagger) and `/openapi.json`
when `ENVIRONMENT` is not `production`.

## Conventions

- **Auth:** cookie session (`phishshield_session`) or `Authorization: Bearer <session-token>`.
- **CSRF:** for cookie-authenticated state-changing requests, send header `X-CSRF-Token`. Obtain
  the value from `GET /api/v1/auth/csrf` (it is bound to the current session). Bearer clients are
  exempt.
- **Tenancy:** every object is scoped to the caller's tenant; cross-tenant access returns 404.
- **Deletes** that remove a resource return `204 No Content`.
- **Errors** use `{ "detail": "...", "errors": [{ "loc": [...], "msg": "..." }] }` for validation
  failures.
- **Roles:** `viewer < analyst < admin < owner`.

## Endpoints

### Health & status

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/health` | Liveness + basic capability snapshot |
| GET | `/readiness` | DB connectivity + capability report |
| GET | `/status/modules` | Per-module availability (truthful) |
| GET | `/status/integrations` | Integration availability/state |

### Auth (`/auth`)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/auth/bootstrap-status` | Whether an owner already exists |
| POST | `/auth/bootstrap` | Create the first owner (only while no users exist) |
| POST | `/auth/login` | Start a session (rate-limited) |
| POST | `/auth/logout` | End the current session |
| GET | `/auth/me` | Current user + tenant + role |
| GET | `/auth/csrf` | CSRF token for the current session |
| POST | `/auth/change-password` | Rotate password |
| POST | `/auth/users` | Create a user (admin/owner) |
| GET | `/auth/sessions` | List active sessions |
| POST | `/auth/sessions/{session_id}/revoke` | Revoke a session |
| GET | `/auth/devices` | List known devices |
| POST | `/auth/mfa/setup` | Begin TOTP enrollment (secret + provisioning URI) |
| POST | `/auth/mfa/enable` | Confirm and enable TOTP MFA |
| POST | `/auth/mfa/disable` | Disable MFA |

### URL / phishing scanner (`/scans`)

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/scans/url` | Analyze a URL → verdict, score, feature breakdown |
| GET | `/scans` | List URL scans (tenant-scoped) |
| GET | `/scans/{scan_id}` | Scan detail |
| GET | `/scans/export.csv` | CSV export |

### Email security (`/emails`)

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/emails/analyze` | Analyze a raw message body/headers |
| POST | `/emails/upload` | Upload an `.eml`/message file |
| GET | `/emails/scans` | List email scans |
| GET | `/emails/scans/{scan_id}` | Email scan detail |

### File analysis (`/files`)

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/files/upload` | Upload a file → type, hashes, heuristics, quarantine |
| GET | `/files` | List file records |
| GET | `/files/export.csv` | CSV export |
| GET | `/files/{file_id}` | File record detail |
| GET | `/files/{file_id}/download` | Download stored artifact |
| DELETE | `/files/{file_id}` | Delete record/artifact (204) |

### SOC (`/soc`)

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/soc/events/ingest` | Ingest one event |
| POST | `/soc/events/batch` | Ingest a batch |
| GET | `/soc/events` | List events |
| POST | `/soc/correlate` | Run correlation over events |
| GET | `/soc/parsers` | Supported input parsers |
| GET | `/soc/sensors` | Known sensors (simulated unless you feed them) |
| POST | `/soc/demo` | Load clearly-labelled demo events |

### Digital forensics (`/forensics`)

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/forensics/evidence` | Register evidence (hashed, stored) |
| GET | `/forensics/evidence` | List evidence |
| GET | `/forensics/evidence/{evidence_id}` | Evidence detail |
| POST | `/forensics/evidence/{evidence_id}/custody` | Add chain-of-custody entry |
| POST | `/forensics/evidence/{evidence_id}/verify` | Re-verify integrity hash |
| GET | `/forensics/cases/{case_name}/timeline` | Case timeline |
| GET | `/forensics/report.csv` | CSV report |

### Vulnerability management (`/vuln`)

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/vuln/assets` · GET `/vuln/assets` · DELETE `/vuln/assets/{asset_id}` | Asset inventory |
| POST | `/vuln/findings/import` | Import scanner output (Trivy/OSV JSON) |
| GET | `/vuln/findings` · PATCH `/vuln/findings/{finding_id}` | Findings + triage |
| GET | `/vuln/scanners` | Which scanner formats are accepted |

### Identity security (`/identity`)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/identity/overview` | Identity risk overview |
| POST | `/identity/correlate` | Correlate ingested identity events |
| POST | `/identity/simulate` | Load labelled demo identities (Simulated) |

### Integrations (`/integrations`)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/integrations/config` | Which providers are configured/enabled |
| POST | `/integrations/{provider}/connect` | Begin OAuth (returns signed state) |
| GET | `/integrations/{provider}/callback` | OAuth redirect handler |
| POST | `/integrations/{provider}/callback-json` | Non-redirect OAuth completion |
| GET | `/integrations/accounts` · GET `/accounts/{account_id}` | Linked accounts |
| POST | `/integrations/accounts/{account_id}/sync` | Trigger sync (enqueues a job) |
| POST | `/integrations/accounts/{account_id}/renew` | Renew subscription/watch |
| POST | `/integrations/accounts/{account_id}/disconnect` | Disconnect/delete tokens |
| POST | `/integrations/gmail/webhook` | Gmail Pub/Sub push endpoint |
| GET/POST | `/integrations/outlook/webhook` | Graph validation + notifications |

### Threat intelligence (`/threat-intel`)

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/threat-intel/lookup` | Look up an indicator across enabled feeds |
| GET | `/threat-intel/providers` | Feed availability (truthful) |

When no feeds are configured, lookups return an explicit "no providers enabled" result — never a
false "clean".

### ML (`/ml`)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/ml/model` | Model availability, algorithm, feature schema |
| POST | `/ml/predict` | Score a URL with the model |

### Alerts & incidents

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/alerts` · GET `/alerts/{alert_id}` | List/detail |
| POST | `/alerts/{alert_id}/acknowledge` · POST `/alerts/{alert_id}/close` | Lifecycle |
| POST | `/incidents` · GET `/incidents` · GET `/incidents/{incident_id}` | Create/list/detail |
| PATCH | `/incidents/{incident_id}` · DELETE `/incidents/{incident_id}` | Update/delete (204) |
| POST | `/incidents/{incident_id}/links` | Link an alert/scan/evidence |
| POST | `/incidents/{incident_id}/notes` | Append a note |

### Audit (`/audit`)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/audit/logs` | Request/audit log |
| GET | `/audit/identity-events` | Identity event log |

## Quick examples

Bootstrap the first owner:

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"tenant_name":"Acme","email":"owner@acme-security.com","password":"Str0ng-Passphrase-1"}'
```

Scan a URL (Bearer-style, as used by the smoke test and mobile/extension clients):

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"owner@acme-security.com","password":"Str0ng-Passphrase-1"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl -s -X POST http://localhost:8000/api/v1/scans/url \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"url":"http://paypal-verify-login.tk/account"}'
```

> Response field names are stable but should be confirmed against `/openapi.json` for your
> pinned version.
