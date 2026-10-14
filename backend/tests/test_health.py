def test_health_ok(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in {"ok", "degraded"}
    assert body["components"]["database"]["status"] == "ok"
    assert "capabilities" in body


def test_readiness(client):
    r = client.get("/api/v1/readiness")
    assert r.status_code == 200
    assert r.json()["ready"] is True


def test_integration_status_honest(client):
    r = client.get("/api/v1/status/integrations")
    assert r.status_code == 200
    body = r.json()
    # Monitoring must never be reported active without accounts.
    assert body["gmail"]["monitoring_active"] is False
    assert body["outlook"]["monitoring_active"] is False
    assert body["webhook"]["https_required"] is True


def test_security_headers(client):
    r = client.get("/api/v1/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in r.headers
    assert r.headers.get("X-Request-ID")


def test_modules_status(client):
    r = client.get("/api/v1/status/modules")
    assert r.status_code == 200
    names = {m["name"] for m in r.json()["modules"]}
    assert {"url_scan", "email_security", "soc_siem", "forensics"}.issubset(names)
