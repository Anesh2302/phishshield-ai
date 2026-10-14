from datetime import UTC, datetime

from tests.conftest import auth_headers


def _h(csrf):
    return auth_headers(csrf)


def test_ingest_native_and_search(owner):
    client, csrf = owner
    r = client.post("/api/v1/soc/events/ingest", headers=_h(csrf), json={
        "format": "native",
        "payload": {
            "source": "phishshield", "severity": "high", "category": "scan.url",
            "actor": "analyst@acme-security.com", "message": "high risk url detected",
            "event_time": datetime.now(UTC).isoformat(),
        },
    })
    assert r.status_code == 201, r.text
    listing = client.get("/api/v1/soc/events", params={"q": "high risk"})
    assert listing.status_code == 200
    assert listing.json()["total"] >= 1


def test_suricata_autodetect(owner):
    client, csrf = owner
    r = client.post("/api/v1/soc/events/ingest", headers=_h(csrf), json={
        "format": "auto",
        "payload": {
            "event_type": "alert", "timestamp": datetime.now(UTC).isoformat(),
            "src_ip": "203.0.113.5", "dest_ip": "10.0.0.9", "proto": "TCP",
            "alert": {"severity": 1, "signature": "ET MALWARE C2", "signature_id": 2000001},
            "flow_id": 42,
        },
    })
    assert r.status_code == 201
    assert r.json()["source"] == "suricata"
    assert r.json()["severity"] == "critical"


def test_malformed_syslog_rejected(owner):
    client, csrf = owner
    r = client.post("/api/v1/soc/events/ingest", headers=_h(csrf),
                    json={"format": "syslog", "payload": "this is not syslog"})
    assert r.status_code == 422


def test_batch_reports_malformed(owner):
    client, csrf = owner
    r = client.post("/api/v1/soc/events/batch", headers=_h(csrf), json={
        "format": "auto",
        "records": [
            {"source": "phishshield", "category": "app", "message": "ok"},
            "definitely not syslog",
        ],
    })
    assert r.status_code == 201
    body = r.json()
    assert body["stored"] >= 1
    assert body["malformed"] >= 1


def test_sensors_only_active_after_events(owner):
    client, csrf = owner
    client.post("/api/v1/soc/events/ingest", headers=_h(csrf), json={
        "format": "native", "payload": {"source": "sensor-a", "message": "hello"},
    })
    r = client.get("/api/v1/soc/sensors")
    assert r.status_code == 200
    assert any(s["sensor"] == "sensor-a" for s in r.json()["sensors"])


def test_demo_is_labelled_and_correlates(owner):
    client, csrf = owner
    demo = client.post("/api/v1/soc/demo", headers=_h(csrf),
                       json={"scenario": "brute_force", "count": 6})
    assert demo.status_code == 201
    assert demo.json()["simulated"] is True
    corr = client.post("/api/v1/soc/correlate", headers=_h(csrf),
                       json={"window_minutes": 30, "brute_force_threshold": 5})
    assert corr.status_code == 200
    assert corr.json()["alerts_created"] >= 1
    alerts = client.get("/api/v1/alerts")
    assert alerts.status_code == 200
    assert alerts.json()["total"] >= 1


def test_parsers_endpoint(owner):
    client, csrf = owner
    r = client.get("/api/v1/soc/parsers")
    assert r.status_code == 200
    assert "native" in r.json()["supported_formats"]
