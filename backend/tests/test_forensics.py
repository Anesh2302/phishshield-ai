from tests.conftest import auth_headers


def test_evidence_lifecycle(owner):
    client, csrf = owner
    r = client.post(
        "/api/v1/forensics/evidence",
        data={"case_name": "CASE-1", "title": "Disk image", "source": "laptop-01"},
        files={"file": ("disk.bin", b"forensic bytes\n", "application/octet-stream")},
        headers=auth_headers(csrf),
    )
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["sha256"]
    assert ev["size"] == len(b"forensic bytes\n")
    eid = ev["id"]

    detail = client.get(f"/api/v1/forensics/evidence/{eid}")
    assert detail.status_code == 200
    assert any(c["action"] == "registered" for c in detail.json()["custody"])
    assert "disclaimer" in detail.json()

    verify = client.post(f"/api/v1/forensics/evidence/{eid}/verify", headers=auth_headers(csrf))
    assert verify.status_code == 200
    assert verify.json()["match"] is True

    custody = client.post(f"/api/v1/forensics/evidence/{eid}/custody",
                          json={"action": "accessed", "note": "opened in examiner tool"},
                          headers=auth_headers(csrf))
    assert custody.status_code == 200

    timeline = client.get("/api/v1/forensics/cases/CASE-1/timeline")
    assert timeline.status_code == 200
    assert len(timeline.json()["timeline"]) >= 2
    times = [t["time"] for t in timeline.json()["timeline"]]
    assert times == sorted(times)


def test_evidence_export_csv(owner):
    client, csrf = owner
    r = client.get("/api/v1/forensics/report.csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "CASE-1" in r.text


def test_evidence_empty_file_rejected(owner):
    client, csrf = owner
    r = client.post(
        "/api/v1/forensics/evidence",
        data={"case_name": "CASE-2", "title": "empty"},
        files={"file": ("empty.bin", b"", "application/octet-stream")},
        headers=auth_headers(csrf),
    )
    assert r.status_code == 400
