from app.modules.vuln.parsers import compute_priority, parse_osv, parse_trivy
from tests.conftest import auth_headers

OSV_SAMPLE = {
    "results": [{
        "source": {"path": "requirements.txt"},
        "packages": [{
            "package": {"name": "log4j-core", "version": "2.14.0", "ecosystem": "Maven"},
            "vulnerabilities": [{
                "id": "GHSA-jfh8-c2jp-5v3q",
                "aliases": ["CVE-2021-44228"],
                "summary": "Log4Shell remote code execution",
                "database_specific": {"severity": "CRITICAL"},
            }],
        }],
    }],
}

TRIVY_SAMPLE = {
    "Results": [{
        "Target": "app:latest (debian 12)",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2023-0001",
            "PkgName": "openssl", "InstalledVersion": "3.0.1",
            "FixedVersion": "3.0.2", "Severity": "HIGH", "Title": "OpenSSL flaw",
        }],
    }],
}


def test_parsers_and_priority():
    osv = parse_osv(OSV_SAMPLE)
    assert osv[0].cve == "CVE-2021-44228"
    assert osv[0].severity == "critical"
    trivy = parse_trivy(TRIVY_SAMPLE)
    assert trivy[0].severity == "high"
    assert trivy[0].fixed_version == "3.0.2"
    assert compute_priority("critical", "critical", "public", exploit_available=True) == "critical"
    assert compute_priority("low", "low", "internal") == "low"


def test_asset_duplicate_guard(owner):
    client, csrf = owner
    payload = {"name": "web-01", "criticality": "high", "exposure": "public"}
    r = client.post("/api/v1/vuln/assets", json=payload, headers=auth_headers(csrf))
    assert r.status_code == 201, r.text
    dup = client.post("/api/v1/vuln/assets", json=payload, headers=auth_headers(csrf))
    assert dup.status_code == 409


def test_import_requires_authorization(owner):
    client, csrf = owner
    r = client.post("/api/v1/vuln/findings/import",
                    json={"tool": "osv", "data": OSV_SAMPLE, "authorized": False},
                    headers=auth_headers(csrf))
    assert r.status_code == 400


def test_import_and_update_finding(owner):
    client, csrf = owner
    r = client.post("/api/v1/vuln/findings/import",
                    json={"tool": "osv", "data": OSV_SAMPLE, "authorized": True,
                          "scope_note": "authorized local dependency scan"},
                    headers=auth_headers(csrf))
    assert r.status_code == 201, r.text
    assert r.json()["imported"] == 1

    listing = client.get("/api/v1/vuln/findings", params={"severity": "critical"})
    assert listing.status_code == 200
    assert listing.json()["total"] >= 1
    finding_id = listing.json()["items"][0]["id"]

    upd = client.patch(f"/api/v1/vuln/findings/{finding_id}",
                       json={"status": "resolved"}, headers=auth_headers(csrf))
    assert upd.status_code == 200
    assert upd.json()["status"] == "resolved"


def test_scanner_status_honest(owner):
    client, csrf = owner
    r = client.get("/api/v1/vuln/scanners")
    assert r.status_code == 200
    assert "osv-scanner" in r.json()["scanners"]
