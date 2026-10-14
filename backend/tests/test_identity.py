from tests.conftest import auth_headers


def test_identity_overview(owner):
    client, csrf = owner
    r = client.get("/api/v1/identity/overview")
    assert r.status_code == 200
    body = r.json()
    assert body["mfa"]["supported"] is True
    assert "role_posture" in body
    assert "token_posture" in body


def test_simulate_bruteforce_and_correlate(owner):
    client, csrf = owner
    sim = client.post("/api/v1/identity/simulate",
                      json={"scenario": "bruteforce", "attempts": 6,
                            "target_email": "victim@acme-security.com"},
                      headers=auth_headers(csrf))
    assert sim.status_code == 200, sim.text
    assert sim.json()["simulated"] is True
    assert sim.json()["correlation"]["alerts_created"] >= 1

    corr = client.post("/api/v1/identity/correlate", params={"window_minutes": 30, "threshold": 5},
                       headers=auth_headers(csrf))
    assert corr.status_code == 200
    assert corr.json()["analyzed"] >= 6
