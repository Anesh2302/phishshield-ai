from tests.conftest import auth_headers


def test_bootstrap_and_me(owner):
    client, csrf = owner
    r = client.get("/api/v1/auth/me")
    assert r.status_code == 200
    assert r.json()["role"] == "owner"
    assert r.json()["email"] == "owner@acme-security.com"


def test_login_wrong_password(client, owner):
    r = client.post("/api/v1/auth/login",
                    json={"email": "owner@acme-security.com", "password": "wrong"})
    assert r.status_code == 401


def test_csrf_required_for_state_change(client, owner):
    # client is authenticated via cookie; POST without CSRF header must fail.
    r = client.post("/api/v1/scans/url", json={"url": "http://example.com"})
    assert r.status_code == 403


def test_csrf_header_allows(owner):
    client, csrf = owner
    r = client.post("/api/v1/scans/url", json={"url": "http://example.com"},
                    headers=auth_headers(csrf))
    assert r.status_code == 201


def test_unauthenticated_rejected(client):
    r = client.get("/api/v1/auth/me")
    assert r.status_code == 401


def test_create_user_and_rbac(owner):
    client, csrf = owner
    r = client.post("/api/v1/auth/users",
                    json={"email": "viewer@acme-security.com", "password": "Str0ng-Pass-2", "role": "viewer"},
                    headers=auth_headers(csrf))
    assert r.status_code == 201, r.text
    # viewer cannot list audit logs (admin+)
    vc = client.__class__(client.app)
    with vc:
        login = vc.post("/api/v1/auth/login",
                        json={"email": "viewer@acme-security.com", "password": "Str0ng-Pass-2"})
        assert login.status_code == 200
        r = vc.get("/api/v1/audit/logs")
        assert r.status_code == 403


def test_logout_revokes_session(owner):
    client, csrf = owner
    assert client.get("/api/v1/auth/me").status_code == 200
    r = client.post("/api/v1/auth/logout", headers=auth_headers(csrf))
    assert r.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_mfa_enable_flow(owner):
    from app.core.security import totp_now

    client, csrf = owner
    setup = client.post("/api/v1/auth/mfa/setup", headers=auth_headers(csrf))
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    enable = client.post("/api/v1/auth/mfa/enable", json={"code": totp_now(secret)},
                         headers=auth_headers(csrf))
    assert enable.status_code == 200
    assert enable.json()["mfa_enabled"] is True
    # Disable again to avoid affecting other tests.
    disable = client.post("/api/v1/auth/mfa/disable", json={"code": totp_now(secret)},
                          headers=auth_headers(csrf))
    assert disable.status_code == 200
