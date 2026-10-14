from app.core.security import decrypt_secret
from app.models import IntegrationAccount
from app.modules.integrations.mock import get_mock
from tests.conftest import auth_headers

PHISH = """From: "PayPal Security" <attacker@evil-domain.tk>
Reply-To: harvest@another-evil.tk
Subject: URGENT verify your account
Message-ID: <phish-int@evil-domain.tk>
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/html

<html><body>Your account is suspended.
<a href="http://paypal.secure-verify-account.tk/login?update=password">Verify</a>
Please enter your password and credit card.</body></html>
"""

BENIGN = """From: coworker@example.com
Subject: notes
Message-ID: <benign-int@example.com>
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass

Here are the meeting notes. Thanks.
"""


def _connect(client, csrf, provider="mock_gmail", email="analyst@acme-security.com"):
    r = client.post(f"/api/v1/integrations/{provider}/connect", headers=auth_headers(csrf))
    assert r.status_code == 200, r.text
    assert r.json()["mock"] is True
    state = r.json()["state"]
    cb = client.post(f"/api/v1/integrations/{provider}/callback-json",
                     json={"code": email, "state": state}, headers=auth_headers(csrf))
    assert cb.status_code == 200, cb.text
    return cb.json()


def test_unknown_provider_404(owner):
    client, csrf = owner
    r = client.post("/api/v1/integrations/definitely-not-real/connect", headers=auth_headers(csrf))
    assert r.status_code == 404


def test_config_is_honest(owner):
    client, csrf = owner
    r = client.get("/api/v1/integrations/config")
    assert r.status_code == 200
    assert r.json()["https_note"].startswith("Provider change notifications")


def test_mock_lifecycle_sync_and_dedup(owner, db):
    client, csrf = owner
    account = _connect(client, csrf)
    assert account["state"] in {"monitoring", "connected"}
    account_id = account["id"]

    row = db.get(IntegrationAccount, account_id)
    token = decrypt_secret(row.access_token_enc)
    get_mock("mock_gmail").queue_message(token, "msg-phish-1", PHISH)
    get_mock("mock_gmail").queue_message(token, "msg-benign-1", BENIGN)

    sync = client.post(f"/api/v1/integrations/accounts/{account_id}/sync",
                       headers=auth_headers(csrf))
    assert sync.status_code == 200
    assert sync.json()["result"]["processed"] == 2

    # Re-queue the same message id -> must be recognized as a duplicate.
    get_mock("mock_gmail").queue_message(token, "msg-phish-1", PHISH)
    sync2 = client.post(f"/api/v1/integrations/accounts/{account_id}/sync",
                        headers=auth_headers(csrf))
    assert sync2.json()["result"]["duplicates"] == 1
    assert sync2.json()["result"]["processed"] == 0

    # A high-risk message should have produced an alert.
    alerts = client.get("/api/v1/alerts")
    assert alerts.json()["total"] >= 1


def test_state_replay_rejected(owner):
    client, csrf = owner
    connect = client.post("/api/v1/integrations/mock_gmail/connect", headers=auth_headers(csrf))
    state = connect.json()["state"]
    first = client.post("/api/v1/integrations/mock_gmail/callback-json",
                        json={"code": "replay@acme-security.com", "state": state},
                        headers=auth_headers(csrf))
    assert first.status_code == 200
    second = client.post("/api/v1/integrations/mock_gmail/callback-json",
                         json={"code": "replay@acme-security.com", "state": state},
                         headers=auth_headers(csrf))
    assert second.status_code == 400


def test_disconnect_clears_tokens(owner):
    client, csrf = owner
    account = _connect(client, csrf, provider="mock_outlook", email="out@acme-security.com")
    account_id = account["id"]
    r = client.post(f"/api/v1/integrations/accounts/{account_id}/disconnect",
                    headers=auth_headers(csrf))
    assert r.status_code == 200
    assert r.json()["account"]["state"] == "disconnected"
    assert r.json()["account"]["monitoring_active"] is False


def test_outlook_validation_handshake(client):
    r = client.get("/api/v1/integrations/outlook/webhook", params={"validationToken": "abc123"})
    assert r.status_code == 200
    assert r.text == "abc123"


def test_outlook_webhook_unverified_rejected(client):
    r = client.post("/api/v1/integrations/outlook/webhook", json={"value": []})
    assert r.status_code == 503


def test_gmail_webhook_unparseable(client):
    r = client.post("/api/v1/integrations/gmail/webhook", json={})
    assert r.status_code == 200
    assert r.json()["accepted"] is False
