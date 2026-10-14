from app.modules.email_security.analyzer import analyze_email
from tests.conftest import auth_headers

BENIGN = """From: Alice Smith <alice@example.com>
To: bob@example.com
Subject: Lunch tomorrow?
Message-ID: <benign-1@example.com>
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain

Hi Bob, are we still on for lunch tomorrow at noon? Thanks, Alice
"""

PHISH = """From: "PayPal Security" <attacker@evil-domain.tk>
Reply-To: harvest@another-evil.tk
Subject: URGENT: Verify your account immediately
Message-ID: <phish-1@evil-domain.tk>
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/html

<html><body>
<p>Your account is suspended. Click below to confirm your identity within 24 hours.</p>
<p><a href="http://paypal.secure-verify-account.tk/login?update=password">Verify now</a></p>
<p>Please update your payment and enter your password and credit card.</p>
</body></html>
"""


def rules(result):
    return {e.rule_id for e in result.evidence}


def test_benign_email_low_score():
    r = analyze_email(BENIGN)
    assert r.score < 20
    assert r.verdict == "benign"


def test_phishing_email_high_score():
    r = analyze_email(PHISH)
    assert r.score >= 65
    assert r.verdict in {"malicious", "suspicious"}
    ids = rules(r)
    assert "email.sender.display_name_impersonation" in ids
    assert "email.auth.dmarc_fail" in ids
    assert "email.replyto.mismatch" in ids


def test_email_body_not_stored_by_default():
    r = analyze_email(PHISH)
    assert r.metadata["body_stored"] is False
    # full body must not be present in the result metadata
    assert "verify now" not in str(r.metadata).lower()


def test_missing_auth_results_is_informational_only():
    raw = "From: a@example.com\nSubject: hi\nMessage-ID: <x@example.com>\n\nhello"
    r = analyze_email(raw)
    ids = rules(r)
    assert "email.auth.missing" in ids
    assert r.score < 40


def test_risky_attachment_detected():
    raw = (
        "From: a@example.com\nSubject: invoice\nMessage-ID: <att@example.com>\n"
        "Content-Type: multipart/mixed; boundary=XYZ\n\n"
        "--XYZ\nContent-Type: text/plain\n\nsee attached\n"
        "--XYZ\nContent-Type: application/octet-stream\n"
        "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\n\nTVqQAAMAAAA=\n--XYZ--\n"
    )
    r = analyze_email(raw)
    assert "email.attachment.risky_type" in rules(r)


def test_email_analyze_api(owner):
    client, csrf = owner
    r = client.post("/api/v1/emails/analyze", json={"raw": PHISH}, headers=auth_headers(csrf))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["result"]["score"] >= 65
    assert body["scan_id"]


def test_email_scan_listing_is_tenant_scoped(owner):
    client, csrf = owner
    client.post("/api/v1/emails/analyze", json={"raw": BENIGN}, headers=auth_headers(csrf))
    r = client.get("/api/v1/emails/scans")
    assert r.status_code == 200
    assert r.json()["total"] >= 1
