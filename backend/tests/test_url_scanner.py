from app.modules.phishing.engine import detect_url
from app.modules.phishing.url_analyzer import analyze_url


def rule_ids(analysis):
    return {e.rule_id for e in analysis.evidence}


def test_benign_url_low_score():
    a = analyze_url("https://www.google.com/search?q=weather")
    assert a.score < 20
    assert a.verdict == "benign"


def test_ip_literal_detected():
    a = analyze_url("http://192.168.10.5/login")
    assert "url.host.ip_literal" in rule_ids(a)
    assert a.score >= 30


def test_userinfo_at_trick():
    a = analyze_url("http://google.com@evil.example.com/verify")
    ids = rule_ids(a)
    assert "url.userinfo.at" in ids
    assert a.score >= 28


def test_punycode_detected():
    a = analyze_url("http://xn--pypal-4ve.com/login")
    assert "url.host.punycode" in rule_ids(a)


def test_brand_impersonation():
    a = analyze_url("http://paypal.secure-login-account.xyz/verify")
    ids = rule_ids(a)
    assert "url.host.brand_impersonation" in ids or "url.tld.suspicious" in ids
    assert a.score >= 40


def test_dangerous_scheme():
    a = analyze_url("javascript:alert(1)")
    assert a.score >= 45
    assert a.verdict in {"malicious", "suspicious"}


def test_double_extension():
    a = analyze_url("http://files.example.com/invoice.pdf.exe")
    ids = rule_ids(a)
    assert "url.path.suspicious_extension" in ids
    assert "url.path.double_extension" in ids


def test_invalid_url():
    a = analyze_url("not a url")
    assert a.verdict == "invalid"


def test_detect_url_produces_detection_result():
    result = detect_url("http://paypal-verify.tk/login")
    assert result.module == "url"
    assert result.score > 0
    assert result.severity in {"low", "medium", "high", "critical"}
    assert result.metadata["ml_available"] is False  # ML disabled in tests
    assert any(e.weight > 0 for e in result.evidence)


def test_recommended_action_present():
    result = detect_url("http://192.0.2.10/secure/login")
    assert result.recommended_action
