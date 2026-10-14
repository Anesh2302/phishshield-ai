
from app.core.logging import redact_text
from app.core.security import (
    decrypt_secret,
    encrypt_secret,
    generate_csrf_token,
    generate_totp_secret,
    hash_password,
    sign_state,
    totp_now,
    verify_csrf_token,
    verify_password,
    verify_state,
    verify_totp,
)


def test_password_hashing_roundtrip():
    h = hash_password("correct horse battery staple")
    assert h != "correct horse battery staple"
    assert verify_password("correct horse battery staple", h)
    assert not verify_password("wrong", h)


def test_token_encryption_roundtrip():
    ct = encrypt_secret("refresh-token-abc")
    assert ct != "refresh-token-abc"
    assert decrypt_secret(ct) == "refresh-token-abc"


def test_csrf_binding():
    token = generate_csrf_token("session-123")
    assert verify_csrf_token("session-123", token)
    assert not verify_csrf_token("session-999", token)


def test_signed_state_rejects_tampering_and_expiry():
    state = sign_state("gmail:user:tenant", ttl_seconds=600)
    ok, payload = verify_state(state)
    assert ok and payload == "gmail:user:tenant"
    # tamper
    ok, _ = verify_state(state[:-1] + ("0" if state[-1] != "0" else "1"))
    assert not ok
    # expired
    expired = sign_state("gmail:user:tenant", ttl_seconds=-10)
    ok, _ = verify_state(expired)
    assert not ok


def test_totp_verification():
    secret = generate_totp_secret()
    assert verify_totp(secret, totp_now(secret))
    assert not verify_totp(secret, "000000")


def test_redaction_of_secrets():
    text = "Authorization: Bearer abc.def.ghi password=hunter2 api_key=XYZ123"
    redacted = redact_text(text)
    assert "hunter2" not in redacted
    assert "XYZ123" not in redacted
    assert "abc.def.ghi" not in redacted


def test_redaction_of_dict():
    from app.core.logging import _redact_obj

    out = _redact_obj({"refresh_token": "secret-value", "ok": "visible"})
    assert out["refresh_token"] == "***REDACTED***"
    assert out["ok"] == "visible"


def test_password_truncation_at_bcrypt_limit():
    long_pw = "a" * 200
    h = hash_password(long_pw)
    assert verify_password(long_pw, h)
