"""Cryptographic helpers: password hashing, session tokens, token encryption,
signed OAuth state, CSRF tokens and TOTP (RFC 6238) for optional MFA."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import UTC, datetime

import bcrypt
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

_BCRYPT_MAX_BYTES = 72


# --- Passwords -------------------------------------------------------------

def hash_password(password: str) -> str:
    pw = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    if not hashed:
        return False
    try:
        pw = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
        return bcrypt.checkpw(pw, hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


# --- Session & CSRF --------------------------------------------------------

def generate_session_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_csrf_token(session_token: str) -> str:
    """Deterministic, session-bound CSRF token (HMAC). Constant-time compared."""
    mac = hmac.new(settings.secret_key.encode(), f"csrf:{session_token}".encode(), hashlib.sha256)
    return mac.hexdigest()


def verify_csrf_token(session_token: str, candidate: str) -> bool:
    if not candidate:
        return False
    return hmac.compare_digest(generate_csrf_token(session_token), candidate)


# --- Symmetric encryption for provider tokens ------------------------------

def _fernet() -> Fernet:
    key = settings.token_encryption_key
    if not key:
        # Derive a stable key from SECRET_KEY so dev works out of the box.
        digest = hashlib.sha256(settings.secret_key.encode()).digest()
        key = base64.urlsafe_b64encode(digest).decode()
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:  # pragma: no cover - config error path
        raise RuntimeError(
            "TOKEN_ENCRYPTION_KEY is not a valid Fernet key. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet;"
            "print(Fernet.generate_key().decode())\""
        ) from exc


def encrypt_secret(plaintext: str | None) -> str | None:
    if plaintext is None:
        return None
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str | None) -> str | None:
    if not ciphertext:
        return None
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Unable to decrypt stored token (key rotated or data corrupt)") from exc


# --- Signed OAuth state ----------------------------------------------------

def sign_state(payload: str, ttl_seconds: int = 600) -> str:
    """Return ``payload.expiry.signature`` where signature is an HMAC-SHA256."""
    expiry = int(time.time()) + ttl_seconds
    body = f"{payload}.{expiry}"
    sig = hmac.new(settings.secret_key.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_state(state: str) -> tuple[bool, str]:
    """Return (valid, payload). Rejects tampered or expired state."""
    if not state or state.count(".") < 2:
        return False, ""
    parts = state.split(".")
    sig = parts[-1]
    expiry_s = parts[-2]
    payload = ".".join(parts[:-2])
    body = f"{payload}.{expiry_s}"
    expected = hmac.new(settings.secret_key.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return False, ""
    try:
        if int(expiry_s) < int(time.time()):
            return False, ""
    except ValueError:
        return False, ""
    return True, payload


# --- TOTP (optional MFA) ---------------------------------------------------

def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_at(secret: str, counter: int, digits: int = 6) -> str:
    pad = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(pad, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def totp_now(secret: str, at: datetime | None = None, step: int = 30) -> str:
    ts = int((at or datetime.now(UTC)).timestamp())
    return _totp_at(secret, ts // step)


def verify_totp(secret: str, code: str, window: int = 1, at: datetime | None = None) -> bool:
    if not secret or not code:
        return False
    ts = int((at or datetime.now(UTC)).timestamp())
    counter = ts // 30
    for offset in range(-window, window + 1):
        if hmac.compare_digest(_totp_at(secret, counter + offset), str(code)):
            return True
    return False


def totp_provisioning_uri(secret: str, account: str, issuer: str = "PhishShield AI") -> str:
    from urllib.parse import quote

    label = quote(f"{issuer}:{account}")
    return (
        f"otpauth://totp/{label}?secret={secret}"
        f"&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )
