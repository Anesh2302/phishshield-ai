"""Authentication, session, MFA and user-management endpoints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit, record_identity_event
from app.core.config import settings
from app.core.database import get_db
from app.core.deps import AuthContext, get_auth_context, require_role
from app.core.rate_limit import RateLimiter, client_ip, rate_limit_dependency
from app.core.security import (
    generate_csrf_token,
    generate_session_token,
    generate_totp_secret,
    hash_password,
    hash_token,
    totp_provisioning_uri,
    verify_password,
    verify_totp,
)
from app.models import DeviceRegistration, Tenant, User, UserSession

router = APIRouter(prefix="/auth", tags=["auth"])

_login_limiter = RateLimiter(settings.login_rate_limit_per_minute, 60)


class BootstrapIn(BaseModel):
    tenant_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    full_name: str = Field(default="", max_length=200)
    password: str = Field(min_length=10, max_length=200)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)
    mfa_code: str | None = None


class UserCreateIn(BaseModel):
    email: EmailStr
    full_name: str = ""
    password: str = Field(min_length=10, max_length=200)
    role: str = "analyst"


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=200)


class MfaCodeIn(BaseModel):
    code: str


class SessionOut(BaseModel):
    id: str
    ip: str | None
    user_agent: str | None
    device_label: str | None
    created_at: datetime
    last_seen_at: datetime | None
    expires_at: datetime
    current: bool = False


def _set_session_cookie(response: Response, token: str, expires: datetime) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        expires=expires,
        path="/",
    )


def _new_session(db: Session, user: User, request: Request) -> tuple[str, str, datetime]:
    token = generate_session_token()
    expires = datetime.now(UTC) + timedelta(minutes=settings.session_ttl_minutes)
    sess = UserSession(
        user_id=user.id,
        tenant_id=user.tenant_id,
        token_hash=hash_token(token),
        csrf_token="",  # set below (bound to session id)
        expires_at=expires,
        ip=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:400] or None,
        last_seen_at=datetime.now(UTC),
    )
    db.add(sess)
    db.flush()
    csrf = generate_csrf_token(sess.id)
    sess.csrf_token = csrf
    db.commit()
    return token, csrf, expires


@router.get("/bootstrap-status")
def bootstrap_status(db: Session = Depends(get_db)) -> dict:
    count = db.execute(select(func.count()).select_from(User)).scalar_one()
    return {"needs_bootstrap": count == 0}


@router.post("/bootstrap", status_code=201)
def bootstrap(
    payload: BootstrapIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict:
    count = db.execute(select(func.count()).select_from(User)).scalar_one()
    if count > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "System already initialized")
    tenant = Tenant(name=payload.tenant_name)
    db.add(tenant)
    db.flush()
    user = User(
        tenant_id=tenant.id,
        email=str(payload.email).lower(),
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role="owner",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    record_audit(
        db, action="auth.bootstrap", tenant_id=tenant.id, user_id=user.id,
        resource_type="tenant", resource_id=tenant.id,
    )
    token, csrf, expires = _new_session(db, user, request)
    _set_session_cookie(response, token, expires)
    return {"csrf_token": csrf, "user_id": user.id, "role": user.role, "tenant_id": tenant.id}


@router.post("/login", dependencies=[Depends(rate_limit_dependency(_login_limiter))])
def login(
    payload: LoginIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict:
    email = str(payload.email).lower()
    users = db.execute(select(User).where(User.email == email)).scalars().all()
    # Constant-ish work to reduce user-enumeration via timing.
    candidate = next((u for u in users if u.is_active), None)
    if candidate is None or not verify_password(payload.password, candidate.hashed_password):
        if users:
            record_identity_event(
                db, event_type="login", tenant_id=users[0].tenant_id, user_id=users[0].id,
                email=email, success=False, ip=client_ip(request),
                user_agent=request.headers.get("user-agent"),
            )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    if candidate.mfa_enabled:
        if not payload.mfa_code or not verify_totp(candidate.mfa_secret or "", payload.mfa_code):
            record_identity_event(
                db, event_type="mfa", tenant_id=candidate.tenant_id, user_id=candidate.id,
                email=email, success=False, ip=client_ip(request),
                user_agent=request.headers.get("user-agent"),
            )
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing MFA code")

    candidate.last_login_at = datetime.now(UTC)
    token, csrf, expires = _new_session(db, candidate, request)
    record_identity_event(
        db, event_type="login", tenant_id=candidate.tenant_id, user_id=candidate.id,
        email=email, success=True, ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    _set_session_cookie(response, token, expires)
    return {
        "csrf_token": csrf,
        "user_id": candidate.id,
        "role": candidate.role,
        "tenant_id": candidate.tenant_id,
        "mfa_enabled": candidate.mfa_enabled,
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict:
    ctx.session.revoked = True
    record_identity_event(
        db, event_type="logout", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
        email=ctx.user.email, success=True, ip=client_ip(request),
        user_agent=request.headers.get("user-agent"), commit=False,
    )
    db.commit()
    response.delete_cookie(settings.session_cookie_name, path="/")
    return {"detail": "logged out"}


class MeOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    tenant_id: str
    tenant_name: str
    mfa_enabled: bool


@router.get("/me", response_model=MeOut)
def me(ctx: AuthContext = Depends(get_auth_context)) -> MeOut:
    return MeOut(
        id=ctx.user.id,
        email=ctx.user.email,
        full_name=ctx.user.full_name,
        role=ctx.user.role,
        tenant_id=ctx.tenant_id,
        tenant_name=ctx.tenant.name,
        mfa_enabled=ctx.user.mfa_enabled,
    )


@router.get("/csrf")
def csrf(ctx: AuthContext = Depends(get_auth_context)) -> dict:
    return {"csrf_token": generate_csrf_token(ctx.session.id)}


@router.post("/change-password")
def change_password(
    payload: ChangePasswordIn,
    request: Request,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict:
    if not verify_password(payload.current_password, ctx.user.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    ctx.user.hashed_password = hash_password(payload.new_password)
    record_audit(
        db, action="auth.password.change", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
        resource_type="user", resource_id=ctx.user_id, commit=False,
    )
    record_identity_event(
        db, event_type="password_change", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
        email=ctx.user.email, ip=client_ip(request), commit=False,
    )
    db.commit()
    return {"detail": "password changed"}


@router.post("/mfa/setup")
def mfa_setup(ctx: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    secret = generate_totp_secret()
    ctx.user.mfa_secret = secret
    ctx.user.mfa_enabled = False
    db.commit()
    return {
        "secret": secret,
        "otpauth_uri": totp_provisioning_uri(secret, ctx.user.email),
        "detail": "Scan the URI with an authenticator app, then confirm with /auth/mfa/enable.",
    }


@router.post("/mfa/enable")
def mfa_enable(
    payload: MfaCodeIn,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict:
    if not ctx.user.mfa_secret or not verify_totp(ctx.user.mfa_secret, payload.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid MFA code")
    ctx.user.mfa_enabled = True
    record_audit(
        db, action="auth.mfa.enable", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
        resource_type="user", resource_id=ctx.user_id, commit=False,
    )
    db.commit()
    return {"detail": "MFA enabled", "mfa_enabled": True}


@router.post("/mfa/disable")
def mfa_disable(
    payload: MfaCodeIn,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict:
    if ctx.user.mfa_enabled and not verify_totp(ctx.user.mfa_secret or "", payload.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid MFA code")
    ctx.user.mfa_enabled = False
    ctx.user.mfa_secret = None
    record_audit(
        db, action="auth.mfa.disable", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
        resource_type="user", resource_id=ctx.user_id, commit=False,
    )
    db.commit()
    return {"detail": "MFA disabled", "mfa_enabled": False}


@router.post("/users", status_code=201, dependencies=[Depends(require_role("admin"))])
def create_user(
    payload: UserCreateIn,
    ctx: AuthContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    if payload.role not in {"viewer", "analyst", "admin", "owner"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid role")
    if payload.role == "owner" and ctx.role != "owner":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an owner can create owners")
    exists = db.execute(
        select(User).where(User.tenant_id == ctx.tenant_id, User.email == str(payload.email).lower())
    ).scalar_one_or_none()
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "User already exists in tenant")
    user = User(
        tenant_id=ctx.tenant_id,
        email=str(payload.email).lower(),
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    record_audit(
        db, action="user.create", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
        resource_type="user", resource_id=user.id, detail={"role": payload.role}, commit=False,
    )
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role}


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(
    ctx: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)
) -> list[SessionOut]:
    rows = db.execute(
        select(UserSession)
        .where(UserSession.user_id == ctx.user_id, UserSession.revoked.is_(False))
        .order_by(UserSession.created_at.desc())
    ).scalars().all()
    return [
        SessionOut(
            id=s.id, ip=s.ip, user_agent=s.user_agent, device_label=s.device_label,
            created_at=s.created_at, last_seen_at=s.last_seen_at, expires_at=s.expires_at,
            current=(s.id == ctx.session.id),
        )
        for s in rows
    ]


@router.post("/sessions/{session_id}/revoke")
def revoke_session(
    session_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict:
    sess = db.get(UserSession, session_id)
    if sess is None or sess.user_id != ctx.user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    sess.revoked = True
    record_audit(
        db, action="session.revoke", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
        resource_type="session", resource_id=sess.id, commit=False,
    )
    db.commit()
    return {"detail": "session revoked"}


@router.get("/devices")
def list_devices(
    ctx: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)
) -> list[dict]:
    rows = db.execute(
        select(DeviceRegistration).where(
            DeviceRegistration.user_id == ctx.user_id, DeviceRegistration.revoked.is_(False)
        )
    ).scalars().all()
    return [
        {
            "id": d.id, "platform": d.platform, "device_label": d.device_label,
            "last_seen_at": d.last_seen_at, "created_at": d.created_at,
        }
        for d in rows
    ]
