"""FastAPI dependencies: authentication, authorization, tenant scoping, CSRF."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import hash_token, verify_csrf_token
from app.models import Tenant, User, UserSession

ROLE_ORDER = {"viewer": 1, "analyst": 2, "admin": 3, "owner": 4}


@dataclass
class AuthContext:
    user: User
    session: UserSession
    tenant: Tenant

    @property
    def tenant_id(self) -> str:
        return self.tenant.id

    @property
    def user_id(self) -> str:
        return self.user.id

    @property
    def role(self) -> str:
        return self.user.role


def _session_cookie_name() -> str:
    return settings.session_cookie_name


def get_auth_context(
    request: Request,
    db: Session = Depends(get_db),
    session_cookie: str | None = Cookie(default=None, alias=settings.session_cookie_name),
) -> AuthContext:
    token = session_cookie
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")

    sess = db.execute(
        select(UserSession).where(UserSession.token_hash == hash_token(token))
    ).scalar_one_or_none()
    if sess is None or sess.revoked:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked session")
    expires = sess.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if expires < datetime.now(UTC):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")

    user = db.get(User, sess.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User inactive")
    tenant = db.get(Tenant, user.tenant_id)
    if tenant is None or not tenant.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Tenant inactive")

    sess.last_seen_at = datetime.now(UTC)
    db.commit()
    return AuthContext(user=user, session=sess, tenant=tenant)


def require_role(minimum: str):
    """Dependency factory enforcing a minimum role within the user's tenant."""

    def _checker(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if ROLE_ORDER.get(ctx.role, 0) < ROLE_ORDER.get(minimum, 99):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient privileges")
        return ctx

    return _checker


def require_csrf(
    request: Request,
    ctx: AuthContext = Depends(get_auth_context),
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> AuthContext:
    """CSRF protection for state-changing cookie-authenticated requests.

    Bearer-token (non-cookie) clients are exempt because they do not rely on
    ambient browser credentials.
    """
    used_cookie = request.cookies.get(_session_cookie_name()) is not None
    if used_cookie:
        # CSRF token is bound to the (opaque, server-side) session id.
        if not verify_csrf_token(ctx.session.id, x_csrf_token or ""):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid CSRF token")
    return ctx


def tenant_scope(query, ctx: AuthContext, model):
    """Apply tenant isolation to a SQLAlchemy select for a tenant-scoped model."""
    return query.where(model.tenant_id == ctx.tenant_id)
