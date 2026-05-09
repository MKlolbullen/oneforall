"""Authentication primitives.

- Password storage: PBKDF2-HMAC-SHA256 with 200k iterations and a random salt.
  Stored as `pbkdf2_sha256$<iters>$<b64(salt)>$<b64(hash)>`.
- API tokens: a random 32-byte secret is shown once. Only the prefix and the
  sha256 of the full token are persisted.
- Request authorization: a FastAPI dependency `current_user` resolves the
  caller from either an `Authorization: Bearer <token>` header or — for local
  unit tests — a transient X-Test-User header. require_role() enforces the
  minimum role rank.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone
from typing import Annotated, Callable

from fastapi import Depends, Header, HTTPException, status
from sqlmodel import Session, select

from app.db import get_session
from app.models import APIKey, ROLE_RANK, Role, User, now_utc

PBKDF2_ITERATIONS = 200_000
PBKDF2_DIGEST = "sha256"
TOKEN_PREFIX_LEN = 8


# ---------------------------- Password hashing ----------------------------

def hash_password(password: str) -> str:
    if not password:
        raise ValueError("password must be non-empty")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(PBKDF2_DIGEST, password.encode("utf-8"),
                                  salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    try:
        method, iters, salt_b64, hash_b64 = stored.split("$", 3)
    except ValueError:
        return False
    if method != "pbkdf2_sha256":
        return False
    try:
        iterations = int(iters)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except Exception:  # noqa: BLE001 — any decode failure is just a bad hash
        return False
    candidate = hashlib.pbkdf2_hmac(PBKDF2_DIGEST, password.encode("utf-8"),
                                     salt, iterations)
    return hmac.compare_digest(candidate, expected)


# ---------------------------- API tokens ----------------------------

def issue_api_token() -> tuple[str, str, str]:
    """Generate a new (token, prefix, sha256(token)) tuple. Caller is
    responsible for persisting the prefix + sha256 — never the token itself.
    The plaintext token is returned once and shown to the user."""
    token = "rcf_" + secrets.token_urlsafe(32)
    prefix = token[:TOKEN_PREFIX_LEN]
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, prefix, digest


def hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------- User bootstrap ----------------------------

def ensure_admin(session: Session, *, username: str, password: str) -> User:
    """Create-or-update an admin user. Used for first-boot seed and tests."""
    existing = session.exec(select(User).where(User.username == username)).first()
    if existing:
        existing.password_hash = hash_password(password)
        existing.role = Role.admin
        existing.is_active = True
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing
    user = User(username=username, password_hash=hash_password(password),
                role=Role.admin, is_active=True)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


# ---------------------------- Request resolution ----------------------------

def _resolve_bearer(session: Session, token: str) -> User | None:
    digest = hash_api_token(token)
    api_key = session.exec(select(APIKey).where(APIKey.token_sha256 == digest)).first()
    if not api_key or api_key.revoked_at is not None:
        return None
    user = session.get(User, api_key.user_id)
    if not user or not user.is_active:
        return None
    api_key.last_used_at = now_utc()
    session.add(api_key)
    session.commit()
    return user


def _allow_test_bypass() -> bool:
    return os.getenv("RECONFORGE_TEST_AUTH_BYPASS") == "1"


def current_user(
    authorization: Annotated[str | None, Header()] = None,
    x_test_user: Annotated[str | None, Header()] = None,
    session: Session = Depends(get_session),
) -> User:
    """Resolve the calling user. Bearer token first; X-Test-User header is
    only honored when RECONFORGE_TEST_AUTH_BYPASS=1 (set by the test harness
    only — never in production)."""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(None, 1)[1].strip()
        user = _resolve_bearer(session, token)
        if not user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid bearer token")
        return user

    if x_test_user and _allow_test_bypass():
        # x_test_user format: "<username>" — must already exist, must be active.
        user = session.exec(select(User).where(User.username == x_test_user)).first()
        if user and user.is_active:
            return user
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            f"unknown or inactive test user {x_test_user!r}")

    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")


def optional_user(
    authorization: Annotated[str | None, Header()] = None,
    x_test_user: Annotated[str | None, Header()] = None,
    session: Session = Depends(get_session),
) -> User | None:
    """Same as current_user but returns None instead of raising. Useful for
    endpoints that may degrade gracefully (e.g. /health)."""
    try:
        return current_user(authorization, x_test_user, session)
    except HTTPException:
        return None


def require_role(min_role: Role) -> Callable[..., User]:
    """Build a dependency that enforces the minimum role rank."""
    def _check(user: User = Depends(current_user)) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[min_role]:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"role '{user.role.value}' lacks privilege; need >= {min_role.value}",
            )
        return user
    return _check
