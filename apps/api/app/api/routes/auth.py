from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.db import get_session
from app.models import APIKey, ROLE_RANK, Role, User, now_utc
from app.services import audit
from app.services.auth import (
    current_user,
    hash_password,
    issue_api_token,
    require_role,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=512)
    name: str = Field(default="cli", max_length=120)


class LoginResponse(BaseModel):
    user_id: str
    username: str
    role: Role
    token: str            # returned ONCE — caller must store
    token_prefix: str
    api_key_id: str


class WhoAmI(BaseModel):
    id: str
    username: str
    role: Role
    is_active: bool
    last_login_at: datetime | None


class APIKeyPublic(BaseModel):
    id: str
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class CreateAPIKeyPayload(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class CreateAPIKeyResponse(BaseModel):
    id: str
    token: str
    prefix: str


class CreateUserPayload(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=8, max_length=512)
    role: Role = Role.viewer


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginPayload, session: Session = Depends(get_session)) -> LoginResponse:
    user = session.exec(select(User).where(User.username == payload.username)).first()
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        # Audit failed logins so brute-force attempts leave a trail.
        audit.record(
            session,
            actor=None,
            action="auth.login.failed",
            target_kind="user",
            target_id=payload.username,
            payload={"username": payload.username},
        )
        session.commit()
        raise HTTPException(401, "Invalid credentials")

    token, prefix, digest = issue_api_token()
    api_key = APIKey(user_id=user.id, name=payload.name, prefix=prefix, token_sha256=digest)
    session.add(api_key)
    user.last_login_at = now_utc()
    session.add(user)
    session.commit()
    session.refresh(api_key)

    audit.record(
        session,
        actor=user,
        action="auth.login.success",
        target_kind="api_key",
        target_id=api_key.id,
        payload={"prefix": prefix, "name": payload.name},
    )
    session.commit()
    return LoginResponse(
        user_id=user.id, username=user.username, role=user.role,
        token=token, token_prefix=prefix, api_key_id=api_key.id,
    )


@router.get("/me", response_model=WhoAmI)
def whoami(user: User = Depends(current_user)) -> WhoAmI:
    return WhoAmI(
        id=user.id, username=user.username, role=user.role,
        is_active=user.is_active, last_login_at=user.last_login_at,
    )


@router.get("/api-keys", response_model=list[APIKeyPublic])
def list_api_keys(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> list[APIKeyPublic]:
    keys = session.exec(select(APIKey).where(APIKey.user_id == user.id)
                          .order_by(APIKey.created_at.desc())).all()
    return [APIKeyPublic.model_validate(k.model_dump()) for k in keys]


@router.post("/api-keys", response_model=CreateAPIKeyResponse, status_code=201)
def create_api_key(
    payload: CreateAPIKeyPayload,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> CreateAPIKeyResponse:
    token, prefix, digest = issue_api_token()
    api_key = APIKey(user_id=user.id, name=payload.name, prefix=prefix, token_sha256=digest)
    session.add(api_key)
    session.commit()
    session.refresh(api_key)
    audit.record(
        session, actor=user, action="auth.api_key.created",
        target_kind="api_key", target_id=api_key.id,
        payload={"name": payload.name, "prefix": prefix},
    )
    session.commit()
    return CreateAPIKeyResponse(id=api_key.id, token=token, prefix=prefix)


@router.delete("/api-keys/{api_key_id}", status_code=204)
def revoke_api_key(
    api_key_id: str,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> None:
    api_key = session.get(APIKey, api_key_id)
    # Owner OR admin may revoke. Anyone else gets 404 (avoid existence oracle).
    if not api_key or (api_key.user_id != user.id and ROLE_RANK[user.role] < ROLE_RANK[Role.admin]):
        raise HTTPException(404, "API key not found")
    if api_key.revoked_at is None:
        api_key.revoked_at = now_utc()
        session.add(api_key)
        session.commit()
    audit.record(
        session, actor=user, action="auth.api_key.revoked",
        target_kind="api_key", target_id=api_key.id, payload={},
    )
    session.commit()


@router.post("/users", response_model=WhoAmI, status_code=201,
             dependencies=[Depends(require_role(Role.admin))])
def create_user(
    payload: CreateUserPayload,
    actor: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> WhoAmI:
    if session.exec(select(User).where(User.username == payload.username)).first():
        raise HTTPException(409, "Username already exists")
    user = User(username=payload.username, password_hash=hash_password(payload.password),
                role=payload.role, is_active=True)
    session.add(user)
    session.commit()
    session.refresh(user)
    audit.record(
        session, actor=actor, action="auth.user.created",
        target_kind="user", target_id=user.id,
        payload={"username": user.username, "role": user.role.value},
    )
    session.commit()
    return WhoAmI(
        id=user.id, username=user.username, role=user.role,
        is_active=user.is_active, last_login_at=user.last_login_at,
    )


@router.get("/audit", dependencies=[Depends(require_role(Role.admin))])
def list_audit(
    session: Session = Depends(get_session),
    limit: int = 100,
) -> dict[str, Any]:
    from app.models import AuditEvent
    rows = session.exec(
        select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(limit)
    ).all()
    breaks = audit.verify_chain(session)
    return {
        "ok": not breaks,
        "breaks": [{"sequence": b.sequence, "reason": b.reason} for b in breaks],
        "events": [r.model_dump() for r in rows],
    }
