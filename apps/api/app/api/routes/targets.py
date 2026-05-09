from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.db import get_session
from app.models import Role, Target, User, Workspace
from app.schemas import TargetCreate
from app.services import audit
from app.services.auth import current_user, require_role

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("", response_model=list[Target])
def list_targets(
    workspace_id: str | None = None,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[Target]:
    query = select(Target).order_by(Target.created_at.desc())
    if workspace_id:
        query = query.where(Target.workspace_id == workspace_id)
    return list(session.exec(query).all())


@router.post("", response_model=Target, status_code=201)
def create_target(
    payload: TargetCreate,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> Target:
    workspace = session.get(Workspace, payload.workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")
    target = Target(**payload.model_dump())
    session.add(target)
    session.commit()
    session.refresh(target)
    audit.record(session, actor=user, action="target.created",
                 target_kind="target", target_id=target.id,
                 payload={"value": target.value, "active_allowed": target.active_allowed})
    session.commit()
    return target
