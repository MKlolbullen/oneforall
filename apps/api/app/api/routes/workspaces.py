from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.db import get_session
from app.models import Role, User, Workspace
from app.schemas import WorkspaceCreate
from app.services import audit
from app.services.auth import current_user, require_role

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


@router.get("", response_model=list[Workspace])
def list_workspaces(
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[Workspace]:
    return list(session.exec(select(Workspace).order_by(Workspace.created_at.desc())).all())


@router.post("", response_model=Workspace, status_code=201)
def create_workspace(
    payload: WorkspaceCreate,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.admin)),
) -> Workspace:
    workspace = Workspace(name=payload.name, description=payload.description)
    session.add(workspace)
    session.commit()
    session.refresh(workspace)
    audit.record(session, actor=user, action="workspace.created",
                 target_kind="workspace", target_id=workspace.id,
                 payload={"name": workspace.name})
    session.commit()
    return workspace


@router.get("/{workspace_id}", response_model=Workspace)
def get_workspace(
    workspace_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> Workspace:
    workspace = session.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return workspace
