from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.db import get_session
from app.models import Workspace
from app.schemas import WorkspaceCreate

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


@router.get("", response_model=list[Workspace])
def list_workspaces(session: Session = Depends(get_session)) -> list[Workspace]:
    return list(session.exec(select(Workspace).order_by(Workspace.created_at.desc())).all())


@router.post("", response_model=Workspace, status_code=201)
def create_workspace(payload: WorkspaceCreate, session: Session = Depends(get_session)) -> Workspace:
    workspace = Workspace(name=payload.name, description=payload.description)
    session.add(workspace)
    session.commit()
    session.refresh(workspace)
    return workspace


@router.get("/{workspace_id}", response_model=Workspace)
def get_workspace(workspace_id: str, session: Session = Depends(get_session)) -> Workspace:
    workspace = session.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return workspace
