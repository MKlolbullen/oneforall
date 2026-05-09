from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.db import get_session
from app.models import Target, Workspace
from app.schemas import TargetCreate

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("", response_model=list[Target])
def list_targets(workspace_id: str | None = None, session: Session = Depends(get_session)) -> list[Target]:
    query = select(Target).order_by(Target.created_at.desc())
    if workspace_id:
        query = query.where(Target.workspace_id == workspace_id)
    return list(session.exec(query).all())


@router.post("", response_model=Target, status_code=201)
def create_target(payload: TargetCreate, session: Session = Depends(get_session)) -> Target:
    workspace = session.get(Workspace, payload.workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")
    target = Target(**payload.model_dump())
    session.add(target)
    session.commit()
    session.refresh(target)
    return target
