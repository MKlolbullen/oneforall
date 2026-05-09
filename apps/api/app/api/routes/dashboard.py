from fastapi import APIRouter, Depends
from sqlmodel import Session, select, func

from app.db import get_session
from app.models import Asset, Finding, Run, Target, Workspace
from app.schemas import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
def stats(session: Session = Depends(get_session)) -> DashboardStats:
    def count(model):
        return session.exec(select(func.count()).select_from(model)).one()

    open_findings = session.exec(
        select(func.count()).select_from(Finding).where(Finding.status != "closed")
    ).one()
    return DashboardStats(
        workspaces=count(Workspace),
        targets=count(Target),
        runs=count(Run),
        assets=count(Asset),
        findings=count(Finding),
        open_findings=open_findings,
    )
