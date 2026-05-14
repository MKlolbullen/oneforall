from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.db import get_session
from app.models import Advice, Finding, Role, Run, Target, User
from app.services import advisor
from app.services.auth import current_user, require_role

router = APIRouter(prefix="/advisor", tags=["advisor"])


class AdviceRead(BaseModel):
    id: str
    workspace_id: str
    kind: str
    ref_id: str | None
    actor_id: str | None
    model: str
    prompt_tokens: int
    completion_tokens: int
    cached_tokens: int
    summary: str
    body: dict[str, Any] = Field(default_factory=dict)


class AskPayload(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    workspace_id: str
    run_id: str | None = None
    target_id: str | None = None


def _ensure_configured() -> None:
    if not advisor.is_configured():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Claude advisor is not configured (ANTHROPIC_API_KEY not set).",
        )


def _to_read(advice: Advice) -> AdviceRead:
    return AdviceRead.model_validate(advice.model_dump())


@router.get("/runs/{run_id}/triage", response_model=AdviceRead | None)
def get_run_triage(
    run_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> AdviceRead | None:
    """Return the cached triage for a run, or 204 if none has been requested yet."""
    advice = session.exec(
        select(Advice).where(Advice.kind == "run_triage", Advice.ref_id == run_id)
    ).first()
    return _to_read(advice) if advice else None


@router.post("/runs/{run_id}/triage", response_model=AdviceRead, status_code=201)
def post_run_triage(
    run_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> AdviceRead:
    _ensure_configured()
    run = session.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    advice = advisor.triage_run(session, run, actor=user)
    return _to_read(advice)


@router.get("/targets/{target_id}/suggest-profile", response_model=AdviceRead | None)
def get_suggest_profile(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> AdviceRead | None:
    advice = session.exec(
        select(Advice).where(
            Advice.kind == "target_suggest_profile", Advice.ref_id == target_id
        )
    ).first()
    return _to_read(advice) if advice else None


@router.post("/targets/{target_id}/suggest-profile",
             response_model=AdviceRead, status_code=201)
def post_suggest_profile(
    target_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> AdviceRead:
    _ensure_configured()
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    advice = advisor.suggest_profile(session, target, actor=user)
    return _to_read(advice)


@router.get("/targets/{target_id}/analyze", response_model=AdviceRead | None)
def get_target_analysis(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> AdviceRead | None:
    advice = session.exec(
        select(Advice).where(
            Advice.kind == "target_analysis", Advice.ref_id == target_id
        )
    ).first()
    return _to_read(advice) if advice else None


@router.post("/targets/{target_id}/analyze",
             response_model=AdviceRead, status_code=201)
def post_target_analysis(
    target_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> AdviceRead:
    _ensure_configured()
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    advice = advisor.analyze_target(session, target, actor=user)
    return _to_read(advice)


@router.get("/findings/{finding_id}/explain", response_model=AdviceRead | None)
def get_finding_explain(
    finding_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> AdviceRead | None:
    advice = session.exec(
        select(Advice).where(Advice.kind == "finding_explain", Advice.ref_id == finding_id)
    ).first()
    return _to_read(advice) if advice else None


@router.post("/findings/{finding_id}/explain",
             response_model=AdviceRead, status_code=201)
def post_finding_explain(
    finding_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> AdviceRead:
    _ensure_configured()
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    advice = advisor.explain_finding(session, finding, actor=user)
    return _to_read(advice)


@router.get("/findings/{finding_id}/pivot", response_model=AdviceRead | None)
def get_finding_pivot(
    finding_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> AdviceRead | None:
    advice = session.exec(
        select(Advice).where(Advice.kind == "finding_pivot",
                              Advice.ref_id == finding_id)
    ).first()
    return _to_read(advice) if advice else None


@router.post("/findings/{finding_id}/pivot",
             response_model=AdviceRead, status_code=201)
def post_finding_pivot(
    finding_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> AdviceRead:
    _ensure_configured()
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    advice = advisor.pivot_from_finding(session, finding, actor=user)
    return _to_read(advice)


@router.post("/ask", response_model=AdviceRead, status_code=201)
def post_ask(
    payload: AskPayload,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> AdviceRead:
    _ensure_configured()
    advice = advisor.ask(
        session,
        workspace_id=payload.workspace_id,
        question=payload.question,
        run_id=payload.run_id,
        target_id=payload.target_id,
        actor=user,
    )
    return _to_read(advice)
