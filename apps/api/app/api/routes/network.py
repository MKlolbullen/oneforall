"""Per-run HTTP traffic browser.

Exposes captured HttpExchange rows for a run, with filters that match the
common Burp-style use cases: by host, by status code, by HTTP method, by step
index. Pagination uses simple before/limit cursors on the started_at index so
viewing a busy run's traffic stays bounded.

All read endpoints are viewer+; the rows themselves are only ever produced by
the runner, so there's no POST surface here.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlmodel import Session, select, func

from app.db import get_session
from app.models import HttpExchange, Run, User
from app.services.auth import current_user

router = APIRouter(prefix="/runs", tags=["network"])


class HttpExchangeSummary(BaseModel):
    id: str
    started_at: str
    method: str
    url: str
    host: str
    response_status: int | None
    response_size_bytes: int | None
    duration_ms: int | None
    step_index: int | None
    tool_id: str | None
    error: str | None


class HttpExchangeDetail(HttpExchangeSummary):
    request_headers: dict[str, Any] = Field(default_factory=dict)
    request_body: str = ""
    request_body_truncated: bool = False
    response_headers: dict[str, Any] = Field(default_factory=dict)
    response_body: str = ""
    response_body_truncated: bool = False


class NetworkPage(BaseModel):
    total: int
    items: list[HttpExchangeSummary]
    hosts: list[str]              # distinct hosts seen so the UI can populate a filter dropdown
    methods: list[str]
    statuses: list[int]


def _summary(row: HttpExchange) -> HttpExchangeSummary:
    return HttpExchangeSummary(
        id=row.id,
        started_at=row.started_at.isoformat(),
        method=row.method,
        url=row.url,
        host=row.host,
        response_status=row.response_status,
        response_size_bytes=row.response_size_bytes,
        duration_ms=row.duration_ms,
        step_index=row.step_index,
        tool_id=row.tool_id,
        error=row.error,
    )


def _ensure_run(session: Session, run_id: str) -> Run:
    run = session.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    return run


@router.get("/{run_id}/network", response_model=NetworkPage)
def get_run_network(
    run_id: str,
    host: str | None = Query(None),
    method: str | None = Query(None),
    status_code: int | None = Query(None, alias="status"),
    step_index: int | None = Query(None, alias="step"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> NetworkPage:
    _ensure_run(session, run_id)

    base = select(HttpExchange).where(HttpExchange.run_id == run_id)
    count_q = select(func.count(HttpExchange.id)).where(HttpExchange.run_id == run_id)
    if host:
        base = base.where(HttpExchange.host == host)
        count_q = count_q.where(HttpExchange.host == host)
    if method:
        base = base.where(HttpExchange.method == method.upper())
        count_q = count_q.where(HttpExchange.method == method.upper())
    if status_code is not None:
        base = base.where(HttpExchange.response_status == status_code)
        count_q = count_q.where(HttpExchange.response_status == status_code)
    if step_index is not None:
        base = base.where(HttpExchange.step_index == step_index)
        count_q = count_q.where(HttpExchange.step_index == step_index)

    total = int(session.exec(count_q).one() or 0)
    rows = list(session.exec(
        base.order_by(HttpExchange.started_at.desc()).offset(offset).limit(limit)
    ).all())

    # Distinct host/method/status across the whole run (no filters) so the UI
    # can offer dropdowns even if the current view is filtered.
    hosts = list(session.exec(
        select(HttpExchange.host).where(HttpExchange.run_id == run_id).distinct()
    ).all())
    methods = list(session.exec(
        select(HttpExchange.method).where(HttpExchange.run_id == run_id).distinct()
    ).all())
    statuses_raw = list(session.exec(
        select(HttpExchange.response_status).where(
            HttpExchange.run_id == run_id, HttpExchange.response_status.is_not(None)  # type: ignore[union-attr]
        ).distinct()
    ).all())
    statuses = sorted(int(s) for s in statuses_raw if s is not None)

    return NetworkPage(
        total=total,
        items=[_summary(r) for r in rows],
        hosts=sorted(h for h in hosts if h),
        methods=sorted(m for m in methods if m),
        statuses=statuses,
    )


@router.get("/{run_id}/network/{exchange_id}", response_model=HttpExchangeDetail)
def get_run_exchange(
    run_id: str,
    exchange_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> HttpExchangeDetail:
    row = session.get(HttpExchange, exchange_id)
    if not row or row.run_id != run_id:
        raise HTTPException(404, "Exchange not found")
    return HttpExchangeDetail(
        **_summary(row).model_dump(),
        request_headers=row.request_headers or {},
        request_body=row.request_body,
        request_body_truncated=row.request_body_truncated,
        response_headers=row.response_headers or {},
        response_body=row.response_body,
        response_body_truncated=row.response_body_truncated,
    )
