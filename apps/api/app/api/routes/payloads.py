"""Payload library — read-only listing + per-file fetch with on-the-fly
encoding (raw / url / url2 / base64 / hex / html / unicode).

Operators use this to grab quick payload sets for dalfox/xsstrike/nuclei
flows without leaving the UI. Files live in PAYLOAD_DIR (defaults to
packages/payloads/) and are loaded lazily through services/payloads.py.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel

from app.models import User
from app.services import payloads as payloads_svc
from app.services.auth import current_user

router = APIRouter(prefix="/payloads", tags=["payloads"])


class PayloadFileMeta(BaseModel):
    category: str
    name: str
    description: str
    payload_count: int
    raw_lines: int
    path: str


class PayloadIndex(BaseModel):
    categories: dict[str, int]
    files: list[PayloadFileMeta]
    encodings: list[str]


@router.get("", response_model=PayloadIndex)
def list_index(_user: User = Depends(current_user)) -> PayloadIndex:
    return PayloadIndex(
        categories=payloads_svc.categories(),
        files=[PayloadFileMeta(**f.__dict__) for f in payloads_svc.list_payloads()],
        encodings=list(payloads_svc.SUPPORTED_ENCODINGS),
    )


class PayloadResponse(BaseModel):
    category: str
    name: str
    encoding: str
    description: str
    payloads: list[str]
    payload_count: int


@router.get("/{category}/{name}", response_model=PayloadResponse)
def get_payload(
    category: str,
    name: str,
    encoding: str = Query("raw", description=f"one of: {', '.join(payloads_svc.SUPPORTED_ENCODINGS)}"),
    _user: User = Depends(current_user),
) -> PayloadResponse:
    if encoding not in payloads_svc.SUPPORTED_ENCODINGS:
        raise HTTPException(
            400,
            f"invalid encoding {encoding!r}; one of {list(payloads_svc.SUPPORTED_ENCODINGS)}",
        )
    try:
        meta, _body, payloads = payloads_svc.get_payload(category, name)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    encoded = payloads_svc.encode_lines(payloads, encoding)
    return PayloadResponse(
        category=meta.category,
        name=meta.name,
        encoding=encoding,
        description=meta.description,
        payloads=encoded,
        payload_count=len(encoded),
    )


@router.get("/{category}/{name}/raw")
def get_payload_raw(
    category: str,
    name: str,
    encoding: str = Query("raw"),
    _user: User = Depends(current_user),
) -> Response:
    """Plain-text download (one payload per line) for piping into a tool."""
    if encoding not in payloads_svc.SUPPORTED_ENCODINGS:
        raise HTTPException(400, f"invalid encoding {encoding!r}")
    try:
        meta, _body, payloads = payloads_svc.get_payload(category, name)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    encoded = payloads_svc.encode_lines(payloads, encoding)
    body = ("\n".join(encoded) + "\n").encode("utf-8")
    return Response(
        content=body,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{meta.category}-{meta.name}-{encoding}.txt"',
            "X-Payload-Count": str(len(encoded)),
            "X-Payload-Encoding": encoding,
        },
    )
