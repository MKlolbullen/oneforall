from __future__ import annotations

import json
import re
from typing import Any

from sqlmodel import Session, select

from app.models import Asset, Finding

DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)
SEVERITY_RE = re.compile(r"\[(critical|high|medium|low|info)\]", re.IGNORECASE)


def upsert_asset(
    session: Session,
    *,
    workspace_id: str,
    run_id: str,
    type_: str,
    value: str,
    source: str,
    confidence: float = 0.8,
    meta: dict[str, Any] | None = None,
) -> Asset:
    existing = session.exec(
        select(Asset).where(
            Asset.workspace_id == workspace_id,
            Asset.type == type_,
            Asset.value == value,
        )
    ).first()
    if existing:
        existing.source = source
        existing.confidence = max(existing.confidence, confidence)
        existing.run_id = run_id
        existing.meta = {**(existing.meta or {}), **(meta or {})}
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing
    asset = Asset(
        workspace_id=workspace_id,
        run_id=run_id,
        type=type_,
        value=value,
        source=source,
        confidence=confidence,
        meta=meta or {},
    )
    session.add(asset)
    session.commit()
    session.refresh(asset)
    return asset


def _finding(
    session: Session,
    *,
    workspace_id: str,
    run_id: str,
    tool_id: str,
    title: str,
    severity: str = "info",
    category: str = "scanner-output",
    evidence: str | None = None,
    meta: dict[str, Any] | None = None,
) -> Finding:
    finding = Finding(
        workspace_id=workspace_id,
        run_id=run_id,
        title=title[:180],
        severity=severity.lower(),
        category=category,
        evidence=evidence or title,
        tool_source=tool_id,
        meta=meta or {},
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def _normalize_json_line(
    session: Session,
    *,
    workspace_id: str,
    run_id: str,
    tool_id: str,
    raw: str,
    data: dict[str, Any],
) -> Asset | Finding | None:
    # ProjectDiscovery-style httpx output commonly has url/input/host fields.
    for key in ("url", "matched-at", "matched", "endpoint"):
        value = data.get(key)
        if isinstance(value, str) and URL_RE.match(value):
            return upsert_asset(
                session,
                workspace_id=workspace_id,
                run_id=run_id,
                type_="url",
                value=value,
                source=tool_id,
                confidence=0.9,
                meta={"raw": raw, "json": data},
            )

    host = data.get("host") or data.get("input") or data.get("ip")
    if isinstance(host, str):
        clean_host = host.split(":", 1)[0].strip()
        if IP_RE.match(clean_host):
            return upsert_asset(
                session,
                workspace_id=workspace_id,
                run_id=run_id,
                type_="ip",
                value=clean_host,
                source=tool_id,
                confidence=0.9,
                meta={"raw": raw, "json": data},
            )
        if DOMAIN_RE.match(clean_host):
            return upsert_asset(
                session,
                workspace_id=workspace_id,
                run_id=run_id,
                type_="domain",
                value=clean_host.lower(),
                source=tool_id,
                confidence=0.9,
                meta={"raw": raw, "json": data},
            )

    # Nuclei JSONL usually exposes template-id, info.severity and matched-at.
    if "template-id" in data or "template" in data:
        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        severity = str(info.get("severity") or data.get("severity") or "info")
        name = str(info.get("name") or data.get("template-id") or data.get("template") or "Nuclei finding")
        matched = str(data.get("matched-at") or data.get("host") or "")
        return _finding(
            session,
            workspace_id=workspace_id,
            run_id=run_id,
            tool_id=tool_id,
            title=f"{name} {matched}".strip(),
            severity=severity,
            category="template-finding",
            evidence=raw,
            meta={"json": data},
        )

    return None


def normalize_tool_line(
    session: Session,
    *,
    workspace_id: str,
    run_id: str,
    tool_id: str,
    line: str,
) -> Asset | Finding | None:
    value = line.strip()
    if not value:
        return None

    if value.startswith("{") and value.endswith("}"):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            normalized = _normalize_json_line(
                session,
                workspace_id=workspace_id,
                run_id=run_id,
                tool_id=tool_id,
                raw=line,
                data=parsed,
            )
            if normalized:
                return normalized

    if URL_RE.match(value):
        return upsert_asset(
            session,
            workspace_id=workspace_id,
            run_id=run_id,
            type_="url",
            value=value,
            source=tool_id,
            meta={"raw": line},
        )
    if IP_RE.match(value):
        return upsert_asset(
            session,
            workspace_id=workspace_id,
            run_id=run_id,
            type_="ip",
            value=value,
            source=tool_id,
            meta={"raw": line},
        )
    if DOMAIN_RE.match(value):
        return upsert_asset(
            session,
            workspace_id=workspace_id,
            run_id=run_id,
            type_="domain",
            value=value.lower(),
            source=tool_id,
            meta={"raw": line},
        )

    severity_match = SEVERITY_RE.search(value)
    if "CVE-" in value or severity_match or ("[" in value and "]" in value):
        return _finding(
            session,
            workspace_id=workspace_id,
            run_id=run_id,
            tool_id=tool_id,
            title=value,
            severity=severity_match.group(1).lower() if severity_match else "info",
            evidence=value,
            meta={"raw": line},
        )
    return None
