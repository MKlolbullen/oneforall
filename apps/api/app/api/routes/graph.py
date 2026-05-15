"""Workspace asset/finding graph for the Network page.

Builds a {nodes, edges} payload from the rows the runner already persists:

  Target    →  Domain assets that match the target (suffix match)
  Domain    →  IP assets that share the same `meta.json.ip` value
  Domain    →  URL assets whose host parses to the same domain
  URL       →  Findings whose run touched that URL (best-effort: by run_id)
  Run       →  Findings (so a finding hangs off the run that produced it)

Nodes get a `centrality` score from networkx (betweenness, normalised) so the
UI can size pivot points larger than leaves. The whole graph is bounded
per-workspace at MAX_NODES so a chatty subdomain dump can't blow out the
browser.

Read-only (viewer+); no POST surface.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import networkx as nx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.db import get_session
from app.models import Asset, Finding, Run, Target, User, Workspace
from app.services.auth import current_user

router = APIRouter(prefix="/workspaces", tags=["graph"])

MAX_NODES = 600   # roughly the comfort ceiling for an in-browser force layout


class GraphNode(BaseModel):
    id: str                 # canonical "kind:value" so cross-asset edges match
    kind: str               # target | domain | ip | url | finding
    label: str
    severity: str | None = None  # only on findings
    centrality: float = 0.0
    # The original ORM id (so the UI can deep-link to the right detail page)
    ref_id: str | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    kind: str               # owns | resolves_to | hosts | finds


class GraphPayload(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    stats: dict[str, Any] = Field(default_factory=dict)
    truncated: bool = False


def _host_of(url: str) -> str | None:
    try:
        return urlparse(url).netloc.split(":", 1)[0].lower() or None
    except Exception:  # noqa: BLE001
        return None


def _matches_target(asset_value: str, target_value: str) -> bool:
    asset_value = asset_value.lower()
    target_value = target_value.lower()
    return asset_value == target_value or asset_value.endswith("." + target_value)


@router.get("/{workspace_id}/graph", response_model=GraphPayload)
def get_workspace_graph(
    workspace_id: str,
    max_nodes: int = Query(MAX_NODES, ge=10, le=2000),
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> GraphPayload:
    workspace = session.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(404, "Workspace not found")

    targets = list(session.exec(
        select(Target).where(Target.workspace_id == workspace_id)
    ).all())
    assets = list(session.exec(
        select(Asset).where(Asset.workspace_id == workspace_id)
    ).all())
    findings = list(session.exec(
        select(Finding).where(Finding.workspace_id == workspace_id)
    ).all())
    runs = {r.id: r for r in session.exec(
        select(Run).where(Run.workspace_id == workspace_id)
    ).all()}

    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []

    def add_node(nid: str, kind: str, label: str, *,
                 severity: str | None = None, ref_id: str | None = None) -> None:
        if nid not in nodes:
            nodes[nid] = GraphNode(id=nid, kind=kind, label=label,
                                    severity=severity, ref_id=ref_id)

    # --- 1. Targets are anchors --------------------------------------------
    for t in targets:
        nid = f"target:{t.value.lower()}"
        add_node(nid, "target", t.value, ref_id=t.id)

    # --- 2. Assets, indexed by type for fast cross-references --------------
    by_type: dict[str, list[Asset]] = defaultdict(list)
    for a in assets:
        by_type[a.type].append(a)

    # Domain assets — link each to the matching target (longest suffix wins;
    # a single subdomain can attach to at most one target so we don't double-count).
    for a in by_type.get("domain", []):
        nid = f"domain:{a.value.lower()}"
        add_node(nid, "domain", a.value, ref_id=a.id)
        match = next(
            (t for t in sorted(targets, key=lambda x: -len(x.value))
             if _matches_target(a.value, t.value)),
            None,
        )
        if match:
            edges.append(GraphEdge(source=f"target:{match.value.lower()}",
                                    target=nid, kind="owns"))

    # IP assets
    for a in by_type.get("ip", []):
        nid = f"ip:{a.value}"
        add_node(nid, "ip", a.value, ref_id=a.id)

    # URL assets — link to host domain + extract IP via meta if present
    for a in by_type.get("url", []):
        nid = f"url:{a.value}"
        add_node(nid, "url", a.value, ref_id=a.id)
        host = _host_of(a.value)
        if host:
            host_nid = f"domain:{host}"
            if host_nid in nodes:
                edges.append(GraphEdge(source=host_nid, target=nid, kind="hosts"))
        meta_json = (a.meta or {}).get("json")
        if isinstance(meta_json, dict):
            ip = meta_json.get("ip") or meta_json.get("a")
            if isinstance(ip, str):
                ip_nid = f"ip:{ip}"
                if ip_nid in nodes:
                    edges.append(GraphEdge(source=nid, target=ip_nid, kind="resolves_to"))

    # --- 3. Findings hang off the run's target ------------------------------
    for f in findings:
        fid = f"finding:{f.id}"
        add_node(fid, "finding", f.title[:100], severity=f.severity, ref_id=f.id)
        run = runs.get(f.run_id) if f.run_id else None
        if run:
            tgt = next((t for t in targets if t.id == run.target_id), None)
            if tgt:
                edges.append(GraphEdge(source=f"target:{tgt.value.lower()}",
                                        target=fid, kind="finds"))

    # --- 4. Bound the graph -----------------------------------------------
    truncated = False
    if len(nodes) > max_nodes:
        # Keep targets + highest-impact subset: rank nodes by edge degree,
        # take the top N - target_count, then add all targets back.
        target_ids = {n.id for n in nodes.values() if n.kind == "target"}
        degree: dict[str, int] = defaultdict(int)
        for e in edges:
            degree[e.source] += 1
            degree[e.target] += 1
        ranked = sorted(nodes.keys(), key=lambda nid: -degree[nid])
        keep: set[str] = set(target_ids)
        for nid in ranked:
            if len(keep) >= max_nodes:
                break
            keep.add(nid)
        nodes = {nid: n for nid, n in nodes.items() if nid in keep}
        edges = [e for e in edges if e.source in keep and e.target in keep]
        truncated = True

    # --- 5. Centrality -----------------------------------------------------
    g = nx.Graph()
    g.add_nodes_from(nodes.keys())
    for e in edges:
        g.add_edge(e.source, e.target)
    centrality = nx.betweenness_centrality(g) if g.number_of_nodes() > 1 else {}
    for nid, score in centrality.items():
        nodes[nid].centrality = round(float(score), 4)

    by_kind: dict[str, int] = defaultdict(int)
    for n in nodes.values():
        by_kind[n.kind] += 1

    return GraphPayload(
        nodes=list(nodes.values()),
        edges=edges,
        stats={"by_kind": dict(by_kind),
               "node_count": len(nodes), "edge_count": len(edges),
               "max_nodes": max_nodes},
        truncated=truncated,
    )
