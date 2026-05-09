from fastapi import APIRouter, Depends, HTTPException, Response
from sqlmodel import Session, select

from app.db import get_session
from app.models import Artifact, Asset, Finding
from app.services.artifacts import ArtifactStore

router = APIRouter(tags=["assets-findings"])


@router.get("/assets", response_model=list[Asset])
def list_assets(workspace_id: str | None = None, session: Session = Depends(get_session)) -> list[Asset]:
    query = select(Asset).order_by(Asset.last_seen.desc())
    if workspace_id:
        query = query.where(Asset.workspace_id == workspace_id)
    return list(session.exec(query).all())


@router.get("/findings", response_model=list[Finding])
def list_findings(workspace_id: str | None = None, session: Session = Depends(get_session)) -> list[Finding]:
    query = select(Finding).order_by(Finding.created_at.desc())
    if workspace_id:
        query = query.where(Finding.workspace_id == workspace_id)
    return list(session.exec(query).all())


@router.get("/artifacts/{artifact_id}", response_model=Artifact)
def get_artifact(artifact_id: str, session: Session = Depends(get_session)) -> Artifact:
    artifact = session.get(Artifact, artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return artifact


@router.get("/artifacts/{artifact_id}/content")
def get_artifact_content(artifact_id: str, session: Session = Depends(get_session)) -> Response:
    artifact = session.get(Artifact, artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    try:
        data = ArtifactStore().read_bytes(artifact)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Artifact content not found") from exc

    return Response(
        content=data,
        media_type=artifact.content_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'inline; filename="{artifact.name}"',
            "X-Artifact-Sha256": artifact.sha256 or "",
            "X-Artifact-Backend": artifact.storage_backend,
        },
    )
