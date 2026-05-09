from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from app.core.config import get_settings
from app.models import Artifact

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class StoredArtifact:
    name: str
    type: str
    path: str
    size_bytes: int
    sha256: str
    storage_backend: str
    bucket: str | None
    object_key: str | None
    content_type: str


class ArtifactStore:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._s3_client: BaseClient | None = None

    def put_text(
        self,
        *,
        run_id: str,
        name: str,
        content: str,
        artifact_type: str = "text",
        content_type: str = "text/plain; charset=utf-8",
    ) -> StoredArtifact:
        data = content.encode("utf-8")
        return self.put_bytes(
            run_id=run_id,
            name=name,
            data=data,
            artifact_type=artifact_type,
            content_type=content_type,
        )

    def put_bytes(
        self,
        *,
        run_id: str,
        name: str,
        data: bytes,
        artifact_type: str = "binary",
        content_type: str = "application/octet-stream",
    ) -> StoredArtifact:
        safe_name = sanitize_artifact_name(name)
        sha = hashlib.sha256(data).hexdigest()

        if self.settings.artifact_backend == "s3":
            bucket = self.settings.minio_bucket
            key = f"runs/{run_id}/{safe_name}"
            client = self._s3()
            last_error: Exception | None = None
            for attempt in range(1, 6):
                try:
                    self._ensure_bucket(client, bucket)
                    client.put_object(
                        Bucket=bucket,
                        Key=key,
                        Body=data,
                        ContentType=content_type,
                        Metadata={"sha256": sha, "run_id": run_id, "artifact_name": safe_name},
                    )
                    last_error = None
                    break
                except Exception as exc:  # noqa: BLE001 - tolerate MinIO startup race during compose boot
                    last_error = exc
                    time.sleep(min(attempt, 3))
            if last_error is not None:
                raise last_error
            return StoredArtifact(
                name=safe_name,
                type=artifact_type,
                path=f"s3://{bucket}/{key}",
                size_bytes=len(data),
                sha256=sha,
                storage_backend="s3",
                bucket=bucket,
                object_key=key,
                content_type=content_type,
            )

        root = Path(self.settings.artifact_dir) / run_id
        root.mkdir(parents=True, exist_ok=True)
        path = root / safe_name
        path.write_bytes(data)
        return StoredArtifact(
            name=safe_name,
            type=artifact_type,
            path=str(path),
            size_bytes=len(data),
            sha256=sha,
            storage_backend="local",
            bucket=None,
            object_key=None,
            content_type=content_type,
        )

    def read_bytes(self, artifact: Artifact) -> bytes:
        if artifact.storage_backend == "s3":
            if not artifact.bucket or not artifact.object_key:
                raise ValueError("S3 artifact missing bucket/object_key")
            body = self._s3().get_object(Bucket=artifact.bucket, Key=artifact.object_key)["Body"]
            return body.read()
        return Path(artifact.path).read_bytes()

    def _s3(self) -> BaseClient:
        if self._s3_client is None:
            self._s3_client = boto3.client(
                "s3",
                endpoint_url=self.settings.minio_endpoint,
                aws_access_key_id=self.settings.minio_access_key,
                aws_secret_access_key=self.settings.minio_secret_key,
                region_name=self.settings.s3_region,
            )
        return self._s3_client

    @staticmethod
    def _ensure_bucket(client: BaseClient, bucket: str) -> None:
        try:
            client.head_bucket(Bucket=bucket)
        except ClientError:
            try:
                client.create_bucket(Bucket=bucket)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
                    raise


def sanitize_artifact_name(name: str) -> str:
    candidate = _SAFE_NAME.sub("_", name.strip()).strip("._")
    if not candidate:
        return "artifact.bin"
    return candidate[:180]
