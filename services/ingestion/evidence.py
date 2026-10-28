"""Raw evidence archive. Payloads are stored byte-for-byte and referenced by URI + SHA-256."""

import base64
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol


class EvidenceStore(Protocol):
    def archive(self, source: str, raw: bytes, received_at: datetime) -> tuple[str, str]:
        """Store the payload unchanged and return (uri, "sha256:<hex>")."""
        ...


def _key(source: str, digest: str, received_at: datetime) -> str:
    return f"raw/{source}/{received_at:%Y/%m/%d}/{digest}.json"


class InMemoryEvidenceStore:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def archive(self, source: str, raw: bytes, received_at: datetime) -> tuple[str, str]:
        digest = hashlib.sha256(raw).hexdigest()
        uri = f"mem://{_key(source, digest, received_at)}"
        self.objects[uri] = raw
        return uri, f"sha256:{digest}"


class LocalEvidenceStore:
    """Writes to a local directory for the docker-compose dev stack."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def archive(self, source: str, raw: bytes, received_at: datetime) -> tuple[str, str]:
        digest = hashlib.sha256(raw).hexdigest()
        path = self.root / _key(source, digest, received_at)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(raw)
        return path.as_uri(), f"sha256:{digest}"


class S3EvidenceStore:
    """S3 archive. The bucket (infra/tofu) enforces SSE-KMS, versioning and Object Lock."""

    def __init__(self, bucket: str, kms_key_id: str, client: Any | None = None) -> None:
        if client is None:
            import boto3

            client = boto3.client("s3")
        self.client = client
        self.bucket = bucket
        self.kms_key_id = kms_key_id

    def archive(self, source: str, raw: bytes, received_at: datetime) -> tuple[str, str]:
        digest = hashlib.sha256(raw)
        key = _key(source, digest.hexdigest(), received_at)
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=raw,
            ContentType="application/json",
            ChecksumSHA256=base64.b64encode(digest.digest()).decode(),
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self.kms_key_id,
        )
        return f"s3://{self.bucket}/{key}", f"sha256:{digest.hexdigest()}"
