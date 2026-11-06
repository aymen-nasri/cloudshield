"""Producer authentication. Every source is rejected unless it is explicitly configured (fail closed).

Two schemes:
- bearer token: Falcosidekick sends a static header (customHeaders), over plain HTTP in the cluster.
- HMAC-SHA256 over the body: producers that can sign, such as the Wazuh integration script.
"""

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass

SIGNATURE_HEADER = "x-cloudshield-signature"


@dataclass(frozen=True)
class SourceCredential:
    token: str | None = None
    hmac_secret: str | None = None


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _same(provided: str, expected: str) -> bool:
    """Compared as bytes: on str, compare_digest raises for non-ASCII, and a caller controls this header."""
    return hmac.compare_digest(provided.encode(), expected.encode())


def authenticate(credential: SourceCredential | None, headers: Mapping[str, str], body: bytes) -> bool:
    if credential is None:
        return False
    if credential.hmac_secret:
        provided = headers.get(SIGNATURE_HEADER, "")
        return _same(provided, sign(credential.hmac_secret, body))
    if credential.token:
        provided = headers.get("authorization", "")
        return _same(provided, f"Bearer {credential.token}")
    return False
