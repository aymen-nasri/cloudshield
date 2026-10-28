"""Analyst authentication for the console API.

Today analysts present a bearer token. Only SHA-256 hashes of tokens are configured, so the
configuration never holds a usable credential. TODO(M5): replace with OIDC SSO; roles stay the same.

    CLOUDSHIELD_ANALYSTS='{"<sha256 hex of token>": {"id": "analyst:a.nasri",
                                                     "roles": ["incident-responder"]}}'
"""

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass

ROLES = frozenset({"viewer", "analyst", "incident-responder", "admin"})


@dataclass(frozen=True)
class Principal:
    id: str
    roles: frozenset[str]

    def has_any(self, roles: frozenset[str]) -> bool:
        return bool(self.roles & roles) or "admin" in self.roles


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class AnalystDirectory:
    def __init__(self, by_hash: Mapping[str, Principal]) -> None:
        unknown = {r for p in by_hash.values() for r in p.roles} - ROLES
        if unknown:
            raise ValueError(f"unknown roles: {sorted(unknown)}")
        self._by_hash = dict(by_hash)

    @classmethod
    def from_json(cls, text: str | None) -> "AnalystDirectory":
        entries = json.loads(text) if text else {}
        return cls({h: Principal(e["id"], frozenset(e.get("roles", ["viewer"]))) for h, e in entries.items()})

    @classmethod
    def from_tokens(cls, tokens: Mapping[str, Principal]) -> "AnalystDirectory":
        """For tests and local demos."""
        return cls({token_hash(t): p for t, p in tokens.items()})

    def authenticate(self, authorization: str | None) -> Principal | None:
        if not authorization or not authorization.startswith("Bearer "):
            return None
        presented = token_hash(authorization.removeprefix("Bearer "))
        for known, principal in self._by_hash.items():
            if hmac.compare_digest(known, presented):
                return principal
        return None
