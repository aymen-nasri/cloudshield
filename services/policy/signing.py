"""Approvals the responder can check for itself, so the API can't invent one.

An approver signs a statement with a private key only they hold. The responder holds the public keys
and recomputes what was signed from the proposal it's asked to run. The API only carries the signature:
a stolen API pod has no private key, and can't reuse a signature for a different action.
"""

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import AwareDatetime, BaseModel

from common.models import ResponseProposal
from policy.approvals import proposal_hash
from policy.engine import PolicyResult

STATEMENT_VERSION = "cloudshield-approval-v1"
# Allows for clocks that disagree a little. An approval dated further ahead would outlive its TTL.
MAX_CLOCK_SKEW = timedelta(minutes=2)


class SignedApproval(BaseModel):
    approver: str
    signed_at: AwareDatetime
    signature: str


@dataclass(frozen=True)
class ApproverKey:
    public_key: Ed25519PublicKey
    roles: frozenset[str]


def approval_statement(proposal: ResponseProposal, approver: str, signed_at: datetime) -> bytes:
    """What gets signed. The requester is included because the proposal hash doesn't cover it, and
    self-approval depends on it."""
    fields = [
        STATEMENT_VERSION,
        proposal_hash(proposal),
        proposal.requested_by,
        approver,
        signed_at.astimezone(UTC).isoformat(),
    ]
    return "\n".join(fields).encode()


def sign_approval(
    key: Ed25519PrivateKey, proposal: ResponseProposal, approver: str, signed_at: datetime
) -> str:
    return base64.b64encode(key.sign(approval_statement(proposal, approver, signed_at))).decode()


def load_approver_keys(text: str) -> dict[str, ApproverKey]:
    """{"analyst:bob": {"public_key": "<base64>", "roles": ["incident-responder"]}}"""
    keys = {}
    for approver, entry in json.loads(text).items():
        raw = base64.b64decode(entry["public_key"], validate=True)
        keys[approver] = ApproverKey(Ed25519PublicKey.from_public_bytes(raw), frozenset(entry["roles"]))
    return keys


def _signature_is_valid(key: ApproverKey, signature: str, statement: bytes) -> bool:
    try:
        key.public_key.verify(base64.b64decode(signature, validate=True), statement)
    except (InvalidSignature, binascii.Error, ValueError):
        return False
    return True


def valid_approvers(
    proposal: ResponseProposal,
    approvals: list[SignedApproval],
    keys: dict[str, ApproverKey],
    policy: PolicyResult,
    *,
    now: datetime,
) -> set[str]:
    """Who has really approved this exact proposal, as far as this process can tell by itself."""
    valid = set()
    for approval in approvals:
        key = keys.get(approval.approver)
        if key is None or approval.approver == proposal.requested_by:
            continue
        if policy.approver_roles and not key.roles & policy.approver_roles:
            continue
        if now > approval.signed_at + policy.approval_ttl or approval.signed_at > now + MAX_CLOCK_SKEW:
            continue
        statement = approval_statement(proposal, approval.approver, approval.signed_at)
        if _signature_is_valid(key, approval.signature, statement):
            valid.add(approval.approver)
    return valid
