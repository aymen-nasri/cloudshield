"""Approvals are bound to a hash of the exact proposal and expire.

If anything material about a proposal changes after approval (target, parameters, environment),
its hash changes and the old approval no longer counts. The hash doubles as the idempotency key.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from common.models import ResponseProposal
from policy.engine import Decision, PolicyResult


def proposal_hash(proposal: ResponseProposal) -> str:
    material = {
        "proposal_id": proposal.proposal_id,
        "case_id": proposal.case_id,
        "action_type": proposal.action_type,
        "target": proposal.target.model_dump(mode="json"),
        "environment": proposal.environment,
        "parameters": proposal.parameters,
    }
    body = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(body.encode()).hexdigest()


@dataclass(frozen=True)
class Approval:
    proposal_id: str
    approver: str
    approver_roles: frozenset[str]
    decision: Literal["approve", "reject"]
    bound_hash: str
    decided_at: datetime
    justification: str


class ApprovalError(Exception):
    pass


def check_approvals(
    proposal: ResponseProposal,
    policy: PolicyResult,
    approvals: list[Approval],
    *,
    now: datetime,
) -> str:
    """Raise ApprovalError unless the proposal may execute now. Returns the idempotency key."""
    if policy.decision is Decision.DENY:
        raise ApprovalError("policy denied this proposal")

    current = proposal_hash(proposal)
    relevant = [a for a in approvals if a.proposal_id == proposal.proposal_id]

    if any(a.decision == "reject" for a in relevant):
        raise ApprovalError("proposal was rejected")

    valid: set[str] = set()
    for a in relevant:
        if a.bound_hash != current:
            continue  # approved a different version of this proposal
        if now > a.decided_at + policy.approval_ttl:
            continue  # expired
        if a.approver == proposal.requested_by:
            continue  # no self-approval
        if policy.approver_roles and not (a.approver_roles & policy.approver_roles):
            continue
        valid.add(a.approver)

    if len(valid) < policy.required_approvals:
        raise ApprovalError(f"{len(valid)} valid approval(s), {policy.required_approvals} required")
    return current
