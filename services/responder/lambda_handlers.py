"""Lambda entry points invoked by the quarantine state machine (statemachine/quarantine.asl.json).

Each invocation re-checks the proposal hash, so a payload altered between approval and execution
is refused. The action is naturally idempotent (an already-labelled pod is a no-op), which makes
Step Functions retries safe.
"""

from typing import Any

from common.models import ResponseProposal
from policy.approvals import proposal_hash
from responder.quarantine import (
    KubernetesPodApi,
    PodApi,
    apply_quarantine,
    verify_quarantine,
)


class ApprovalMismatch(Exception):
    """The approved hash does not match the proposal being executed."""


_api: PodApi | None = None


def _pod_api() -> PodApi:
    global _api
    if _api is None:
        _api = KubernetesPodApi()
    return _api


def handler(event: dict[str, Any], _context: Any = None, api: PodApi | None = None) -> dict[str, Any]:
    api = api or _pod_api()
    proposal = ResponseProposal.model_validate(event["proposal"])
    expected = proposal_hash(proposal)
    if event.get("proposal_hash") != expected:
        raise ApprovalMismatch("proposal changed after it was submitted")

    mode = event["mode"]
    if mode == "dry_run":
        return {"status": apply_quarantine(api, proposal.target, dry_run=True).status}

    if mode == "execute":
        if (event.get("approval") or {}).get("bound_hash") != expected:
            raise ApprovalMismatch("approval is bound to a different version of this proposal")
        result = apply_quarantine(api, proposal.target, dry_run=False)
        return {"status": result.status, "detail": result.detail}

    if mode == "verify":
        report = verify_quarantine(api, proposal.target)
        return {"passed": report.passed, "checks": report.checks, "notes": report.notes}

    raise ValueError(f"unknown mode {mode!r}")
