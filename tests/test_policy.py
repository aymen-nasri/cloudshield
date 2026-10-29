"""The policy decision table from docs/response.md, plus approval binding (T-07)."""

from datetime import UTC, datetime, timedelta

import pytest

from common.models import ResponseProposal, Target
from policy.approvals import Approval, ApprovalError, check_approvals, proposal_hash
from policy.engine import Decision, PolicyEngine, load_policies

NOW = datetime(2026, 10, 28, 14, 6, tzinfo=UTC)
POD = Target(kind="Pod", name="checkout-7d9f6c-x2k8p", uid="8b0e3c52", cluster="cs-lab-eks", namespace="shop")


def proposal(**overrides) -> ResponseProposal:
    fields = {
        "proposal_id": "prp_1",
        "case_id": "case_1",
        "action_type": "k8s.pod.quarantine_label",
        "target": POD,
        "environment": "lab",
        "rationale": "remote script piped to shell",
        "requested_by": "ai-response-advisor",
        "created_at": NOW,
        "dry_run_passed": True,
    }
    fields.update(overrides)
    return ResponseProposal(**fields)


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine(load_policies(), is_fresh=lambda t: t.uid == "8b0e3c52")


def test_allowlisted_fresh_reversible_action_awaits_approval(engine):
    result = engine.evaluate(proposal())
    assert result.decision is Decision.AWAIT_APPROVAL
    assert result.required_approvals == 1
    assert result.rollback == "k8s.pod.remove_quarantine_label"


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"target": POD.model_copy(update={"namespace": "kube-system"})}, "protected"),
        ({"target": POD.model_copy(update={"namespace": "payments"})}, "not in the allowlist"),
        ({"target": POD.model_copy(update={"uid": "changed"})}, "stale target"),
        ({"environment": "prod"}, "not allowed in environment"),
        ({"action_type": "aws.security_group.modify"}, "not allowlisted"),
        ({"action_type": "k8s.pod.delete"}, "not allowlisted"),
        ({"dry_run_passed": False}, "dry-run"),
        ({"dry_run_passed": None}, "dry-run"),
        ({"target": POD.model_copy(update={"kind": "Deployment"})}, "kind"),
    ],
)
def test_unsafe_proposals_are_denied(engine, overrides, reason):
    result = engine.evaluate(proposal(**overrides))
    assert result.decision is Decision.DENY
    assert reason in result.reasons[0]


def test_critical_tier_escalates_to_two_approvers(engine):
    critical = POD.model_copy(update={"labels": {"cloudshield.io/tier": "critical"}})
    result = engine.evaluate(proposal(target=critical))
    assert result.decision is Decision.ESCALATE
    assert result.required_approvals == 2


def _approval(p: ResponseProposal, **overrides) -> Approval:
    fields = {
        "proposal_id": p.proposal_id,
        "approver": "analyst:a.nasri",
        "approver_roles": frozenset({"incident-responder"}),
        "decision": "approve",
        "bound_hash": proposal_hash(p),
        "decided_at": NOW,
        "justification": "confirmed curl | sh from an external IP",
    }
    fields.update(overrides)
    return Approval(**fields)


def test_valid_approval_returns_idempotency_key(engine):
    p = proposal()
    key = check_approvals(p, engine.evaluate(p), [_approval(p)], now=NOW + timedelta(minutes=5))
    assert key == proposal_hash(p)


@pytest.mark.parametrize(
    "approval_overrides, now_offset",
    [
        ({}, timedelta(minutes=16)),  # T-07: expired
        ({"decision": "reject"}, timedelta(minutes=1)),  # T-07: rejected
        ({"bound_hash": "sha256:old"}, timedelta(minutes=1)),  # approved another version
        ({"approver": "ai-response-advisor"}, timedelta(minutes=1)),  # self-approval
        ({"approver_roles": frozenset({"viewer"})}, timedelta(minutes=1)),
    ],
)
def test_invalid_approvals_never_allow_execution(engine, approval_overrides, now_offset):
    p = proposal()
    with pytest.raises(ApprovalError):
        check_approvals(p, engine.evaluate(p), [_approval(p, **approval_overrides)], now=NOW + now_offset)


def test_changing_the_target_after_approval_invalidates_it(engine):
    approved = proposal()
    approval = _approval(approved)
    swapped = proposal(target=POD.model_copy(update={"name": "cart-5c8b7d-m4q2z"}))
    with pytest.raises(ApprovalError):
        check_approvals(swapped, engine.evaluate(proposal()), [approval], now=NOW)


def test_denied_policy_cannot_be_overridden_by_approvals(engine):
    p = proposal(environment="prod")
    with pytest.raises(ApprovalError):
        check_approvals(p, engine.evaluate(p), [_approval(p)], now=NOW)
