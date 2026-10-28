"""Quarantine execution, idempotency, stale targets, verification and Lambda hash binding."""

import copy
from datetime import UTC, datetime

import pytest

from common.models import ResponseProposal, Target
from policy.approvals import proposal_hash
from responder.lambda_handlers import ApprovalMismatch, handler
from responder.quarantine import QUARANTINE_LABEL, apply_quarantine, remove_quarantine, verify_quarantine

TARGET = Target(kind="Pod", name="checkout-1", uid="uid-1", namespace="shop")

DEFAULT_DENY = {"metadata": {"name": "default-deny-all"},
                "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}
CHECKOUT_ALLOW = {
    "metadata": {"name": "checkout-allow"},
    "spec": {
        "podSelector": {
            "matchLabels": {"app": "checkout"},
            "matchExpressions": [{"key": QUARANTINE_LABEL, "operator": "NotIn", "values": ["true"]}],
        },
        "policyTypes": ["Ingress", "Egress"],
        "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "cart"}}}]}],
    },
}
LEAKY_ALLOW = {  # an allow-policy that forgot the exclusion (Kyverno would block it)
    "metadata": {"name": "leaky"},
    "spec": {"podSelector": {"matchLabels": {"app": "checkout"}}, "policyTypes": ["Egress"],
             "egress": [{}]},
}


class FakePodApi:
    def __init__(self, policies=None):
        self.pod = {"metadata": {"name": "checkout-1", "uid": "uid-1", "labels": {"app": "checkout"}},
                    "status": {"phase": "Running"}}
        self.policies = policies if policies is not None else [DEFAULT_DENY, CHECKOUT_ALLOW]
        self.patches = []

    def get_pod(self, namespace, name):
        return copy.deepcopy(self.pod) if name == self.pod["metadata"]["name"] else None

    def patch_pod_labels(self, namespace, name, labels, *, dry_run):
        self.patches.append((labels, dry_run))
        if not dry_run:
            for k, v in labels.items():
                if v is None:
                    self.pod["metadata"]["labels"].pop(k, None)
                else:
                    self.pod["metadata"]["labels"][k] = v

    def list_network_policies(self, namespace):
        return self.policies


def test_dry_run_changes_nothing():
    api = FakePodApi()
    assert apply_quarantine(api, TARGET, dry_run=True).status == "dry_run_ok"
    assert QUARANTINE_LABEL not in api.pod["metadata"]["labels"]


def test_apply_is_idempotent():
    api = FakePodApi()
    assert apply_quarantine(api, TARGET, dry_run=False).status == "applied"
    assert apply_quarantine(api, TARGET, dry_run=False).status == "already_applied"
    assert len(api.patches) == 1


def test_stale_target_is_refused():
    api = FakePodApi()
    api.pod["metadata"]["uid"] = "uid-2"  # same name, different pod
    assert apply_quarantine(api, TARGET, dry_run=False).status == "stale_target"
    assert api.patches == []


def test_verification_passes_after_quarantine():
    api = FakePodApi()
    apply_quarantine(api, TARGET, dry_run=False)
    report = verify_quarantine(api, TARGET)
    assert report.passed
    assert report.checks["no_allow_policy_selects_pod"] is True
    assert report.checks["egress_probe"] is None  # reported as skipped, not as passed


def test_verification_fails_when_an_allow_policy_lacks_the_exclusion():
    api = FakePodApi(policies=[DEFAULT_DENY, CHECKOUT_ALLOW, LEAKY_ALLOW])
    apply_quarantine(api, TARGET, dry_run=False)
    report = verify_quarantine(api, TARGET)
    assert not report.passed
    assert "leaky" in report.notes["no_allow_policy_selects_pod"]


def test_rollback_removes_the_label():
    api = FakePodApi()
    apply_quarantine(api, TARGET, dry_run=False)
    assert remove_quarantine(api, TARGET, dry_run=False).status == "removed"
    assert QUARANTINE_LABEL not in api.pod["metadata"]["labels"]


def _event(mode, **extra):
    proposal = ResponseProposal(
        proposal_id="prp_1", case_id="case_1", action_type="k8s.pod.quarantine_label", target=TARGET,
        environment="lab", rationale="x", requested_by="ai", created_at=datetime(2026, 10, 28, tzinfo=UTC),
        dry_run_passed=True,
    )
    h = proposal_hash(proposal)
    return {"mode": mode, "proposal": proposal.model_dump(mode="json"), "proposal_hash": h,
            "approval": {"bound_hash": h}, **extra}


def test_lambda_executes_only_with_matching_approval():
    api = FakePodApi()
    assert handler(_event("execute"), api=api)["status"] == "applied"

    with pytest.raises(ApprovalMismatch):
        handler(_event("execute", approval={"bound_hash": "sha256:other"}), api=FakePodApi())


def test_lambda_refuses_a_tampered_proposal():
    event = _event("execute")
    event["proposal"]["target"]["name"] = "cart-1"
    with pytest.raises(ApprovalMismatch):
        handler(event, api=FakePodApi())
