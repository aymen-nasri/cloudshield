"""Policy gate: schema -> allowlist -> environment -> target -> freshness -> escalation -> dry-run.

The policy file is data, not code: there is no expression evaluation, so nothing in a proposal
(which may echo attacker-controlled text) can change how a rule is interpreted.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from common.models import ActionClass, ResponseProposal, Target


class Decision(StrEnum):
    AWAIT_APPROVAL = "await_approval"
    ESCALATE = "escalate"
    DENY = "deny"


@dataclass(frozen=True)
class ActionPolicy:
    action_type: str
    action_class: ActionClass
    environments: frozenset[str]
    kinds: frozenset[str]
    allowed_namespaces: frozenset[str]
    denied_namespaces: frozenset[str]
    min_approvals: int
    approver_roles: frozenset[str]
    approval_ttl: timedelta
    escalate_when_labels: dict[str, str]
    escalated_min: int
    require_dry_run: bool
    rollback: str | None

    @classmethod
    def from_dict(cls, action_type: str, raw: dict[str, Any]) -> "ActionPolicy":
        target = raw.get("target", {})
        approvals = raw.get("approvals", {})
        return cls(
            action_type=action_type,
            action_class=ActionClass(raw["class"]),
            environments=frozenset(raw.get("environments", [])),
            kinds=frozenset(target.get("kinds", [])),
            allowed_namespaces=frozenset(target.get("allowed_namespaces", [])),
            denied_namespaces=frozenset(target.get("denied_namespaces", [])),
            min_approvals=int(approvals.get("min", 1)),
            approver_roles=frozenset(approvals.get("roles", [])),
            approval_ttl=timedelta(minutes=int(approvals.get("ttl_minutes", 15))),
            escalate_when_labels=dict(approvals.get("escalate_when_labels", {})),
            escalated_min=int(approvals.get("escalated_min", 2)),
            require_dry_run=bool(raw.get("require_dry_run", True)),
            rollback=raw.get("rollback"),
        )


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reasons: list[str] = field(default_factory=list)
    required_approvals: int = 0
    approver_roles: frozenset[str] = frozenset()
    approval_ttl: timedelta = timedelta(0)
    rollback: str | None = None


def load_policies(path: Path | None = None) -> dict[str, ActionPolicy]:
    if path is None:
        text = resources.files("policy").joinpath("policies/actions.yaml").read_text(encoding="utf-8")
    else:
        text = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    return {name: ActionPolicy.from_dict(name, body) for name, body in doc["actions"].items()}


FreshnessCheck = Callable[[Target], bool]


class PolicyEngine:
    def __init__(self, policies: dict[str, ActionPolicy], is_fresh: FreshnessCheck) -> None:
        self.policies = policies
        self.is_fresh = is_fresh

    def evaluate(self, proposal: ResponseProposal) -> PolicyResult:
        def deny(reason: str) -> PolicyResult:
            return PolicyResult(Decision.DENY, [reason])

        policy = self.policies.get(proposal.action_type)
        if policy is None:
            return deny(f"action {proposal.action_type!r} is not allowlisted")
        if policy.action_class is ActionClass.IRREVERSIBLE:
            return deny("irreversible actions are out of scope")
        if proposal.environment not in policy.environments:
            return deny(f"action not allowed in environment {proposal.environment!r}")

        target = proposal.target
        if target.kind not in policy.kinds:
            return deny(f"target kind {target.kind!r} not allowed")
        if target.namespace in policy.denied_namespaces:
            return deny(f"namespace {target.namespace!r} is protected")
        if policy.allowed_namespaces and target.namespace not in policy.allowed_namespaces:
            return deny(f"namespace {target.namespace!r} is not in the allowlist")
        if not self.is_fresh(target):
            return deny("stale target: it no longer exists or its UID changed")

        reasons = ["allowlisted", "target fresh"]
        required = policy.min_approvals
        decision = Decision.AWAIT_APPROVAL
        matched = {k: v for k, v in policy.escalate_when_labels.items() if target.labels.get(k) == v}
        if matched:
            decision = Decision.ESCALATE
            required = max(required, policy.escalated_min)
            reasons.append(f"escalated: target labels {matched}")

        if policy.require_dry_run and proposal.dry_run_passed is not True:
            return deny("dry-run missing or failed")

        return PolicyResult(
            decision=decision,
            reasons=reasons,
            required_approvals=required,
            approver_roles=policy.approver_roles,
            approval_ttl=policy.approval_ttl,
            rollback=policy.rollback,
        )
