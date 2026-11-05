"""In-process executor for the lab. In the AWS lab the same calls run inside the Step Functions
workflow (statemachine/quarantine.asl.json) with the responder's own IAM/RBAC identity.
"""

from collections.abc import Callable, Sequence
from typing import Any, Protocol

from common.models import ResponseProposal, Target
from policy.approvals import Approval
from responder.quarantine import (
    ExecutionResult,
    PodApi,
    TrafficProbe,
    VerificationReport,
    apply_quarantine,
    peer_can_connect,
    preview_quarantine,
    remove_quarantine,
    verify_quarantine,
    verify_release,
)


class UnsupportedAction(Exception):
    pass


class Executor(Protocol):
    identity: str

    def current_labels(self, target: Target) -> dict[str, str] | None:
        """Live labels of the target, or None if it does not exist with this UID."""
        ...

    def is_fresh(self, target: Target) -> bool: ...

    def dry_run(self, proposal: ResponseProposal) -> tuple[ExecutionResult, dict[str, Any]]: ...

    def execute(self, proposal: ResponseProposal, approvals: Sequence[Approval] = ()) -> ExecutionResult: ...

    def verify(self, proposal: ResponseProposal) -> VerificationReport: ...


Action = Callable[..., ExecutionResult]
Verifier = Callable[[PodApi, Target, TrafficProbe | None], VerificationReport]

_ACTIONS: dict[str, tuple[Action, Verifier]] = {
    "k8s.pod.quarantine_label": (apply_quarantine, verify_quarantine),
    "k8s.pod.remove_quarantine_label": (remove_quarantine, verify_release),
}


class KubernetesExecutor:
    def __init__(
        self, api: PodApi, identity: str = "cloudshield-responder", probe: TrafficProbe | None = None
    ) -> None:
        self.api = api
        self.identity = identity
        self.probe = probe  # optional: verify with real traffic, not only policy state
        # Whether the peer could connect just before each quarantine. Kept in this process only:
        # after a restart the check is skipped, never passed.
        self._peer_before: dict[str, bool | None] = {}

    def _action(self, action_type: str) -> tuple[Action, Verifier]:
        if action_type not in _ACTIONS:
            raise UnsupportedAction(f"no executor for {action_type!r}")
        return _ACTIONS[action_type]

    def current_labels(self, target: Target) -> dict[str, str] | None:
        if target.kind != "Pod" or target.namespace is None:
            return None
        pod = self.api.get_pod(target.namespace, target.name)
        if pod is None or pod["metadata"]["uid"] != target.uid:
            return None
        return dict(pod["metadata"].get("labels") or {})

    def is_fresh(self, target: Target) -> bool:
        return self.current_labels(target) is not None

    def dry_run(self, proposal: ResponseProposal) -> tuple[ExecutionResult, dict[str, Any]]:
        action, _ = self._action(proposal.action_type)
        result = action(self.api, proposal.target, dry_run=True)
        impact = (
            preview_quarantine(self.api, proposal.target)
            if proposal.action_type == "k8s.pod.quarantine_label"
            else {}
        )
        return result, impact

    def execute(self, proposal: ResponseProposal, approvals: Sequence[Approval] = ()) -> ExecutionResult:
        # Approvals are the caller's to check: this class runs inside the process that decides.
        action, _ = self._action(proposal.action_type)
        if proposal.action_type == "k8s.pod.quarantine_label":
            before = peer_can_connect(self.api, proposal.target, self.probe)
            self._peer_before[proposal.proposal_id] = before
        return action(self.api, proposal.target, dry_run=False)

    def verify(self, proposal: ResponseProposal) -> VerificationReport:
        _, verifier = self._action(proposal.action_type)
        if proposal.action_type == "k8s.pod.quarantine_label":
            before = self._peer_before.pop(proposal.proposal_id, None)
            return verify_quarantine(self.api, proposal.target, self.probe, peer_connected_before=before)
        return verifier(self.api, proposal.target, self.probe)
