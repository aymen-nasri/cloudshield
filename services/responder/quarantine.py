"""Reversible pod quarantine: label the pod so it drops out of every allow-policy.

The namespace runs a default-deny NetworkPolicy, and Kyverno requires every allow-policy to
exclude `cloudshield.io/quarantine=true`. Labelling the pod therefore leaves only default-deny
in force, while the pod keeps running for forensics. Rollback removes the label.
"""

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from common.models import Target
from responder.selectors import allow_policies_selecting, is_default_deny

QUARANTINE_LABEL = "cloudshield.io/quarantine"

Status = Literal["dry_run_ok", "applied", "already_applied", "removed", "stale_target", "not_found"]


class PodApi(Protocol):
    """The subset of the Kubernetes API the responder needs, as plain dicts."""

    def get_pod(self, namespace: str, name: str) -> dict[str, Any] | None: ...

    def patch_pod_labels(
        self, namespace: str, name: str, labels: dict[str, str | None], *, dry_run: bool
    ) -> None: ...

    def list_network_policies(self, namespace: str) -> list[dict[str, Any]]: ...


@dataclass(frozen=True)
class ExecutionResult:
    status: Status
    detail: str = ""


@dataclass
class VerificationReport:
    checks: dict[str, bool | None] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        # Skipped checks (None) do not fail verification but are reported to the analyst.
        return all(v is not False for v in self.checks.values())


def _check_target(api: PodApi, target: Target) -> tuple[dict[str, Any] | None, ExecutionResult | None]:
    if target.namespace is None:
        return None, ExecutionResult("not_found", "target has no namespace")
    pod = api.get_pod(target.namespace, target.name)
    if pod is None:
        return None, ExecutionResult("not_found", "pod no longer exists")
    if pod["metadata"]["uid"] != target.uid:
        return None, ExecutionResult("stale_target", "pod name now belongs to a different pod (UID changed)")
    return pod, None


def apply_quarantine(api: PodApi, target: Target, *, dry_run: bool) -> ExecutionResult:
    pod, problem = _check_target(api, target)
    if problem or pod is None or target.namespace is None:
        return problem or ExecutionResult("not_found")
    if (pod["metadata"].get("labels") or {}).get(QUARANTINE_LABEL) == "true":
        return ExecutionResult("already_applied", "label already present; nothing to do")  # idempotent
    api.patch_pod_labels(target.namespace, target.name, {QUARANTINE_LABEL: "true"}, dry_run=dry_run)
    return ExecutionResult("dry_run_ok" if dry_run else "applied")


def remove_quarantine(api: PodApi, target: Target, *, dry_run: bool) -> ExecutionResult:
    _, problem = _check_target(api, target)
    if problem or target.namespace is None:
        return problem or ExecutionResult("not_found")
    # A JSON merge patch with null deletes the label.
    api.patch_pod_labels(target.namespace, target.name, {QUARANTINE_LABEL: None}, dry_run=dry_run)
    return ExecutionResult("dry_run_ok" if dry_run else "removed")


def verify_quarantine(api: PodApi, target: Target) -> VerificationReport:
    report = VerificationReport()
    pod, problem = _check_target(api, target)
    if problem or pod is None or target.namespace is None:
        report.checks["target_exists"] = False
        report.notes["target_exists"] = problem.detail if problem else "missing"
        return report

    labels = pod["metadata"].get("labels") or {}
    policies = api.list_network_policies(target.namespace)
    still_allowed = allow_policies_selecting(policies, labels)

    report.checks["label_present"] = labels.get(QUARANTINE_LABEL) == "true"
    report.checks["default_deny_present"] = any(is_default_deny(p) for p in policies)
    report.checks["no_allow_policy_selects_pod"] = not still_allowed
    if still_allowed:
        report.notes["no_allow_policy_selects_pod"] = f"still selected by {still_allowed}"
    report.checks["pod_preserved_for_forensics"] = (pod.get("status") or {}).get("phase") == "Running"

    # TODO(M4): run an egress probe from an ephemeral debug container and record the result.
    report.checks["egress_probe"] = None
    report.notes["egress_probe"] = "not yet implemented; policy state verified instead"
    return report


class KubernetesPodApi:
    """PodApi backed by the official Kubernetes client (in-cluster config, responder service account)."""

    def __init__(self) -> None:
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        self._core = client.CoreV1Api()
        self._net = client.NetworkingV1Api()
        self._serialize = client.ApiClient().sanitize_for_serialization

    def get_pod(self, namespace: str, name: str) -> dict[str, Any] | None:
        from kubernetes.client.exceptions import ApiException

        try:
            return self._serialize(self._core.read_namespaced_pod(name, namespace))
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    def patch_pod_labels(
        self, namespace: str, name: str, labels: dict[str, str | None], *, dry_run: bool
    ) -> None:
        self._core.patch_namespaced_pod(
            name, namespace, {"metadata": {"labels": labels}}, dry_run="All" if dry_run else None
        )

    def list_network_policies(self, namespace: str) -> list[dict[str, Any]]:
        items = self._net.list_namespaced_network_policy(namespace).items
        return [self._serialize(p) for p in items]
