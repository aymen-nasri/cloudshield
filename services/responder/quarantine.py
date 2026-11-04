"""Reversible pod quarantine: label the pod so it drops out of every allow-policy.

The namespace runs a default-deny NetworkPolicy, and Kyverno requires every allow-policy to
exclude `cloudshield.io/quarantine=true`. Labelling the pod therefore leaves only default-deny
in force, while the pod keeps running for forensics. Rollback removes the label.

Verification checks the policy state and, when a traffic probe is configured, real traffic: a
peer that the policies normally allow must fail to connect to the quarantined pod, and must
connect again after rollback. A block only counts if that peer could connect beforehand; otherwise
the check is skipped, because a peer that was never allowed proves nothing by failing.
"""

import time
from dataclasses import dataclass, field
from pathlib import Path
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


class TrafficProbe(Protocol):
    """Opens a new TCP connection from a peer the policies normally allow (e.g. a cart pod)."""

    def covers(self, namespace: str, labels: dict[str, str]) -> bool:
        """Is this peer meant to be able to reach a pod like this one?"""
        ...

    def can_connect(self, ip: str, port: int) -> bool | None:
        """True or False; None when the probe itself could not run."""
        ...


# A label change takes a few seconds to reach the CNI, so the probe waits for the expected answer.
PROBE_ATTEMPTS = 5
PROBE_WAIT_SECONDS = 2.0


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


def _endpoint(pod: dict[str, Any]) -> tuple[str, int] | None:
    ip = (pod.get("status") or {}).get("podIP")
    for container in (pod.get("spec") or {}).get("containers") or []:
        for port in container.get("ports") or []:
            if ip and port.get("containerPort"):
                return ip, int(port["containerPort"])
    return None


def _probe_skip_reason(probe: TrafficProbe | None, pod: dict[str, Any], namespace: str) -> str | None:
    if probe is None:
        return "no traffic probe configured; policy state verified instead"
    if _endpoint(pod) is None:
        return "the pod exposes no port to probe; policy state verified instead"
    if not probe.covers(namespace, pod["metadata"].get("labels") or {}):
        return "the probe's peer is not meant to reach this pod; policy state verified instead"
    return None


def peer_can_connect(api: PodApi, target: Target, probe: TrafficProbe | None) -> bool | None:
    """One connection attempt before a quarantine; None when the probe doesn't apply to this pod."""
    pod, problem = _check_target(api, target)
    if probe is None or problem or pod is None or target.namespace is None:
        return None
    endpoint = _endpoint(pod)
    if endpoint is None or _probe_skip_reason(probe, pod, target.namespace):
        return None
    return probe.can_connect(*endpoint)


def _probe_traffic(
    report: VerificationReport,
    probe: TrafficProbe | None,
    pod: dict[str, Any],
    namespace: str,
    *,
    expect_connect: bool,
) -> None:
    """Record whether an allowed peer can connect, waiting briefly for the expected answer."""
    skip = _probe_skip_reason(probe, pod, namespace)
    endpoint = _endpoint(pod)
    if skip or probe is None or endpoint is None:
        report.checks["traffic_probe"] = None
        report.notes["traffic_probe"] = skip or "no traffic probe configured"
        return
    ip, port = endpoint
    connected: bool | None = None
    for attempt in range(PROBE_ATTEMPTS):
        connected = probe.can_connect(ip, port)
        if connected is None or connected is expect_connect:
            break
        if attempt < PROBE_ATTEMPTS - 1:
            time.sleep(PROBE_WAIT_SECONDS)
    if connected is None:
        report.checks["traffic_probe"] = None
        report.notes["traffic_probe"] = "the probe could not run"
        return
    report.checks["traffic_probe"] = connected is expect_connect
    report.notes["traffic_probe"] = f"allowed peer -> {ip}:{port}: {'connected' if connected else 'blocked'}"


def verify_quarantine(
    api: PodApi,
    target: Target,
    probe: TrafficProbe | None = None,
    *,
    peer_connected_before: bool | None = None,
) -> VerificationReport:
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
    if _probe_skip_reason(probe, pod, target.namespace) is None and peer_connected_before is not True:
        report.checks["traffic_probe"] = None
        report.notes["traffic_probe"] = (
            "the peer could not connect before this action, so a block would prove nothing"
        )
        return report
    _probe_traffic(report, probe, pod, target.namespace, expect_connect=False)
    return report


def verify_release(api: PodApi, target: Target, probe: TrafficProbe | None = None) -> VerificationReport:
    """After rollback: the label is gone, so the pod's normal allow-policies apply again."""
    report = VerificationReport()
    pod, problem = _check_target(api, target)
    if problem or pod is None or target.namespace is None:
        report.checks["target_exists"] = False
        report.notes["target_exists"] = problem.detail if problem else "missing"
        return report
    labels = pod["metadata"].get("labels") or {}
    report.checks["label_removed"] = QUARANTINE_LABEL not in labels
    selecting = allow_policies_selecting(api.list_network_policies(target.namespace), labels)
    report.checks["allow_policies_apply_again"] = bool(selecting)
    report.notes["allow_policies_apply_again"] = f"selected by {selecting}" if selecting else "none"
    _probe_traffic(report, probe, pod, target.namespace, expect_connect=True)
    return report


def preview_quarantine(api: PodApi, target: Target) -> dict[str, Any]:
    """What the analyst should know before approving: which allowed paths this pod will lose."""
    pod, problem = _check_target(api, target)
    if problem or pod is None or target.namespace is None:
        return {"error": problem.detail if problem else "missing"}
    labels = pod["metadata"].get("labels") or {}
    policies = api.list_network_policies(target.namespace)
    return {
        "pod_phase": (pod.get("status") or {}).get("phase"),
        "allow_policies_lost": allow_policies_selecting(policies, labels),
        "default_deny_present": any(is_default_deny(p) for p in policies),
        "pod_keeps_running": True,
        "caveat": "Whether already-open connections are cut depends on the CNI.",
    }


def api_client_from_token_file(token_file: Path) -> Any:
    """A Kubernetes client acting as the service account whose token is in this file."""
    from kubernetes import client, config

    token = token_file.read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError(f"Kubernetes token file {token_file} is empty")
    cfg = client.Configuration()
    try:
        config.load_incluster_config(client_configuration=cfg)
    except config.ConfigException:
        config.load_kube_config(client_configuration=cfg)
    cfg.refresh_api_key_hook = None  # or the in-cluster loader swaps back to this pod's identity
    cfg.cert_file = cfg.key_file = None  # or a kubeconfig's client certificate wins over the token
    cfg.api_key = {"authorization": f"Bearer {token}"}
    return client.ApiClient(cfg)


class KubernetesPodApi:
    """PodApi backed by the official Kubernetes client (in-cluster config, responder service account)."""

    def __init__(self, api_client: Any | None = None) -> None:
        """`api_client` overrides the ambient config, e.g. to act as the responder service account."""
        from kubernetes import client, config

        if api_client is None:
            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config()
            api_client = client.ApiClient()
        self._core = client.CoreV1Api(api_client)
        self._net = client.NetworkingV1Api(api_client)
        self._serialize = api_client.sanitize_for_serialization

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


class ExecTrafficProbe:
    """TrafficProbe that runs curl in one dedicated probe pod through the Kubernetes exec API.

    It acts as the cloudshield-prober service account, whose only permission is exec into that one
    pod (RBAC resourceNames), so it cannot run commands anywhere else. `target_selector` names the
    pods the NetworkPolicies let this peer reach; any other pod is out of scope for the probe.
    """

    def __init__(
        self,
        namespace: str,
        pod: str = "probe",
        container: str = "curl",
        *,
        api_client: Any,
        target_selector: dict[str, str],
        timeout: int = 3,
    ) -> None:
        from kubernetes import client

        self._core = client.CoreV1Api(api_client)
        self.namespace, self.pod, self.container, self.timeout = namespace, pod, container, timeout
        self.target_selector = target_selector

    @classmethod
    def from_token_file(
        cls, namespace: str, pod: str, *, token_file: Path, target_selector: dict[str, str]
    ) -> "ExecTrafficProbe":
        """Authenticate as the prober, whose token is mounted separately from this process's identity."""
        return cls(
            namespace, pod, api_client=api_client_from_token_file(token_file), target_selector=target_selector
        )

    def covers(self, namespace: str, labels: dict[str, str]) -> bool:
        wanted = self.target_selector.items()
        return namespace == self.namespace and bool(wanted) and all(labels.get(k) == v for k, v in wanted)

    def can_connect(self, ip: str, port: int) -> bool | None:
        from kubernetes.client.exceptions import ApiException
        from kubernetes.stream import stream

        command = ["curl", "-s", "-o", "/dev/null", "-m", str(self.timeout), f"http://{ip}:{port}/"]
        try:
            ws = stream(
                self._core.connect_get_namespaced_pod_exec, self.pod, self.namespace,
                container=self.container, command=command,
                stderr=True, stdin=False, stdout=True, tty=False, _preload_content=False,
            )  # fmt: skip
            ws.run_forever(timeout=self.timeout + 5)
            code = ws.returncode
            ws.close()
        except (ApiException, OSError):
            return None
        return None if code is None else code == 0
