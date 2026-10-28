"""Test doubles shared across test modules."""

import copy
from datetime import datetime, timedelta
from typing import Any

from responder.quarantine import QUARANTINE_LABEL

DEFAULT_DENY = {
    "metadata": {"name": "default-deny-all"},
    "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
}
CHECKOUT_ALLOW = {
    "metadata": {"name": "checkout-allow"},
    "spec": {
        "podSelector": {
            "matchLabels": {"app": "checkout"},
            "matchExpressions": [{"key": QUARANTINE_LABEL, "operator": "NotIn", "values": ["true"]}],
        },
        "policyTypes": ["Ingress"],
        "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "cart"}}}]}],
    },
}


class FakePodApi:
    """One pod plus the namespace's NetworkPolicies, in Kubernetes JSON form."""

    def __init__(
        self,
        name: str = "checkout-1",
        uid: str = "uid-1",
        labels: dict[str, str] | None = None,
        policies: list[dict[str, Any]] | None = None,
    ) -> None:
        self.pod: dict[str, Any] | None = {
            "metadata": {"name": name, "uid": uid, "labels": dict(labels or {"app": "checkout"})},
            "status": {"phase": "Running"},
        }
        self.policies = policies if policies is not None else [DEFAULT_DENY, CHECKOUT_ALLOW]
        self.patches: list[tuple[dict[str, str | None], bool]] = []

    @property
    def labels(self) -> dict[str, str]:
        return self.pod["metadata"]["labels"] if self.pod else {}

    def get_pod(self, namespace: str, name: str) -> dict[str, Any] | None:
        if self.pod is None or name != self.pod["metadata"]["name"]:
            return None
        return copy.deepcopy(self.pod)

    def patch_pod_labels(
        self, namespace: str, name: str, labels: dict[str, str | None], *, dry_run: bool
    ) -> None:
        self.patches.append((labels, dry_run))
        if not dry_run and self.pod is not None:
            for key, value in labels.items():
                if value is None:
                    self.pod["metadata"]["labels"].pop(key, None)
                else:
                    self.pod["metadata"]["labels"][key] = value

    def list_network_policies(self, namespace: str) -> list[dict[str, Any]]:
        return self.policies

    @property
    def real_patches(self) -> list[dict[str, str | None]]:
        return [labels for labels, dry_run in self.patches if not dry_run]


class Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)
