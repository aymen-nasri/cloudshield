"""Kubernetes label-selector matching, used to prove which NetworkPolicies select a pod.

Works on the Kubernetes JSON form (camelCase), e.g. the output of
ApiClient().sanitize_for_serialization(policy).
"""

from typing import Any


def matches(selector: dict[str, Any] | None, labels: dict[str, str]) -> bool:
    if not selector:
        return True  # an empty podSelector selects every pod in the namespace
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != value:
            return False
    for expr in selector.get("matchExpressions") or []:
        key, op, values = expr["key"], expr["operator"], expr.get("values") or []
        if op == "In" and labels.get(key) not in values:
            return False
        if op == "NotIn" and key in labels and labels[key] in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def is_default_deny(policy: dict[str, Any]) -> bool:
    """A policy that selects all pods, covers both directions and allows nothing."""
    spec = policy.get("spec") or {}
    return (
        not spec.get("podSelector")
        and set(spec.get("policyTypes") or []) == {"Ingress", "Egress"}
        and not spec.get("ingress")
        and not spec.get("egress")
    )


def allow_policies_selecting(policies: list[dict[str, Any]], labels: dict[str, str]) -> list[str]:
    """Names of non-default-deny policies that select a pod with these labels."""
    return [
        p["metadata"]["name"]
        for p in policies
        if not is_default_deny(p) and matches((p.get("spec") or {}).get("podSelector"), labels)
    ]
