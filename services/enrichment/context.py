"""Resolve pod -> workload -> service account -> IAM role -> node/instance.

Each lookup is read-only and timestamped. Anything that cannot be resolved is returned as None
and shown as unresolved, never guessed.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from common.timeutil import utcnow

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PodContext:
    namespace: str
    pod: str
    pod_uid: str | None
    node: str | None
    service_account: str | None
    owner_kind: str | None
    owner_name: str | None
    labels: dict[str, str]
    iam_role_arn: str | None
    instance_id: str | None
    resolved_at: datetime


def owner_chain(core: Any, apps: Any, namespace: str, pod: Any) -> tuple[str | None, str | None]:
    """Follow Pod -> ReplicaSet -> Deployment owner references."""
    refs = pod.metadata.owner_references or []
    if not refs:
        return None, None
    ref = refs[0]
    if ref.kind == "ReplicaSet":
        rs = apps.read_namespaced_replica_set(ref.name, namespace)
        rs_refs = rs.metadata.owner_references or []
        if rs_refs and rs_refs[0].kind == "Deployment":
            return "Deployment", rs_refs[0].name
    return ref.kind, ref.name


def pod_identity_role(eks: Any, cluster: str, namespace: str, service_account: str) -> str | None:
    """EKS Pod Identity association for this service account, if any."""
    found = eks.list_pod_identity_associations(
        clusterName=cluster, namespace=namespace, serviceAccount=service_account
    ).get("associations", [])
    if not found:
        return None
    detail = eks.describe_pod_identity_association(
        clusterName=cluster, associationId=found[0]["associationId"]
    )
    return detail["association"]["roleArn"]


def instance_for_node(ec2: Any, node_name: str) -> str | None:
    """EKS node names are the instance's private DNS name."""
    reservations = ec2.describe_instances(Filters=[{"Name": "private-dns-name", "Values": [node_name]}]).get(
        "Reservations", []
    )
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            return instance["InstanceId"]
    return None


def _optional(lookup: Callable[[], str | None], what: str) -> str | None:
    """AWS context is a bonus: if it can't be read (no AWS in the kind lab, throttling), leave it
    unresolved rather than losing the Kubernetes context too."""
    try:
        return lookup()
    except Exception:
        log.warning("could not resolve %s; leaving it unresolved", what, exc_info=True)
        return None


def resolve_pod_context(
    *, core: Any, apps: Any, eks: Any, ec2: Any, cluster: str, namespace: str, pod_name: str
) -> PodContext:
    pod = core.read_namespaced_pod(pod_name, namespace)
    owner_kind, owner_name = owner_chain(core, apps, namespace, pod)
    service_account = pod.spec.service_account_name
    node = pod.spec.node_name
    role = (
        _optional(lambda: pod_identity_role(eks, cluster, namespace, service_account), "IAM role")
        if service_account
        else None
    )
    instance = _optional(lambda: instance_for_node(ec2, node), "EC2 instance") if node else None
    return PodContext(
        namespace=namespace,
        pod=pod_name,
        pod_uid=pod.metadata.uid,
        node=node,
        service_account=service_account,
        owner_kind=owner_kind,
        owner_name=owner_name,
        labels=dict(pod.metadata.labels or {}),
        iam_role_arn=role,
        instance_id=instance,
        resolved_at=utcnow(),
    )
