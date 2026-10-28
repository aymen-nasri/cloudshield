"""Enrichment step that runs between normalization and correlation.

For an event about a Kubernetes pod it resolves the pod's workload, service account, IAM role and
EC2 instance, fills the event's identity and correlation keys, and records the entity graph.
Failures never drop the event: it continues unenriched and the fields stay unresolved.
"""

import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from common.models import NormalizedEvent
from common.timeutil import utcnow
from enrichment.context import PodContext, resolve_pod_context
from enrichment.graph import Edge, Entity, EntityStore

log = logging.getLogger(__name__)

PodResolver = Callable[[str, str], PodContext]  # (namespace, pod) -> context


def pod_ref(resource_id: str | None) -> tuple[str, str] | None:
    """`k8s:pod/<namespace>/<name>` -> (namespace, name)."""
    if not resource_id or not resource_id.startswith("k8s:pod/"):
        return None
    parts = resource_id.removeprefix("k8s:pod/").split("/")
    return (parts[0], parts[1]) if len(parts) == 2 and all(parts) else None


def graph_for(ctx: PodContext, event: NormalizedEvent) -> tuple[list[Entity], list[Edge]]:
    scope: dict[str, Any] = {"account_id": event.account_id, "cluster": event.cluster}
    at = ctx.resolved_at
    pod_id = f"k8s:pod/{ctx.namespace}/{ctx.pod}"
    entities = [
        Entity(
            pod_id,
            "pod",
            at,
            namespace=ctx.namespace,
            attributes={"uid": ctx.pod_uid, "labels": ctx.labels, "node": ctx.node},
            **scope,
        ),
    ]
    edges: list[Edge] = []
    evidence = (event.event_id,)

    if ctx.owner_kind and ctx.owner_name:
        owner_id = f"k8s:{ctx.owner_kind.lower()}/{ctx.namespace}/{ctx.owner_name}"
        entities.append(Entity(owner_id, ctx.owner_kind.lower(), at, namespace=ctx.namespace, **scope))
        edges.append(Edge(pod_id, owner_id, "belongs_to", "configured", evidence))
    if ctx.service_account:
        sa_id = f"k8s:sa/{ctx.namespace}/{ctx.service_account}"
        entities.append(Entity(sa_id, "service_account", at, namespace=ctx.namespace, **scope))
        edges.append(Edge(pod_id, sa_id, "uses_identity", "configured", evidence))
        if ctx.iam_role_arn:
            role_id = f"aws:iam-role/{ctx.iam_role_arn}"
            entities.append(Entity(role_id, "iam_role", at, attributes={"arn": ctx.iam_role_arn}, **scope))
            edges.append(Edge(sa_id, role_id, "uses_identity", "configured", evidence))
    if ctx.instance_id:
        instance = f"aws:ec2/{ctx.instance_id}"
        entities.append(Entity(instance, "ec2_instance", at, attributes={"node": ctx.node}, **scope))
        edges.append(Edge(pod_id, instance, "runs_on", "observed", evidence))
    return entities, edges


class Enricher:
    def __init__(
        self,
        resolve_pod: PodResolver,
        entities: EntityStore,
        *,
        cache_ttl: timedelta = timedelta(minutes=5),
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.resolve_pod = resolve_pod
        self.entities = entities
        self.cache_ttl = cache_ttl
        self.clock = clock
        self._cache: dict[tuple[str, str], tuple[datetime, PodContext]] = {}

    def _context(self, namespace: str, pod: str) -> PodContext:
        key = (namespace, pod)
        hit = self._cache.get(key)
        if hit and self.clock() - hit[0] < self.cache_ttl:
            return hit[1]
        ctx = self.resolve_pod(namespace, pod)
        self._cache[key] = (self.clock(), ctx)
        return ctx

    def __call__(self, event: NormalizedEvent) -> NormalizedEvent:
        ref = pod_ref(event.resource_id)
        if ref is None:
            return event
        try:
            ctx = self._context(*ref)
        except Exception:
            log.warning("enrichment failed for %s; continuing unresolved", event.resource_id, exc_info=True)
            return event

        # A pod name can be reused; only trust the lookup if the UIDs agree (or the event had none).
        if event.keys.pod_uid and ctx.pod_uid and event.keys.pod_uid != ctx.pod_uid:
            log.warning("pod %s/%s UID changed since the event; not enriching", *ref)
            return event

        entities, edges = graph_for(ctx, event)
        self.entities.upsert(entities, edges)

        keys = event.keys.model_copy(
            update={
                "pod_uid": event.keys.pod_uid or ctx.pod_uid,
                "instance_id": event.keys.instance_id or ctx.instance_id,
                "principal_arn": event.keys.principal_arn or ctx.iam_role_arn,
            }
        )
        identity = event.identity_id or (
            f"k8s:sa/{ctx.namespace}/{ctx.service_account}" if ctx.service_account else None
        )
        return event.model_copy(update={"keys": keys, "identity_id": identity})


def kubernetes_pod_resolver(cluster: str, region: str | None = None) -> PodResolver:
    """Resolver backed by the Kubernetes API (investigator RBAC) and read-only AWS calls."""
    import boto3
    from kubernetes import client, config

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    core, apps = client.CoreV1Api(), client.AppsV1Api()
    eks: Any = boto3.client("eks", region_name=region)
    ec2: Any = boto3.client("ec2", region_name=region)

    def resolve(namespace: str, pod: str) -> PodContext:
        return resolve_pod_context(
            core=core, apps=apps, eks=eks, ec2=ec2, cluster=cluster, namespace=namespace, pod_name=pod
        )

    return resolve
