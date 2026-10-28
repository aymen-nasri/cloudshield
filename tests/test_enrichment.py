"""Enrichment: pod -> workload -> service account -> IAM role -> instance, never guessed."""

from datetime import timedelta
from types import SimpleNamespace as NS

from fastapi.testclient import TestClient

from core.app import Settings, create_app
from enrichment.context import PodContext, resolve_pod_context
from enrichment.enricher import Enricher, pod_ref
from enrichment.graph import InMemoryEntityStore
from ingestion.auth import SourceCredential
from tests.conftest import NOW, fixture_bytes

POD_UID = "8b0e3c52-1d7a-4f43-9e6b-3a2c5d9f0e17"
ROLE = "arn:aws:iam::123456789012:role/shop-checkout-pod"


def _ctx(uid: str = POD_UID) -> PodContext:
    return PodContext(
        namespace="shop",
        pod="checkout-7d9f6c-x2k8p",
        pod_uid=uid,
        node="ip-10-20-3-41.eu-west-1.compute.internal",
        service_account="checkout",
        owner_kind="Deployment",
        owner_name="checkout",
        labels={"app": "checkout"},
        iam_role_arn=ROLE,
        instance_id="i-0a1b2c3d4e5f60718",
        resolved_at=NOW,
    )


def _falco_event(falco):
    payload = falco.parse(fixture_bytes("s1_suspicious_process", "falco_alert.json"))
    return falco.to_event(payload, event_id="evt_1", ingest_time=NOW, raw_uri="mem://x", checksum="sha256:x")


def test_pod_ref_parses_only_pod_resources():
    assert pod_ref("k8s:pod/shop/checkout-1") == ("shop", "checkout-1")
    assert pod_ref("k8s:pods/shop/checkout-1") is None
    assert pod_ref("aws:ec2/i-123") is None
    assert pod_ref(None) is None


def test_enrichment_fills_identity_keys_and_graph(falco):
    graph = InMemoryEntityStore()
    enriched = Enricher(lambda ns, pod: _ctx(), graph)(_falco_event(falco))

    assert enriched.identity_id == "k8s:sa/shop/checkout"
    ids = enriched.keys
    assert ids.instance_id == "i-0a1b2c3d4e5f60718"
    assert ids.principal_arn == ROLE

    relations = {(e.from_entity, e.relation, e.to_entity, e.assurance) for e in graph.edges.values()}
    pod = "k8s:pod/shop/checkout-7d9f6c-x2k8p"
    assert (pod, "belongs_to", "k8s:deployment/shop/checkout", "configured") in relations
    assert (pod, "uses_identity", "k8s:sa/shop/checkout", "configured") in relations
    assert ("k8s:sa/shop/checkout", "uses_identity", f"aws:iam-role/{ROLE}", "configured") in relations
    assert (pod, "runs_on", "aws:ec2/i-0a1b2c3d4e5f60718", "observed") in relations


def test_lookup_failure_keeps_the_event_unresolved(falco):
    def broken(ns, pod):
        raise TimeoutError("kubernetes API unreachable")

    event = _falco_event(falco)
    assert Enricher(broken, InMemoryEntityStore())(event) == event


def test_reused_pod_name_with_a_different_uid_is_not_trusted(falco):
    graph = InMemoryEntityStore()
    event = _falco_event(falco)
    assert Enricher(lambda ns, pod: _ctx(uid="another-pod"), graph)(event) == event
    assert graph.entities == {}


def test_lookups_are_cached_per_pod(falco):
    calls = []
    now = [NOW]

    def resolver(ns, pod):
        calls.append(pod)
        return _ctx()

    enricher = Enricher(resolver, InMemoryEntityStore(), clock=lambda: now[0])
    enricher(_falco_event(falco))
    enricher(_falco_event(falco))
    assert len(calls) == 1
    now[0] = NOW + timedelta(minutes=6)
    enricher(_falco_event(falco))
    assert len(calls) == 2


def test_resolve_pod_context_follows_owners_and_aws_lookups():
    pod = NS(
        metadata=NS(uid=POD_UID, labels={"app": "checkout"},
                    owner_references=[NS(kind="ReplicaSet", name="checkout-7d9f6c")]),
        spec=NS(service_account_name="checkout", node_name="ip-10-20-3-41.eu-west-1.compute.internal"),
    )  # fmt: skip
    core = NS(read_namespaced_pod=lambda name, ns: pod)
    apps = NS(read_namespaced_replica_set=lambda name, ns: NS(
        metadata=NS(owner_references=[NS(kind="Deployment", name="checkout")])))  # fmt: skip
    eks = NS(
        list_pod_identity_associations=lambda **kw: {"associations": [{"associationId": "a-1"}]},
        describe_pod_identity_association=lambda **kw: {"association": {"roleArn": ROLE}},
    )
    ec2 = NS(describe_instances=lambda **kw: {"Reservations": [{"Instances": [{"InstanceId": "i-9"}]}]})

    ctx = resolve_pod_context(core=core, apps=apps, eks=eks, ec2=ec2, cluster="cs-lab-eks",
                              namespace="shop", pod_name="checkout-7d9f6c-x2k8p")  # fmt: skip
    assert (ctx.owner_kind, ctx.owner_name) == ("Deployment", "checkout")
    assert ctx.iam_role_arn == ROLE
    assert ctx.instance_id == "i-9"


def test_aws_failures_keep_the_kubernetes_context():
    pod = NS(
        metadata=NS(uid=POD_UID, labels={}, owner_references=[]),
        spec=NS(service_account_name="checkout", node_name="node-1"),
    )

    def no_aws(**kw):
        raise ConnectionError("no AWS credentials in the kind lab")

    ctx = resolve_pod_context(
        core=NS(read_namespaced_pod=lambda name, ns: pod),
        apps=NS(),
        eks=NS(list_pod_identity_associations=no_aws),
        ec2=NS(describe_instances=no_aws),
        cluster="kind",
        namespace="shop",
        pod_name="checkout-1",
    )
    assert (ctx.service_account, ctx.node) == ("checkout", "node-1")
    assert (ctx.iam_role_arn, ctx.instance_id) == (None, None)


def test_graph_endpoint_serves_the_enriched_neighborhood():
    settings = Settings(
        cluster="cs-lab-eks",
        account_id="123456789012",
        credentials={"falco": SourceCredential(token="t")},
    )
    client = TestClient(create_app(settings, pod_resolver=lambda ns, pod: _ctx()))
    body = fixture_bytes("s1_suspicious_process", "falco_alert.json")
    assert (
        client.post("/v1/ingest/falco", content=body, headers={"authorization": "Bearer t"}).status_code
        == 202
    )

    graph = client.get("/v1/entities/k8s:pod/shop/checkout-7d9f6c-x2k8p/graph").json()
    assert {e["kind"] for e in graph["entities"]} >= {"pod", "deployment", "service_account", "iam_role"}
    assert client.get("/v1/entities/k8s:pod/shop/nope/graph").status_code == 404

    [timeline_entry] = client.get(f"/v1/cases/{client.get('/v1/cases').json()[0]['case_id']}/timeline").json()
    assert timeline_entry["identity_id"] == "k8s:sa/shop/checkout"
