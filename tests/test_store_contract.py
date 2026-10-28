"""Behavior every store implementation must share (in-memory and PostgreSQL)."""

from datetime import UTC, datetime, timedelta

import pytest

from cases.audit import verify_chain
from correlation.engine import CorrelationEngine
from enrichment.graph import Edge, Entity
from ingestion.evidence import InMemoryEvidenceStore
from ingestion.pipeline import DuplicateEventError, IngestPipeline
from tests.conftest import NOW, fixture_bytes

S1 = "s1_suspicious_process"


def _pipeline(stores):
    engine = CorrelationEngine(stores.cases)
    return IngestPipeline(
        stores.events, InMemoryEvidenceStore(), on_accepted=engine.correlate, clock=lambda: NOW
    )


def test_event_round_trips_exactly(stores, falco):
    result = _pipeline(stores).ingest(fixture_bytes(S1, "falco_alert.json"), falco)
    stored = stores.events.get(result.event_id)

    assert stored is not None
    assert stored.title == "Unexpected Process in Protected Workload"
    ids = stored.keys  # (not `stored.keys.x == "..."`: Gitleaks reads that as an API key)
    assert ids.pod_uid == "8b0e3c52-1d7a-4f43-9e6b-3a2c5d9f0e17"
    assert stored.event_time == datetime(2026, 10, 28, 14, 2, 40, 512345, tzinfo=UTC)
    assert stored.ocsf["attacks"][0]["technique"]["uid"] == "T1059"
    assert stores.events.exists(result.dedup_key)


def test_store_rejects_a_second_insert_of_the_same_dedup_key(stores, falco):
    result = _pipeline(stores).ingest(fixture_bytes(S1, "falco_alert.json"), falco)
    event = stores.events.get(result.event_id)
    with pytest.raises(DuplicateEventError):
        stores.events.insert(event.model_copy(update={"event_id": "evt_other"}), result.dedup_key)


def test_s1_case_survives_a_reload_with_links_in_order(stores, falco, guardduty):
    pipeline = _pipeline(stores)
    pipeline.ingest(fixture_bytes(S1, "guardduty_finding.json"), guardduty)
    pipeline.ingest(fixture_bytes(S1, "falco_alert.json"), falco)
    pipeline.ingest(fixture_bytes(S1, "falco_alert.json"), falco)  # duplicate delivery

    [case] = stores.cases.list()
    reloaded = stores.cases.get(case.case_id)

    assert [link.rule for link in reloaded.links] == ["C-00", "C-01"]
    assert [e.source for e in reloaded.timeline()] == ["falco", "guardduty"]
    assert reloaded.severity.value == "medium"
    assert [c.case_id for c in stores.cases.open_cases()] == [case.case_id]
    assert stores.cases.get("case_missing") is None


def test_audit_chain_is_intact_and_filterable(stores):
    stores.audit.append("service", "correlation-engine", "case.event_linked", {"case_id": "c1"})
    stores.audit.append("model", "investigator", "investigation.created", {"case_id": "c2"})
    stores.audit.append("human", "analyst:a.nasri", "proposal.approved", {"case_id": "c1", "n": 1})

    records = stores.audit.records()
    assert [r.seq for r in records] == [1, 2, 3]
    assert stores.audit.verify() is None
    assert verify_chain(records) is None
    assert [r.seq for r in stores.audit.records("c1")] == [1, 3]


def test_entity_graph_merges_evidence_and_walks_both_directions(stores):
    at = NOW
    pod, sa, role = "k8s:pod/shop/checkout-1", "k8s:sa/shop/checkout", "aws:iam-role/arn:aws:iam::1:role/r"
    stores.entities.upsert(
        [Entity(pod, "pod", at), Entity(sa, "service_account", at), Entity(role, "iam_role", at)],
        [
            Edge(pod, sa, "uses_identity", "configured", ("evt_1",)),
            Edge(sa, role, "uses_identity", "configured", ("evt_1",)),
        ],
    )
    stores.entities.upsert(
        [Entity(pod, "pod", at + timedelta(minutes=1), attributes={"uid": "u1"})],
        [Edge(pod, sa, "uses_identity", "configured", ("evt_2",))],
    )

    assert stores.entities.get(pod).attributes == {"uid": "u1"}
    nodes, edges = stores.entities.neighborhood(role, depth=2)
    assert {n.entity_id for n in nodes} == {pod, sa, role}
    pod_edge = next(e for e in edges if e.from_entity == pod)
    assert set(pod_edge.evidence_ids) == {"evt_1", "evt_2"}

    nodes, _ = stores.entities.neighborhood(role, depth=1)
    assert {n.entity_id for n in nodes} == {sa, role}
