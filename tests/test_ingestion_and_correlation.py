"""Test catalog T-02, T-03 and correlation rules C-01 / C-04."""

import json

from correlation.engine import CorrelationEngine
from ingestion.adapters import FalcoAdapter
from ingestion.evidence import InMemoryEvidenceStore
from ingestion.pipeline import IngestPipeline, InMemoryEventStore
from tests.conftest import NOW, fixture_bytes

S1 = "s1_suspicious_process"


def test_t02_duplicate_delivery_creates_one_event_and_one_case(pipeline, falco, cases):
    raw = fixture_bytes(S1, "falco_alert.json")
    first = pipeline.ingest(raw, falco)
    second = pipeline.ingest(raw, falco)

    assert first.status == "accepted"
    assert second.status == "duplicate"
    assert second.dedup_key == first.dedup_key
    assert len(cases.list()) == 1
    assert len(cases.list()[0].events) == 1


def test_raw_evidence_is_archived_unchanged_with_checksum(cases, falco):
    evidence = InMemoryEvidenceStore()
    events = InMemoryEventStore()
    raw = fixture_bytes(S1, "falco_alert.json")
    result = IngestPipeline(events, evidence, clock=lambda: NOW).ingest(raw, falco)

    event = events.get(result.event_id)
    assert evidence.objects[event.raw_evidence_uri] == raw
    assert event.checksum.startswith("sha256:")


def test_s1_falco_and_guardduty_join_one_case_via_c01(pipeline, falco, guardduty, cases):
    pipeline.ingest(fixture_bytes(S1, "guardduty_finding.json"), guardduty)
    pipeline.ingest(fixture_bytes(S1, "falco_alert.json"), falco)

    [case] = cases.list()
    assert [link.rule for link in case.links] == ["C-00", "C-01"]
    assert "pod_uid=8b0e3c52" in case.links[1].rationale


def test_t03_out_of_order_events_are_ordered_by_event_time(pipeline, falco, guardduty, cases):
    # GuardDuty (14:03:05) arrives before Falco (14:02:40).
    pipeline.ingest(fixture_bytes(S1, "guardduty_finding.json"), guardduty)
    pipeline.ingest(fixture_bytes(S1, "falco_alert.json"), falco)

    [case] = cases.list()
    assert [e.source for e in case.events] == ["guardduty", "falco"]
    assert [e.source for e in case.timeline()] == ["falco", "guardduty"]


def test_c04_never_merges_across_clusters(cases, guardduty):
    engine = CorrelationEngine(cases)
    pipe = IngestPipeline(InMemoryEventStore(), InMemoryEvidenceStore(), on_accepted=engine.correlate)
    other_cluster = FalcoAdapter(cluster="another-cluster", account_id="123456789012")

    pipe.ingest(fixture_bytes(S1, "guardduty_finding.json"), guardduty)
    pipe.ingest(fixture_bytes(S1, "falco_alert.json"), other_cluster)

    assert len(cases.list()) == 2


def test_events_outside_the_window_open_a_new_case(pipeline, falco, cases):
    raw = json.loads(fixture_bytes(S1, "falco_alert.json"))
    pipeline.ingest(json.dumps(raw).encode(), falco)
    raw["uuid"] = "later-event"
    raw["time"] = "2026-10-28T15:30:00Z"  # 87 minutes later, beyond C-01's 15 minutes
    pipeline.ingest(json.dumps(raw).encode(), falco)

    assert len(cases.list()) == 2
