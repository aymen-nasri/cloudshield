from pathlib import Path

from investigator.runbooks import RunbookLibrary, parse_runbook
from tests.conftest import NOW, fixture_bytes

RUNBOOKS = Path(__file__).resolve().parents[1] / "runbooks"


def _event(adapter, scenario, name):
    payload = adapter.parse(fixture_bytes(scenario, name))
    return adapter.to_event(
        payload, event_id="evt_x", ingest_time=NOW, raw_uri="mem://x", checksum="sha256:x"
    )


def test_repository_runbooks_parse():
    library = RunbookLibrary.from_dir(RUNBOOKS)
    ids = {r.doc_id for r in library.runbooks}
    assert {"RB-001", "RB-002"} <= ids
    rb1 = next(r for r in library.runbooks if r.doc_id == "RB-001")
    assert "process.unexpected_execution" in rb1.applies_to
    assert [h for h, _ in rb1.sections][0] == "1. Confirm what ran"


def test_s1_events_retrieve_the_pod_runbook_first(falco, guardduty):
    library = RunbookLibrary.from_dir(RUNBOOKS)
    events = [
        _event(falco, "s1_suspicious_process", "falco_alert.json"),
        _event(guardduty, "s1_suspicious_process", "guardduty_finding.json"),
    ]
    passages = library.passages_for(events)
    assert passages
    assert passages[0]["doc_id"] == "RB-001"
    assert all({"doc_id", "title", "section", "text"} <= p.keys() for p in passages)
    assert len(passages) <= 6


def test_unrelated_events_retrieve_nothing(falco):
    library = RunbookLibrary.from_dir(RUNBOOKS)
    event = _event(falco, "s1_suspicious_process", "falco_alert.json").model_copy(
        update={"event_type": "network.port_scan", "ocsf": {"attacks": []}}
    )
    assert library.passages_for([event]) == []


def test_files_without_front_matter_are_ignored(tmp_path):
    (tmp_path / "notes.md").write_text("# just notes\n", encoding="utf-8")
    assert RunbookLibrary.from_dir(tmp_path).runbooks == []
    assert RunbookLibrary.from_dir(None).runbooks == []
    assert parse_runbook("no front matter") is None
