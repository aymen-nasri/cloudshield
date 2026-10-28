"""AI investigations end to end, against both store backends."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.auth import Principal
from correlation.engine import CorrelationEngine
from ingestion.evidence import InMemoryEvidenceStore
from ingestion.pipeline import IngestPipeline
from investigator.offline import OfflineBaselineModel
from investigator.runbooks import RunbookLibrary
from investigator.workflow import Conflict, Forbidden, InvestigationService, NotFound, Rejected, Unavailable
from tests.conftest import fixture_bytes

RUNBOOKS = Path(__file__).resolve().parents[1] / "runbooks"
ALICE = Principal("analyst:alice", frozenset({"analyst"}))
BOB = Principal("analyst:bob", frozenset({"incident-responder"}))
VIC = Principal("analyst:vic", frozenset({"viewer"}))


class InventingModel:
    """A model that cites an event that does not exist, every time."""

    model_id = "test-inventing-model"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str:
        self.calls += 1
        return json.dumps(
            {
                "synopsis": "Root compromise of the node.",
                "observed_facts": [{"statement": "Attacker has root", "evidence_ids": ["evt_INVENTED"]}],
                "hypotheses": [],
                "missing_evidence": [],
                "containment_options": [],
                "confidence_limits": "none",
            }
        )


def _service(stores, model):
    return InvestigationService(
        stores.investigations, stores.cases, stores.audit, RunbookLibrary.from_dir(RUNBOOKS), model
    )


@pytest.fixture
def env(stores, falco, guardduty):
    engine = CorrelationEngine(stores.cases)
    pipeline = IngestPipeline(stores.events, InMemoryEvidenceStore(), on_accepted=engine.correlate)
    pipeline.ingest(fixture_bytes("s1_suspicious_process", "guardduty_finding.json"), guardduty)
    pipeline.ingest(fixture_bytes("s1_suspicious_process", "falco_alert.json"), falco)
    [case] = stores.cases.list()
    return SimpleNamespace(stores=stores, case=case, service=_service(stores, OfflineBaselineModel()))


def test_investigation_is_grounded_stored_and_audited(env):
    record = env.service.run(env.case.case_id, ALICE)

    event_ids = {e.event_id for e in env.case.events}
    cited = {i for f in record.output.observed_facts for i in f.evidence_ids}
    assert cited == event_ids  # every fact cites a real event, and every event is covered
    assert record.retrieved_doc_ids[0] == "RB-001"
    assert record.output.containment_options[0].target_entity_id == "k8s:pod/shop/checkout-7d9f6c-x2k8p"
    assert record.review_status == "unreviewed"

    reloaded = env.service.get(record.investigation_id)
    assert reloaded.output == record.output
    assert [r.investigation_id for r in env.service.list_for_case(env.case.case_id)] == [
        record.investigation_id
    ]

    [audit] = [r for r in env.stores.audit.records(env.case.case_id) if r.action == "investigation.created"]
    assert (audit.actor_type, audit.actor_id) == ("model", "cloudshield-offline-baseline-v1")
    assert audit.details["prompt_version"] == "investigate_v1"
    assert set(audit.details["cited_event_ids"]) == event_ids
    assert env.stores.audit.verify() is None


def test_ungrounded_output_is_rejected_and_never_stored(env):
    model = InventingModel()
    service = _service(env.stores, model)
    with pytest.raises(Rejected) as exc:
        service.run(env.case.case_id, ALICE)

    assert model.calls == 2  # one retry with the validator's feedback, then give up
    assert "unknown evidence" in str(exc.value)
    assert service.list_for_case(env.case.case_id) == []
    assert any(r.action == "investigation.rejected" for r in env.stores.audit.records(env.case.case_id))


def test_review_happens_once_and_is_audited(env):
    record = env.service.run(env.case.case_id, ALICE)
    reviewed = env.service.review(record.investigation_id, BOB, "accepted", "matches the Falco evidence")
    assert (reviewed.review_status, reviewed.reviewed_by) == ("accepted", BOB.id)

    with pytest.raises(Conflict, match="already accepted"):
        env.service.review(record.investigation_id, ALICE, "rejected", "second opinion")
    assert any(r.action == "investigation.accepted" for r in env.stores.audit.records(env.case.case_id))


def test_roles_cases_and_configuration_are_checked(env):
    with pytest.raises(Forbidden):
        env.service.run(env.case.case_id, VIC)
    with pytest.raises(NotFound):
        env.service.run("case_missing", ALICE)
    with pytest.raises(NotFound):
        env.service.get("inv_missing")
    with pytest.raises(Unavailable):
        _service(env.stores, None).run(env.case.case_id, ALICE)


def test_injected_instructions_reach_the_model_only_as_evidence(env, falco):
    pipeline = IngestPipeline(env.stores.events, InMemoryEvidenceStore(),
                              on_accepted=CorrelationEngine(env.stores.cases).correlate)  # fmt: skip
    pipeline.ingest(fixture_bytes("s8_prompt_injection", "falco_alert.json"), falco)
    case = next(c for c in env.stores.cases.list() if c.case_id != env.case.case_id)

    seen = {}

    class Recorder(OfflineBaselineModel):
        def complete(self, system, user, *, max_tokens=2000):
            seen["system"], seen["user"] = system, user
            return super().complete(system, user, max_tokens=max_tokens)

    record = _service(env.stores, Recorder()).run(case.case_id, ALICE)

    assert "ignore all previous instructions" not in seen["system"]
    start, end = seen["user"].index("<untrusted_evidence"), seen["user"].index("</untrusted_evidence")
    assert start < seen["user"].index("ignore all previous instructions") < end
    assert record.output.containment_options[0].action_type == "k8s.pod.quarantine_label"
