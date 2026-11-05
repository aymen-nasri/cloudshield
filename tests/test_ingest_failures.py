"""What happens when ingestion fails partway, or the input is hostile. All of these were real bugs."""

import json

import pytest
from fastapi.testclient import TestClient

from core.app import Settings, build_stores, create_app
from core.auth import AnalystDirectory, Principal
from correlation.engine import CorrelationEngine
from ingestion.adapters import PayloadError
from ingestion.auth import SIGNATURE_HEADER, SourceCredential
from ingestion.evidence import InMemoryEvidenceStore
from ingestion.pipeline import IngestPipeline
from responder.executor import KubernetesExecutor
from responder.server import build_app
from tests.conftest import fixture_bytes
from tests.fakes import FakePodApi

S1 = "s1_suspicious_process"
FALCO_TOKEN = "falco-token"  # noqa: S105
READER = {"authorization": "Bearer reader"}
FALCO = {"authorization": f"Bearer {FALCO_TOKEN}"}
NON_ASCII = "Bearer café".encode("latin-1")


class FailsOnce:
    """Wraps a callable so its first call raises, as a brief database outage would."""

    def __init__(self, wrapped) -> None:
        self.wrapped = wrapped
        self.failed = False

    def __call__(self, *args, **kwargs):
        if not self.failed:
            self.failed = True
            raise ConnectionError("database went away")
        return self.wrapped(*args, **kwargs)


def _app_client(stores=None) -> TestClient:
    settings = Settings(
        cluster="cs-lab-eks",
        account_id="123456789012",
        credentials={
            "falco": SourceCredential(token=FALCO_TOKEN),
            "wazuh": SourceCredential(hmac_secret="wazuh-secret"),
        },
        analysts=AnalystDirectory.from_tokens({"reader": Principal("analyst:r", frozenset({"viewer"}))}),
    )
    return TestClient(create_app(settings, stores=stores), raise_server_exceptions=False)


# --- A retry after a partial failure ------------------------------------------------------------


def test_a_retry_finishes_linking_when_correlation_failed(stores, falco):
    """The event is stored, then correlation fails. The retry used to be a duplicate, so it never joined."""
    engine = CorrelationEngine(stores.cases)
    pipeline = IngestPipeline(stores.events, InMemoryEvidenceStore(), on_accepted=FailsOnce(engine.correlate))
    body = fixture_bytes(S1, "falco_alert.json")

    with pytest.raises(ConnectionError):
        pipeline.ingest(body, falco)
    assert stores.cases.list() == []

    assert pipeline.ingest(body, falco).status == "duplicate"

    [case] = stores.cases.list()
    assert len(case.events) == 1


def test_a_retry_finishes_linking_when_saving_the_case_failed(stores, falco):
    stores.cases.save = FailsOnce(stores.cases.save)
    pipeline = IngestPipeline(
        stores.events, InMemoryEvidenceStore(), on_accepted=CorrelationEngine(stores.cases).correlate
    )
    body = fixture_bytes(S1, "falco_alert.json")

    with pytest.raises(ConnectionError):
        pipeline.ingest(body, falco)
    pipeline.ingest(body, falco)

    [case] = stores.cases.list()
    assert len(case.events) == 1


def test_a_redelivery_never_links_an_event_twice(stores, falco):
    pipeline = IngestPipeline(
        stores.events, InMemoryEvidenceStore(), on_accepted=CorrelationEngine(stores.cases).correlate
    )
    body = fixture_bytes(S1, "falco_alert.json")

    for _ in range(3):
        pipeline.ingest(body, falco)

    [case] = stores.cases.list()
    assert len(case.events) == 1
    assert len(case.links) == 1


def test_the_next_startup_links_an_event_nobody_resent(stores):
    """The producer got a 500 and never tried again. Nothing else would ever have linked this event."""
    real_save = stores.cases.save
    stores.cases.save = FailsOnce(real_save)
    client = _app_client(stores)
    body = fixture_bytes(S1, "falco_alert.json")
    assert client.post("/v1/ingest/falco", content=body, headers=FALCO).status_code == 500
    [waiting] = stores.events.unlinked(stores.cases)
    assert stores.cases.list() == []

    _app_client(stores)  # the process restarts

    [case] = stores.cases.list()
    assert [e.event_id for e in case.events] == [waiting.event_id]
    assert stores.events.unlinked(stores.cases) == []
    assert len([r for r in stores.audit.records() if r.action == "case.event_linked"]) == 1


def test_a_restart_changes_nothing_when_everything_is_linked(stores):
    client = _app_client(stores)
    client.post("/v1/ingest/falco", content=fixture_bytes(S1, "falco_alert.json"), headers=FALCO)
    audit_before = len(stores.audit.records())

    _app_client(stores)

    [case] = stores.cases.list()
    assert len(case.events) == 1
    assert len(stores.audit.records()) == audit_before


def test_a_retry_writes_the_audit_record_a_failed_attempt_missed():
    """The case link is saved, then the audit write fails. The retry has to finish the job, once."""
    stores = build_stores(Settings())
    stores.audit.append = FailsOnce(stores.audit.append)
    client = _app_client(stores)
    body = fixture_bytes(S1, "falco_alert.json")

    assert client.post("/v1/ingest/falco", content=body, headers=FALCO).status_code == 500
    assert client.post("/v1/ingest/falco", content=body, headers=FALCO).json()["status"] == "duplicate"
    assert client.post("/v1/ingest/falco", content=body, headers=FALCO).json()["status"] == "duplicate"

    linked = [r for r in stores.audit.records() if r.action == "case.event_linked"]
    assert len(linked) == 1
    [case] = stores.cases.list()
    assert len(case.events) == 1


def test_an_ordinary_redelivery_writes_no_second_audit_record():
    stores = build_stores(Settings())
    client = _app_client(stores)
    body = fixture_bytes(S1, "falco_alert.json")

    client.post("/v1/ingest/falco", content=body, headers=FALCO)
    client.post("/v1/ingest/falco", content=body, headers=FALCO)

    assert len([r for r in stores.audit.records() if r.action == "case.event_linked"]) == 1
    assert stores.audit.verify() is None


# --- A payload with the right shape and wrong values --------------------------------------------


def _garbage_time(fixture: str) -> bytes:
    return json.dumps({**json.loads(fixture_bytes(S1, fixture)), "time": "not a time"}).encode()


@pytest.mark.parametrize("bad_time", ["not a time", 12345, None, ["2026"]])
def test_a_bad_timestamp_is_a_payload_error_and_nothing_is_kept(stores, falco, bad_time):
    evidence = InMemoryEvidenceStore()
    pipeline = IngestPipeline(stores.events, evidence)
    body = json.dumps({**json.loads(fixture_bytes(S1, "falco_alert.json")), "time": bad_time}).encode()

    with pytest.raises(PayloadError):
        pipeline.ingest(body, falco)

    assert evidence.objects == {}


def test_a_bad_guardduty_timestamp_is_a_payload_error(stores, guardduty):
    payload = json.loads(fixture_bytes(S1, "guardduty_finding.json"))
    payload["detail"]["updatedAt"] = "not a time"
    payload["detail"]["service"]["eventLastSeen"] = "not a time"

    with pytest.raises(PayloadError):
        IngestPipeline(stores.events, InMemoryEvidenceStore()).ingest(json.dumps(payload).encode(), guardduty)


def test_the_api_answers_422_for_a_bad_timestamp():
    client = _app_client()
    response = client.post("/v1/ingest/falco", content=_garbage_time("falco_alert.json"), headers=FALCO)

    assert response.status_code == 422
    assert client.get("/v1/cases", headers=READER).json() == []


# --- Hostile bytes in a credential ---------------------------------------------------------------


def test_a_non_ascii_producer_token_is_a_401():
    client = _app_client()
    body = fixture_bytes(S1, "falco_alert.json")

    response = client.post("/v1/ingest/falco", content=body, headers={"authorization": NON_ASCII})

    assert response.status_code == 401


def test_a_non_ascii_producer_signature_is_a_401():
    client = _app_client()
    response = client.post(
        "/v1/ingest/wazuh", content=b"{}", headers={SIGNATURE_HEADER: "sha256=café".encode("latin-1")}
    )
    assert response.status_code == 401


def test_a_non_ascii_analyst_token_is_a_401():
    response = _app_client().get("/v1/cases", headers={"authorization": NON_ASCII})
    assert response.status_code == 401


def test_a_non_ascii_token_at_the_responder_is_a_401():
    server = TestClient(
        build_app(KubernetesExecutor(FakePodApi(name="p", uid="u")), "responder-token"),
        raise_server_exceptions=False,
    )
    response = server.post("/v1/responder/labels", json={}, headers={"authorization": NON_ASCII})
    assert response.status_code == 401
