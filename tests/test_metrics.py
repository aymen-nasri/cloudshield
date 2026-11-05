"""/metrics reports what really happened, needs a login, and alerts can't create new series."""

from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

from core.app import Settings, create_app
from core.auth import AnalystDirectory, Principal
from ingestion.auth import SourceCredential
from responder.executor import KubernetesExecutor
from tests.conftest import fixture_bytes
from tests.fakes import FakePodApi

POD_UID = "8b0e3c52-1d7a-4f43-9e6b-3a2c5d9f0e17"
TARGET = {"kind": "Pod", "name": "checkout-7d9f6c-x2k8p", "uid": POD_UID, "namespace": "shop"}
ALICE = {"authorization": "Bearer alice-test"}
BOB = {"authorization": "Bearer bob-test"}
FALCO = {"authorization": "Bearer falco-test"}
QUARANTINE = ("action_type", "k8s.pod.quarantine_label")


def _client(pods=None) -> TestClient:
    settings = Settings(
        cluster="cs-lab-eks",
        credentials={"falco": SourceCredential(token="falco-test")},
        analysts=AnalystDirectory.from_tokens(
            {
                "alice-test": Principal("analyst:alice", frozenset({"analyst"})),
                "bob-test": Principal("analyst:bob", frozenset({"incident-responder"})),
            }
        ),
    )
    pods = pods or FakePodApi(name=TARGET["name"], uid=POD_UID)
    return TestClient(create_app(settings, executor=KubernetesExecutor(pods)))


def _values(client: TestClient) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    response = client.get("/metrics", headers=ALICE)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    return {
        (s.name, tuple(sorted(s.labels.items()))): s.value
        for family in text_string_to_metric_families(response.text)
        for s in family.samples
    }


def _ingested(values, result):
    return values.get(("cloudshield_ingest_events_total", (("result", result), ("source", "falco"))), 0)


def test_metrics_need_a_login():
    assert _client().get("/metrics").status_code == 401


def test_ingest_results_are_counted():
    client = _client()
    alert = fixture_bytes("s1_suspicious_process", "falco_alert.json")
    client.post("/v1/ingest/falco", content=alert, headers=FALCO)
    client.post("/v1/ingest/falco", content=alert, headers=FALCO)
    client.post("/v1/ingest/falco", content=alert)
    client.post("/v1/ingest/falco", content=b"{not json", headers=FALCO)

    values = _values(client)
    assert _ingested(values, "accepted") == 1
    assert _ingested(values, "duplicate") == 1
    assert _ingested(values, "unauthenticated") == 1
    assert _ingested(values, "invalid") == 1
    assert values[("cloudshield_ingest_lag_seconds_count", (("source", "falco"),))] == 1


def test_unknown_sources_create_no_series():
    client = _client()
    client.post("/v1/ingest/attacker-chosen", content=b"{}", headers=FALCO)
    assert "attacker-chosen" not in client.get("/metrics", headers=ALICE).text


def test_alert_text_never_reaches_the_labels():
    client = _client()
    alert = fixture_bytes("s8_prompt_injection", "falco_alert.json")
    client.post("/v1/ingest/falco", content=alert, headers=FALCO)
    text = client.get("/metrics", headers=ALICE).text
    assert "ignore all previous instructions" not in text
    assert "checkout-" not in text


def test_silence_is_reported_as_degraded():
    client = _client()
    values = _values(client)
    assert values[("cloudshield_source_degraded", (("source", "falco"),))] == 1
    assert ("cloudshield_source_heartbeat_age_seconds", (("source", "falco"),)) not in values

    alert = fixture_bytes("s1_suspicious_process", "falco_alert.json")
    client.post("/v1/ingest/falco", content=alert, headers=FALCO)
    values = _values(client)
    assert values[("cloudshield_source_degraded", (("source", "falco"),))] == 0
    assert values[("cloudshield_source_heartbeat_age_seconds", (("source", "falco"),))] >= 0


def _quarantine(client: TestClient) -> dict:
    alert = fixture_bytes("s1_suspicious_process", "falco_alert.json")
    client.post("/v1/ingest/falco", content=alert, headers=FALCO)
    case_id = client.get("/v1/cases", headers=ALICE).json()[0]["case_id"]
    body = {"action_type": "k8s.pod.quarantine_label", "target": TARGET, "rationale": "curl | sh"}
    pid = client.post(f"/v1/cases/{case_id}/proposals", json=body, headers=ALICE).json()["proposal_id"]
    checked = client.post(f"/v1/proposals/{pid}/dry-run", headers=BOB).json()
    decision = {"proposal_hash": checked["proposal_hash"], "justification": "confirmed"}
    client.post(f"/v1/proposals/{pid}/approve", json=decision, headers=BOB)
    return client.post(f"/v1/proposals/{pid}/execute", headers=BOB).json()


def test_a_verified_action_and_its_checks_are_counted():
    client = _client()
    assert _quarantine(client)["state"] == "verified"
    values = _values(client)
    checks = "cloudshield_verification_checks_total"
    assert values[("cloudshield_response_executions_total", (QUARANTINE, ("outcome", "verified")))] == 1
    assert values[("cloudshield_response_duration_seconds_count", (QUARANTINE,))] == 1
    assert values[(checks, (("check", "label_present"), ("result", "passed")))] == 1
    # No probe configured here: a skipped check is reported as skipped, never as passed.
    assert values[(checks, (("check", "traffic_probe"), ("result", "skipped")))] == 1


def test_a_failed_execution_is_counted_as_failed():
    class Broken(FakePodApi):
        def patch_pod_labels(self, namespace, name, labels, *, uid, dry_run):
            if not dry_run:
                raise RuntimeError("API server unavailable")
            super().patch_pod_labels(namespace, name, labels, uid=uid, dry_run=dry_run)

    client = _client(Broken(name=TARGET["name"], uid=POD_UID))
    assert _quarantine(client)["state"] == "failed"
    failed = ("cloudshield_response_executions_total", (QUARANTINE, ("outcome", "failed")))
    assert _values(client)[failed] == 1
