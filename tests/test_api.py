"""HTTP layer: authentication fails closed, payload limits, coverage (T-04)."""

from datetime import timedelta

from fastapi.testclient import TestClient

from core.app import Settings, create_app
from ingestion.auth import SIGNATURE_HEADER, SourceCredential, sign
from tests.conftest import fixture_bytes

TOKEN = "test-falco-token"
SECRET = "test-replay-secret"


def _client() -> TestClient:
    settings = Settings(
        cluster="cs-lab-eks",
        account_id="123456789012",
        credentials={"falco": SourceCredential(token=TOKEN), "guardduty": SourceCredential(hmac_secret=SECRET)},
        max_silence={"falco": timedelta(minutes=5), "wazuh": timedelta(minutes=5)},
    )
    return TestClient(create_app(settings))


def test_ingest_requires_authentication():
    client = _client()
    body = fixture_bytes("s1_suspicious_process", "falco_alert.json")

    assert client.post("/v1/ingest/falco", content=body).status_code == 401
    assert client.post("/v1/ingest/falco", content=body,
                       headers={"authorization": "Bearer wrong"}).status_code == 401
    # Wazuh has no credential configured, so it is rejected even with a token.
    assert client.post("/v1/ingest/wazuh", content=body,
                       headers={"authorization": f"Bearer {TOKEN}"}).status_code == 401


def test_end_to_end_replay_builds_a_case_and_audit_trail():
    client = _client()
    gd = fixture_bytes("s1_suspicious_process", "guardduty_finding.json")
    falco = fixture_bytes("s1_suspicious_process", "falco_alert.json")

    r1 = client.post("/v1/ingest/guardduty", content=gd, headers={SIGNATURE_HEADER: sign(SECRET, gd)})
    r2 = client.post("/v1/ingest/falco", content=falco, headers={"authorization": f"Bearer {TOKEN}"})
    assert (r1.status_code, r2.status_code) == (202, 202)

    [case] = client.get("/v1/cases").json()
    assert case["event_count"] == 2
    timeline = client.get(f"/v1/cases/{case['case_id']}/timeline").json()
    assert [t["source"] for t in timeline] == ["falco", "guardduty"]

    audit = client.get("/v1/audit", params={"case_id": case["case_id"]}).json()
    assert audit["chain_intact"] is True
    assert len(audit["records"]) == 2


def test_malformed_payload_returns_422():
    client = _client()
    assert client.post("/v1/ingest/falco", content=b"{}",
                       headers={"authorization": f"Bearer {TOKEN}"}).status_code == 422


def test_t04_silent_sensor_is_reported_as_not_ok():
    client = _client()
    body = fixture_bytes("s1_suspicious_process", "falco_alert.json")
    client.post("/v1/ingest/falco", content=body, headers={"authorization": f"Bearer {TOKEN}"})

    coverage = client.get("/v1/health/coverage").json()
    assert coverage["sources"]["falco"]["state"] == "ok"
    assert coverage["sources"]["wazuh"]["state"] == "unknown"  # never heard from: not "ok"
    assert coverage["overall"] == "degraded"
