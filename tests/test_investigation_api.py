"""Investigation routes over HTTP."""

from fastapi.testclient import TestClient

from core.app import Settings, build_model, create_app
from core.auth import AnalystDirectory, Principal
from ingestion.auth import SourceCredential
from investigator.offline import OfflineBaselineModel
from tests.conftest import fixture_bytes

ALICE = {"authorization": "Bearer alice-test"}
BOB = {"authorization": "Bearer bob-test"}


def _client(investigator: str | None = "offline") -> tuple[TestClient, str]:
    settings = Settings(
        cluster="cs-lab-eks",
        account_id="123456789012",
        investigator=investigator,
        credentials={"falco": SourceCredential(token="falco-test")},
        analysts=AnalystDirectory.from_tokens(
            {
                "alice-test": Principal("analyst:alice", frozenset({"analyst"})),
                "bob-test": Principal("analyst:bob", frozenset({"incident-responder"})),
            }
        ),
    )
    client = TestClient(create_app(settings))
    body = fixture_bytes("s1_suspicious_process", "falco_alert.json")
    client.post("/v1/ingest/falco", content=body, headers={"authorization": "Bearer falco-test"})
    return client, client.get("/v1/cases").json()[0]["case_id"]


def test_run_list_get_and_review_over_http():
    client, case_id = _client()
    assert client.post(f"/v1/cases/{case_id}/investigations").status_code == 401

    created = client.post(f"/v1/cases/{case_id}/investigations", headers=ALICE)
    assert created.status_code == 201
    inv = created.json()
    assert inv["model_id"] == "cloudshield-offline-baseline-v1"
    assert inv["retrieved_doc_ids"][0] == "RB-001"
    assert inv["output"]["observed_facts"][0]["evidence_ids"]

    assert [
        i["investigation_id"] for i in client.get(f"/v1/cases/{case_id}/investigations", headers=BOB).json()
    ] == [inv["investigation_id"]]
    review = {"decision": "accepted", "note": "consistent with the timeline"}
    reviewed = client.post(f"/v1/investigations/{inv['investigation_id']}/review", json=review, headers=BOB)
    assert reviewed.json()["review_status"] == "accepted"
    again = client.post(f"/v1/investigations/{inv['investigation_id']}/review", json=review, headers=ALICE)
    assert again.status_code == 409


def test_without_a_model_the_route_says_so():
    client, case_id = _client(investigator=None)
    assert client.post(f"/v1/cases/{case_id}/investigations", headers=ALICE).status_code == 503


def test_model_selection():
    assert isinstance(build_model(Settings(investigator="offline")), OfflineBaselineModel)
    assert build_model(Settings()) is None
