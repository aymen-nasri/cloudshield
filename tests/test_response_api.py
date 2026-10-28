"""The response workflow over HTTP: authentication, roles, hash binding."""

import json

from fastapi.testclient import TestClient

from core.app import Settings, create_app
from core.auth import AnalystDirectory, Principal, token_hash
from ingestion.auth import SourceCredential
from responder.executor import KubernetesExecutor
from responder.quarantine import QUARANTINE_LABEL
from tests.conftest import fixture_bytes
from tests.fakes import FakePodApi

POD_UID = "8b0e3c52-1d7a-4f43-9e6b-3a2c5d9f0e17"
TARGET = {"kind": "Pod", "name": "checkout-7d9f6c-x2k8p", "uid": POD_UID, "namespace": "shop"}

ALICE = {"authorization": "Bearer alice-test"}
BOB = {"authorization": "Bearer bob-test"}
VIC = {"authorization": "Bearer vic-test"}


def _client() -> tuple[TestClient, FakePodApi]:
    pods = FakePodApi(name="checkout-7d9f6c-x2k8p", uid=POD_UID)
    settings = Settings(
        cluster="cs-lab-eks",
        account_id="123456789012",
        credentials={"falco": SourceCredential(token="falco-test")},
        analysts=AnalystDirectory.from_tokens(
            {
                "alice-test": Principal("analyst:alice", frozenset({"analyst"})),
                "bob-test": Principal("analyst:bob", frozenset({"incident-responder"})),
                "vic-test": Principal("analyst:vic", frozenset({"viewer"})),
            }
        ),
    )
    client = TestClient(create_app(settings, executor=KubernetesExecutor(pods)))
    falco = fixture_bytes("s1_suspicious_process", "falco_alert.json")
    client.post("/v1/ingest/falco", content=falco, headers={"authorization": "Bearer falco-test"})
    return client, pods


def _case_id(client: TestClient) -> str:
    return client.get("/v1/cases").json()[0]["case_id"]


def test_every_response_route_needs_an_analyst():
    client, _ = _client()
    case_id = _case_id(client)
    body = {"action_type": "k8s.pod.quarantine_label", "target": TARGET, "rationale": "x"}
    assert client.post(f"/v1/cases/{case_id}/proposals", json=body).status_code == 401
    unknown = {"authorization": "Bearer nope"}
    assert client.post(f"/v1/cases/{case_id}/proposals", json=body, headers=unknown).status_code == 401
    assert client.get("/v1/proposals/prp_missing").status_code == 401


def test_full_flow_over_http():
    client, pods = _client()
    case_id = _case_id(client)
    body = {"action_type": "k8s.pod.quarantine_label", "target": TARGET, "rationale": "curl | sh"}

    assert client.post(f"/v1/cases/{case_id}/proposals", json=body, headers=VIC).status_code == 403
    created = client.post(f"/v1/cases/{case_id}/proposals", json=body, headers=ALICE)
    assert created.status_code == 201
    pid = created.json()["proposal_id"]

    checked = client.post(f"/v1/proposals/{pid}/dry-run", headers=BOB).json()
    assert checked["state"] == "awaiting_approval"
    assert checked["policy"]["required_approvals"] == 1

    decision = {"proposal_hash": "sha256:stale", "justification": "confirmed"}
    assert client.post(f"/v1/proposals/{pid}/approve", json=decision, headers=BOB).status_code == 409
    decision["proposal_hash"] = checked["proposal_hash"]
    assert client.post(f"/v1/proposals/{pid}/approve", json=decision, headers=ALICE).status_code == 403
    assert (
        client.post(f"/v1/proposals/{pid}/approve", json=decision, headers=BOB).json()["state"] == "approved"
    )

    executed = client.post(f"/v1/proposals/{pid}/execute", headers=BOB).json()
    assert executed["state"] == "verified"
    assert executed["execution"]["checks"]["label_present"] is True
    assert pods.labels[QUARANTINE_LABEL] == "true"
    assert client.post(f"/v1/proposals/{pid}/execute", headers=BOB).status_code == 409

    listed = client.get(f"/v1/cases/{case_id}/proposals", headers=VIC).json()
    assert [p["state"] for p in listed] == ["verified"]
    assert client.get("/v1/audit", params={"case_id": case_id}).json()["chain_intact"] is True


def test_directory_loads_hashed_tokens_only():
    directory = AnalystDirectory.from_json(
        json.dumps({token_hash("s3cret-test"): {"id": "analyst:a", "roles": ["incident-responder"]}})
    )
    assert directory.authenticate("Bearer s3cret-test") == Principal(
        "analyst:a", frozenset({"incident-responder"})
    )
    assert directory.authenticate("Bearer wrong") is None
    assert directory.authenticate(None) is None
