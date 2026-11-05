"""The responder as a separate service: the API drives it over HTTP, and it decides for itself."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from common.models import ResponseProposal, Target
from core.app import Settings, create_app
from core.auth import AnalystDirectory, Principal
from ingestion.auth import SourceCredential
from responder.executor import KubernetesExecutor
from responder.quarantine import QUARANTINE_LABEL
from responder.remote import RemoteExecutor, ResponderError
from responder.server import build_app
from tests.conftest import fixture_bytes
from tests.fakes import FakePodApi

POD, POD_UID = "checkout-7d9f6c-x2k8p", "8b0e3c52-1d7a-4f43-9e6b-3a2c5d9f0e17"
TARGET = Target(kind="Pod", name=POD, uid=POD_UID, namespace="shop")
TOKEN = "responder-test-token"  # noqa: S105
AUTH = {"authorization": f"Bearer {TOKEN}"}


def _proposal(**changes) -> ResponseProposal:
    fields = {
        "proposal_id": "prp_1", "case_id": "case_1", "action_type": "k8s.pod.quarantine_label",
        "target": TARGET, "environment": "lab", "rationale": "x", "requested_by": "analyst:a",
        "created_at": datetime(2026, 11, 5, tzinfo=UTC), "dry_run_passed": True,
    }  # fmt: skip
    return ResponseProposal(**{**fields, **changes})


@pytest.fixture
def pods() -> FakePodApi:
    return FakePodApi(name=POD, uid=POD_UID)


@pytest.fixture
def server(pods) -> TestClient:
    return TestClient(build_app(KubernetesExecutor(pods), TOKEN))


def _post(server, path, proposal, headers=AUTH):
    return server.post(f"/v1/responder/{path}", json=proposal.model_dump(mode="json"), headers=headers)


@pytest.mark.parametrize("path", ["dry-run", "execute", "verify", "labels"])
@pytest.mark.parametrize("headers", [{}, {"authorization": "Bearer wrong"}], ids=["none", "wrong"])
def test_every_route_needs_the_token(server, pods, path, headers):
    assert _post(server, path, _proposal(), headers).status_code == 401
    assert QUARANTINE_LABEL not in pods.labels


def test_it_refuses_to_start_without_a_token(pods):
    with pytest.raises(ValueError, match="token"):
        build_app(KubernetesExecutor(pods), "")


@pytest.mark.parametrize(
    "bad",
    [
        {"action_type": "k8s.pod.delete"},
        {"target": Target(kind="Pod", name=POD, uid=POD_UID, namespace="kube-system")},
        {"target": Target(kind="Pod", name=POD, uid=POD_UID, namespace="cloudshield")},
        {"target": Target(kind="Pod", name=POD, uid="another-uid", namespace="shop")},
        {"target": Target(kind="Deployment", name=POD, uid=POD_UID, namespace="shop")},
        {"environment": "prod"},
    ],
    ids=["not-allowlisted", "kube-system", "own-namespace", "stale-uid", "wrong-kind", "other-environment"],
)
def test_a_valid_token_only_buys_allowlisted_actions(server, pods, bad):
    assert _post(server, "execute", _proposal(**bad)).status_code == 403
    assert QUARANTINE_LABEL not in pods.labels


def test_execution_still_needs_a_dry_run_but_a_dry_run_does_not(server, pods):
    assert _post(server, "execute", _proposal(dry_run_passed=None)).status_code == 403
    assert _post(server, "dry-run", _proposal(dry_run_passed=None)).status_code == 200
    assert QUARANTINE_LABEL not in pods.labels


def test_an_allowed_action_runs(server, pods):
    response = _post(server, "execute", _proposal())
    assert response.status_code == 200
    assert response.json()["result"]["status"] == "applied"
    assert pods.labels[QUARANTINE_LABEL] == "true"


def _api(pods) -> tuple[TestClient, RemoteExecutor]:
    remote = RemoteExecutor(TestClient(build_app(KubernetesExecutor(pods), TOKEN)), TOKEN)
    settings = Settings(
        cluster="cs-lab-eks",
        credentials={"falco": SourceCredential(token="falco-test")},
        analysts=AnalystDirectory.from_tokens(
            {
                "alice": Principal("analyst:alice", frozenset({"analyst"})),
                "bob": Principal("analyst:bob", frozenset({"incident-responder"})),
            }
        ),
    )
    return TestClient(create_app(settings, executor=remote)), remote


def test_the_whole_workflow_runs_across_the_two_services(pods):
    api, _ = _api(pods)
    alice, bob = {"authorization": "Bearer alice"}, {"authorization": "Bearer bob"}
    alert = fixture_bytes("s1_suspicious_process", "falco_alert.json")
    api.post("/v1/ingest/falco", content=alert, headers={"authorization": "Bearer falco-test"})
    case_id = api.get("/v1/cases", headers=alice).json()[0]["case_id"]

    target = TARGET.model_dump(mode="json")
    body = {"action_type": "k8s.pod.quarantine_label", "target": target, "rationale": "curl | sh"}
    pid = api.post(f"/v1/cases/{case_id}/proposals", json=body, headers=alice).json()["proposal_id"]
    checked = api.post(f"/v1/proposals/{pid}/dry-run", headers=bob).json()
    assert checked["state"] == "awaiting_approval"
    assert checked["impact_preview"]["pod_keeps_running"] is True

    decision = {"proposal_hash": checked["proposal_hash"], "justification": "confirmed"}
    api.post(f"/v1/proposals/{pid}/approve", json=decision, headers=bob)
    done = api.post(f"/v1/proposals/{pid}/execute", headers=bob).json()

    assert done["state"] == "verified"
    assert done["execution"]["checks"]["label_present"] is True
    assert pods.labels[QUARANTINE_LABEL] == "true"


def test_a_refusal_reaches_the_caller_as_an_error(pods):
    remote = RemoteExecutor(TestClient(build_app(KubernetesExecutor(pods), TOKEN)), "wrong-token")
    with pytest.raises(ResponderError, match="401"):
        remote.execute(_proposal())
    assert QUARANTINE_LABEL not in pods.labels
