"""A stolen API pod can't start an action: the responder checks approvals for itself.

Each test plays the attacker: it holds the responder's token and can send anything, but holds no
approver's private key.
"""

import base64
import importlib.util
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from common.models import ResponseProposal, Target
from policy.approvals import Approval
from policy.signing import ApproverKey, load_approver_keys, sign_approval
from responder.executor import KubernetesExecutor
from responder.quarantine import QUARANTINE_LABEL
from responder.remote import RemoteExecutor, ResponderError
from responder.server import build_app
from tests.fakes import FakePodApi

_spec = importlib.util.spec_from_file_location(
    "sign_approval", Path(__file__).resolve().parents[1] / "scripts/sign_approval.py"
)
assert _spec and _spec.loader
sign_tool = importlib.util.module_from_spec(_spec)
sys.modules["sign_approval"] = sign_tool
_spec.loader.exec_module(sign_tool)

POD, POD_UID = "checkout-1", "uid-1"
TOKEN = "responder-test-token"  # noqa: S105
AUTH = {"authorization": f"Bearer {TOKEN}"}
BOB, CAROL, ALICE, VIEWER = "analyst:bob", "analyst:carol", "analyst:alice", "analyst:vic"
PRIVATE = {name: Ed25519PrivateKey.generate() for name in (BOB, CAROL, ALICE, VIEWER)}
RESPONDERS = frozenset({"incident-responder"})
KEYS = {
    BOB: ApproverKey(PRIVATE[BOB].public_key(), RESPONDERS),
    CAROL: ApproverKey(PRIVATE[CAROL].public_key(), RESPONDERS),
    ALICE: ApproverKey(PRIVATE[ALICE].public_key(), RESPONDERS),
    VIEWER: ApproverKey(PRIVATE[VIEWER].public_key(), frozenset({"viewer"})),
}
NOW = datetime(2026, 11, 5, 12, tzinfo=UTC)


def _proposal(**changes) -> ResponseProposal:
    fields = {
        "proposal_id": "prp_1",
        "case_id": "case_1",
        "action_type": "k8s.pod.quarantine_label",
        "target": Target(kind="Pod", name=POD, uid=POD_UID, namespace="shop"),
        "environment": "lab",
        "rationale": "x",
        "requested_by": ALICE,
        "created_at": NOW,
        "dry_run_passed": True,
    }
    return ResponseProposal(**{**fields, **changes})


def _signed(proposal, approver=BOB, *, key=None, at=NOW) -> dict:
    return {
        "approver": approver,
        "signed_at": at.isoformat(),
        "signature": sign_approval(key or PRIVATE[approver], proposal, approver, at),
    }


@pytest.fixture
def pods() -> FakePodApi:
    return FakePodApi(name=POD, uid=POD_UID)


@pytest.fixture
def server(pods) -> TestClient:
    return TestClient(build_app(KubernetesExecutor(pods), TOKEN, approver_keys=KEYS, clock=lambda: NOW))


def _execute(server, proposal, approvals):
    body = {"proposal": proposal.model_dump(mode="json"), "approvals": approvals}
    return server.post("/v1/responder/execute", json=body, headers=AUTH)


def test_a_properly_signed_approval_runs(server, pods):
    proposal = _proposal()
    assert _execute(server, proposal, [_signed(proposal)]).status_code == 200
    assert pods.labels[QUARANTINE_LABEL] == "true"


def _forged(proposal) -> list[dict]:
    return [_signed(proposal, BOB, key=Ed25519PrivateKey.generate())]


def _garbage(_) -> list[dict]:
    return [{"approver": BOB, "signed_at": NOW.isoformat(), "signature": "not base64!"}]


def _wrong_length(_) -> list[dict]:
    return [{"approver": BOB, "signed_at": NOW.isoformat(), "signature": base64.b64encode(b"x").decode()}]


def _for_another_proposal(_) -> list[dict]:
    return [_signed(_proposal(proposal_id="prp_other"))]


def _for_another_pod(_) -> list[dict]:
    other = Target(kind="Pod", name="cart-1", uid="uid-2", namespace="shop")
    return [_signed(_proposal(target=other))]


def _for_another_action(_) -> list[dict]:
    return [_signed(_proposal(action_type="k8s.pod.remove_quarantine_label"))]


def _with_another_requester(_) -> list[dict]:
    return [_signed(_proposal(requested_by=CAROL))]  # the requester isn't in the hash, but it is signed


def _expired(proposal) -> list[dict]:
    return [_signed(proposal, at=NOW - timedelta(minutes=16))]


def _dated_ahead(proposal) -> list[dict]:
    return [_signed(proposal, at=NOW + timedelta(hours=1))]


def _self_approved(proposal) -> list[dict]:
    return [_signed(proposal, ALICE)]


def _wrong_role(proposal) -> list[dict]:
    return [_signed(proposal, VIEWER)]


def _unknown_person(proposal) -> list[dict]:
    return [_signed(proposal, "analyst:mallory", key=Ed25519PrivateKey.generate())]


def _claiming_to_be_bob(proposal) -> list[dict]:
    return [_signed(proposal, BOB, key=PRIVATE[CAROL])]


@pytest.mark.parametrize(
    "attack",
    [
        lambda _: [],
        _forged,
        _garbage,
        _wrong_length,
        _for_another_proposal,
        _for_another_pod,
        _for_another_action,
        _with_another_requester,
        _expired,
        _dated_ahead,
        _self_approved,
        _wrong_role,
        _unknown_person,
        _claiming_to_be_bob,
    ],
    ids=[
        "no-approval",
        "forged",
        "not-base64",
        "wrong-length",
        "another-proposal",
        "another-pod",
        "another-action",
        "another-requester",
        "expired",
        "dated-ahead",
        "self-approved",
        "wrong-role",
        "unknown-person",
        "signed-by-someone-else",
    ],
)
def test_a_stolen_token_cannot_start_an_action(server, pods, attack):
    proposal = _proposal()
    response = _execute(server, proposal, attack(proposal))

    assert response.status_code == 403
    assert "valid signed approval" in response.text
    assert pods.real_patches == []


def test_a_change_to_the_proposal_after_signing_is_refused(server, pods):
    signed = [_signed(_proposal())]
    changed = _proposal(parameters={"anything": "else"})
    assert _execute(server, changed, signed).status_code == 403
    assert pods.real_patches == []


@pytest.fixture
def critical(pods) -> FakePodApi:
    pods.pod["metadata"]["labels"]["cloudshield.io/tier"] = "critical"
    return pods


def test_a_critical_pod_needs_two_people_whatever_the_proposal_says(server, critical):
    """The live label counts. A proposal written without it needs two signatures all the same."""
    proposal = _proposal()
    assert "cloudshield.io/tier" not in proposal.target.labels

    assert _execute(server, proposal, [_signed(proposal)]).status_code == 403
    assert critical.real_patches == []

    assert _execute(server, proposal, [_signed(proposal), _signed(proposal, CAROL)]).status_code == 200


def test_one_person_signing_twice_counts_once(server, critical):
    proposal = _proposal()
    twice = [_signed(proposal), _signed(proposal, at=NOW - timedelta(minutes=1))]
    assert _execute(server, proposal, twice).status_code == 403
    assert critical.real_patches == []


def test_a_signed_approval_cannot_be_replayed(server, pods):
    proposal = _proposal()
    approvals = [_signed(proposal)]
    assert _execute(server, proposal, approvals).status_code == 200
    pods.pod["metadata"]["labels"].pop(QUARANTINE_LABEL)  # released, say

    assert _execute(server, proposal, approvals).status_code == 409
    assert QUARANTINE_LABEL not in pods.labels


def test_a_small_clock_difference_is_allowed(server):
    proposal = _proposal()
    assert _execute(server, proposal, [_signed(proposal, at=NOW + timedelta(minutes=1))]).status_code == 200


def test_the_remote_executor_sends_only_signed_approvals(pods):
    client = TestClient(build_app(KubernetesExecutor(pods), TOKEN, approver_keys=KEYS, clock=lambda: NOW))
    remote = RemoteExecutor(client, TOKEN)
    proposal = _proposal()
    unsigned = Approval("prp_1", BOB, RESPONDERS, "approve", "sha256:x", NOW, "ok")

    with pytest.raises(ResponderError, match="403"):
        remote.execute(proposal, [unsigned])
    assert pods.real_patches == []

    signature = sign_approval(PRIVATE[BOB], proposal, BOB, NOW)
    good = Approval("prp_1", BOB, RESPONDERS, "approve", "sha256:x", NOW, "ok", signature, NOW)
    assert remote.execute(proposal, [good]).status == "applied"


# --- The approver's tool ------------------------------------------------------------------------


def _view(proposal) -> dict:
    from policy.approvals import proposal_hash

    return {
        **proposal.model_dump(mode="json"),
        "proposal_hash": proposal_hash(proposal),
        "state": "awaiting_approval",
    }


def test_the_tool_produces_what_the_responder_accepts(server, pods):
    proposal = _proposal()
    made = sign_tool.approve(_view(proposal), PRIVATE[BOB], BOB, now=NOW)
    approval = {"approver": BOB, "signed_at": made["signed_at"], "signature": made["signature"]}

    assert _execute(server, proposal, [approval]).status_code == 200


def test_the_tool_refuses_a_hash_that_does_not_match_what_it_shows(pods):
    """A tampered API could show one action and ask you to sign another. The tool computes it for itself."""
    view = _view(_proposal())
    view["target"]["name"] = "something-harmless-looking"
    with pytest.raises(ValueError, match="hash"):
        sign_tool.approve(view, PRIVATE[BOB], BOB)


def test_the_tool_refuses_to_approve_your_own_request():
    with pytest.raises(ValueError, match="requested"):
        sign_tool.approve(_view(_proposal()), PRIVATE[ALICE], ALICE)


def test_the_tool_shows_what_is_being_approved():
    text = sign_tool.summary(_proposal())
    assert "k8s.pod.quarantine_label" in text
    assert f"shop/{POD}" in text
    assert POD_UID in text


def test_a_generated_key_loads_at_the_responder_and_verifies(tmp_path):
    path = tmp_path / "bob.pem"
    entry = sign_tool.generate(path, BOB)

    keys = load_approver_keys(json.dumps(entry))

    assert keys[BOB].roles == RESPONDERS
    raw = keys[BOB].public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert base64.b64encode(raw).decode() == entry[BOB]["public_key"]


def test_generating_never_overwrites_a_key(tmp_path):
    path = tmp_path / "bob.pem"
    path.write_text("existing")
    with pytest.raises(FileExistsError):
        sign_tool.generate(path, BOB)
    assert path.read_text() == "existing"
