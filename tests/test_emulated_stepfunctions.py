"""Our real state machine, run by AWS's Step Functions Local, calling our real Lambda handler.

Run by scripts/emulated_aws.sh. Lambda itself is a small local HTTP server standing in for the Lambda
Invoke API, around the real handler and a fake Kubernetes API. Not covered: IAM, real Lambda, and
the 15-minute approval timeout, which would take 15 minutes to wait for.
"""

import json
import os
import threading
import time
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

boto3 = pytest.importorskip("boto3")

from common.models import ResponseProposal, Target  # noqa: E402
from policy.approvals import proposal_hash  # noqa: E402
from responder.lambda_handlers import handler  # noqa: E402
from responder.quarantine import QUARANTINE_LABEL  # noqa: E402
from tests.fakes import FakePodApi  # noqa: E402

ENDPOINT = os.getenv("CLOUDSHIELD_STEPFUNCTIONS_LOCAL")
pytestmark = pytest.mark.skipif(
    not ENDPOINT, reason="needs Step Functions Local: run scripts/emulated_aws.sh"
)

ASL = Path(__file__).parents[1] / "services/responder/statemachine/quarantine.asl.json"
LAMBDA_PORT = 5050
EXECUTOR = "arn:aws:lambda:us-east-1:123456789012:function:cloudshield-executor"
NOTIFIER = "arn:aws:lambda:us-east-1:123456789012:function:cloudshield-approval-notifier"
POD, POD_UID = "checkout-1", "uid-1"


class Lab:
    """What the fake Lambda functions see."""

    def __init__(self) -> None:
        self.pods = FakePodApi(name=POD, uid=POD_UID)
        self.tokens: dict[str, str] = {}
        self.refusals: list[str] = []


lab = Lab()


class FakeLambda(BaseHTTPRequestHandler):
    """The Lambda Invoke API: POST /2015-03-31/functions/{name}/invocations."""

    def do_POST(self) -> None:  # noqa: N802
        event = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        function_error = None
        if "approval-notifier" in self.path:
            lab.tokens[event["proposal_id"]] = event["task_token"]
            result: dict = {}
        else:
            try:
                result = handler(event, api=lab.pods)
            except Exception as exc:  # what Lambda does when a handler raises
                function_error = "Unhandled"
                lab.refusals.append(type(exc).__name__)
                result = {"errorType": type(exc).__name__, "errorMessage": str(exc)}
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if function_error:
            self.send_header("X-Amz-Function-Error", function_error)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


@pytest.fixture(scope="module", autouse=True)
def fake_lambda():
    server = ThreadingHTTPServer(("127.0.0.1", LAMBDA_PORT), FakeLambda)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield
    server.shutdown()


@pytest.fixture(scope="module")
def sfn():
    return boto3.client("stepfunctions", endpoint_url=ENDPOINT, region_name="us-east-1")


@pytest.fixture(scope="module")
def machine(sfn) -> str:
    definition = ASL.read_text(encoding="utf-8")
    definition = definition.replace("${ExecutorFunctionArn}", EXECUTOR)
    definition = definition.replace("${ApprovalNotifierFunctionArn}", NOTIFIER)
    return sfn.create_state_machine(
        name=f"cloudshield-quarantine-{uuid.uuid4().hex[:8]}",
        definition=definition,
        roleArn="arn:aws:iam::123456789012:role/emulated",
    )["stateMachineArn"]


@pytest.fixture(autouse=True)
def fresh_pod():
    lab.pods = FakePodApi(name=POD, uid=POD_UID)
    lab.refusals.clear()


def _proposal(uid: str = POD_UID) -> ResponseProposal:
    return ResponseProposal(
        proposal_id=f"prp_{uuid.uuid4().hex[:8]}", case_id="case_1", action_type="k8s.pod.quarantine_label",
        target=Target(kind="Pod", name=POD, uid=uid, namespace="shop"), environment="lab", rationale="x",
        requested_by="analyst:alice", created_at=datetime(2026, 11, 5, tzinfo=UTC), dry_run_passed=True,
    )  # fmt: skip


def _start(sfn, machine: str, proposal: ResponseProposal, claimed_hash: str | None = None) -> str:
    payload = {
        "proposal": proposal.model_dump(mode="json"),
        "proposal_hash": claimed_hash or proposal_hash(proposal),
    }
    return sfn.start_execution(stateMachineArn=machine, input=json.dumps(payload))["executionArn"]


def _token(proposal: ResponseProposal) -> str:
    for _ in range(100):
        if proposal.proposal_id in lab.tokens:
            return lab.tokens[proposal.proposal_id]
        time.sleep(0.2)
    raise AssertionError("the workflow never reached the approval step")


def _finish(sfn, execution: str) -> dict:
    for _ in range(100):
        result = sfn.describe_execution(executionArn=execution)
        if result["status"] != "RUNNING":
            return result
        time.sleep(0.2)
    raise AssertionError("the workflow did not finish")


def _failed_with(sfn, execution: str) -> str:
    events = sfn.get_execution_history(executionArn=execution, reverseOrder=True)["events"]
    return next(e["executionFailedEventDetails"]["error"] for e in events if e["type"] == "ExecutionFailed")


def test_it_waits_for_approval_then_acts_and_verifies(sfn, machine):
    proposal = _proposal()
    execution = _start(sfn, machine, proposal)
    token = _token(proposal)

    assert sfn.describe_execution(executionArn=execution)["status"] == "RUNNING"
    assert QUARANTINE_LABEL not in lab.pods.labels  # nothing happens before the approval

    sfn.send_task_success(taskToken=token, output=json.dumps({"bound_hash": proposal_hash(proposal)}))

    assert _finish(sfn, execution)["status"] == "SUCCEEDED"
    assert lab.pods.labels[QUARANTINE_LABEL] == "true"


def test_a_rejected_approval_changes_nothing(sfn, machine):
    proposal = _proposal()
    execution = _start(sfn, machine, proposal)
    sfn.send_task_failure(taskToken=_token(proposal), error="ApprovalRejected", cause="not this pod")

    assert _finish(sfn, execution)["status"] == "FAILED"
    assert _failed_with(sfn, execution) == "Rejected"
    assert QUARANTINE_LABEL not in lab.pods.labels


def test_an_approval_for_a_different_version_changes_nothing(sfn, machine):
    proposal = _proposal()
    execution = _start(sfn, machine, proposal)
    sfn.send_task_success(taskToken=_token(proposal), output=json.dumps({"bound_hash": "sha256:stale"}))

    assert _finish(sfn, execution)["status"] == "FAILED"
    assert _failed_with(sfn, execution) == "ResponseFailed"
    assert QUARANTINE_LABEL not in lab.pods.labels


def test_a_tampered_proposal_never_reaches_approval(sfn, machine):
    proposal = _proposal()
    execution = _start(sfn, machine, proposal, claimed_hash="sha256:not-this-proposal")

    assert _finish(sfn, execution)["status"] == "FAILED"
    # The handler itself refused it: not a failure to reach Lambda, which would also end in FAILED.
    assert "SdkClient" not in _failed_with(sfn, execution)
    assert lab.refusals == ["ApprovalMismatch"]
    assert proposal.proposal_id not in lab.tokens
    assert QUARANTINE_LABEL not in lab.pods.labels


def test_a_stale_target_never_reaches_approval(sfn, machine):
    proposal = _proposal(uid="a-different-pod")
    execution = _start(sfn, machine, proposal)

    assert _finish(sfn, execution)["status"] == "FAILED"
    assert _failed_with(sfn, execution) == "Rejected"
    assert proposal.proposal_id not in lab.tokens
