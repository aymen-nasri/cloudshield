"""Static checks on the Step Functions definition that runs approved actions in AWS."""

import json
import re
from datetime import timedelta
from pathlib import Path

from policy.engine import load_policies

ASL = Path(__file__).resolve().parents[1] / "services" / "responder" / "statemachine" / "quarantine.asl.json"
DEFINITION = json.loads(ASL.read_text(encoding="utf-8"))
STATES: dict = DEFINITION["States"]


def _targets(state: dict) -> list[str]:
    found = [state[k] for k in ("Next", "Default") if k in state]
    found += [c["Next"] for c in state.get("Choices", [])]
    found += [c["Next"] for c in state.get("Catch", [])]
    return found


def test_every_transition_points_at_a_real_state():
    assert DEFINITION["StartAt"] in STATES
    for name, state in STATES.items():
        for target in _targets(state):
            assert target in STATES, f"{name} -> {target} does not exist"


def test_every_state_is_reachable_and_every_path_ends():
    seen, todo = set(), [DEFINITION["StartAt"]]
    while todo:
        name = todo.pop()
        if name not in seen:
            seen.add(name)
            todo.extend(_targets(STATES[name]))
    assert seen == set(STATES), f"unreachable: {set(STATES) - seen}"
    for name, state in STATES.items():
        terminal = state["Type"] in ("Succeed", "Fail") or state.get("End") is True
        assert terminal or _targets(state), f"{name} neither ends nor moves on"


def test_tasks_are_time_bounded():
    for name, state in STATES.items():
        if state["Type"] == "Task":
            assert 0 < state.get("TimeoutSeconds", 0) <= 900, f"{name} needs a timeout"


def test_approval_wait_matches_the_policy_ttl():
    ttl = load_policies()["k8s.pod.quarantine_label"].approval_ttl
    wait = STATES["AwaitApproval"]
    assert wait["Resource"].endswith(".waitForTaskToken")
    assert timedelta(seconds=wait["TimeoutSeconds"]) == ttl
    caught = {c["ErrorEquals"][0]: c["Next"] for c in wait["Catch"]}
    assert caught == {"States.Timeout": "Expired", "ApprovalRejected": "Rejected"}


def test_execute_never_retries_on_arbitrary_errors():
    # Only Lambda's own transient errors are retried; anything else must not re-run the action.
    for retry in STATES["Execute"].get("Retry", []):
        assert "States.ALL" not in retry["ErrorEquals"]
        assert set(retry["ErrorEquals"]) <= {"Lambda.ServiceException", "Lambda.TooManyRequestsException"}


def test_only_expected_placeholders_are_substituted():
    placeholders = set(re.findall(r"\$\{(\w+)\}", ASL.read_text(encoding="utf-8")))
    assert placeholders == {"ExecutorFunctionArn", "ApprovalNotifierFunctionArn"}
