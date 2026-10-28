import dataclasses

import pytest

from cases.audit import AuditLog, verify_chain
from cases.state import InvalidTransition, ProposalState, transition


def _log() -> AuditLog:
    log = AuditLog()
    log.append("service", "correlation-engine", "case.event_linked", {"case_id": "c1", "event_id": "e1"})
    log.append("model", "investigator", "investigation.created", {"case_id": "c1"})
    log.append("human", "analyst:a.nasri", "proposal.approved", {"case_id": "c1", "proposal_id": "p1"})
    return log


def test_intact_chain_verifies():
    assert _log().verify() is None


def test_editing_a_record_is_detected():
    records = _log().records()
    records[1] = dataclasses.replace(records[1], details={"case_id": "c1", "note": "edited"})
    assert verify_chain(records) == 2


def test_deleting_a_record_is_detected():
    records = _log().records()
    del records[1]
    assert verify_chain(records) == 3


def test_happy_path_transitions():
    s = ProposalState.DRAFT
    for nxt in ["evidence_collected", "proposed", "risk_checked", "awaiting_approval",
                "approved", "executing", "verified", "closed"]:
        s = transition(s, ProposalState(nxt))
    assert s is ProposalState.CLOSED


@pytest.mark.parametrize("current, new", [
    (ProposalState.PROPOSED, ProposalState.EXECUTING),           # skipping policy and approval
    (ProposalState.AWAITING_APPROVAL, ProposalState.EXECUTING),  # skipping approval
    (ProposalState.REJECTED, ProposalState.APPROVED),
    (ProposalState.CLOSED, ProposalState.EXECUTING),
])
def test_unsafe_transitions_are_refused(current, new):
    with pytest.raises(InvalidTransition):
        transition(current, new)
