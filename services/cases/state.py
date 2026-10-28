"""Response proposal state machine. Any transition not listed here is refused."""

from enum import StrEnum


class ProposalState(StrEnum):
    DRAFT = "draft"
    EVIDENCE_COLLECTED = "evidence_collected"
    PROPOSED = "proposed"
    RISK_CHECKED = "risk_checked"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    VERIFIED = "verified"
    FAILED = "failed"
    CLOSED = "closed"


S = ProposalState

TRANSITIONS: dict[ProposalState, frozenset[ProposalState]] = {
    S.DRAFT: frozenset({S.EVIDENCE_COLLECTED}),
    S.EVIDENCE_COLLECTED: frozenset({S.PROPOSED}),
    S.PROPOSED: frozenset({S.RISK_CHECKED}),
    S.RISK_CHECKED: frozenset({S.AWAITING_APPROVAL, S.REJECTED}),
    S.AWAITING_APPROVAL: frozenset({S.APPROVED, S.REJECTED}),
    S.APPROVED: frozenset({S.EXECUTING}),
    S.EXECUTING: frozenset({S.VERIFIED, S.FAILED}),
    S.VERIFIED: frozenset({S.CLOSED}),
    S.FAILED: frozenset({S.CLOSED}),
    S.REJECTED: frozenset({S.CLOSED}),
    S.CLOSED: frozenset(),
}


class InvalidTransition(Exception):
    pass


def transition(current: ProposalState, new: ProposalState) -> ProposalState:
    if new not in TRANSITIONS[current]:
        raise InvalidTransition(f"{current} -> {new} is not allowed")
    return new
