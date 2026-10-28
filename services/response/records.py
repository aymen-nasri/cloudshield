"""What the response workflow stores about each proposal, and the in-memory store."""

import threading
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Protocol

from cases.state import ProposalState
from common.models import ResponseProposal
from policy.approvals import Approval, proposal_hash
from policy.engine import PolicyResult


@dataclass
class Execution:
    execution_id: str
    executor_identity: str
    started_at: datetime
    status: str = "running"
    result: dict[str, Any] = field(default_factory=dict)
    checks: dict[str, bool | None] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)
    finished_at: datetime | None = None


@dataclass
class ProposalRecord:
    proposal: ResponseProposal
    state: ProposalState
    action_class: str
    expires_at: datetime
    policy: PolicyResult | None = None
    approvals: list[Approval] = field(default_factory=list)
    execution: Execution | None = None

    @property
    def proposal_hash(self) -> str:
        return proposal_hash(self.proposal)

    def view(self) -> dict[str, Any]:
        return {
            **self.proposal.model_dump(mode="json"),
            "proposal_hash": self.proposal_hash,
            "state": self.state.value,
            "action_class": self.action_class,
            "expires_at": self.expires_at.isoformat(),
            "policy": self.policy.to_dict() if self.policy else None,
            "approvals": [
                {
                    "approver": a.approver,
                    "decision": a.decision,
                    "decided_at": a.decided_at.isoformat(),
                    "justification": a.justification,
                    "bound_to_current_version": a.bound_hash == self.proposal_hash,
                }
                for a in self.approvals
            ],
            "execution": None
            if self.execution is None
            else {
                "execution_id": self.execution.execution_id,
                "executor_identity": self.execution.executor_identity,
                "status": self.execution.status,
                "result": self.execution.result,
                "checks": self.execution.checks,
                "notes": self.execution.notes,
                "started_at": self.execution.started_at.isoformat(),
                "finished_at": self.execution.finished_at.isoformat() if self.execution.finished_at else None,
            },
        }


class DuplicateApproval(Exception):
    """This approver already decided on this proposal."""


class AlreadyExecuted(Exception):
    """An execution already exists for this proposal; actions run at most once."""


class ProposalStore(Protocol):
    def insert(self, record: ProposalRecord) -> None: ...

    def get(self, proposal_id: str) -> ProposalRecord | None: ...

    def list_for_case(self, case_id: str) -> list[ProposalRecord]: ...

    def update(self, record: ProposalRecord) -> None:
        """Persist state, dry-run result, impact preview and policy decision."""
        ...

    def add_approval(self, approval: Approval) -> None: ...

    def start_execution(self, proposal_id: str, execution: Execution) -> None: ...

    def finish_execution(self, proposal_id: str, execution: Execution) -> None: ...


class InMemoryProposalStore:
    def __init__(self) -> None:
        self._records: dict[str, ProposalRecord] = {}
        self._lock = threading.Lock()

    def insert(self, record: ProposalRecord) -> None:
        with self._lock:
            self._records[record.proposal.proposal_id] = replace(record)

    def get(self, proposal_id: str) -> ProposalRecord | None:
        record = self._records.get(proposal_id)
        # Hand out copies so callers can't change stored state without going through the store.
        return replace(record, approvals=list(record.approvals)) if record else None

    def list_for_case(self, case_id: str) -> list[ProposalRecord]:
        found = [r for r in self._records.values() if r.proposal.case_id == case_id]
        return sorted(found, key=lambda r: r.proposal.created_at)

    def update(self, record: ProposalRecord) -> None:
        with self._lock:
            stored = self._records[record.proposal.proposal_id]
            stored.proposal = record.proposal
            stored.state = record.state
            stored.policy = record.policy

    def add_approval(self, approval: Approval) -> None:
        with self._lock:
            stored = self._records[approval.proposal_id]
            if any(a.approver == approval.approver for a in stored.approvals):
                raise DuplicateApproval(approval.approver)
            stored.approvals.append(approval)

    def start_execution(self, proposal_id: str, execution: Execution) -> None:
        with self._lock:
            stored = self._records[proposal_id]
            if stored.execution is not None:
                raise AlreadyExecuted(proposal_id)
            stored.execution = replace(execution)

    def finish_execution(self, proposal_id: str, execution: Execution) -> None:
        with self._lock:
            self._records[proposal_id].execution = replace(execution)
