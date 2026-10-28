"""The response workflow. Every step goes through the proposal state machine and the audit log.

create   -> PROPOSED            target must belong to the case; labels come from the live object
dry_run  -> AWAITING_APPROVAL   dry-run + impact preview + policy gate (or REJECTED)
decide   -> APPROVED            hash-bound, role-checked approvals; no self-approval (or REJECTED)
execute  -> VERIFIED / FAILED   approvals and target freshness re-checked; runs at most once
"""

import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any, Literal

from cases.audit import AuditStore
from cases.state import ProposalState as S
from cases.state import transition
from cases.store import CaseStore
from common.ids import new_id
from common.models import ResponseProposal, Target
from common.timeutil import utcnow
from core.auth import Principal
from policy.approvals import Approval, ApprovalError, check_approvals
from policy.engine import ActionPolicy, Decision, PolicyEngine, PolicyResult
from responder.executor import Executor, UnsupportedAction
from response.records import AlreadyExecuted, DuplicateApproval, Execution, ProposalRecord, ProposalStore

PROPOSERS = frozenset({"analyst", "incident-responder"})
# Notifications (notify.slack, case.escalate) are allowlisted but have no executor yet.
EXECUTABLE_ACTIONS = frozenset({"k8s.pod.quarantine_label", "k8s.pod.remove_quarantine_label"})


class ResponseError(Exception):
    status = 400


class NotFound(ResponseError):
    status = 404


class Forbidden(ResponseError):
    status = 403


class Conflict(ResponseError):
    status = 409


class Invalid(ResponseError):
    status = 422


class Unavailable(ResponseError):
    status = 503


class ResponseService:
    def __init__(
        self,
        proposals: ProposalStore,
        cases: CaseStore,
        audit: AuditStore,
        policies: dict[str, ActionPolicy],
        executor: Executor | None,
        *,
        environment: str,
        proposal_ttl: timedelta = timedelta(hours=1),
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.proposals = proposals
        self.cases = cases
        self.audit = audit
        self.policies = policies
        self.executor = executor
        self.environment = environment
        self.proposal_ttl = proposal_ttl
        self.clock = clock
        # One workflow step at a time per process; the database constraints cover the rest.
        self._lock = threading.Lock()

    # -- helpers ---------------------------------------------------------------------------

    def _record(self, proposal_id: str) -> ProposalRecord:
        record = self.proposals.get(proposal_id)
        if record is None:
            raise NotFound("proposal not found")
        return record

    def _move(self, record: ProposalRecord, new: S, actor: Principal | str, **details: Any) -> None:
        record.state = transition(record.state, new)
        self.proposals.update(record)
        actor_id = actor.id if isinstance(actor, Principal) else actor
        self.audit.append(
            "human" if isinstance(actor, Principal) else "service",
            actor_id,
            f"proposal.{new.value}",
            {"case_id": record.proposal.case_id, "proposal_id": record.proposal.proposal_id, **details},
        )

    def _require(self, record: ProposalRecord, *states: S) -> None:
        if record.state not in states:
            allowed = ", ".join(s.value for s in states)
            raise Conflict(f"proposal is {record.state.value}; this step needs {allowed}")

    def _engine(self) -> PolicyEngine:
        executor = self.executor
        return PolicyEngine(self.policies, is_fresh=executor.is_fresh if executor else lambda t: False)

    def _expire_if_needed(self, record: ProposalRecord) -> None:
        if self.clock() > record.expires_at:
            self._move(record, S.REJECTED, "response-service", reason="proposal expired")
            raise Conflict("proposal expired; create a new one")

    # -- workflow --------------------------------------------------------------------------

    def create(
        self,
        case_id: str,
        principal: Principal,
        *,
        action_type: str,
        target: Target,
        rationale: str,
        parameters: dict[str, Any] | None = None,
    ) -> ProposalRecord:
        if not principal.has_any(PROPOSERS):
            raise Forbidden("proposing a response needs the analyst or incident-responder role")
        case = self.cases.get(case_id)
        if case is None:
            raise NotFound("case not found")

        if action_type not in EXECUTABLE_ACTIONS:
            raise Invalid(f"no executor supports {action_type!r} yet")
        if target.kind != "Pod":
            raise Invalid(f"{action_type} targets a Pod")
        resource = f"k8s:pod/{target.namespace}/{target.name}"
        if resource not in {e.resource_id for e in case.events}:
            raise Invalid(f"{resource} does not appear in case {case_id}")
        if target.cluster not in (None, case.cluster):
            raise Invalid("target cluster differs from the case's cluster")
        if self.executor is None:
            raise Unavailable("no executor is configured for Kubernetes actions")
        # Labels decide escalation, so they come from the live pod, never from the request.
        live = self.executor.current_labels(target)
        if live is None:
            raise Invalid("target pod not found with this UID")
        target = target.model_copy(update={"labels": live, "cluster": case.cluster})

        now = self.clock()
        policy = self.policies.get(action_type)
        record = ProposalRecord(
            proposal=ResponseProposal(
                proposal_id=new_id("prp"),
                case_id=case_id,
                action_type=action_type,
                target=target,
                environment=self.environment,
                parameters=parameters or {},
                rationale=rationale,
                requested_by=principal.id,
                created_at=now,
            ),
            state=S.DRAFT,
            action_class=policy.action_class.value if policy else "unlisted",
            expires_at=now + self.proposal_ttl,
        )
        with self._lock:
            self.proposals.insert(record)
            self._move(record, S.EVIDENCE_COLLECTED, principal)
            self._move(record, S.PROPOSED, principal, action_type=action_type, target=target.name)
        return record

    def dry_run(self, proposal_id: str, principal: Principal) -> ProposalRecord:
        with self._lock:
            record = self._record(proposal_id)
            self._require(record, S.PROPOSED)
            self._expire_if_needed(record)
            if self.executor is None:
                raise Unavailable("no executor is configured")
            try:
                result, impact = self.executor.dry_run(record.proposal)
            except UnsupportedAction as exc:
                result_status, impact, detail = "unsupported", {}, str(exc)
            else:
                result_status, detail = result.status, result.detail

            record.proposal = record.proposal.model_copy(
                update={"dry_run_passed": result_status == "dry_run_ok", "impact_preview": impact}
            )
            record.policy = self._engine().evaluate(record.proposal)
            self._move(record, S.RISK_CHECKED, principal, dry_run=result_status, detail=detail)
            if record.policy.decision is Decision.DENY:
                self._move(record, S.REJECTED, "policy-engine", reasons=record.policy.reasons)
            else:
                self._move(
                    record,
                    S.AWAITING_APPROVAL,
                    "policy-engine",
                    decision=record.policy.decision.value,
                    required_approvals=record.policy.required_approvals,
                    proposal_hash=record.proposal_hash,
                )
            return record

    def decide(
        self,
        proposal_id: str,
        principal: Principal,
        *,
        decision: Literal["approve", "reject"],
        bound_hash: str,
        justification: str,
    ) -> ProposalRecord:
        with self._lock:
            record = self._record(proposal_id)
            self._require(record, S.AWAITING_APPROVAL)
            self._expire_if_needed(record)
            policy = record.policy
            if policy is None:
                raise Conflict("proposal has no policy decision")
            if principal.id == record.proposal.requested_by:
                raise Forbidden("the requester cannot approve or reject their own proposal")
            if not principal.has_any(policy.approver_roles):
                raise Forbidden(f"deciding needs one of the roles {sorted(policy.approver_roles)}")
            if bound_hash != record.proposal_hash:
                raise Conflict("proposal_hash does not match the current proposal; review it again")
            if not justification.strip():
                raise Invalid("a justification is required")

            approval = Approval(
                proposal_id=proposal_id,
                approver=principal.id,
                approver_roles=principal.roles,
                decision=decision,
                bound_hash=bound_hash,
                decided_at=self.clock(),
                justification=justification,
            )
            try:
                self.proposals.add_approval(approval)
            except DuplicateApproval as exc:
                raise Conflict("you already decided on this proposal") from exc
            record.approvals.append(approval)
            self.audit.append(
                "human",
                principal.id,
                f"proposal.{decision}d" if decision == "approve" else "proposal.rejected_by_human",
                {
                    "case_id": record.proposal.case_id,
                    "proposal_id": proposal_id,
                    "bound_hash": bound_hash,
                    "justification": justification,
                },
            )

            if decision == "reject":
                self._move(record, S.REJECTED, principal, reason="rejected by approver")
                return record
            try:
                check_approvals(record.proposal, policy, record.approvals, now=self.clock())
            except ApprovalError:
                return record  # more approvals needed
            self._move(record, S.APPROVED, principal, approvals=[a.approver for a in record.approvals])
            return record

    def execute(self, proposal_id: str, principal: Principal) -> ProposalRecord:
        with self._lock:
            record = self._record(proposal_id)
            self._require(record, S.APPROVED)
            if not principal.has_any(frozenset({"incident-responder"})):
                raise Forbidden("executing needs the incident-responder role")
            if self.executor is None:
                raise Unavailable("no executor is configured")
            policy = record.policy or PolicyResult(Decision.DENY, ["missing policy decision"])

            # Re-check at the moment of execution: approvals may have expired, the target may be gone.
            try:
                idempotency_key = check_approvals(record.proposal, policy, record.approvals, now=self.clock())
            except ApprovalError as exc:
                self._move(record, S.REJECTED, "response-service", reason=f"approvals no longer valid: {exc}")
                raise Conflict(f"approvals no longer valid: {exc}") from exc
            recheck = self._engine().evaluate(record.proposal)
            if recheck.decision is Decision.DENY:
                self._move(record, S.REJECTED, "policy-engine", reasons=recheck.reasons)
                raise Conflict(f"policy now denies this action: {'; '.join(recheck.reasons)}")

            execution = Execution(new_id("exe"), self.executor.identity, started_at=self.clock())
            try:
                self.proposals.start_execution(proposal_id, execution)
            except AlreadyExecuted as exc:
                raise Conflict("this proposal was already executed") from exc
            self._move(record, S.EXECUTING, principal, idempotency_key=idempotency_key)

            try:
                result = self.executor.execute(record.proposal)
                report = self.executor.verify(record.proposal)
            except Exception as exc:  # the executor talks to real infrastructure; record and escalate
                execution = replace(
                    execution, status="error", result={"error": str(exc)}, finished_at=self.clock()
                )
                self.proposals.finish_execution(proposal_id, execution)
                record.execution = execution
                self._move(record, S.FAILED, "response-service", error=str(exc), escalate="on-call")
                return record

            succeeded = result.status in ("applied", "already_applied", "removed") and report.passed
            execution = replace(
                execution,
                status=result.status,
                result={"detail": result.detail},
                checks=report.checks,
                notes=report.notes,
                finished_at=self.clock(),
            )
            self.proposals.finish_execution(proposal_id, execution)
            record.execution = execution
            self._move(
                record,
                S.VERIFIED if succeeded else S.FAILED,
                "verifier",
                status=result.status,
                checks=report.checks,
                **({} if succeeded else {"escalate": "on-call"}),
            )
            return record

    def get(self, proposal_id: str) -> ProposalRecord:
        return self._record(proposal_id)

    def list_for_case(self, case_id: str) -> list[ProposalRecord]:
        if self.cases.get(case_id) is None:
            raise NotFound("case not found")
        return self.proposals.list_for_case(case_id)
