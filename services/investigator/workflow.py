"""Run an investigation on a case: gather evidence and runbooks, call the model, validate, store, audit.

The model's answer is stored only if it passes validation (every fact cites a real event, every
target is an entity in the case). An analyst then accepts or rejects it; nothing in an investigation
can start a response action.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Literal

from cases.audit import AuditStore
from cases.store import CaseStore
from common.ids import new_id
from common.timeutil import utcnow
from core.auth import Principal
from investigator.bundle import build_bundle
from investigator.records import InvestigationRecord, InvestigationStore
from investigator.runbooks import RunbookLibrary
from investigator.service import Investigator, LanguageModel
from investigator.validate import InvestigationRejected

ANALYSTS = frozenset({"analyst", "incident-responder"})


class InvestigationError(Exception):
    status = 400


class NotFound(InvestigationError):
    status = 404


class Forbidden(InvestigationError):
    status = 403


class Conflict(InvestigationError):
    status = 409


class Rejected(InvestigationError):
    status = 422

    def __init__(self, problems: list[str]) -> None:
        super().__init__("model output failed validation: " + "; ".join(problems))
        self.problems = problems


class Unavailable(InvestigationError):
    status = 503


def _entities(resource_ids: list[str | None]) -> list[dict[str, str]]:
    seen = dict.fromkeys(r for r in resource_ids if r)
    return [{"entity_id": r, "kind": r.split(":", 1)[1].split("/", 1)[0]} for r in seen]


class InvestigationService:
    def __init__(
        self,
        investigations: InvestigationStore,
        cases: CaseStore,
        audit: AuditStore,
        runbooks: RunbookLibrary,
        model: LanguageModel | None,
        *,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.investigations = investigations
        self.cases = cases
        self.audit = audit
        self.runbooks = runbooks
        self.model = model
        self.clock = clock

    def run(self, case_id: str, principal: Principal, question: str | None = None) -> InvestigationRecord:
        if not principal.has_any(ANALYSTS):
            raise Forbidden("running an investigation needs the analyst or incident-responder role")
        case = self.cases.get(case_id)
        if case is None:
            raise NotFound("case not found")
        if self.model is None:
            raise Unavailable("no investigator model is configured (CLOUDSHIELD_INVESTIGATOR)")

        passages = self.runbooks.passages_for(case.events)
        bundle = build_bundle(case, _entities([e.resource_id for e in case.events]), passages)
        doc_ids = sorted({p["doc_id"] for p in passages})
        try:
            run = Investigator(self.model).investigate(bundle, question)
        except InvestigationRejected as exc:
            self.audit.append(
                "model",
                self.model.model_id,
                "investigation.rejected",
                {"case_id": case_id, "problems": exc.problems, "requested_by": principal.id},
            )
            raise Rejected(exc.problems) from exc

        record = InvestigationRecord(
            investigation_id=new_id("inv"),
            case_id=case_id,
            model_id=run.model_id,
            prompt_version=run.prompt_version,
            retrieved_doc_ids=doc_ids,
            output=run.investigation,
            attempts=run.attempts,
            requested_by=principal.id,
            created_at=self.clock(),
        )
        self.investigations.insert(record)
        self.audit.append(
            "model",
            run.model_id,
            "investigation.created",
            {
                "case_id": case_id,
                "investigation_id": record.investigation_id,
                "prompt_version": run.prompt_version,
                "retrieved_doc_ids": doc_ids,
                "cited_event_ids": sorted(
                    {i for f in run.investigation.observed_facts for i in f.evidence_ids}
                ),
                "attempts": run.attempts,
                "requested_by": principal.id,
            },
        )
        return record

    def review(
        self,
        investigation_id: str,
        principal: Principal,
        decision: Literal["accepted", "rejected"],
        note: str,
    ) -> InvestigationRecord:
        if not principal.has_any(ANALYSTS):
            raise Forbidden("reviewing needs the analyst or incident-responder role")
        record = self.get(investigation_id)
        if not self.investigations.set_review(investigation_id, decision, principal.id):
            raise Conflict(f"already {record.review_status} by {record.reviewed_by}")
        self.audit.append(
            "human",
            principal.id,
            f"investigation.{decision}",
            {"case_id": record.case_id, "investigation_id": investigation_id, "note": note},
        )
        return self.get(investigation_id)

    def get(self, investigation_id: str) -> InvestigationRecord:
        record = self.investigations.get(investigation_id)
        if record is None:
            raise NotFound("investigation not found")
        return record

    def list_for_case(self, case_id: str) -> list[InvestigationRecord]:
        if self.cases.get(case_id) is None:
            raise NotFound("case not found")
        return self.investigations.list_for_case(case_id)
