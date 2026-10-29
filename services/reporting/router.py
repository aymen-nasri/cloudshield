"""GET /v1/cases/{id}/report: the post-incident report as Markdown."""

from collections.abc import Callable
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import PlainTextResponse

from cases.audit import AuditStore
from cases.store import CaseStore
from common.timeutil import utcnow
from core.auth import AnalystDirectory
from enrichment.graph import EntityStore
from investigator.records import InvestigationStore
from reporting.report import ReportInputs, build_report
from response.records import ProposalStore


def build_router(
    cases: CaseStore,
    investigations: InvestigationStore,
    proposals: ProposalStore,
    audit: AuditStore,
    entities: EntityStore,
    analysts: AnalystDirectory,
    clock: Callable[[], datetime] = utcnow,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["reports"])

    @router.get("/cases/{case_id}/report", response_class=PlainTextResponse)
    def report(case_id: str, authorization: Annotated[str | None, Header()] = None) -> PlainTextResponse:
        # Reports name approvers and include justifications, so they need an authenticated analyst.
        who = analysts.authenticate(authorization)
        if who is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "analyst not authenticated")
        case = cases.get(case_id)
        if case is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")

        pod = next((e.resource_id for e in case.events if (e.resource_id or "").startswith("k8s:pod/")), None)
        related = entities.neighborhood(pod, depth=3)[0] if pod and entities.get(pod) else []
        markdown = build_report(
            ReportInputs(
                case=case,
                investigations=investigations.list_for_case(case_id),
                proposals=proposals.list_for_case(case_id),
                audit=audit.records(case_id),
                chain_intact=audit.verify() is None,
                entities=related,
                generated_at=clock(),
                generated_by=who.id,
            )
        )
        filename = f"cloudshield-{case_id}-report.md"
        return PlainTextResponse(
            markdown,
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )

    return router
