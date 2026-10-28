"""Read API for cases, timelines and audit records."""

from typing import Any

from fastapi import APIRouter, HTTPException, status

from cases.audit import AuditLog, to_dict
from cases.store import CaseStore


def build_router(cases: CaseStore, audit: AuditLog) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["cases"])

    def _get(case_id: str) -> Any:
        case = cases.get(case_id)
        if case is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")
        return case

    @router.get("/cases")
    async def list_cases() -> list[dict[str, Any]]:
        return [c.summary() for c in cases.list()]

    @router.get("/cases/{case_id}")
    async def get_case(case_id: str) -> dict[str, Any]:
        case = _get(case_id)
        return {
            **case.summary(),
            "links": [vars(link) for link in case.links],
            "events": [e.model_dump(mode="json") for e in case.events],
        }

    @router.get("/cases/{case_id}/timeline")
    async def timeline(case_id: str) -> list[dict[str, Any]]:
        return [
            {
                "event_time": e.event_time.isoformat(),
                "source": e.source,
                "title": e.title,
                "severity": e.severity.normalized.value,
                "event_id": e.event_id,
            }
            for e in _get(case_id).timeline()
        ]

    @router.get("/audit")
    async def audit_records(case_id: str | None = None) -> dict[str, Any]:
        return {
            "chain_intact": audit.verify() is None,
            "records": [to_dict(r) for r in audit.records(case_id)],
        }

    return router
