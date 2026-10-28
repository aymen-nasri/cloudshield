"""Read API for cases, timelines, the entity graph and audit records.

Handlers are plain `def`: FastAPI runs them in a worker thread, so blocking store calls
(PostgreSQL) never stall the event loop.
"""

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status

from cases.audit import AuditStore, to_dict
from cases.models import Case
from cases.store import CaseStore
from enrichment.graph import EntityStore


def build_router(cases: CaseStore, audit: AuditStore, entities: EntityStore) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["cases"])

    def _get(case_id: str) -> Case:
        case = cases.get(case_id)
        if case is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")
        return case

    @router.get("/cases")
    def list_cases() -> list[dict[str, Any]]:
        return [c.summary() for c in cases.list()]

    @router.get("/cases/{case_id}")
    def get_case(case_id: str) -> dict[str, Any]:
        case = _get(case_id)
        return {
            **case.summary(),
            "links": [vars(link) for link in case.links],
            "events": [e.model_dump(mode="json") for e in case.events],
        }

    @router.get("/cases/{case_id}/timeline")
    def timeline(case_id: str) -> list[dict[str, Any]]:
        return [
            {
                "event_time": e.event_time.isoformat(),
                "source": e.source,
                "title": e.title,
                "severity": e.severity.normalized.value,
                "event_id": e.event_id,
                "resource_id": e.resource_id,
                "identity_id": e.identity_id,
            }
            for e in _get(case_id).timeline()
        ]

    @router.get("/entities/{entity_id:path}/graph")
    def entity_graph(entity_id: str, depth: int = Query(2, ge=1, le=4)) -> dict[str, Any]:
        if entities.get(entity_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "entity not found")
        nodes, edges = entities.neighborhood(entity_id, depth)
        return {
            "root": entity_id,
            "entities": [{**asdict(n), "observed_at": n.observed_at.isoformat()} for n in nodes],
            "edges": [asdict(e) for e in edges],
        }

    @router.get("/audit")
    def audit_records(case_id: str | None = None) -> dict[str, Any]:
        return {
            "chain_intact": audit.verify() is None,
            "records": [to_dict(r) for r in audit.records(case_id)],
        }

    return router
