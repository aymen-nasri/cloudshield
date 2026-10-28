"""HTTP routes for AI investigations. Every route needs an authenticated analyst."""

from collections.abc import Callable
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from core.auth import AnalystDirectory, Principal
from investigator.workflow import InvestigationError, InvestigationService, Rejected


class InvestigationRequest(BaseModel):
    question: str | None = Field(default=None, max_length=1000)


class ReviewRequest(BaseModel):
    decision: Literal["accepted", "rejected"]
    note: str = Field(min_length=1, max_length=2000)


def build_router(service: InvestigationService, analysts: AnalystDirectory) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["investigations"])

    def principal(authorization: Annotated[str | None, Header()] = None) -> Principal:
        found = analysts.authenticate(authorization)
        if found is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "analyst not authenticated")
        return found

    Analyst = Annotated[Principal, Depends(principal)]

    def run(step: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            return step(*args, **kwargs)
        except Rejected as exc:
            raise HTTPException(
                exc.status, {"error": "model output rejected", "problems": exc.problems}
            ) from exc
        except InvestigationError as exc:
            raise HTTPException(exc.status, str(exc)) from exc

    @router.post("/cases/{case_id}/investigations", status_code=status.HTTP_201_CREATED)
    def create(case_id: str, who: Analyst, body: InvestigationRequest | None = None) -> dict[str, Any]:
        return dict(run(service.run, case_id, who, body.question if body else None).view())

    @router.get("/cases/{case_id}/investigations")
    def list_for_case(case_id: str, who: Analyst) -> list[dict[str, Any]]:
        return [r.view() for r in run(service.list_for_case, case_id)]

    @router.get("/investigations/{investigation_id}")
    def get(investigation_id: str, who: Analyst) -> dict[str, Any]:
        return dict(run(service.get, investigation_id).view())

    @router.post("/investigations/{investigation_id}/review")
    def review(investigation_id: str, body: ReviewRequest, who: Analyst) -> dict[str, Any]:
        return dict(run(service.review, investigation_id, who, body.decision, body.note).view())

    return router
