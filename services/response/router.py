"""HTTP routes for the response workflow. Every route needs an authenticated analyst."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from common.models import Target
from core.auth import AnalystDirectory, Principal
from response.service import ResponseError, ResponseService


class ProposalRequest(BaseModel):
    action_type: str
    target: Target
    rationale: str = Field(min_length=1, max_length=2000)
    parameters: dict[str, Any] = {}


class DecisionRequest(BaseModel):
    proposal_hash: str
    justification: str = Field(min_length=1, max_length=2000)


def build_router(service: ResponseService, analysts: AnalystDirectory) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["response"])

    def principal(authorization: Annotated[str | None, Header()] = None) -> Principal:
        found = analysts.authenticate(authorization)
        if found is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "analyst not authenticated")
        return found

    Analyst = Annotated[Principal, Depends(principal)]

    def run(step: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return dict(step(*args, **kwargs).view())
        except ResponseError as exc:
            raise HTTPException(exc.status, str(exc)) from exc

    @router.post("/cases/{case_id}/proposals", status_code=status.HTTP_201_CREATED)
    def create(case_id: str, body: ProposalRequest, who: Analyst) -> dict[str, Any]:
        return run(
            service.create,
            case_id,
            who,
            action_type=body.action_type,
            target=body.target,
            rationale=body.rationale,
            parameters=body.parameters,
        )

    @router.get("/cases/{case_id}/proposals")
    def list_for_case(case_id: str, who: Analyst) -> list[dict[str, Any]]:
        try:
            return [r.view() for r in service.list_for_case(case_id)]
        except ResponseError as exc:
            raise HTTPException(exc.status, str(exc)) from exc

    @router.get("/proposals/{proposal_id}")
    def get(proposal_id: str, who: Analyst) -> dict[str, Any]:
        return run(service.get, proposal_id)

    @router.post("/proposals/{proposal_id}/dry-run")
    def dry_run(proposal_id: str, who: Analyst) -> dict[str, Any]:
        return run(service.dry_run, proposal_id, who)

    @router.post("/proposals/{proposal_id}/approve")
    def approve(proposal_id: str, body: DecisionRequest, who: Analyst) -> dict[str, Any]:
        return run(
            service.decide,
            proposal_id,
            who,
            decision="approve",
            bound_hash=body.proposal_hash,
            justification=body.justification,
        )

    @router.post("/proposals/{proposal_id}/reject")
    def reject(proposal_id: str, body: DecisionRequest, who: Analyst) -> dict[str, Any]:
        return run(
            service.decide,
            proposal_id,
            who,
            decision="reject",
            bound_hash=body.proposal_hash,
            justification=body.justification,
        )

    @router.post("/proposals/{proposal_id}/execute")
    def execute(proposal_id: str, who: Analyst) -> dict[str, Any]:
        return run(service.execute, proposal_id, who)

    return router
