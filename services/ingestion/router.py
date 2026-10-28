"""HTTP ingestion endpoints."""

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool

from ingestion.adapters import MAX_PAYLOAD_BYTES, PayloadError, SourceAdapter
from ingestion.auth import SourceCredential, authenticate
from ingestion.coverage import CoverageTracker
from ingestion.pipeline import IngestPipeline


def build_router(
    pipeline: IngestPipeline,
    adapters: dict[str, SourceAdapter],
    credentials: dict[str, SourceCredential],
    coverage: CoverageTracker,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["ingestion"])

    @router.post("/ingest/{source}", status_code=status.HTTP_202_ACCEPTED)
    async def ingest(source: str, request: Request) -> dict[str, str | None]:
        adapter = adapters.get(source)
        if adapter is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown source {source!r}")

        body = await request.body()
        if len(body) > MAX_PAYLOAD_BYTES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "payload too large")
        if not authenticate(credentials.get(source), request.headers, body):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "producer not authenticated")

        try:
            # Storage and enrichment calls block; keep them off the event loop.
            result = await run_in_threadpool(pipeline.ingest, body, adapter)
        except PayloadError as exc:
            raise HTTPException(422, str(exc)) from exc

        coverage.heartbeat(source)
        return {"status": result.status, "event_id": result.event_id, "dedup_key": result.dedup_key}

    @router.get("/health/coverage")
    async def health_coverage() -> dict[str, object]:
        return {"overall": coverage.overall(), "sources": coverage.status()}

    return router
