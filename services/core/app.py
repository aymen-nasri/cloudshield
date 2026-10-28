"""Application factory. Run with: uvicorn core.app:create_app --factory"""

import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI

from cases.audit import AuditLog, AuditStore
from cases.router import build_router as build_cases_router
from cases.store import CaseStore, InMemoryCaseStore
from common.models import NormalizedEvent
from correlation.engine import CorrelationEngine
from enrichment.context import PodContext
from enrichment.enricher import Enricher, kubernetes_pod_resolver
from enrichment.graph import EntityStore, InMemoryEntityStore
from ingestion.adapters import FalcoAdapter, GuardDutyAdapter, SourceAdapter, WazuhAdapter
from ingestion.auth import SourceCredential
from ingestion.coverage import CoverageTracker
from ingestion.evidence import EvidenceStore, InMemoryEvidenceStore, LocalEvidenceStore
from ingestion.pipeline import EventStore, IngestPipeline, InMemoryEventStore
from ingestion.router import build_router as build_ingestion_router


@dataclass
class Settings:
    cluster: str | None = None
    account_id: str | None = None
    region: str | None = None
    evidence_dir: Path | None = None
    # postgresql://user:pass@host/db. Unset means in-memory stores (tests, quick demos).
    database_url: str | None = None
    database_schema: str | None = None
    # "k8s" resolves pod context from the Kubernetes API and AWS. Unset means no enrichment.
    enrichment: str | None = None
    credentials: dict[str, SourceCredential] = field(default_factory=dict)
    max_silence: dict[str, timedelta] = field(
        default_factory=lambda: {"falco": timedelta(minutes=5), "guardduty": timedelta(hours=6)}
    )

    @classmethod
    def from_env(cls) -> "Settings":
        credentials: dict[str, SourceCredential] = {}
        if token := os.getenv("CLOUDSHIELD_FALCO_TOKEN"):
            credentials["falco"] = SourceCredential(token=token)
        if secret := os.getenv("CLOUDSHIELD_WAZUH_HMAC_SECRET"):
            credentials["wazuh"] = SourceCredential(hmac_secret=secret)
        if secret := os.getenv("CLOUDSHIELD_REPLAY_HMAC_SECRET"):
            # Lab only: lets scripts/replay_fixture.py submit recorded GuardDuty findings over HTTP.
            credentials["guardduty"] = SourceCredential(hmac_secret=secret)
        evidence_dir = os.getenv("CLOUDSHIELD_EVIDENCE_DIR")
        return cls(
            cluster=os.getenv("CLOUDSHIELD_CLUSTER"),
            account_id=os.getenv("CLOUDSHIELD_ACCOUNT_ID"),
            region=os.getenv("AWS_REGION"),
            evidence_dir=Path(evidence_dir) if evidence_dir else None,
            database_url=os.getenv("CLOUDSHIELD_DATABASE_URL"),
            enrichment=os.getenv("CLOUDSHIELD_ENRICHMENT"),
            credentials=credentials,
        )


@dataclass
class Stores:
    events: EventStore
    cases: CaseStore
    entities: EntityStore
    audit: AuditStore
    close: Callable[[], None] = lambda: None


def build_stores(settings: Settings) -> Stores:
    if not settings.database_url:
        return Stores(InMemoryEventStore(), InMemoryCaseStore(), InMemoryEntityStore(), AuditLog())

    from storage.database import Database, apply_migrations
    from storage.postgres import (
        PostgresAuditLog,
        PostgresCaseStore,
        PostgresEntityStore,
        PostgresEventStore,
    )

    db = Database(settings.database_url, schema=settings.database_schema)
    apply_migrations(db)
    return Stores(
        PostgresEventStore(db),
        PostgresCaseStore(db),
        PostgresEntityStore(db),
        PostgresAuditLog(db),
        close=db.close,
    )


def create_app(
    settings: Settings | None = None,
    *,
    pod_resolver: Callable[[str, str], PodContext] | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    stores = build_stores(settings)

    engine = CorrelationEngine(stores.cases)
    evidence: EvidenceStore = (
        LocalEvidenceStore(settings.evidence_dir) if settings.evidence_dir else InMemoryEvidenceStore()
    )

    if pod_resolver is None and settings.enrichment == "k8s" and settings.cluster:
        pod_resolver = kubernetes_pod_resolver(settings.cluster, settings.region)
    enrich = Enricher(pod_resolver, stores.entities) if pod_resolver else None

    def on_accepted(event: NormalizedEvent) -> None:
        case, link = engine.correlate(event)
        stores.audit.append(
            "service",
            "correlation-engine",
            "case.event_linked",
            {
                "case_id": case.case_id,
                "event_id": event.event_id,
                "rule": link.rule,
                "rationale": link.rationale,
            },
        )

    pipeline = IngestPipeline(stores.events, evidence, on_accepted=on_accepted, enrich=enrich)
    adapters: dict[str, SourceAdapter] = {
        "falco": FalcoAdapter(cluster=settings.cluster, account_id=settings.account_id),
        "wazuh": WazuhAdapter(account_id=settings.account_id),
        # GuardDuty arrives through the SQS worker; the HTTP route exists for replaying fixtures.
        "guardduty": GuardDutyAdapter(),
    }
    coverage = CoverageTracker(settings.max_silence)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        stores.close()

    app = FastAPI(title="CloudShield", version="0.2.0", lifespan=lifespan)
    app.include_router(build_ingestion_router(pipeline, adapters, settings.credentials, coverage))
    app.include_router(build_cases_router(stores.cases, stores.audit, stores.entities))

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
