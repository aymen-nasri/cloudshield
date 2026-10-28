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
from core.auth import AnalystDirectory
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
from investigator.offline import OfflineBaselineModel
from investigator.records import InMemoryInvestigationStore, InvestigationStore
from investigator.router import build_router as build_investigation_router
from investigator.runbooks import RunbookLibrary
from investigator.service import LanguageModel
from investigator.workflow import InvestigationService
from policy.engine import load_policies
from responder.executor import Executor, KubernetesExecutor
from response.records import InMemoryProposalStore, ProposalStore
from response.router import build_router as build_response_router
from response.service import ResponseService


def _default_runbooks() -> Path | None:
    """CLOUDSHIELD_RUNBOOKS_DIR, else the repository's runbooks/ when running from a checkout."""
    configured = os.getenv("CLOUDSHIELD_RUNBOOKS_DIR")
    if configured:
        return Path(configured)
    checkout = Path(__file__).resolve().parents[2] / "runbooks"
    return checkout if checkout.is_dir() else None


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
    # "k8s" runs approved actions in-process with the responder identity (lab). Unset: none.
    executor: str | None = None
    # Which policy environment this deployment is ("lab" or "prod"); the allowlist is per environment.
    environment: str = "lab"
    # "offline" = deterministic baseline (no LLM); "bedrock" = Amazon Bedrock. Unset: investigations off.
    investigator: str | None = None
    bedrock_model_id: str | None = None
    bedrock_guardrail_id: str | None = None
    runbooks_dir: Path | None = field(default_factory=lambda: _default_runbooks())
    analysts: AnalystDirectory = field(default_factory=lambda: AnalystDirectory({}))
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
            executor=os.getenv("CLOUDSHIELD_EXECUTOR"),
            environment=os.getenv("CLOUDSHIELD_ENVIRONMENT", "lab"),
            analysts=AnalystDirectory.from_json(os.getenv("CLOUDSHIELD_ANALYSTS")),
            investigator=os.getenv("CLOUDSHIELD_INVESTIGATOR"),
            bedrock_model_id=os.getenv("CLOUDSHIELD_BEDROCK_MODEL_ID"),
            bedrock_guardrail_id=os.getenv("CLOUDSHIELD_BEDROCK_GUARDRAIL_ID"),
            credentials=credentials,
        )


@dataclass
class Stores:
    events: EventStore
    cases: CaseStore
    entities: EntityStore
    audit: AuditStore
    proposals: ProposalStore
    investigations: InvestigationStore
    close: Callable[[], None] = lambda: None


def build_stores(settings: Settings) -> Stores:
    if not settings.database_url:
        return Stores(
            InMemoryEventStore(),
            InMemoryCaseStore(),
            InMemoryEntityStore(),
            AuditLog(),
            InMemoryProposalStore(),
            InMemoryInvestigationStore(),
        )

    from storage.database import Database, apply_migrations
    from storage.postgres import (
        PostgresAuditLog,
        PostgresCaseStore,
        PostgresEntityStore,
        PostgresEventStore,
        PostgresInvestigationStore,
        PostgresProposalStore,
    )

    db = Database(settings.database_url, schema=settings.database_schema)
    apply_migrations(db)
    return Stores(
        PostgresEventStore(db),
        PostgresCaseStore(db),
        PostgresEntityStore(db),
        PostgresAuditLog(db),
        PostgresProposalStore(db),
        PostgresInvestigationStore(db),
        close=db.close,
    )


def build_model(settings: Settings) -> LanguageModel | None:
    if settings.investigator == "offline":
        return OfflineBaselineModel()
    if settings.investigator == "bedrock":
        if not settings.bedrock_model_id:
            raise ValueError("CLOUDSHIELD_INVESTIGATOR=bedrock needs CLOUDSHIELD_BEDROCK_MODEL_ID")
        from investigator.bedrock import BedrockClient

        return BedrockClient(
            settings.bedrock_model_id, region=settings.region, guardrail_id=settings.bedrock_guardrail_id
        )
    return None


def create_app(
    settings: Settings | None = None,
    *,
    pod_resolver: Callable[[str, str], PodContext] | None = None,
    executor: Executor | None = None,
    stores: Stores | None = None,
    model: LanguageModel | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    stores = stores or build_stores(settings)

    if executor is None and settings.executor == "k8s":
        from responder.quarantine import KubernetesPodApi

        executor = KubernetesExecutor(KubernetesPodApi())
    response = ResponseService(
        stores.proposals,
        stores.cases,
        stores.audit,
        load_policies(),
        executor,
        environment=settings.environment,
    )
    investigations = InvestigationService(
        stores.investigations,
        stores.cases,
        stores.audit,
        RunbookLibrary.from_dir(settings.runbooks_dir),
        model or build_model(settings),
    )

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
    app.include_router(build_response_router(response, settings.analysts))
    app.include_router(build_investigation_router(investigations, settings.analysts))

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
