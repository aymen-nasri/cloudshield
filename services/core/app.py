"""Application factory. Run with: uvicorn core.app:create_app --factory"""

import os
import threading
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, Response
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST

from cases.audit import AuditLog, AuditStore
from cases.router import build_router as build_cases_router
from cases.store import CaseStore, InMemoryCaseStore
from common.models import NormalizedEvent
from console.router import build_router as build_console_router
from core.auth import AnalystDirectory, require_analyst
from core.metrics import Metrics
from correlation.engine import CorrelationEngine
from enrichment.context import PodContext
from enrichment.enricher import Enricher, kubernetes_pod_resolver
from enrichment.graph import EntityStore, InMemoryEntityStore
from ingestion.adapters import FalcoAdapter, GuardDutyAdapter, SourceAdapter, WazuhAdapter
from ingestion.auth import SourceCredential
from ingestion.coverage import CoverageTracker
from ingestion.evidence import EvidenceStore, InMemoryEvidenceStore, LocalEvidenceStore, S3EvidenceStore
from ingestion.pipeline import EventStore, IngestPipeline, InMemoryEventStore
from ingestion.router import build_router as build_ingestion_router
from ingestion.sqs_consumer import SqsConsumer
from investigator.offline import OfflineBaselineModel
from investigator.records import InMemoryInvestigationStore, InvestigationStore
from investigator.router import build_router as build_investigation_router
from investigator.runbooks import RunbookLibrary
from investigator.service import LanguageModel
from investigator.workflow import InvestigationService
from policy.engine import load_policies
from reporting.router import build_router as build_report_router
from responder.executor import Executor, KubernetesExecutor
from responder.quarantine import ExecTrafficProbe, TrafficProbe
from responder.remote import RemoteExecutor
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
    # S3 evidence, instead of a directory. The bucket and its KMS key go together.
    evidence_bucket: str | None = None
    evidence_kms_key_id: str | None = None
    # Reads GuardDuty findings from this queue (EventBridge -> SQS). Unset: no worker runs.
    findings_queue_url: str | None = None
    findings_wait_seconds: int = 20
    # postgresql://user:pass@host/db. Unset means in-memory stores (tests, quick demos).
    database_url: str | None = None
    database_schema: str | None = None
    # "k8s" resolves pod context from the Kubernetes API and AWS. Unset means no enrichment.
    enrichment: str | None = None
    # "remote" asks the responder service to act, so this process holds no write access.
    # "k8s" acts in-process with this process's own identity. Unset: no executor.
    executor: str | None = None
    responder_url: str | None = None
    responder_api_token_file: Path | None = None
    # Verify quarantines with real traffic. All three together or none: "namespace/pod" of the peer,
    # the mounted cloudshield-prober token, and "key=value,..." labels of the pods it may reach.
    probe_pod: str | None = None
    probe_token_file: Path | None = None
    probe_target_selector: str | None = None
    # Which policy environment this deployment is ("lab" or "prod"); the allowlist is per environment.
    environment: str = "lab"
    # "offline" = deterministic baseline (no LLM); "ollama" = a model on your own machine;
    # "bedrock" = Amazon Bedrock. Unset: investigations off.
    investigator: str | None = None
    bedrock_model_id: str | None = None
    bedrock_guardrail_id: str | None = None
    ollama_model: str | None = None
    ollama_url: str = "http://127.0.0.1:11434"
    runbooks_dir: Path | None = field(default_factory=lambda: _default_runbooks())
    # Lab demos only: lets the console open signed in as this analyst token (see console/router.py).
    console_demo_token: str | None = None
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
        probe_token_file = os.getenv("CLOUDSHIELD_PROBE_TOKEN_FILE")
        responder_token_file = os.getenv("CLOUDSHIELD_RESPONDER_API_TOKEN_FILE")
        return cls(
            cluster=os.getenv("CLOUDSHIELD_CLUSTER"),
            account_id=os.getenv("CLOUDSHIELD_ACCOUNT_ID"),
            region=os.getenv("AWS_REGION"),
            evidence_dir=Path(evidence_dir) if evidence_dir else None,
            evidence_bucket=os.getenv("CLOUDSHIELD_EVIDENCE_BUCKET"),
            evidence_kms_key_id=os.getenv("CLOUDSHIELD_EVIDENCE_KMS_KEY_ID"),
            findings_queue_url=os.getenv("CLOUDSHIELD_FINDINGS_QUEUE_URL"),
            database_url=os.getenv("CLOUDSHIELD_DATABASE_URL"),
            enrichment=os.getenv("CLOUDSHIELD_ENRICHMENT"),
            executor=os.getenv("CLOUDSHIELD_EXECUTOR"),
            responder_url=os.getenv("CLOUDSHIELD_RESPONDER_URL"),
            responder_api_token_file=Path(responder_token_file) if responder_token_file else None,
            probe_pod=os.getenv("CLOUDSHIELD_PROBE_POD"),
            probe_token_file=Path(probe_token_file) if probe_token_file else None,
            probe_target_selector=os.getenv("CLOUDSHIELD_PROBE_TARGET_SELECTOR"),
            environment=os.getenv("CLOUDSHIELD_ENVIRONMENT", "lab"),
            analysts=AnalystDirectory.from_json(os.getenv("CLOUDSHIELD_ANALYSTS")),
            investigator=os.getenv("CLOUDSHIELD_INVESTIGATOR"),
            bedrock_model_id=os.getenv("CLOUDSHIELD_BEDROCK_MODEL_ID"),
            bedrock_guardrail_id=os.getenv("CLOUDSHIELD_BEDROCK_GUARDRAIL_ID"),
            ollama_model=os.getenv("CLOUDSHIELD_OLLAMA_MODEL"),
            ollama_url=os.getenv("CLOUDSHIELD_OLLAMA_URL", "http://127.0.0.1:11434"),
            console_demo_token=os.getenv("CLOUDSHIELD_CONSOLE_DEMO_TOKEN"),
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


def build_evidence(settings: Settings) -> EvidenceStore:
    """Half a configuration fails at startup, rather than quietly keeping evidence somewhere else."""
    if bool(settings.evidence_bucket) != bool(settings.evidence_kms_key_id):
        raise ValueError(
            "S3 evidence needs both CLOUDSHIELD_EVIDENCE_BUCKET and CLOUDSHIELD_EVIDENCE_KMS_KEY_ID"
        )
    if settings.evidence_bucket and settings.evidence_dir:
        raise ValueError("set CLOUDSHIELD_EVIDENCE_BUCKET or CLOUDSHIELD_EVIDENCE_DIR, not both")
    if settings.evidence_bucket and settings.evidence_kms_key_id:
        import boto3

        client = boto3.client("s3", region_name=settings.region)
        return S3EvidenceStore(settings.evidence_bucket, settings.evidence_kms_key_id, client=client)
    return LocalEvidenceStore(settings.evidence_dir) if settings.evidence_dir else InMemoryEvidenceStore()


def build_model(settings: Settings) -> LanguageModel | None:
    if settings.investigator == "offline":
        return OfflineBaselineModel()
    if settings.investigator == "ollama":
        if not settings.ollama_model:
            raise ValueError("CLOUDSHIELD_INVESTIGATOR=ollama needs CLOUDSHIELD_OLLAMA_MODEL")
        from investigator.ollama import OllamaClient

        return OllamaClient(settings.ollama_model, url=settings.ollama_url)
    if settings.investigator == "bedrock":
        if not settings.bedrock_model_id:
            raise ValueError("CLOUDSHIELD_INVESTIGATOR=bedrock needs CLOUDSHIELD_BEDROCK_MODEL_ID")
        from investigator.bedrock import BedrockClient

        return BedrockClient(
            settings.bedrock_model_id, region=settings.region, guardrail_id=settings.bedrock_guardrail_id
        )
    return None


def build_traffic_probe(settings: Settings) -> TrafficProbe | None:
    """The verifier's traffic probe. Half a configuration fails at startup rather than skipping checks."""
    pod_ref, token_file, selector_text = (
        settings.probe_pod, settings.probe_token_file, settings.probe_target_selector,
    )  # fmt: skip
    if not (pod_ref or token_file or selector_text):
        return None
    if not (pod_ref and token_file and selector_text):
        raise ValueError(
            "the traffic probe needs CLOUDSHIELD_PROBE_POD, CLOUDSHIELD_PROBE_TOKEN_FILE "
            "and CLOUDSHIELD_PROBE_TARGET_SELECTOR together"
        )
    namespace, _, pod = pod_ref.partition("/")
    pairs = [part.partition("=") for part in selector_text.split(",")]
    if not (namespace and pod) or not all(key and sep and value for key, sep, value in pairs):
        raise ValueError("expected CLOUDSHIELD_PROBE_POD=namespace/pod and a selector of key=value,...")
    selector = {key.strip(): value.strip() for key, _, value in pairs}

    return ExecTrafficProbe.from_token_file(namespace, pod, token_file=token_file, target_selector=selector)


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

    coverage = CoverageTracker(settings.max_silence)
    metrics = Metrics(coverage)

    if executor is None and settings.executor == "k8s":
        from responder.quarantine import KubernetesPodApi

        executor = KubernetesExecutor(KubernetesPodApi(), probe=build_traffic_probe(settings))
    if executor is None and settings.executor == "remote":
        if not (settings.responder_url and settings.responder_api_token_file):
            raise ValueError(
                "CLOUDSHIELD_EXECUTOR=remote needs CLOUDSHIELD_RESPONDER_URL "
                "and CLOUDSHIELD_RESPONDER_API_TOKEN_FILE"
            )
        token = settings.responder_api_token_file.read_text(encoding="utf-8").strip()
        executor = RemoteExecutor.connect(settings.responder_url, token)
    response = ResponseService(
        stores.proposals,
        stores.cases,
        stores.audit,
        load_policies(),
        executor,
        environment=settings.environment,
        on_finished=metrics.observe_response,
    )
    response.recover_interrupted()
    investigations = InvestigationService(
        stores.investigations,
        stores.cases,
        stores.audit,
        RunbookLibrary.from_dir(settings.runbooks_dir),
        model or build_model(settings),
    )

    engine = CorrelationEngine(stores.cases)
    evidence = build_evidence(settings)

    if pod_resolver is None and settings.enrichment == "k8s" and settings.cluster:
        pod_resolver = kubernetes_pod_resolver(settings.cluster, settings.region)
    enrich = Enricher(pod_resolver, stores.entities) if pod_resolver else None

    link_lock = threading.Lock()

    def on_accepted(event: NormalizedEvent) -> None:
        """Also runs on a redelivery, to finish anything a failed attempt left undone."""
        with link_lock:  # two deliveries of one event must not both write its audit record
            case, link = engine.correlate(event)
            already_audited = any(
                r.action == "case.event_linked" and r.details.get("event_id") == event.event_id
                for r in stores.audit.records(case.case_id)
            )
            if already_audited:
                return
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
        metrics.observe_event(event)

    pipeline = IngestPipeline(stores.events, evidence, on_accepted=on_accepted, enrich=enrich)
    adapters: dict[str, SourceAdapter] = {
        "falco": FalcoAdapter(cluster=settings.cluster, account_id=settings.account_id),
        "wazuh": WazuhAdapter(account_id=settings.account_id),
        # GuardDuty arrives through the SQS worker; the HTTP route exists for replaying fixtures.
        "guardduty": GuardDutyAdapter(),
    }

    def on_finding(result: str) -> None:
        metrics.ingest_events.labels("guardduty", result).inc()
        if result != "invalid":  # the same rule as the HTTP route: a bad payload isn't a sign of life
            coverage.heartbeat("guardduty")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        stop = threading.Event()
        worker = None
        if settings.findings_queue_url:
            import boto3

            consumer = SqsConsumer(
                settings.findings_queue_url,
                pipeline,
                adapters["guardduty"],
                client=boto3.client("sqs", region_name=settings.region),
                on_result=on_finding,
            )
            worker = threading.Thread(
                target=consumer.run,
                args=(stop,),
                kwargs={"wait_seconds": settings.findings_wait_seconds},
                name="findings-consumer",
                daemon=True,
            )
            worker.start()
        yield
        stop.set()
        if worker:
            worker.join(settings.findings_wait_seconds + 5)  # it can be in the middle of a long poll
        stores.close()

    app = FastAPI(title="CloudShield", version="0.7.0", lifespan=lifespan)
    app.include_router(
        build_ingestion_router(pipeline, adapters, settings.credentials, coverage, settings.analysts, metrics)
    )
    app.include_router(build_cases_router(stores.cases, stores.audit, stores.entities, settings.analysts))
    app.include_router(build_response_router(response, settings.analysts))
    app.include_router(build_investigation_router(investigations, settings.analysts))
    app.include_router(build_console_router(settings.analysts, settings.console_demo_token))
    app.include_router(
        build_report_router(
            stores.cases,
            stores.investigations,
            stores.proposals,
            stores.audit,
            stores.entities,
            settings.analysts,
        )
    )

    @app.get(
        "/metrics",
        response_class=PlainTextResponse,
        # Sensor silence is useful to an attacker too, so this needs a login like every other route.
        # Prometheus sends a token with its `authorization` scrape setting.
        dependencies=[Depends(require_analyst(settings.analysts))],
    )
    def prometheus_metrics() -> Response:
        return Response(metrics.render(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
