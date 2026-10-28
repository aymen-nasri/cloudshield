"""Application factory. Run with: uvicorn core.app:create_app --factory"""

import os
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI

from cases.audit import AuditLog
from cases.router import build_router as build_cases_router
from cases.store import InMemoryCaseStore
from common.models import NormalizedEvent
from correlation.engine import CorrelationEngine
from ingestion.adapters import FalcoAdapter, GuardDutyAdapter, SourceAdapter, WazuhAdapter
from ingestion.auth import SourceCredential
from ingestion.coverage import CoverageTracker
from ingestion.evidence import EvidenceStore, InMemoryEvidenceStore, LocalEvidenceStore
from ingestion.pipeline import IngestPipeline, InMemoryEventStore
from ingestion.router import build_router as build_ingestion_router


@dataclass
class Settings:
    cluster: str | None = None
    account_id: str | None = None
    evidence_dir: Path | None = None
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
            evidence_dir=Path(evidence_dir) if evidence_dir else None,
            credentials=credentials,
        )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    cases = InMemoryCaseStore()
    audit = AuditLog()
    engine = CorrelationEngine(cases)
    evidence: EvidenceStore = (
        LocalEvidenceStore(settings.evidence_dir) if settings.evidence_dir else InMemoryEvidenceStore()
    )

    def on_accepted(event: NormalizedEvent) -> None:
        case, link = engine.correlate(event)
        audit.append(
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

    pipeline = IngestPipeline(InMemoryEventStore(), evidence, on_accepted=on_accepted)
    adapters: dict[str, SourceAdapter] = {
        "falco": FalcoAdapter(cluster=settings.cluster, account_id=settings.account_id),
        "wazuh": WazuhAdapter(account_id=settings.account_id),
        # GuardDuty arrives through the SQS worker; the HTTP route exists for replaying fixtures.
        "guardduty": GuardDutyAdapter(),
    }
    coverage = CoverageTracker(settings.max_silence)

    app = FastAPI(title="CloudShield", version="0.1.0")
    app.include_router(build_ingestion_router(pipeline, adapters, settings.credentials, coverage))
    app.include_router(build_cases_router(cases, audit))

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
