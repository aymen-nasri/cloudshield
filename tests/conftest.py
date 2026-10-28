from datetime import UTC, datetime
from pathlib import Path

import pytest

from cases.store import InMemoryCaseStore
from correlation.engine import CorrelationEngine
from ingestion.adapters import FalcoAdapter, GuardDutyAdapter
from ingestion.evidence import InMemoryEvidenceStore
from ingestion.pipeline import IngestPipeline, InMemoryEventStore

FIXTURES = Path(__file__).resolve().parents[1] / "detections" / "fixtures"
CLUSTER = "cs-lab-eks"
ACCOUNT = "123456789012"
NOW = datetime(2026, 10, 28, 14, 5, tzinfo=UTC)


def fixture_bytes(scenario: str, name: str) -> bytes:
    return (FIXTURES / scenario / name).read_bytes()


@pytest.fixture
def falco() -> FalcoAdapter:
    return FalcoAdapter(cluster=CLUSTER, account_id=ACCOUNT)


@pytest.fixture
def guardduty() -> GuardDutyAdapter:
    return GuardDutyAdapter()


@pytest.fixture
def cases() -> InMemoryCaseStore:
    return InMemoryCaseStore()


@pytest.fixture
def pipeline(cases: InMemoryCaseStore) -> IngestPipeline:
    engine = CorrelationEngine(cases)
    return IngestPipeline(
        InMemoryEventStore(), InMemoryEvidenceStore(), on_accepted=engine.correlate, clock=lambda: NOW
    )
