import os
import secrets
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cases.store import InMemoryCaseStore
from core.app import Settings, Stores, build_stores
from correlation.engine import CorrelationEngine
from ingestion.adapters import FalcoAdapter, GuardDutyAdapter
from ingestion.evidence import InMemoryEvidenceStore
from ingestion.pipeline import IngestPipeline, InMemoryEventStore

FIXTURES = Path(__file__).resolve().parents[1] / "detections" / "fixtures"
CLUSTER = "cs-lab-eks"
ACCOUNT = "123456789012"
NOW = datetime(2026, 10, 28, 14, 5, tzinfo=UTC)

# A disposable PostgreSQL database for store tests. CI provides a postgres:16 service container.
PG_URL = os.getenv("CLOUDSHIELD_TEST_DATABASE_URL")


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


@pytest.fixture
def pg_schema() -> Iterator[str]:
    """A fresh schema per test, dropped afterwards."""
    if not PG_URL:
        if os.getenv("CLOUDSHIELD_REQUIRE_POSTGRES_TESTS"):
            pytest.fail("PostgreSQL tests are required here but CLOUDSHIELD_TEST_DATABASE_URL is not set")
        pytest.skip("CLOUDSHIELD_TEST_DATABASE_URL not set")
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql

    schema = f"test_{secrets.token_hex(6)}"
    with psycopg.connect(PG_URL, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    try:
        yield schema
    finally:
        with psycopg.connect(PG_URL, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
def stores(request: pytest.FixtureRequest) -> Iterator[Stores]:
    """Every store contract test runs against both implementations."""
    if request.param == "memory":
        built = build_stores(Settings())
    else:
        schema = request.getfixturevalue("pg_schema")
        built = build_stores(Settings(database_url=PG_URL, database_schema=schema))
    try:
        yield built
    finally:
        built.close()
