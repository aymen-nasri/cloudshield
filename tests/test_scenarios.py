"""Every attack scenario in detections/fixtures replays to what its expected.yaml says.

Adding a scenario folder with an expected.yaml adds a test: no code change needed.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from core.app import Settings, build_stores
from core.auth import Principal
from correlation.engine import CorrelationEngine
from enrichment.context import PodContext
from enrichment.enricher import Enricher
from ingestion.adapters import FalcoAdapter, GuardDutyAdapter, WazuhAdapter
from ingestion.evidence import InMemoryEvidenceStore
from ingestion.pipeline import IngestPipeline
from investigator.offline import OfflineBaselineModel
from investigator.runbooks import RunbookLibrary
from investigator.workflow import InvestigationService
from tests.conftest import ACCOUNT, CLUSTER, FIXTURES, fixture_bytes

SCENARIOS = sorted(p for p in FIXTURES.iterdir() if (p / "expected.yaml").exists())
RUNBOOKS = Path(__file__).resolve().parents[1] / "runbooks"
ROLE = "arn:aws:iam::123456789012:role/shop-checkout-pod"
ANALYST = Principal("analyst:test", frozenset({"analyst"}))


def _adapters():
    return {
        "falco": FalcoAdapter(cluster=CLUSTER, account_id=ACCOUNT),
        "guardduty": GuardDutyAdapter(),
        "wazuh": WazuhAdapter(account_id=ACCOUNT),
    }


def _replay(stores, folder: Path, names: list[str], enrich=None) -> None:
    engine = CorrelationEngine(stores.cases)
    pipeline = IngestPipeline(
        stores.events, InMemoryEvidenceStore(), on_accepted=engine.correlate, enrich=enrich
    )
    adapters = _adapters()
    for name in names:
        pipeline.ingest((folder / name).read_bytes(), adapters[name.split("_")[0]])


def test_every_scenario_folder_is_covered():
    expected = {"s1_suspicious_process", "s2_identity_misuse", "s3_host_compromise"}
    expected |= {"s6_benign_exec", "s8_prompt_injection"}
    assert {p.name for p in SCENARIOS} >= expected


@pytest.mark.parametrize("folder", SCENARIOS, ids=lambda p: p.name)
def test_scenario_replays_as_expected(folder: Path):
    spec = yaml.safe_load((folder / "expected.yaml").read_text(encoding="utf-8"))
    expect = spec["expect"]
    stores = build_stores(Settings())
    _replay(stores, folder, spec.get("replay_order") or sorted(p.name for p in folder.glob("*.json")))

    cases = stores.cases.list()
    assert len(cases) == expect["cases"]
    case = max(cases, key=lambda c: len(c.events))
    if "links" in expect:
        assert [(e.source, link.rule) for e, link in zip(case.events, case.links, strict=True)] == [
            (x["source"], x["rule"]) for x in expect["links"]
        ]
    if "severity" in expect:
        assert case.severity.value == expect["severity"]
    if "containment" in expect:
        service = InvestigationService(
            stores.investigations,
            stores.cases,
            stores.audit,
            RunbookLibrary.from_dir(RUNBOOKS),
            OfflineBaselineModel(),
        )
        record = service.run(case.case_id, ANALYST)
        assert bool(record.output.containment_options) is expect["containment"]
        cited = {i for f in record.output.observed_facts for i in f.evidence_ids}
        assert cited == {e.event_id for e in case.events}


def _pod_context(namespace: str, pod: str) -> PodContext:
    return PodContext(
        namespace=namespace, pod=pod, pod_uid="8b0e3c52-1d7a-4f43-9e6b-3a2c5d9f0e17", node="node-1",
        service_account="checkout", owner_kind="Deployment", owner_name="checkout", labels={},
        iam_role_arn=ROLE, instance_id="i-0a1b2c3d4e5f60718", resolved_at=datetime.now(UTC),
    )  # fmt: skip


def test_stolen_pod_credentials_join_the_pod_case_across_layers():
    """S1's pod alert, enriched with the pod's IAM role, and S2's credential-exfiltration finding on
    that role: rule C-03 joins a Kubernetes runtime alert and an AWS identity finding in one case."""
    stores = build_stores(Settings())
    enrich = Enricher(_pod_context, stores.entities)
    _replay(stores, FIXTURES / "s1_suspicious_process", ["falco_alert.json"], enrich)
    _replay(stores, FIXTURES / "s2_identity_misuse", ["guardduty_exfiltration.json"], enrich)

    [case] = stores.cases.list()
    assert [(e.source, link.rule) for e, link in zip(case.events, case.links, strict=True)] == [
        ("falco", "C-00"),
        ("guardduty", "C-03"),
    ]
    assert case.cluster == CLUSTER
    assert case.severity.value == "high"


def test_account_level_case_takes_the_first_cluster_and_then_refuses_others():
    stores = build_stores(Settings())
    enrich = Enricher(_pod_context, stores.entities)
    _replay(stores, FIXTURES / "s2_identity_misuse", ["guardduty_exfiltration.json"])
    [case] = stores.cases.list()
    assert case.cluster is None

    _replay(stores, FIXTURES / "s1_suspicious_process", ["falco_alert.json"], enrich)
    [case] = stores.cases.list()
    assert case.cluster == CLUSTER

    other = FalcoAdapter(cluster="another-cluster", account_id=ACCOUNT)
    engine = CorrelationEngine(stores.cases)
    IngestPipeline(
        stores.events, InMemoryEvidenceStore(), on_accepted=engine.correlate, enrich=enrich
    ).ingest(fixture_bytes("s6_benign_exec", "falco_alert.json"), other)
    assert len(stores.cases.list()) == 2  # same role, different cluster: never merged (C-04)
