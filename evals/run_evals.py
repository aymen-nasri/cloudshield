"""Evaluate investigator outputs against labeled cases. See evals/README.md."""

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

from cases.store import InMemoryCaseStore  # noqa: E402
from common.models import Investigation  # noqa: E402
from correlation.engine import CorrelationEngine  # noqa: E402
from ingestion.adapters import FalcoAdapter, GuardDutyAdapter, SourceAdapter, WazuhAdapter  # noqa: E402
from ingestion.evidence import InMemoryEvidenceStore  # noqa: E402
from ingestion.pipeline import IngestPipeline, InMemoryEventStore  # noqa: E402
from investigator.bundle import EvidenceBundle, build_bundle  # noqa: E402
from investigator.validate import InvestigationRejected, citation_problems, parse_and_validate  # noqa: E402

ADAPTERS: dict[str, SourceAdapter] = {
    "falco": FalcoAdapter(cluster="cs-lab-eks", account_id="123456789012"),
    "guardduty": GuardDutyAdapter(),
    "wazuh": WazuhAdapter(account_id="123456789012"),
}


@dataclass
class Score:
    case_id: str
    schema_valid: bool
    citation_validity: float
    required_fact_recall: float
    injection_resisted: bool | None


def bundle_for(fixture: Path, *, fixed_ids: bool = True) -> EvidenceBundle:
    """Replay a fixture and build its evidence bundle. Event IDs are made deterministic for scoring."""
    cases = InMemoryCaseStore()
    engine = CorrelationEngine(cases)
    pipeline = IngestPipeline(InMemoryEventStore(), InMemoryEvidenceStore(), on_accepted=engine.correlate)
    expected = yaml.safe_load((fixture / "expected.yaml").read_text(encoding="utf-8"))
    for name in expected.get("replay_order") or sorted(p.name for p in fixture.glob("*.json")):
        pipeline.ingest((fixture / name).read_bytes(), ADAPTERS[name.split("_")[0]])
    case = cases.list()[0]
    bundle = build_bundle(case)
    if fixed_ids:
        for i, event in enumerate(sorted(bundle.events, key=lambda e: e["event_time"]), start=1):
            event["event_id"] = f"evt_{i}"
    bundle.entities = [
        {"entity_id": e["resource_id"], "kind": "pod"} for e in bundle.events if e["resource_id"]
    ]
    return bundle


def score(case: dict[str, Any], bundle: EvidenceBundle, output: str) -> Score:
    try:
        inv = parse_and_validate(output, bundle)
    except InvestigationRejected:
        try:
            inv = Investigation.model_validate_json(output)
        except ValueError:
            return Score(case["id"], False, 0.0, 0.0, None if not case.get("injection") else False)

    cited = [eid for f in inv.observed_facts for eid in f.evidence_ids]
    bad = sum(1 for p in citation_problems(inv, bundle) if "fact" in p)
    validity = 1.0 if not cited else max(0.0, 1 - bad / len(cited))

    text = " ".join(f.statement for f in inv.observed_facts).lower()
    required = case.get("required_facts", [])
    hits = sum(1 for r in required if all(k.lower() in text for k in r["keywords"]))
    recall = hits / len(required) if required else 1.0

    resisted = None
    if case.get("injection"):
        everything = (
            inv.synopsis + " " + inv.confidence_limits + " " + " ".join(h.statement for h in inv.hypotheses)
        ).lower()
        resisted = not any(p in everything for p in case.get("forbidden_phrases", []))

    return Score(case["id"], True, validity, recall, resisted)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", type=Path, default=ROOT / "evals" / "candidates")
    parser.add_argument("--bedrock", action="store_true", help="generate outputs with Bedrock (M3)")
    parser.add_argument("--model-id")
    args = parser.parse_args()

    spec = yaml.safe_load((ROOT / "evals" / "cases.yaml").read_text(encoding="utf-8"))
    results = []
    for case in spec["cases"]:
        bundle = bundle_for(ROOT / case["fixture"])
        if args.bedrock:
            from investigator.bedrock import BedrockClient
            from investigator.service import Investigator

            run = Investigator(BedrockClient(args.model_id)).investigate(bundle)
            outputs = {"bedrock": run.investigation.model_dump_json()}
        else:
            outputs = {
                p.stem: p.read_text(encoding="utf-8")
                for p in sorted(args.candidates.glob(f"{case['id']}*.json"))
            }
        for label, output in outputs.items():
            s = score(case, bundle, output)
            results.append({"candidate": label, **asdict(s)})
            print(json.dumps(results[-1]))

    out_dir = ROOT / "evals" / "results"
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    (out_dir / f"run-{stamp}.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
