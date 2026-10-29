"""Run the analyst console locally against demo data.

    python scripts/console_demo.py            # then open http://127.0.0.1:8090/console

Starts the real core API in memory, replays scenario S1 (and the S8 prompt-injection alert),
runs an investigation with the offline baseline model and leaves a quarantine proposal waiting for
approval. The Kubernetes API and AWS lookups are simulated (scripts/demo.py). The page opens
signed in as bob, an incident-responder, so the approve and execute buttons work; alice proposed
the action, so bob is allowed to approve it.
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "scripts"))

import uvicorn  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from core.app import Settings, create_app  # noqa: E402
from core.auth import AnalystDirectory, Principal  # noqa: E402
from demo import POD, POD_UID, SimulatedPodApi, simulated_pod_context  # noqa: E402
from ingestion.auth import SIGNATURE_HEADER, SourceCredential, sign  # noqa: E402
from responder.executor import KubernetesExecutor  # noqa: E402

FIXTURES = ROOT / "detections" / "fixtures"
REPLAY_KEY, FALCO_KEY = "console-demo-replay", "console-demo-falco"
ALICE, BOB = "alice-console-demo", "bob-console-demo"


def build():
    settings = Settings(
        cluster="cs-lab-eks",
        account_id="123456789012",
        investigator="offline",
        console_demo_token=BOB,
        credentials={
            "falco": SourceCredential(token=FALCO_KEY),
            "guardduty": SourceCredential(hmac_secret=REPLAY_KEY),
        },
        analysts=AnalystDirectory.from_tokens(
            {
                ALICE: Principal("analyst:alice", frozenset({"analyst"})),
                BOB: Principal("analyst:bob", frozenset({"incident-responder"})),
            }
        ),
    )
    return create_app(
        settings, pod_resolver=simulated_pod_context, executor=KubernetesExecutor(SimulatedPodApi())
    )


def preload(app) -> None:
    api = TestClient(app)
    falco = {"authorization": f"Bearer {FALCO_KEY}"}
    alice = {"authorization": f"Bearer {ALICE}"}

    gd = (FIXTURES / "s1_suspicious_process" / "guardduty_finding.json").read_bytes()
    api.post("/v1/ingest/guardduty", content=gd, headers={SIGNATURE_HEADER: sign(REPLAY_KEY, gd)})
    api.post(
        "/v1/ingest/falco",
        content=(FIXTURES / "s1_suspicious_process" / "falco_alert.json").read_bytes(),
        headers=falco,
    )
    api.post(
        "/v1/ingest/falco",
        content=(FIXTURES / "s8_prompt_injection" / "falco_alert.json").read_bytes(),
        headers=falco,
    )

    s1 = next(c for c in api.get("/v1/cases").json() if c["event_count"] == 2)["case_id"]
    api.post(f"/v1/cases/{s1}/investigations", headers=alice)
    body = {"action_type": "k8s.pod.quarantine_label", "rationale": "curl | sh from 198.51.100.23",
            "target": {"kind": "Pod", "name": POD, "uid": POD_UID, "namespace": "shop"}}  # fmt: skip
    proposal = api.post(f"/v1/cases/{s1}/proposals", json=body, headers=alice).json()
    api.post(f"/v1/proposals/{proposal['proposal_id']}/dry-run", headers=alice)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    app = build()
    preload(app)
    print(f"CloudShield console: http://127.0.0.1:{args.port}/console  (demo data, simulated cluster)")
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
