"""End-to-end demo of scenario S1 through the real HTTP API, in one process.

    python scripts/demo.py                 # print the walkthrough
    python scripts/demo.py --svg docs/demo.svg

Everything runs through CloudShield's actual code: ingestion, OCSF normalization, enrichment,
correlation, the policy gate, approvals, execution, verification and the audit log. Only the
outside world is simulated: the Kubernetes API (a single pod plus its NetworkPolicies) and the
AWS lookups for that pod. No cluster or cloud account is needed.
"""

import argparse
import copy
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

from fastapi.testclient import TestClient  # noqa: E402

from core.app import Settings, create_app  # noqa: E402
from core.auth import AnalystDirectory, Principal  # noqa: E402
from enrichment.context import PodContext  # noqa: E402
from ingestion.auth import SIGNATURE_HEADER, SourceCredential, sign  # noqa: E402
from responder.executor import KubernetesExecutor  # noqa: E402

FIXTURES = ROOT / "detections" / "fixtures" / "s1_suspicious_process"
POD, POD_UID = "checkout-7d9f6c-x2k8p", "8b0e3c52-1d7a-4f43-9e6b-3a2c5d9f0e17"
ROLE = "arn:aws:iam::123456789012:role/shop-checkout-pod"


class SimulatedPodApi:
    """Stands in for the Kubernetes API: one pod and the namespace's quarantine-ready policies."""

    def __init__(self) -> None:
        self.pod = {
            "metadata": {"name": POD, "uid": POD_UID, "labels": {"app": "checkout"}},
            "status": {"phase": "Running"},
        }
        exclusion = {"key": "cloudshield.io/quarantine", "operator": "NotIn", "values": ["true"]}
        self.policies = [
            {"metadata": {"name": "default-deny-all"},
             "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
            {"metadata": {"name": "checkout-allow"},
             "spec": {"podSelector": {"matchLabels": {"app": "checkout"}, "matchExpressions": [exclusion]},
                      "policyTypes": ["Ingress"], "ingress": [{}]}},
        ]  # fmt: skip

    def get_pod(self, namespace: str, name: str) -> dict[str, Any] | None:
        return copy.deepcopy(self.pod) if name == POD else None

    def patch_pod_labels(
        self, namespace: str, name: str, labels: dict[str, str | None], *, dry_run: bool
    ) -> None:
        if not dry_run:
            self.pod["metadata"]["labels"].update({k: v for k, v in labels.items() if v is not None})

    def list_network_policies(self, namespace: str) -> list[dict[str, Any]]:
        return self.policies


def simulated_pod_context(namespace: str, pod: str) -> PodContext:
    return PodContext(
        namespace=namespace, pod=pod, pod_uid=POD_UID, node="ip-10-20-3-41.eu-west-1.compute.internal",
        service_account="checkout", owner_kind="Deployment", owner_name="checkout",
        labels={"app": "checkout"}, iam_role_arn=ROLE, instance_id="i-0a1b2c3d4e5f60718",
        resolved_at=datetime.now(UTC),
    )  # fmt: skip


class Transcript:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str]] = []  # (style, text)
        self.report = ""

    def say(self, text: str, style: str = "") -> None:
        self.lines.append((style, text))
        print(text)


def run() -> Transcript:
    out = Transcript()
    secret, falco_token = "demo-replay-key", "demo-falco-key"
    settings = Settings(
        cluster="cs-lab-eks",
        account_id="123456789012",
        investigator="offline",
        credentials={
            "falco": SourceCredential(token=falco_token),
            "guardduty": SourceCredential(hmac_secret=secret),
        },
        analysts=AnalystDirectory.from_tokens(
            {
                "alice-demo": Principal("analyst:alice", frozenset({"analyst"})),
                "bob-demo": Principal("analyst:bob", frozenset({"incident-responder"})),
            }
        ),
    )
    pods = SimulatedPodApi()
    api = TestClient(
        create_app(settings, pod_resolver=simulated_pod_context, executor=KubernetesExecutor(pods))
    )
    alice, bob = {"authorization": "Bearer alice-demo"}, {"authorization": "Bearer bob-demo"}

    def row(num: str, verb: str, what: str, result: str = "", style: str = "") -> None:
        out.say(f"{num:<3}{verb:<9}{what:<47}{'-> ' + result if result else ''}".rstrip(), style)

    def note(text: str) -> None:
        out.say(" " * 12 + text, "dim")

    out.say("CloudShield · scenario S1: suspicious process in a pod", "title")
    out.say("real API and logic · simulated Kubernetes API and AWS lookups", "dim")
    out.say("")

    gd = (FIXTURES / "guardduty_finding.json").read_bytes()
    r = api.post("/v1/ingest/guardduty", content=gd, headers={SIGNATURE_HEADER: sign(secret, gd)})
    row("1", "ingest", "GuardDuty: new binary executed in pod", f"{r.status_code} {r.json()['status']}")
    fa = (FIXTURES / "falco_alert.json").read_bytes()
    falco_auth = {"authorization": f"Bearer {falco_token}"}
    r = api.post("/v1/ingest/falco", content=fa, headers=falco_auth)
    row(
        "2", "ingest", "Falco: curl | sh in container (arrives late)", f"{r.status_code} {r.json()['status']}"
    )
    r = api.post("/v1/ingest/falco", content=fa, headers=falco_auth)
    row("", "replay", "same Falco alert delivered twice", f"{r.status_code} {r.json()['status']}", "dim")

    [case] = api.get("/v1/cases").json()
    detail = api.get(f"/v1/cases/{case['case_id']}").json()
    row(
        "3", "case", f"{case['event_count']} events in one case, severity {case['severity']}", case["case_id"]
    )
    note(f"joined by rule {detail['links'][1]['rule']}: same pod UID within 15 min")
    for t in api.get(f"/v1/cases/{case['case_id']}/timeline").json():
        note(f"{t['event_time'][11:19]}Z  {t['source']:<9} {t['title'][:40]}")
    graph = api.get(f"/v1/entities/k8s:pod/shop/{POD}/graph").json()
    row("4", "enrich", "pod > deployment > service account > IAM role", f"{len(graph['entities'])} entities")
    inv = api.post(f"/v1/cases/{case['case_id']}/investigations", headers=alice).json()
    facts = inv["output"]["observed_facts"]
    row("5", "AI", f"{len(facts)} facts, each citing a real event ID", "stored for review")
    note(f"runbook retrieved: {', '.join(inv['retrieved_doc_ids'])} · offline baseline model (no LLM)")
    review = {"decision": "accepted", "note": "facts match the Falco and GuardDuty evidence"}
    r = api.post(f"/v1/investigations/{inv['investigation_id']}/review", json=review, headers=bob)
    note(f"analyst review: {r.json()['review_status']} by bob")

    body = {"action_type": "k8s.pod.quarantine_label", "rationale": "curl | sh from 198.51.100.23",
            "target": {"kind": "Pod", "name": POD, "uid": POD_UID, "namespace": "shop"}}  # fmt: skip
    p = api.post(f"/v1/cases/{case['case_id']}/proposals", json=body, headers=alice).json()
    row("6", "propose", "alice: quarantine the pod", p["state"])
    p = api.post(f"/v1/proposals/{p['proposal_id']}/dry-run", headers=bob).json()
    row("7", "gate", "dry-run passed, policy allows with approval", p["state"])
    note(f"impact: pod keeps running, loses {', '.join(p['impact_preview']['allow_policies_lost'])}")

    pid, decision = p["proposal_id"], {"justification": "confirmed remote script execution"}
    stale = {**decision, "proposal_hash": "sha256:stale"}
    current = {**decision, "proposal_hash": p["proposal_hash"]}
    r = api.post(f"/v1/proposals/{pid}/approve", json=stale, headers=bob)
    row("8", "approve", "bob, quoting an outdated proposal hash", f"{r.status_code} refused", "bad")
    r = api.post(f"/v1/proposals/{pid}/approve", json=current, headers=alice)
    row("", "approve", "alice, approving her own proposal", f"{r.status_code} refused", "bad")
    r = api.post(f"/v1/proposals/{pid}/approve", json=current, headers=bob)
    row("", "approve", "bob, current hash", r.json()["state"], "good")

    x = api.post(f"/v1/proposals/{pid}/execute", headers=bob).json()
    row("9", "execute", "label the pod, then verify", x["state"], "good")
    marks = {True: "ok", False: "FAILED", None: "skipped (planned)"}
    for name, passed in x["execution"]["checks"].items():
        note(f"{name:<30} {marks[passed]}")
    r = api.post(f"/v1/proposals/{pid}/execute", headers=bob)
    row("", "execute", "run it a second time", f"{r.status_code} refused", "bad")

    audit = api.get("/v1/audit", params={"case_id": case["case_id"]}).json()
    intact = "intact" if audit["chain_intact"] else "BROKEN"
    row("10", "audit", f"{len(audit['records'])} hash-chained records", f"chain {intact}", "good")

    report = api.get(f"/v1/cases/{case['case_id']}/report", headers=bob)
    out.report = report.text
    row(
        "11",
        "report",
        "post-incident report from recorded evidence",
        f"{len(report.text.splitlines())} lines",
    )
    return out


COLORS = {"title": "#e6edf3", "dim": "#8b949e", "good": "#3fb950", "bad": "#f0883e", "": "#c9d1d9"}


def to_svg(transcript: Transcript, command: str = "python scripts/demo.py") -> str:
    from html import escape

    line_h, pad, char_w = 19, 18, 7.4
    width = int(max(len(t) for _, t in transcript.lines) * char_w + 2 * pad)
    height = len(transcript.lines) * line_h + 2 * pad + 22
    rows = []
    for i, (style, text) in enumerate(transcript.lines):
        y = pad + 30 + i * line_h
        weight = ' font-weight="bold"' if style == "title" else ""
        attrs = f'x="{pad}" y="{y}" fill="{COLORS[style]}"{weight} xml:space="preserve"'
        rows.append(f"<text {attrs}>{escape(text)}</text>")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" '
        f'font-size="12.5">\n'
        f'<rect width="{width}" height="{height}" rx="8" fill="#0d1117"/>\n'
        f'<circle cx="18" cy="16" r="5" fill="#ff5f56"/><circle cx="34" cy="16" r="5" fill="#ffbd2e"/>'
        f'<circle cx="50" cy="16" r="5" fill="#27c93f"/>\n'
        f'<text x="{width - pad}" y="20" fill="#6e7681" text-anchor="end">{escape(command)}</text>\n'
        + "\n".join(rows)
        + "\n</svg>\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--svg", type=Path, help="also write the transcript as an SVG terminal image")
    parser.add_argument("--report", type=Path, help="also write the incident report it generates")
    args = parser.parse_args()
    transcript = run()
    if args.svg:
        args.svg.parent.mkdir(parents=True, exist_ok=True)
        args.svg.write_text(to_svg(transcript), encoding="utf-8", newline="\n")
        print(f"\nwrote {args.svg}")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(transcript.report, encoding="utf-8", newline="\n")
        print(f"wrote {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
