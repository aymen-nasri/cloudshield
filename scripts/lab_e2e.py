"""Scenario S1 against a real Kubernetes cluster: the kind lab, end to end.

    make lab-up && make lab-e2e            # or: python scripts/lab_e2e.py --svg lab-run.svg

Unlike scripts/demo.py, nothing on the Kubernetes side is simulated. The S1 Falco alert is
re-addressed to a live checkout pod; enrichment reads the cluster as the investigator service
account; the quarantine runs as the responder service account; and a probe pod proves with real
traffic that the NetworkPolicies cut the quarantined pod off and that rollback restores it. Only AWS
is missing (kind has no EKS Pod Identity or EC2), so those fields stay unresolved.

Exits non-zero if any check fails, so CI can run it on every pull request.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "scripts"))

from fastapi.testclient import TestClient  # noqa: E402
from kubernetes import client, config  # noqa: E402
from kubernetes.client.exceptions import ApiException  # noqa: E402

from core.app import Settings, create_app  # noqa: E402
from core.auth import AnalystDirectory, Principal  # noqa: E402
from demo import Transcript, to_svg  # noqa: E402
from enrichment.context import PodContext, resolve_pod_context  # noqa: E402
from ingestion.auth import SourceCredential  # noqa: E402
from responder.executor import KubernetesExecutor  # noqa: E402
from responder.quarantine import KubernetesPodApi  # noqa: E402

FIXTURE = ROOT / "detections" / "fixtures" / "s1_suspicious_process" / "falco_alert.json"
CLUSTER, NS, PROBE = "kind-cloudshield-lab", "shop", "probe"


def kubectl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["kubectl", *args], capture_output=True, text=True, check=check)  # noqa: S603, S607


def as_service_account(name: str) -> client.ApiClient:
    """An API client that authenticates as cloudshield/<name>, not as the cluster admin."""
    token = kubectl("-n", "cloudshield", "create", "token", name, "--duration=1h").stdout.strip()
    cfg = client.Configuration()
    config.load_kube_config(client_configuration=cfg)
    cfg.cert_file = cfg.key_file = None  # drop the admin client certificate
    cfg.api_key = {"authorization": f"Bearer {token}"}
    return client.ApiClient(cfg)


def reachable(ip: str, *, expect: bool = True) -> bool:
    """Can the probe pod (labelled like cart) open a new connection to this pod on 8080?

    Calico applies a label change within seconds, so retry briefly until the expected answer shows.
    """
    for attempt in range(5):
        r = kubectl("-n", NS, "exec", PROBE, "--", "curl", "-s", "-m", "3", f"http://{ip}:8080/", check=False)
        ok = r.returncode == 0 and "checkout ok" in r.stdout
        if ok is expect or attempt == 4:
            return ok
        time.sleep(2)
    return False


def forbidden(call: Callable[[], Any]) -> bool:
    try:
        call()
    except ApiException as exc:
        return exc.status == 403
    return False


class NoAws:
    """kind has no EKS Pod Identity or EC2: these lookups fail and are left unresolved."""

    def __getattr__(self, name: str) -> Any:
        raise RuntimeError("no AWS account in the kind lab")


def falco_alert_for(pod: Any) -> bytes:
    """The S1 fixture, re-addressed to a live pod, as Falcosidekick would deliver it."""
    alert = json.loads(FIXTURE.read_text(encoding="utf-8"))
    old = alert["output_fields"]["k8s.pod.name"]
    alert["uuid"] = str(uuid.uuid4())
    alert["time"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    alert["hostname"] = pod.spec.node_name
    alert["output"] = alert["output"].replace(old, pod.metadata.name)
    alert["output_fields"]["k8s.pod.name"] = pod.metadata.name
    alert["output_fields"]["k8s.pod.uid"] = pod.metadata.uid
    return json.dumps(alert).encode()


def run() -> tuple[Transcript, list[str]]:
    out, failures = Transcript(), []
    config.load_kube_config()
    admin = client.CoreV1Api()
    investigator, responder = (
        as_service_account("cloudshield-investigator"),
        as_service_account("cloudshield-responder"),
    )

    def row(num: str, verb: str, what: str, result: str = "", ok: bool | None = None) -> None:
        style = {True: "good", False: "bad", None: ""}[ok]
        out.say(f"{num:<3}{verb:<9}{what:<50}{'-> ' + result if result else ''}".rstrip(), style)
        if ok is False:
            failures.append(f"{verb}: {what}")

    def note(text: str) -> None:
        out.say(" " * 12 + text, "dim")

    def resolve(namespace: str, pod: str) -> PodContext:
        return resolve_pod_context(
            core=client.CoreV1Api(investigator), apps=client.AppsV1Api(investigator),
            eks=NoAws(), ec2=NoAws(), cluster=CLUSTER, namespace=namespace, pod_name=pod,
        )  # fmt: skip

    settings = Settings(
        cluster=CLUSTER,
        investigator="offline",
        credentials={"falco": SourceCredential(token="lab-falco-key")},  # noqa: S106
        analysts=AnalystDirectory.from_tokens(
            {
                "alice-lab": Principal("analyst:alice", frozenset({"analyst"})),
                "bob-lab": Principal("analyst:bob", frozenset({"incident-responder"})),
            }
        ),
    )
    executor = KubernetesExecutor(KubernetesPodApi(responder), identity="cloudshield-responder")
    api = TestClient(create_app(settings, pod_resolver=resolve, executor=executor))
    alice, bob = {"authorization": "Bearer alice-lab"}, {"authorization": "Bearer bob-lab"}

    out.say("CloudShield · scenario S1 on a real Kubernetes cluster (kind)", "title")
    out.say("real API, cluster, RBAC and NetworkPolicies · no AWS (IAM role and EC2 stay unresolved)", "dim")
    out.say("")

    nodes = admin.list_node().items
    pods = sorted(
        (p for p in admin.list_namespaced_pod(NS, label_selector="app=checkout").items
         if p.status.phase == "Running"),
        key=lambda p: p.metadata.name,
    )  # fmt: skip
    target, other = pods[0], pods[1]
    row("1", "cluster", f"{len(nodes)} nodes, Calico, shop app with {len(pods)} checkout pods", "ready")
    note(f"target {target.metadata.name} ({target.status.pod_ip}) on {target.spec.node_name}")
    before = reachable(target.status.pod_ip) and reachable(other.status.pod_ip)
    row("", "traffic", "probe -> both checkout pods on 8080", "reachable" if before else "BLOCKED", before)

    r = api.post("/v1/ingest/falco", content=falco_alert_for(target),
                 headers={"authorization": "Bearer lab-falco-key"})  # fmt: skip
    row("2", "ingest", "Falco: curl | sh in the target pod", f"{r.status_code} {r.json().get('status')}",
        r.status_code < 300)  # fmt: skip
    [case] = api.get("/v1/cases").json()
    row("3", "case", f"{case['event_count']} event, severity {case['severity']}", case["case_id"])

    pod_id = f"k8s:pod/{NS}/{target.metadata.name}"
    graph = api.get(f"/v1/entities/{pod_id}/graph").json()
    ids = {e["entity_id"] for e in graph.get("entities", [])}
    traced = f"k8s:deployment/{NS}/checkout" in ids
    row("4", "enrich", "pod > deployment > service account > node", f"{len(ids)} entities", traced)
    note("read as cloudshield-investigator (read-only RBAC); IAM role and EC2: unresolved")

    body = {"action_type": "k8s.pod.quarantine_label", "rationale": "curl | sh in a protected workload",
            "target": {"kind": "Pod", "name": target.metadata.name, "uid": target.metadata.uid,
                       "namespace": NS}}  # fmt: skip
    p = api.post(f"/v1/cases/{case['case_id']}/proposals", json=body, headers=alice).json()
    row("5", "propose", "alice: quarantine the target pod", p["state"])
    p = api.post(f"/v1/proposals/{p['proposal_id']}/dry-run", headers=bob).json()
    lost = (p.get("impact_preview") or {}).get("allow_policies_lost") or []
    row("6", "gate", "dry run as the responder, then the policy gate", p["state"],
        "checkout-allow" in lost)  # fmt: skip
    note(f"impact: pod keeps running, loses {', '.join(lost)}")

    decision = {"justification": "confirmed remote script execution", "proposal_hash": p["proposal_hash"]}
    p = api.post(f"/v1/proposals/{p['proposal_id']}/approve", json=decision, headers=bob).json()
    row("7", "approve", "bob, incident responder", p["state"])
    x = api.post(f"/v1/proposals/{p['proposal_id']}/execute", headers=bob).json()
    row("8", "execute", "label the live pod as cloudshield-responder", x["state"], x["state"] == "verified")
    marks = {True: "ok", False: "FAILED", None: "skipped"}
    for name, passed in x["execution"]["checks"].items():
        note(f"{name:<30} {marks[passed]}")

    cut = not reachable(target.status.pod_ip, expect=False)
    row("9", "traffic", "probe -> quarantined pod", "blocked" if cut else "STILL REACHABLE", cut)
    spared = reachable(other.status.pod_ip)
    row("", "traffic", "probe -> another checkout pod", "reachable" if spared else "BLOCKED", spared)
    phase = admin.read_namespaced_pod(target.metadata.name, NS).status.phase
    row("", "forensic", "quarantined pod still running", phase, phase == "Running")

    body = {**body, "action_type": "k8s.pod.remove_quarantine_label", "rationale": "rollback after review"}
    p = api.post(f"/v1/cases/{case['case_id']}/proposals", json=body, headers=alice).json()
    p = api.post(f"/v1/proposals/{p['proposal_id']}/dry-run", headers=bob).json()
    decision = {"justification": "evidence collected", "proposal_hash": p["proposal_hash"]}
    p = api.post(f"/v1/proposals/{p['proposal_id']}/approve", json=decision, headers=bob).json()
    x = api.post(f"/v1/proposals/{p['proposal_id']}/execute", headers=bob).json()
    released = x["state"] == "verified"
    row("10", "rollback", "remove the label (proposed, approved, verified)", x["state"], released)
    back = reachable(target.status.pod_ip)
    row("", "traffic", "probe -> released pod", "reachable" if back else "BLOCKED", back)

    resp, inv = client.CoreV1Api(responder), client.CoreV1Api(investigator)
    patch = {"metadata": {"labels": {"x": "y"}}}
    checks = {
        "responder cannot delete the pod": forbidden(
            lambda: resp.delete_namespaced_pod(target.metadata.name, NS, dry_run="All")),
        "responder cannot read secrets": forbidden(lambda: resp.list_namespaced_secret(NS)),
        "responder cannot touch kube-system": forbidden(
            lambda: resp.patch_namespaced_pod("coredns", "kube-system", patch, dry_run="All")),
        "investigator cannot patch pods": forbidden(
            lambda: inv.patch_namespaced_pod(target.metadata.name, NS, patch, dry_run="All")),
        "investigator cannot read secrets": forbidden(lambda: inv.list_namespaced_secret(NS)),
    }  # fmt: skip
    row("11", "rbac", "least privilege, checked against the API server",
        f"{sum(checks.values())}/{len(checks)} refused", all(checks.values()))  # fmt: skip
    for name, refused in checks.items():
        note(f"{name:<34} {'403' if refused else 'ALLOWED'}")

    audit = api.get("/v1/audit", params={"case_id": case["case_id"]}).json()
    intact = audit["chain_intact"]
    chain = "chain intact" if intact else "BROKEN"
    row("12", "audit", f"{len(audit['records'])} hash-chained records", chain, intact)
    out.say("")
    verdict = f"{len(failures)} check(s) FAILED" if failures else "all checks passed"
    out.say(verdict, "bad" if failures else "good")
    return out, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--svg", type=Path, help="also write the transcript as an SVG terminal image")
    args = parser.parse_args()
    logging.getLogger("enrichment.context").setLevel(logging.ERROR)  # the expected "no AWS" warnings
    transcript, failures = run()
    text = "\n".join(t for _, t in transcript.lines)
    if summary := os.getenv("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"### Kind lab: scenario S1 end to end\n\n```text\n{text}\n```\n")
    if args.svg:
        args.svg.parent.mkdir(parents=True, exist_ok=True)
        args.svg.write_text(to_svg(transcript, "python scripts/lab_e2e.py"), encoding="utf-8", newline="\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
