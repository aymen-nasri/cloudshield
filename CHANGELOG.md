# Changelog

All notable changes to CloudShield. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- The traffic probe can be turned on through settings (`CLOUDSHIELD_PROBE_POD`, `CLOUDSHIELD_PROBE_TOKEN_FILE`, `CLOUDSHIELD_PROBE_TARGET_SELECTOR`). Half a configuration fails at startup. The kind lab uses these settings and fails if the probe was skipped.
- The Kyverno image policy runs in the kind lab in Enforce mode. In the `cloudshield` namespace, the lab checks that the image signed by this repository's workflow is admitted, an unsigned image is rejected (`no signatures found`), and an image signed by someone else is rejected (`subject mismatch`).
- CloudShield runs as a pod in the kind lab, installed by its Helm chart from this commit's image, and Falcosidekick posts to its Service. The pod runs as the read-only investigator and mounts separate tokens for the responder and the prober. The lab no longer runs the API on the CI machine.
- On `main`, a new job deploys the image just signed with image verification enforced from the start, and checks that an unsigned image is refused for real.

### Changed
- With no AWS region, the IAM role and EC2 lookups are off rather than failing at startup. The Helm chart's default image is now the signed one on GHCR.

### Fixed
- **Reads had no login.** `/v1/cases`, case details, timelines, the entity graph, `/v1/audit` and `/v1/health/coverage` answered anyone, including the attacker's command line in case details, while the docs listed required scopes that didn't exist. They now need an analyst, and a test sweeps every route in the API schema, so a new route can't be left open by accident.
- A `viewer` could run a proposal's dry run and move it to awaiting approval. It now needs the `analyst` or `incident-responder` role.
- The API table now says who can really call each route, and no longer lists `/v1/events`, which doesn't exist.
- The image policy only checked images under CloudShield's own names, so an image under any other name went unchecked. It now matches every image in the `cloudshield` namespace.
- The traffic probe could report a false pass. Quarantining a pod its peer was never allowed to reach failed to connect and counted as blocked. A block now counts only if the peer could connect just before the quarantine, and pods outside the probe's configured reach are skipped in both directions.

## [0.3.0] - 2026-11-04

Scenario S1 now runs for real: on every pull request, a live attack in a kind cluster is detected by
Falco and carried through to a verified quarantine and rollback. Images are published and signed.
It has not yet run on EKS, a real AWS account or Bedrock.

### Added
- CI job `kind lab, scenario S1 end to end`: a three-node kind cluster with Calico runs `scripts/lab_e2e.py`. CloudShield quarantines a live pod as its responder service account, a probe pod confirms with real traffic that the pod is cut off and that rollback restores it, and six RBAC checks are refused by the API server. Run it locally with `make lab-e2e`.
- The kind lab runs Falco (modern eBPF) and Falcosidekick. CI executes a download-and-run inside a live pod; Falco's own alert reaches CloudShield through the token-authenticated webhook and drives the whole scenario, with no fixture.
- Kyverno v1.19.2 runs in the kind lab with the quarantine guard in Enforce mode. CI checks that the API server rejects an allow-policy that forgets the quarantine exclusion and admits the same policy with it.
- Dependency review on every pull request (fails on a high or critical vulnerability or a GPL/AGPL license), and Dependabot weekly updates for Python packages, GitHub Actions and the Docker base image.
- The verifier tests real traffic. With a traffic probe configured, a quarantine passes only when a peer the policies normally allow can no longer connect, and a rollback only when it can connect again. The probe runs as a new `cloudshield-prober` identity that may exec into the probe pod and nothing else. The check is renamed from `egress_probe` to `traffic_probe`.
- Every push to `main` publishes the image to `ghcr.io/aymen-nasri/cloudshield`, signs it keylessly with Cosign, attaches the CycloneDX SBOM as a signed attestation, and verifies both against the workflow's identity. No AWS account needed.

### Changed
- The Kyverno quarantine guard moved from Audit to Enforce. The image signature policy also covers GHCR, and stays in Audit.
- GitHub Actions updated to their Node 24 versions, including checkout v7, setup-python v7, upload-artifact v7 and gitleaks-action v3.
- The README is now a short front page with one build status table, with deep dives in `docs/` and a guide in each main folder.

### Fixed
- CloudShield's Falco rules are ordered specific-first: Falco fires only the first matching rule, so the catch-all rule was hiding the critical `curl | sh` rule. Rule outputs now include the pod UID and container ID.
- The kind lab retries applying the Kyverno policy until its webhook answers, and raises the runner's inotify limits so that Falco starts on every node.

## [0.2.0] - 2026-10-29

More attack coverage, and the cross-layer link between a Kubernetes runtime alert and an AWS
identity finding.

### Added
- Replayable attack scenarios S2 (stolen pod credentials used outside AWS), S3 (Linux host compromise via Wazuh) and S6 (benign interactive shell); `tests/test_scenarios.py` replays every fixture against its `expected.yaml`.
- GuardDuty IAM findings carry the principal's ARN, so they correlate with pod alerts on the same role (C-03); Wazuh and GuardDuty evidence details reach the investigation.

### Changed
- C-04: account-level findings (no cluster) may join a cluster's case in the same account; two different clusters still never merge.
- The offline baseline recommends containment only for corroborated evidence (two sources, or a high-severity finding), and lists missing evidence by resource type.

## [0.1.0] - 2026-10-29

First release: the full detect → investigate → approve → contain → verify → report loop works in
code and in CI. It has not yet run on a real cluster or AWS account (see the README roadmap).

### Added
- **Ingestion:** Falco, GuardDuty and Wazuh adapters normalized to an OCSF subset; fail-closed
  producer authentication (bearer token, HMAC-SHA256); idempotent delivery; raw evidence archived
  with SHA-256; sensor coverage reported as degraded when a source goes quiet.
- **Correlation and cases:** rules C-01 to C-04 (pod UID, instance, IAM principal, never across
  account or cluster); event-time timelines; tamper-evident hash-chained audit log.
- **Enrichment and entity graph:** pod → deployment → service account → IAM role (EKS Pod Identity)
  → EC2 instance, with assurance levels; reused pod names and AWS outages leave fields unresolved.
- **Storage:** PostgreSQL stores behind the same interfaces as the in-memory ones; versioned
  migrations applied on startup; one contract test suite runs against both.
- **Response workflow:** propose → dry-run and policy gate → hash-bound, expiring, role-checked
  approvals (never by the requester) → execute at most once → verify; reversible pod quarantine
  with rollback; Step Functions definition for the AWS path.
- **AI investigations:** evidence bundles wrapped as untrusted, runbook retrieval by event type and
  ATT&CK technique, answers stored only if every citation is real, analyst review; offline
  baseline model for running without AWS; Bedrock client; evaluation harness.
- **Analyst console:** the incident page served by the API, built from text nodes only, with a
  strict Content-Security-Policy.
- **Post-incident report:** `GET /v1/cases/{id}/report` and a console download button; Markdown built
  only from recorded evidence, with attacker-supplied text escaped.
- **Infrastructure:** OpenTofu AWS lab (VPC, EKS, GuardDuty → EventBridge → SQS, S3 Object Lock,
  budgets, GitHub OIDC), kind lab, quarantine-ready NetworkPolicies, Kyverno policies, RBAC, Helm,
  Ansible.
- **CI:** ruff, mypy, pytest with a PostgreSQL service, schema drift check, eval harness, Gitleaks,
  Trivy image scan and SBOM, and infrastructure validation (tofu validate, helm lint, kubeconform,
  kyverno test, Ansible syntax check).

[0.3.0]: https://github.com/aymen-nasri/cloudshield/releases/tag/v0.3.0
[0.2.0]: https://github.com/aymen-nasri/cloudshield/releases/tag/v0.2.0
[0.1.0]: https://github.com/aymen-nasri/cloudshield/releases/tag/v0.1.0
