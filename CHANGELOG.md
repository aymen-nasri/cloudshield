# Changelog

All notable changes to CloudShield. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- CI job `kind lab, scenario S1 end to end`: a three-node kind cluster with Calico runs `scripts/lab_e2e.py`. CloudShield quarantines a live pod as its responder service account, a probe pod confirms with real traffic that the pod is cut off and that rollback restores it, and five RBAC checks are refused by the API server. Run it locally with `make lab-e2e`.
- The kind lab runs Falco (modern eBPF) and Falcosidekick. CI executes a download-and-run inside a live pod; Falco's own alert reaches CloudShield through the token-authenticated webhook and drives the whole scenario, with no fixture.
- Kyverno v1.19.2 runs in the kind lab with the quarantine guard in Enforce mode. CI checks that the API server rejects an allow-policy that forgets the quarantine exclusion and admits the same policy with it.
- Dependency review on every pull request (fails on a high or critical vulnerability or a GPL/AGPL license), and Dependabot weekly updates for Python packages, GitHub Actions and the Docker base image.
- The verifier tests real traffic. With a traffic probe configured, a quarantine passes only when a peer the policies normally allow can no longer connect, and a rollback only when it can connect again. The probe runs as a new `cloudshield-prober` identity that may exec into the probe pod and nothing else. The check is renamed from `egress_probe` to `traffic_probe`.

### Fixed
- CloudShield's Falco rules are ordered specific-first: Falco fires only the first matching rule, so the catch-all rule was hiding the critical `curl | sh` rule. Rule outputs now include the pod UID and container ID.

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

[0.2.0]: https://github.com/aymen-nasri/cloudshield/releases/tag/v0.2.0
[0.1.0]: https://github.com/aymen-nasri/cloudshield/releases/tag/v0.1.0
