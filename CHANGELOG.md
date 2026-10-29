# Changelog

All notable changes to CloudShield. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

[0.1.0]: https://github.com/aymen-nasri/cloudshield/releases/tag/v0.1.0
