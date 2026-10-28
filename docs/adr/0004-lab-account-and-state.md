# ADR 0004: Dedicated lab account, budget first, remote state

**Status:** accepted · 2026-10-28

## Decision
- The AWS lab runs in its own AWS account, never alongside anything real.
- `guardrails.tf` (AWS Budgets at 50/80/100%, alert topic) is applied before EKS or GuardDuty.
- OpenTofu state lives in a versioned, encrypted S3 bucket created once by hand and passed at
  init time: `tofu init -backend-config="bucket=<state-bucket>" -backend-config="region=<region>"`.
  S3 native locking (`use_lockfile`) replaces a DynamoDB lock table.
- The lab is torn down with `tofu destroy` after each demo window.

## Consequences
- Cost is bounded and visible.
- No state or credentials are ever committed (see `.gitignore`).
