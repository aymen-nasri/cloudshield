# Roadmap

Milestones, exit criteria, the definition of the MVP and the planned features. Part of the [CloudShield documentation](../README.md#documentation).

Status markers: ✅ built and tested · 🧩 written as code, not deployed · 📐 designed only · 🔬 run on an emulator or a stand-in, not on real AWS.

## Roadmap

The roadmap is ordered by **learning and risk reduction**, not by the number of tools installed. Each milestone has a hard exit criterion.

| Milestone | Build | Exit criterion | Deliberately avoid | Status |
|---|---|---|---|---|
| **M1 · Protected lab and repeatable deployment** | Small app on Kubernetes, a Linux host, network baseline, AWS logging and identity, IaC and documentation | Another engineer can reproduce the isolated lab and inspect its topology | Agentic AI, multiple clusters, destructive response | 🟡 In progress |
| **M2 · Security operations core** | Two source types, OCSF normalization, PostgreSQL + OpenSearch, basic cases and dashboard, simple correlation | A simulated alert can be traced to its raw evidence and correct resource context | Recreating a full SIEM | 🟡 In progress |
| **M3 · AI investigator (read-only)** | One LLM, runbook corpus, retrieval, bounded evidence packets, structured cited summaries, evaluation fixtures | Grounded summaries on labeled incidents; all negative tests pass | Trusting model-generated commands or exploitability claims | 🟡 In progress |
| **M4 · Controlled response** | Response state machine, approval, policy gate, one reversible lab action, audit and verification | Detect → investigate → approve → act → verify, end to end | Real production auto-isolation | 🟡 In progress |
| **M5 · Cross-layer expansion** | Hubble/Cilium, deeper AWS identity context, network relationship mapping, broader runbooks, scoped multi-step read-only agent | A second, distinct scenario handled with measured improvement | Any tool that doesn't improve a validated workflow | ⬜ Planned |

### Definition of the MVP

**One** protected test workload + **one** runtime detector + **one** cloud context source + **one** evidence and case backend + **one** LLM investigator + **one** human approval gate + **one** reversible response + **one** verification report.

### Planned features

Designed and scheduled, not built yet. Each one moves to ✅ in the [Build status](status.md#build-status) table only when it runs in CI or in a lab.

| Feature | What it adds | Milestone |
|---|---|---|
| **AWS lab bring-up** | GuardDuty → EventBridge → SQS → CloudShield on a real account, with budget alarms | M1 |
| **Bedrock with a Guardrail** | The evaluation harness scored against a real model before it is trusted | M3 |
| **OpenSearch** | Search across events, and similar past cases for the investigator | M2 |
| **Security Hub and CloudTrail ingestion** | Wider AWS coverage through the same adapters and correlation rules | M5 |
| **More response actions** | Revoke an IAM role's sessions; isolate an EC2 instance with a Security Group | M5 |
| **Cilium and Hubble** | Network flow evidence for the unexpected-egress scenario (S4) | M5 |
| **Approvals from Slack or Teams** | Approve from chat, still bound to the proposal hash and the approver's role | M5 |
| **Multi-step read-only agent** | Deeper investigations with LangGraph and MCP tools, still without write access | M5 |
