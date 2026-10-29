# Design decisions

Trade-offs, environments, cost guardrails and the build checklist. Part of the [CloudShield documentation](../README.md#documentation).

Status markers: ✅ built and tested · 🧩 written as code, not deployed · 📐 designed only.

## Design decisions and trade-offs

| Decision | Chosen | Alternative considered | Why |
|---|---|---|---|
| Correlation approach | Deterministic, entity- and time-window rules | ML clustering | Explainable, testable, no labeled data needed; ML can come later on top |
| First detector | Falco | Wazuh first | Best fit for container runtime behavior; Wazuh adds host breadth as the second source |
| Case store | PostgreSQL | Graph database | Transactional approvals and audit; the graph lives in typed edge tables until queries demand more |
| Search | OpenSearch, lexical first (planned; runbooks use front-matter matching today) | Vector-only retrieval | Exact matching on IDs and IOCs matters more early; vectors are added for similarity later |
| Event schema | OCSF subset + raw preserved | Custom schema | Vendor-neutral semantics without losing source fidelity |
| LLM hosting | Amazon Bedrock | Self-hosted model | Data stays in the AWS account and IAM boundary, with managed Guardrails; local models evaluated later for cost or privacy |
| AI output | Pydantic-validated structure, closed action vocabulary | Free-text answers | Machine-checkable citations; no executable output possible |
| Response orchestration | Step Functions + Lambda | Long-running worker | Durable approval waits, timeouts, retries and visible execution history |
| Quarantine mechanism | Label + default-deny + Kyverno-enforced exclusion | Deleting the pod / scaling to zero | Reversible, preserves forensics, works with additive NetworkPolicy semantics |
| CI credentials | GitHub OIDC → AWS STS | Stored access keys | No long-lived secrets to leak |
| Networking start | Native NetworkPolicies + VPC context | Cilium from day one | Lower operational risk; eBPF added when observability needs it |

---

## Deployment environments and cost guardrails

| Environment | Good for | What to avoid |
|---|---|---|
| **Local Kubernetes lab** (kind) | Fast iteration on Falco, the backend, cases and the test workload | Assuming local results match EKS exactly |
| **Small AWS lab** | CloudTrail, GuardDuty, EKS identity, EventBridge integration | Always-on EKS, always-on OpenSearch, excess log retention |
| **Hybrid simulation** | EC2/RHEL host plus cluster, optional pfSense | Complex networks before there's a clear use case |
| **Production-like demo** | Security boundaries, CI/CD, recovery and audit tests | Claiming production readiness without load and security testing |

**Main cost drivers:** the EKS control plane and worker nodes, NAT gateways, load balancers and data transfer; CloudTrail, GuardDuty and Security Hub settings; OpenSearch; S3 evidence retention; Bedrock inference and embeddings; network telemetry volume; CI and registry usage.

**Guardrails:**

- AWS Budgets and alarms are set **before** anything is provisioned, in a dedicated lab account.
- Cloud resources run in on-demand demo windows and are torn down afterwards (`make lab-down`).
- Managed OpenSearch and multi-cluster setups are deferred until justified; smaller local components come first.
- Event volume is measured before retention is set; unnecessary logs are redacted and minimized.
- A written list of enabled AWS features is kept, and current regional pricing is checked before each deployment.

---

## First implementation checklist

| Area | Definition of done |
|---|---|
| Product definition | One target user, one incident scenario, an expected response decision, a success metric |
| Lab boundary | Isolated AWS account or local cluster, synthetic data, budget alarms, cleanup plan |
| Detection | One meaningful Falco finding and one cloud-side evidence source |
| Ingestion | Validated adapters, raw evidence, deduplication, normalized IDs |
| Context | Correct pod / service / instance mapping with clear evidence links |
| Cases | Incident state, timeline, affected entity, provenance, analyst notes |
| AI | Bounded evidence input, runbook retrieval, fact/hypothesis separation, citations |
| Approvals | Authenticated analyst, specific target, policy gate, denial handling |
| Response | One reversible action with idempotency, timeout and verification |
| DevSecOps | Tests, secrets hygiene, scanned and signed artifacts, least privilege |
| Operations | Health checks, error logging, rate limits, retention, cost limits |
| Proof | Recorded demo, negative tests, metrics, reproducible instructions |
