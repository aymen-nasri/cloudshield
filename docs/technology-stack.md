# Technology stack

Every technology by layer, what it is for, and whether it is built. Part of the [CloudShield documentation](../README.md#documentation).

Status markers: ✅ built and tested · 🧩 written as code, not deployed · 📐 designed only.

## Technology stack by layer

### AWS cloud layer

| Technology | Responsibility | Integration and constraints | Status |
|---|---|---|---|
| **Amazon VPC** | Network boundary, subnets, routing and security context | Security Groups, flow logs and network inventory | 🧩 |
| **Amazon EC2** | Linux hosts and demo workloads | Host agents, instance metadata, approved isolation actions | 🧩 hosts · 📐 isolation |
| **Amazon EKS** | Managed Kubernetes | Workload and cluster metadata, EKS identity context | 🧩 |
| **AWS IAM** | Authorization and roles | Least-privilege *read* roles, separately scoped *response* roles | 🧩 |
| **AWS CloudTrail** | AWS API activity history | Selective query and export; not a host activity feed | 📐 |
| **Amazon GuardDuty** | Managed threat detection | Findings delivered via EventBridge [[R2]](references.md#references); CloudShield never duplicates managed detection | ✅ adapter · 🧩 detector |
| **AWS Security Hub** | Finding aggregation and posture | Can re-publish GuardDuty findings [[R3]](references.md#references), so canonical IDs and dedup are mandatory | 📐 |
| **Amazon EventBridge** | Routing selected security events | Rule filters → SQS → CloudShield adapter | 🧩 |
| **Amazon SQS** | Durable buffering between AWS and CloudShield | Redrive to a dead-letter queue; no silent loss | ✅ consumer · 🧩 queues |
| **AWS Lambda** | Short, explicitly scoped response handlers | Invoked only after authorization and approval | ✅ handler · 🧩 deployment |
| **AWS Step Functions** | Durable response orchestration | Tracks steps, approval waits, timeouts and retries | 🧩 definition, statically tested |
| **Amazon S3** | Evidence and report storage | SSE-KMS, versioning, Object Lock, lifecycle, checksums | ✅ store · 🧩 bucket |
| **Amazon Bedrock** | Managed LLM inference | Investigation summaries only; no AWS mutation rights | 🧩 client, not yet run |
| **Amazon ECR** | Container image registry | Only signed, scanned images are deployed | 🧩 |

**Identity design.** CloudShield workloads on EKS get narrowly scoped AWS permissions through **EKS Pod Identity** [[R4]](references.md#references). Read-only evidence roles are separate from action roles. No static AWS access keys exist in containers or CI jobs.

### Linux and Kubernetes layer

| Technology | Why it belongs | How it connects | Status |
|---|---|---|---|
| **RHEL / Amazon Linux** | Realistic host administration and process-level scenarios | Wazuh agent or curated host log export | 🧩 |
| **Kubernetes (EKS)** | Runs the protected apps and CloudShield's own services | Pod, namespace, service account, event and audit context | ✅ kind in CI · 🧩 EKS |
| **Helm** | Repeatable cluster components | Versioned, per-environment releases | 🧩 |
| **Falco** | Near-real-time Linux and container runtime detection | Falcosidekick → token-authenticated webhook → adapter [[R6]](references.md#references) | ✅ rules and adapter |
| **Wazuh** | Host logs, security events, file integrity, endpoint visibility | Wazuh integrator → adapter [[R5]](references.md#references) | ✅ adapter · 🧩 agent |
| **Kubernetes RBAC** | Bounded cluster access by role and namespace | Read-only investigator identity; separate responder identity | ✅ refusals checked on kind in CI |
| **EKS Pod Identity** | AWS permissions per service account | Scoped credential delivery [[R4]](references.md#references) | ✅ enrichment · 🧩 association |
| **Trivy** | Vulnerability and misconfiguration scanning | CI reports and optional case enrichment | ✅ CI scan · 📐 case enrichment |
| **Kyverno** | Admission policy, image verification | Policy reports; audit mode first, then enforce [[R13]](references.md#references) | ✅ policy tests · 🧩 admission |

> **Falco and Wazuh are complementary, not interchangeable.** Falco is the primary source for container runtime behavior. Wazuh adds breadth for host and endpoint events. They can overlap, and the correlation engine treats them as distinct sources of evidence.

### Networking and eBPF

| Component | Role | Key limitation | Status |
|---|---|---|---|
| **VPC Flow Logs** | Flow metadata: IPs, ports, accept/reject | No payloads; must be explicitly enabled | 🧩 enabled · 📐 ingested |
| **Security Groups** | AWS network access controls | A change can affect critical services | 📐 |
| **Kubernetes NetworkPolicies** | Pod ingress and egress control | Enforcement depends on the CNI | ✅ traffic-tested on kind with Calico |
| **Cilium** *(advanced)* | eBPF networking and security | Operational learning curve | 📐 |
| **Hubble** *(advanced)* | Service-to-service flow visibility on Cilium | Does not replace host or AWS logs [[R7]](references.md#references) | 📐 |
| **pfSense** *(optional)* | Hybrid/on-prem firewall simulation | Outside the first EKS scenario | 📐 |

eBPF lets supported programs run safely in the Linux kernel. Falco uses kernel-level event sources for behavioral detection, while Cilium and Hubble give a richer picture of communication between Kubernetes services. CloudShield treats these as **different sensors with different jobs**, not one universal sensor.

> **Why networking matters to response safety:** an isolation action can block malicious egress *and* break calls to a payment service or database. CloudShield shows the affected workload and its known communications before proposing a policy, and it never treats "no traffic seen in the observation window" as proof that no dependency exists.

---

## How the components connect

Every integration in CloudShield defines what crosses it **and** the protection enforced at that boundary.

| From → to | What flows | Rule / protection |
|---|---|---|
| GuardDuty → EventBridge → SQS → adapter | Finding IDs, resource references, timestamps | Filter event types, verify origin, deduplicate |
| Wazuh → adapter | Host and security alerts with source metadata | Authenticate source; preserve raw event |
| Falco → Falcosidekick → adapter | Runtime alerts with container and pod context | Bearer token inside the cluster; alert text treated as **untrusted input** |
| Kubernetes API → enrichment | Pod, namespace, owner, service account metadata | Read-only RBAC; lookups cached and timestamped |
| AWS read role → enrichment | Resource attributes, scoped IAM context | Least privilege; no write permissions |
| VPC Flow Logs / Hubble → correlation | Observed endpoints and flow metadata | Never infer full reachability from partial logs |
| Adapters → OCSF mapping | Normalized fields, source links, stable IDs | Versioned mappings; originals never discarded |
| Correlation → PostgreSQL / OpenSearch | Cases, event relationships, timeline, search index | Lineage and access boundaries preserved |
| Evidence + runbooks → RAG → LLM | Curated evidence and reference passages | Redaction, scoped retrieval, mandatory citations |
| LLM → analyst console | Summary, hypotheses, questions, non-executable proposal | Schema validation; uncertainty shown explicitly |
| Analyst + policy → response engine | Approved, target-scoped request | Strong auth, independent allowlist, approval trace |
| Response engine → AWS / Kubernetes | One permitted action plus a verification query | Scoped IAM/RBAC, timeout, idempotency |
| Execution → case / report | Observed result, evidence and status | Hash-chained audit events and post-checks |
| GitHub Actions → ECR → cluster | Built, scanned, signed releases | OIDC, policy gates, health checks, rollback |
