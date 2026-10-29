# Problem, users and positioning

Why CloudShield exists, who it is for, and how it sits next to existing tools. Part of the [CloudShield documentation](../README.md#documentation).

Status markers: ✅ built and tested · 🧩 written as code, not deployed · 📐 designed only.

## The problem it solves

Picture a growing SaaS company: applications on EKS, Linux machines on EC2, databases, public APIs, CI/CD pipelines and a small security and platform team. An incident fires signals in CloudTrail, GuardDuty, host logs and Kubernetes runtime monitoring, and **no single alert explains the full situation**.

| Pain point | Today's failure mode | With CloudShield |
|---|---|---|
| Fragmented visibility | Engineers jump between consoles, SIEM searches and cluster tools | One connected case with source-specific evidence |
| Alert fatigue | Duplicate and related alerts compete for attention | Deduplication and explainable incident grouping |
| Slow investigations | Resource, owner and workload context is gathered by hand | Automatic evidence retrieval, with unknowns stated explicitly |
| Unsafe response | Automated isolation can break production or destroy evidence | Risk preview, approval, safeguards and verification |
| Weak documentation | Actions and decisions are poorly recorded | A reproducible timeline, evidence index and after-action report |
| Inconsistent process | Different engineers follow different manual playbooks | Approved, testable workflows with access controls |

### Who it is for

| User | What they need from CloudShield |
|---|---|
| **SOC analyst** | Connected evidence, triage context, investigation help and a clear audit trail |
| **Cloud security engineer** | AWS identity, resource and permission context for planning a response |
| **Platform / SRE engineer** | The availability impact of a containment action *before* it happens |
| **Security team lead** | Measurable incident handling and repeatable, approved procedures |

**First target customer:** a small cloud security team (2–5 engineers) running workloads on AWS EKS. Enterprise multi-account coverage comes later.

> Success is not measured by the number of integrations. Every tool in CloudShield has to reduce analyst steps, improve evidence completeness or make risky changes safer. Otherwise it only adds operating cost.

---

## Key capabilities

| # | Capability | How CloudShield delivers it |
|---|---|---|
| 1 | **Unified visibility** | Relates AWS findings, Linux activity, Kubernetes events and network flows to applications, identities, hosts, containers and services |
| 2 | **Faster investigation** | Gathers linked evidence automatically, groups related signals, builds a timeline and shows what is known, suspected and still missing |
| 3 | **Less alert fatigue** | Deduplicates repeated findings and ranks cases by source confidence, exposure, affected assets and business criticality |
| 4 | **Safer response automation** | Scoped action proposals, consequence preview, mandatory approval, separate execution permissions and verified outcomes |
| 5 | **Cloud and Kubernetes attack visibility** | Suspicious runtime behavior, unsafe workload-to-IAM links, unusual service communication and security-relevant config changes |
| 6 | **Better security posture** | Combines known vulnerabilities (Trivy), configuration risk and runtime evidence to prioritize what is actually deployed and reachable |
| 7 | **Evidence preservation and learning** | Integrity-protected raw evidence, recorded decisions and reviewed improvements fed back into detections and runbooks |
| 8 | **Repeatable at scale** | Versioned infrastructure, common schemas, reusable workflows and modular source adapters |

---

## Positioning against existing tools

CloudShield respects and builds on the tools that already exist:

| Existing capability | Reference solution | What CloudShield adds |
|---|---|---|
| AWS managed findings and AI analysis | GuardDuty and its AI-powered investigations [[R1]](references.md#references) [[R18]](references.md#references) | Linux and Kubernetes context, plus independent response safety |
| Host monitoring and SIEM | Wazuh [[R5]](references.md#references) | Unified case context and cross-source evidence |
| Kubernetes runtime detection | Falco [[R6]](references.md#references) | Evidence correlation, analyst workflow and action safeguards |
| SIEM correlation | OpenSearch Security Analytics [[R9]](references.md#references) | Resource and identity mapping, controlled end-to-end response |
| Cloud workflow automation | EventBridge, Lambda, Step Functions [[R2]](references.md#references) | A policy and review layer with verified outcomes |
| LLM safeguards | Bedrock Guardrails, OWASP guidance [[R10]](references.md#references) [[R12]](references.md#references) | A concrete security design and evaluation, not just an AI label |

---

## Product decisions

Answers to the questions that shape the first release:

| Question | Decision |
|---|---|
| **Who is the first customer?** | A small cloud security team (2–5 people) on AWS EKS. SOC-team and DevSecOps-team variants follow. |
| **Which incident is the most representative and reproducible?** | A suspicious process in a pod. It reproduces locally and on EKS, touches every layer and has a clean reversible response. |
| **What must an analyst see before trusting an action?** | The cited evidence, the exact target, the blast radius and known dependencies, the dry-run result, the rollback path and the approval expiry. |
| **What are the first five things on the incident page?** | Synopsis + severity; the affected-entity chain; a sourced timeline; facts vs hypotheses vs missing evidence; the proposed action with its impact preview. |
| **What are the minimum controls for one safe response?** | An allowlist, a hash-bound and time-limited named approval, an idempotency key, a dry-run, a separate executor identity, verification and an audit record. |
| **What can't a solo project collect cheaply?** | Full packet capture, long-retention flow logs at scale, organization-wide multi-account GuardDuty, always-on managed OpenSearch. These are replaced with fixtures and replayable incidents. |
| **What counts as a genuine improvement over existing tools?** | A measured drop in case assembly time against a manual baseline, higher evidence completeness and zero unsafe actions passing the gate. |

| Decision register | Initial choice | Revisit when |
|---|---|---|
| Product identity | Unified CloudShield with one focused first scenario | The first analyst workflow is validated |
| Where to begin | Local lab, then a small AWS account with EKS | Cloud-specific evidence is needed |
| Detection inputs | Falco + one GuardDuty path | Case correlation is reliable |
| Backend | Python/FastAPI + PostgreSQL + a limited search store | Event volume requires scaling |
| AI | One Bedrock model + a small RAG corpus | Evidence and safety tests pass |
| Response action | One lab-contained, reversible action | Approval and verification are reliable |
| Networking | Native Kubernetes policies + AWS flow context | eBPF observability is needed |
| CI/CD | GitHub Actions + reviewed deployment, GitOps later | Continuous cluster reconciliation is needed |

---

## Glossary

| Term | Meaning |
|---|---|
| **SOC** | Security Operations Center: the people and workflows that detect, investigate and respond to security events |
| **SIEM** | Security Information and Event Management: aggregation, search, alerting and analysis of security data |
| **SOAR** | Security Orchestration, Automation and Response: repeatable integrations and action workflows |
| **EKS** | Amazon Elastic Kubernetes Service |
| **IAM** | Identity and Access Management |
| **RBAC** | Role-Based Access Control for the Kubernetes API |
| **eBPF** | A Linux kernel mechanism used by tools like Falco and Cilium for observation and enforcement |
| **OCSF** | Open Cybersecurity Schema Framework, a vendor-neutral schema for security events |
| **RAG** | Retrieval-Augmented Generation: adding selected evidence or reference text to an LLM request |
| **MCP** | Model Context Protocol, for exposing tools and context to AI applications |
| **GitOps** | Managing deployment state declaratively in version-controlled repositories |
| **SBOM** | Software Bill of Materials: an inventory of software components and dependencies |
| **HITL** | Human-in-the-loop: an explicit review or approval point in automation |
| **Blast radius** | The operational and security scope affected by an incident or a proposed action |
| **Provenance** | The recorded origin and processing history of a piece of data, an analysis or an action |
| **Idempotency** | The property that repeating an operation has the same effect as doing it once |
| **MITRE ATT&CK** | A knowledge base of adversary tactics and techniques used to label detections |
